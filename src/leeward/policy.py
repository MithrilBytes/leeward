# SPDX-License-Identifier: Apache-2.0
"""Resolve a call to the policy that governs it, and remember why.

Every field of a resolved policy carries what decided it: a rule, the origin's own
Cache-Control, a method with side effects, or the defaults. `leeward classify`
prints that provenance, because a policy nobody can explain is one nobody will
trust during an outage.

The volatility class is decided by the first matching rule, then the origin's
Cache-Control, then side effect heuristics, then the configured default.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Literal
from urllib.parse import urlsplit

from leeward.cache.freshness import delta_seconds, header_values, parse_cache_control
from leeward.config import ClassMapping, Config, Rule
from leeward.units import human_duration
from leeward.vocab import Volatility

CLASS_STALE_ON_ERROR_S: Mapping[Volatility, float] = {
    Volatility.STATIC: 30 * 86400.0,
    Volatility.SLOW: 7 * 86400.0,
    Volatility.VOLATILE: 3600.0,
    Volatility.LIVE: 0.0,
    Volatility.NEVER: 0.0,
}
MODEL_SOFT_DEADLINE_S = 20.0
MODEL_HARD_DEADLINE_S = 120.0
SAFE_METHODS = frozenset({"GET", "HEAD"})
"""Safe and cacheable by default: RFC 9110 §9.2.1 and RFC 9111 §3."""

ONE_DAY_S = 86400
ONE_YEAR_S = 31536000
"""RFC 9111 §5.2.2.1 caps a meaningful max-age near one year for "never expires"."""

_IDENTIFIER_SEGMENT = re.compile(
    r"^(?:[0-9]+|[0-9a-fA-F]{16,}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})$"
)
_DEFAULT_PORTS = {"http": 80, "https": 443}

TargetKind = Literal["http", "tool", "tier"]


@dataclass(frozen=True, slots=True)
class CallTarget:
    """What a call is aimed at: a URL and method, an MCP `server/tool`, or a model tier."""

    kind: TargetKind
    name: str
    method: str | None = None

    @classmethod
    def http(cls, url: str, method: str = "GET") -> CallTarget:
        return cls("http", url, method.upper())

    @classmethod
    def tool(cls, server: str, tool: str) -> CallTarget:
        return cls("tool", f"{server}/{tool}")

    @classmethod
    def tier(cls, name: str) -> CallTarget:
        return cls("tier", name)

    @classmethod
    def parse(cls, text: str) -> CallTarget:
        """Read a target the way the CLI accepts one: a URL, `tier:name`, or `server/tool`."""
        if "://" in text:
            return cls.http(text)
        if text.startswith("tier:"):
            return cls.tier(text.removeprefix("tier:"))
        server, _, tool = text.partition("/")
        if not server or not tool:
            raise ValueError(f"{text!r} is not a URL, a server/tool name, or tier:name")
        return cls.tool(server, tool)

    @property
    def host(self) -> str | None:
        return urlsplit(self.name).hostname if self.kind == "http" else None

    @property
    def origin(self) -> str | None:
        """scheme://host:port with the port always written, the key for host state."""
        if self.kind != "http":
            return None
        parts = urlsplit(self.name)
        host = parts.hostname or ""
        host = f"[{host}]" if ":" in host else host
        return f"{parts.scheme}://{host}:{parts.port or _DEFAULT_PORTS.get(parts.scheme, 0)}"

    @property
    def endpoint(self) -> str:
        """Endpoint identity: scheme, host and path template for HTTP.

        Path segments that are plainly identifiers (all digits, long hex, UUIDs)
        become `{id}`, so /tickets/123 and /tickets/456 share one breaker. The query
        string is not part of the endpoint.
        """
        if self.kind == "tool":
            return self.name
        if self.kind == "tier":
            return f"tier:{self.name}"
        parts = urlsplit(self.name)
        host = parts.hostname or ""
        host = f"[{host}]" if ":" in host else host
        port = parts.port
        netloc = host if port in (None, _DEFAULT_PORTS.get(parts.scheme)) else f"{host}:{port}"
        path = "/".join(
            "{id}" if _IDENTIFIER_SEGMENT.match(segment) else segment
            for segment in parts.path.split("/")
        )
        return f"{parts.scheme}://{netloc}{path or '/'}"


@dataclass(frozen=True, slots=True)
class ResolvedPolicy:
    target: CallTarget
    rule_index: int | None
    rule_name: str | None
    volatility: Volatility
    volatility_source: str
    soft_deadline_s: float
    hard_deadline_s: float
    deadline_source: str
    stale_on_error_s: float
    stale_while_revalidate_s: float
    stale_source: str
    max_attempts: int
    idempotent: bool
    cacheable: bool
    cacheable_reason: str
    vary_on: tuple[str, ...]
    max_body_bytes: int
    class_mappings: tuple[ClassMapping, ...]
    max_attempts_explicit: bool = False
    """True when a rule set max_attempts, which then outranks a class's own cap."""

    @property
    def endpoint(self) -> str:
        return self.target.endpoint

    def explain(self) -> list[tuple[str, str, str]]:
        """(field, value, decided by) rows, in the order an operator reads them."""
        soft, hard = human_duration(self.soft_deadline_s), human_duration(self.hard_deadline_s)
        stale = (
            f"{human_duration(self.stale_on_error_s)} on error, "
            f"{human_duration(self.stale_while_revalidate_s)} revalidating"
        )
        return [
            ("endpoint", self.endpoint, "target"),
            ("class", str(self.volatility), self.volatility_source),
            ("deadlines", f"soft {soft}, hard {hard}", self.deadline_source),
            ("stale allowance", stale, self.stale_source),
            ("cacheable", "yes" if self.cacheable else "no", self.cacheable_reason),
            ("idempotent", "yes" if self.idempotent else "no", "rule, else method"),
            ("max attempts", str(self.max_attempts), "rule, else defaults"),
        ]


def _rule_label(index: int, rule: Rule) -> str:
    return f"rules[{index}]" + (f" ({rule.name})" if rule.name else "")


def matches(rule: Rule, target: CallTarget) -> bool:
    """Every key the rule's match names must hold for the target."""
    match = rule.match
    checks = (
        match.url is None or (target.kind == "http" and fnmatchcase(target.name, match.url)),
        match.host is None
        or (target.host is not None and fnmatchcase(target.host.lower(), match.host.lower())),
        match.tool is None or (target.kind == "tool" and fnmatchcase(target.name, match.tool)),
        match.method is None or (target.kind == "http" and match.method in ("*", target.method)),
        match.tier is None or (target.kind == "tier" and fnmatchcase(target.name, match.tier)),
    )
    return all(checks)


def first_match(config: Config, target: CallTarget) -> tuple[int, Rule] | None:
    """Rules are ordered and the first match wins."""
    for index, rule in enumerate(config.rules):
        if matches(rule, target):
            return index, rule
    return None


def volatility_from_origin(headers: Mapping[str, str] | None) -> tuple[Volatility, str] | None:
    """A class implied by the origin's Cache-Control, when it implies one.

    no-store means nothing may be kept (RFC 9111 §5.2.2.5). no-cache, or max-age=0
    with must-revalidate, means every use needs the origin (§5.2.2.4, §5.2.2.2),
    which is what live means. immutable (RFC 8246) or a max-age of about a year is
    static; a day or more is slow; any shorter max-age is volatile.
    """
    if not headers:
        return None
    directives = parse_cache_control(header_values(headers, "cache-control"))
    if not directives:
        return None
    max_age = delta_seconds(directives.get("max-age"))
    if "no-store" in directives:
        return Volatility.NEVER, "origin Cache-Control: no-store"
    if ("no-cache" in directives and directives["no-cache"] is None) or (
        max_age == 0 and "must-revalidate" in directives
    ):
        return Volatility.LIVE, "origin Cache-Control: revalidate on every use"
    if "immutable" in directives or (max_age is not None and max_age >= ONE_YEAR_S):
        return Volatility.STATIC, "origin Cache-Control: immutable or max-age of a year"
    if max_age is not None and max_age >= ONE_DAY_S:
        return Volatility.SLOW, f"origin Cache-Control: max-age={max_age}"
    if max_age is not None:
        return Volatility.VOLATILE, f"origin Cache-Control: max-age={max_age}"
    return None


def volatility_from_side_effects(
    config: Config, target: CallTarget
) -> tuple[Volatility, str] | None:
    if target.kind == "http" and target.method not in SAFE_METHODS:
        return Volatility.NEVER, f"method {target.method} may have side effects"
    if target.kind == "tier":
        return Volatility.NEVER, "model completions are not cached"
    if target.kind == "tool":
        tool = target.name.split("/", 1)[1]
        if re.search(config.defaults.write_tool_pattern, tool):
            return Volatility.NEVER, "tool name matches defaults.write_tool_pattern"
    return None


def resolve(
    config: Config, target: CallTarget, origin_headers: Mapping[str, str] | None = None
) -> ResolvedPolicy:
    found = first_match(config, target)
    index, rule = found if found is not None else (None, None)
    label = _rule_label(index, rule) if index is not None and rule is not None else None
    defaults = config.defaults

    decided = (
        (rule.volatility, label)
        if rule is not None and rule.volatility is not None and label is not None
        else volatility_from_origin(origin_headers)
        or volatility_from_side_effects(config, target)
        or (defaults.volatility, "defaults.class")
    )
    volatility, volatility_source = decided

    model = target.kind == "tier"
    soft = MODEL_SOFT_DEADLINE_S if model else defaults.soft_deadline
    hard = MODEL_HARD_DEADLINE_S if model else defaults.hard_deadline
    deadline_source = "model call defaults" if model else "defaults"
    if rule is not None and label is not None and (rule.soft_deadline or rule.hard_deadline):
        soft = rule.soft_deadline if rule.soft_deadline is not None else soft
        hard = rule.hard_deadline if rule.hard_deadline is not None else hard
        deadline_source = label
    soft = min(soft, hard)

    directives = parse_cache_control(header_values(origin_headers or {}, "cache-control"))
    if volatility in (Volatility.LIVE, Volatility.NEVER):
        stale_on_error, revalidating, stale_source = 0.0, 0.0, f"class {volatility} is never stale"
    else:
        origin_sie = delta_seconds(directives.get("stale-if-error"))
        origin_swr = delta_seconds(directives.get("stale-while-revalidate"))
        if rule is not None and rule.stale_on_error is not None and label is not None:
            stale_on_error, stale_source = rule.stale_on_error, label
        elif origin_sie is not None:
            stale_on_error, stale_source = float(origin_sie), "origin stale-if-error"
        else:
            stale_on_error, stale_source = CLASS_STALE_ON_ERROR_S[volatility], f"class {volatility}"
        if rule is not None and rule.stale_while_revalidate is not None:
            revalidating = rule.stale_while_revalidate
        elif origin_swr is not None:
            revalidating = float(origin_swr)
        else:
            synthesized = volatility in (Volatility.STATIC, Volatility.SLOW)
            revalidating = stale_on_error if synthesized else 0.0

    pure = rule.pure if rule is not None else False
    if target.kind == "http":
        idempotent_default = target.method in SAFE_METHODS
    else:
        idempotent_default = target.kind == "tool" and pure
    idempotent = (
        rule.idempotent if rule is not None and rule.idempotent is not None else idempotent_default
    )

    if volatility is Volatility.NEVER:
        cacheable, cacheable_reason = False, "class never is not cached"
    elif target.kind == "tier":
        cacheable, cacheable_reason = False, "model completions are not cached"
    elif target.kind == "http" and target.method in SAFE_METHODS:
        cacheable, cacheable_reason = True, f"method {target.method}"
    elif pure:
        cacheable, cacheable_reason = True, f"{label} marks it pure"
    else:
        cacheable, cacheable_reason = False, "only GET, HEAD, or calls a rule marks pure are cached"

    mappings = (rule.classes if rule is not None else []) + config.classes
    return ResolvedPolicy(
        target=target,
        rule_index=index,
        rule_name=rule.name if rule is not None else None,
        volatility=volatility,
        volatility_source=volatility_source,
        soft_deadline_s=soft,
        hard_deadline_s=hard,
        deadline_source=deadline_source,
        stale_on_error_s=stale_on_error,
        stale_while_revalidate_s=revalidating,
        stale_source=stale_source,
        max_attempts=rule.max_attempts
        if rule is not None and rule.max_attempts
        else defaults.max_attempts,
        max_attempts_explicit=rule is not None and rule.max_attempts is not None,
        idempotent=idempotent,
        cacheable=cacheable,
        cacheable_reason=cacheable_reason,
        vary_on=tuple(h.lower() for h in (rule.vary_on if rule is not None else [])),
        max_body_bytes=rule.max_body_bytes
        if rule is not None and rule.max_body_bytes
        else defaults.max_body_bytes,
        class_mappings=tuple(mappings),
    )


def policy_warnings(config: Config) -> list[str]:
    """Startup warnings for rules that could serve a response across credentials."""
    warnings: list[str] = []
    for index, rule in enumerate(config.rules):
        http_rule = rule.match.url or rule.match.host or rule.match.method
        if http_rule and rule.pure and "authorization" not in {h.lower() for h in rule.vary_on}:
            warnings.append(
                f"{_rule_label(index, rule)} caches non-GET responses without"
                " vary_on: [authorization]; an authenticated response could be served to a"
                " request with different credentials"
            )
    return warnings
