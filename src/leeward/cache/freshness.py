# SPDX-License-Identifier: Apache-2.0
"""HTTP caching semantics: the subset of RFC 9111 and RFC 5861 that leeward applies."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from enum import StrEnum

from leeward.vocab import STALE_SERVABLE, Volatility, WithheldReason

DELTA_SECONDS_CEILING = 2**31
"""RFC 9111 §1.2.2: a delta-seconds value too large to represent is taken as 2^31."""

_DIGITS = re.compile(r"^[0-9]+$")
_QUOTED_PAIR = re.compile(r"\\(.)")


def _split_list(field: str) -> list[str]:
    """Split a comma-separated field value, leaving commas inside quoted strings alone.

    RFC 9110 §5.6.1 defines the list syntax and §5.6.4 the quoted-string, whose
    backslash escapes a quote.
    """
    items: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for char in field:
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            items.append("".join(current))
            current = []
            continue
        current.append(char)
    items.append("".join(current))
    return [item.strip() for item in items if item.strip()]


def parse_cache_control(field_values: Iterable[str]) -> dict[str, str | None]:
    """Directives from one or more Cache-Control field lines (RFC 9111 §5.2).

    Names are case-insensitive. A directive without an argument maps to None. When
    a directive repeats, the first occurrence is used, which RFC 9111 §4.2.1 allows.
    """
    directives: dict[str, str | None] = {}
    for field in field_values:
        for item in _split_list(field):
            name, separator, value = item.partition("=")
            name = name.strip().lower()
            if not name:
                continue
            value = value.strip()
            if separator and len(value) >= 2 and value[0] == value[-1] == '"':
                value = _QUOTED_PAIR.sub(r"\1", value[1:-1])
            directives.setdefault(name, value if separator else None)
    return directives


def delta_seconds(value: str | None) -> int | None:
    """A delta-seconds argument (RFC 9111 §1.2.2), or None when absent or malformed."""
    if value is None or not _DIGITS.match(value):
        return None
    return min(int(value), DELTA_SECONDS_CEILING)


def header_values(headers: Mapping[str, str], name: str) -> list[str]:
    """Every value of a field, matched case-insensitively (RFC 9110 §5.1)."""
    wanted = name.lower()
    return [value for key, value in headers.items() if key.lower() == wanted]


HEURISTICALLY_CACHEABLE = frozenset({200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501})
"""RFC 9111 §4.2.2 and §3: statuses a cache may keep without being told to."""

HEURISTIC_FRACTION = 0.1
HEURISTIC_CAP_S = 86400.0
"""A tenth of the time since the document last changed, and never more than a day.
RFC 9111 §4.2.2 leaves the fraction to the cache and only warns about it; a tenth,
capped at a day, is where long-lived caches have settled."""

FORBIDS_STALE = ("must-revalidate", "proxy-revalidate")
"""RFC 9111 §4.2.4: with these, a stale response may not be served at all."""


class NeverStaleError(RuntimeError):
    """A class that is never served stale was about to be. Nothing may allow this."""


class StaleReason(StrEnum):
    ERROR = "ERROR"
    REVALIDATING = "REVALIDATING"
    SLOW = "SLOW"
    ACCEPTED = "ACCEPTED"


class Situation(StrEnum):
    """Where in a call the question "may this copy be served?" is being asked."""

    START = "START"
    SOFT_DEADLINE = "SOFT_DEADLINE"
    ORIGIN_FAILED = "ORIGIN_FAILED"


@dataclass(frozen=True, slots=True)
class StaleAllowance:
    """How far past freshness this endpoint's class lets a copy be served."""

    volatility: Volatility
    on_error_s: float = 0.0
    while_revalidating_s: float = 0.0
    operator_set: bool = False
    """True when a rule set the allowance, which then outranks the origin's own
    must-revalidate. The operator is entitled to say that a labeled old copy beats
    nothing at all; the origin cannot say that for them."""

    @property
    def servable(self) -> bool:
        return self.volatility in STALE_SERVABLE


@dataclass(frozen=True, slots=True)
class StoredResponse:
    """A stored response and everything needed to judge it later."""

    key: str
    url: str
    method: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body_sha256: str
    body_bytes: int
    requested_at: float
    received_at: float
    volatility: Volatility
    vary: tuple[tuple[str, str], ...] = ()
    endpoint: str = ""
    pinned: bool = False
    stored_at: float = 0.0

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        found = [value for key, value in self.headers if key.lower() == wanted]
        return ", ".join(found) if found else None

    def directives(self) -> dict[str, str | None]:
        value = self.header("cache-control")
        return parse_cache_control([value]) if value else {}

    @property
    def validators(self) -> tuple[str | None, str | None]:
        return self.header("etag"), self.header("last-modified")


@dataclass(frozen=True, slots=True)
class Freshness:
    age_s: float
    lifetime_s: float
    source: str

    @property
    def fresh(self) -> bool:
        return self.age_s < self.lifetime_s

    @property
    def stale_by_s(self) -> float:
        return max(self.age_s - self.lifetime_s, 0.0)


def parse_http_date(value: str | None) -> float | None:
    """An HTTP-date as a timestamp (RFC 9110 §5.6.7), or None if it is not one."""
    if not value:
        return None
    try:
        return parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError):
        return None


def current_age(entry: StoredResponse, now: float) -> float:
    """The stored response's age, by the arithmetic in RFC 9111 §4.2.3."""
    date_value = parse_http_date(entry.header("date"))
    age_value = delta_seconds(entry.header("age")) or 0
    apparent_age = max(0.0, entry.received_at - date_value) if date_value is not None else 0.0
    corrected_age_value = age_value + max(entry.received_at - entry.requested_at, 0.0)
    corrected_initial_age = max(apparent_age, corrected_age_value)
    return corrected_initial_age + max(now - entry.received_at, 0.0)


def freshness_lifetime(entry: StoredResponse) -> tuple[float, str]:
    """How long the origin said this may be reused, by RFC 9111 §4.2.1 and §4.2.2."""
    directives = entry.directives()
    max_age = delta_seconds(directives.get("max-age"))
    if max_age is not None:
        return float(max_age), "max-age"
    expires = parse_http_date(entry.header("expires"))
    date_value = parse_http_date(entry.header("date"))
    if expires is not None:
        return max(
            expires - (date_value if date_value is not None else entry.received_at), 0.0
        ), "Expires"
    last_modified = parse_http_date(entry.header("last-modified"))
    if (
        last_modified is not None
        and date_value is not None
        and entry.status in HEURISTICALLY_CACHEABLE
    ):
        gap = max(date_value - last_modified, 0.0)
        return min(gap * HEURISTIC_FRACTION, HEURISTIC_CAP_S), "heuristic"
    return 0.0, "none"


def freshness(entry: StoredResponse, now: float) -> Freshness:
    lifetime, source = freshness_lifetime(entry)
    return Freshness(age_s=current_age(entry, now), lifetime_s=lifetime, source=source)


@dataclass(frozen=True, slots=True)
class NoEntry:
    """Nothing usable is stored, so the origin is the only answer."""


@dataclass(frozen=True, slots=True)
class ServeFresh:
    entry: StoredResponse
    age_s: float


@dataclass(frozen=True, slots=True)
class ServeStale:
    """A copy served past its freshness. It cannot be built for a class that forbids it.

    This is the one place a stale response comes from, so the check that a live
    endpoint is never served stale is a check nothing can route around.
    """

    entry: StoredResponse
    age_s: float
    reason: StaleReason
    volatility: Volatility

    def __post_init__(self) -> None:
        if self.volatility not in STALE_SERVABLE:
            raise NeverStaleError(
                f"{self.entry.url or self.entry.key} is classified {self.volatility},"
                " which is never served stale"
            )


@dataclass(frozen=True, slots=True)
class Withhold:
    """A copy exists and is deliberately not being served. The agent is told both."""

    reason: WithheldReason
    age_s: float
    entry: StoredResponse | None = None


Decision = NoEntry | ServeFresh | ServeStale | Withhold


def vary_matches(entry: StoredResponse, request_headers: Mapping[str, str] | None) -> bool:
    """Whether the request this entry was stored for matches the one being served now."""
    if any(name == "*" for name, _value in entry.vary):
        return False
    headers = {name.lower(): value for name, value in (request_headers or {}).items()}
    return all(headers.get(name.lower(), "") == value for name, value in entry.vary)


def _stale_window(allowance: StaleAllowance, situation: Situation, accept_stale: bool) -> float:
    if accept_stale:
        return float("inf")
    if situation is Situation.START:
        return allowance.while_revalidating_s
    return allowance.on_error_s


def decide(
    entry: StoredResponse | None,
    allowance: StaleAllowance,
    situation: Situation,
    now: float,
    *,
    request_headers: Mapping[str, str] | None = None,
    accept_stale: bool = False,
) -> Decision:
    """What may be served from the cache right now, and when it may not, why."""
    if entry is None:
        return NoEntry()
    request_directives = parse_cache_control(header_values(request_headers or {}, "cache-control"))
    if "no-store" in request_directives or "no-cache" in request_directives:
        return NoEntry()
    age = current_age(entry, now)
    if not vary_matches(entry, request_headers):
        return Withhold(WithheldReason.VARY_MISMATCH, int(age), entry)
    if freshness(entry, now).fresh:
        return ServeFresh(entry, age)
    if allowance.volatility is Volatility.LIVE:
        return Withhold(WithheldReason.VOLATILITY_LIVE, int(age), entry)
    if allowance.volatility is Volatility.NEVER:
        return Withhold(WithheldReason.VOLATILITY_NEVER, int(age), entry)
    directives = entry.directives()
    refused_by_origin = "no-cache" in directives or any(
        name in directives for name in FORBIDS_STALE
    )
    if refused_by_origin and not allowance.operator_set:
        return Withhold(WithheldReason.BEYOND_STALE_ALLOWANCE, int(age), entry)
    if age > _stale_window(allowance, situation, accept_stale):
        return Withhold(WithheldReason.BEYOND_STALE_ALLOWANCE, int(age), entry)
    reason = {
        Situation.START: StaleReason.REVALIDATING,
        Situation.SOFT_DEADLINE: StaleReason.SLOW,
        Situation.ORIGIN_FAILED: StaleReason.ERROR,
    }[situation]
    return ServeStale(
        entry, age, StaleReason.ACCEPTED if accept_stale else reason, allowance.volatility
    )


def may_store(
    status: int,
    response_headers: Mapping[str, str],
    request_headers: Mapping[str, str],
    allowance: StaleAllowance,
    vary_on: Sequence[str],
    credential_headers: frozenset[str],
) -> tuple[bool, str]:
    """Whether this response may be written down, and in plain words why not.

    The credential rule is leeward's, not RFC 9111's: a response to a request that
    carried a token is not stored unless the rule says the token is part of the key,
    because the alternative is handing one caller's answer to another.
    """
    if allowance.volatility is Volatility.NEVER:
        return False, "the endpoint is classified never"
    response_directives = parse_cache_control(header_values(response_headers, "cache-control"))
    if "no-store" in response_directives:
        return False, "the origin sent Cache-Control: no-store"
    if "no-store" in parse_cache_control(header_values(request_headers, "cache-control")):
        return False, "the request asked for no-store"
    varied = {name.lower() for name in vary_on}
    carried = {name.lower() for name in request_headers} & credential_headers
    if carried - varied:
        names = ", ".join(sorted(carried - varied))
        return False, f"the request carried {names} and the rule does not vary on it"
    explicit = "max-age" in response_directives or response_headers.get("expires") is not None
    if not explicit and status not in HEURISTICALLY_CACHEABLE:
        return False, f"status {status} has no freshness and is not cacheable by default"
    return True, ""
