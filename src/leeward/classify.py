# SPDX-License-Identifier: Apache-2.0
"""Failure classification: what went wrong, whether retrying can ever help, and for whom.

This module is a pure function. It reads what the transport observed, the policy in
force, and a snapshot of the run, and it returns a class, a disposition and a scope.
It opens no socket and reads no clock, so every judgment it makes can be replayed
from an event and explained by `leeward classify`.

The disposition is derived, never looked up by class alone. A 429 that asks for
five seconds while the run can still afford to wait is WAIT; the same 429 asking
for an hour is QUOTA_EXHAUSTED, because no retry inside this run can succeed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Literal, assert_never, cast

from leeward.config import ClassMapping
from leeward.policy import ResolvedPolicy
from leeward.units import human_bytes, human_duration
from leeward.vocab import ClockTrust, Disposition, FailureClass, FailureScope

CLASSIFY_SAMPLE_BYTES = 64 * 1024
"""How much of a failed response body classification may read. Never logged."""

X509_VALIDITY_CODES = frozenset({9, 10, 11, 12})
"""OpenSSL include/openssl/x509_vfy.h: X509_V_ERR_CERT_NOT_YET_VALID (9),
X509_V_ERR_CERT_HAS_EXPIRED (10), X509_V_ERR_CRL_NOT_YET_VALID (11),
X509_V_ERR_CRL_HAS_EXPIRED (12). The errors a wrong local clock produces."""

DNS_RCODE_NOERROR = 0
DNS_RCODE_NXDOMAIN = 3
"""RFC 1035 §4.1.1: RCODE 3 is Name Error, the name does not exist."""

JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603
JSONRPC_SERVER_ERRORS = range(-32099, -31999)
"""JSON-RPC 2.0 specification §5.1, error object codes. MCP reports an unknown tool
as invalid params."""

EPOCH_THRESHOLD_S = 1_000_000_000
"""X-RateLimit-Reset is epoch seconds at GitHub and a delay elsewhere; a value past
this (September 2001) can only be a timestamp."""

QUOTA_CODES = frozenset(
    {
        "insufficient_quota",
        "billing_hard_limit_reached",
        "insufficient_credits",
        "credit_balance_too_low",
        "quota_exceeded",
        "payment_required",
    }
)
"""Provider error codes that mean money or quota ran out, not a momentary limit."""

_GO_DURATION = re.compile(r"([0-9]+(?:\.[0-9]+)?)(ms|h|m|s)")
_GO_UNITS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}
_UNKNOWN_TOOL = re.compile(r"unknown tool|tool .* not found|no such tool", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Response:
    """The origin answered with a status line."""

    status: int
    headers: Mapping[str, str]
    body_sample: bytes = b""


@dataclass(frozen=True, slots=True)
class ResolutionFailed:
    """The name did not resolve. rcode comes from a confirming DNS query, if one answered."""

    rcode: int | None
    resolved_before: bool = False


@dataclass(frozen=True, slots=True)
class ConnectRefused:
    pass


@dataclass(frozen=True, slots=True)
class ConnectTimedOut:
    pass


@dataclass(frozen=True, slots=True)
class TlsRejected:
    """The handshake failed. verify_code is OpenSSL's, when certificate verification failed."""

    verify_code: int | None


@dataclass(frozen=True, slots=True)
class ReadTimedOut:
    bytes_received: int


@dataclass(frozen=True, slots=True)
class DeadlineReached:
    """The hard deadline arrived first. connected says whether a connection was open."""

    connected: bool
    deadline_s: float


@dataclass(frozen=True, slots=True)
class Malformed:
    """An unparseable body, a schema violation, truncated JSON, or broken framing."""

    detail: str


@dataclass(frozen=True, slots=True)
class TooLarge:
    limit_bytes: int


@dataclass(frozen=True, slots=True)
class ToolError:
    """A JSON-RPC error answering an MCP tools/call."""

    code: int
    message: str
    listed_before: bool


@dataclass(frozen=True, slots=True)
class ToolAbsent:
    """The tool left tools/list, or its server exited or closed the session."""

    reason: Literal["delisted", "server_exited", "session_closed"]


@dataclass(frozen=True, slots=True)
class Injected:
    """A fault armed by `leeward chaos`, standing in for evidence of that class."""

    failure_class: FailureClass
    retry_after_s: float | None = None


Evidence = (
    Response
    | ResolutionFailed
    | ConnectRefused
    | ConnectTimedOut
    | TlsRejected
    | ReadTimedOut
    | DeadlineReached
    | Malformed
    | TooLarge
    | ToolError
    | ToolAbsent
    | Injected
)


@dataclass(frozen=True, slots=True)
class RunSnapshot:
    """The parts of the run's state a classification may depend on."""

    now: float
    retry_seconds_remaining: float
    wedged_before: int = 0
    clock: ClockTrust = ClockTrust.UNCHECKED


@dataclass(frozen=True, slots=True)
class Classification:
    failure_class: FailureClass
    disposition: Disposition | None
    scope: FailureScope | None
    reason: str
    retry_after_s: float | None = None
    attempt_cap: int | None = None
    underlying_class: FailureClass | None = None
    injected: bool = False

    @property
    def ok(self) -> bool:
        return self.failure_class is FailureClass.OK


OK = Classification(FailureClass.OK, None, None, "success")

DEFAULT_DISPOSITION: Mapping[FailureClass, tuple[Disposition, FailureScope]] = {
    FailureClass.DNS_NXDOMAIN: (Disposition.NEVER, FailureScope.HOST),
    FailureClass.DNS_FAILURE: (Disposition.TRANSIENT, FailureScope.HOST),
    FailureClass.CONNECT_REFUSED: (Disposition.TRANSIENT, FailureScope.HOST),
    FailureClass.CONNECT_TIMEOUT: (Disposition.TRANSIENT, FailureScope.HOST),
    FailureClass.TLS_CLOCK_SKEW: (Disposition.NEVER, FailureScope.HOST),
    FailureClass.TLS_OTHER: (Disposition.NEVER, FailureScope.HOST),
    FailureClass.READ_TIMEOUT: (Disposition.TRANSIENT, FailureScope.ENDPOINT),
    FailureClass.WEDGED: (Disposition.TRANSIENT, FailureScope.ENDPOINT),
    FailureClass.AUTH_FAILURE: (Disposition.NEVER, FailureScope.RUN),
    FailureClass.NOT_FOUND: (Disposition.NEVER, FailureScope.REQUEST),
    FailureClass.INVALID_REQUEST: (Disposition.NEVER, FailureScope.REQUEST),
    FailureClass.RATE_LIMITED: (Disposition.TRANSIENT, FailureScope.RUN),
    FailureClass.QUOTA_EXHAUSTED: (Disposition.NEVER, FailureScope.RUN),
    FailureClass.SERVER_ERROR: (Disposition.TRANSIENT, FailureScope.ENDPOINT),
    FailureClass.TOOL_GONE: (Disposition.NEVER, FailureScope.ENDPOINT),
    FailureClass.PROTOCOL_ERROR: (Disposition.TRANSIENT, FailureScope.ENDPOINT),
    FailureClass.CONTENT_TOO_LARGE: (Disposition.NEVER, FailureScope.REQUEST),
}

ATTEMPT_CAPS: Mapping[FailureClass, int] = {
    FailureClass.SERVER_ERROR: 2,
    FailureClass.PROTOCOL_ERROR: 2,
}
"""Server errors get two attempts, protocol errors one retry, whatever the policy allows."""


def _seconds(value: float) -> str:
    return f"{value:.0f}s" if value >= 1 else human_duration(value)


def _go_duration(text: str) -> float | None:
    """Durations such as '6m0s' or '20ms', as OpenAI's x-ratelimit-reset headers send them."""
    parts = _GO_DURATION.findall(text.strip())
    if not parts or "".join(number + unit for number, unit in parts) != text.strip():
        return None
    return sum(float(number) * _GO_UNITS[unit] for number, unit in parts)


def _http_date_wait(value: str, now: float) -> list[float]:
    """Seconds until an HTTP-date, or nothing when the value is not one."""
    try:
        moment = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return []
    return [max(moment.timestamp() - now, 0.0)]


def wait_hint_s(headers: Mapping[str, str], now: float) -> float | None:
    """The longest wait any rate limit header asks for, in seconds, or None.

    Retry-After is delay-seconds or an HTTP-date (RFC 9110 §10.2.3). RateLimit-Reset
    and the reset parameter of RateLimit come from draft-ietf-httpapi-ratelimit-headers.
    When several are present the longest wins, since the limit that was hit is not
    named.
    """
    lowered = {name.lower(): value.strip() for name, value in headers.items()}
    waits: list[float] = []
    retry_after = lowered.get("retry-after")
    if retry_after is not None:
        if retry_after.isdigit():
            waits.append(float(retry_after))
        else:
            waits.extend(_http_date_wait(retry_after, now))
    for name in ("ratelimit-reset", "x-ratelimit-reset"):
        value = lowered.get(name)
        if value is not None and value.isdigit():
            number = float(value)
            waits.append(max(number - now, 0.0) if number > EPOCH_THRESHOLD_S else number)
    structured = lowered.get("ratelimit")
    if structured is not None:
        match = re.search(r"(?:^|[;,\s])(?:t|reset)=([0-9]+)", structured)
        if match is not None:
            waits.append(float(match.group(1)))
    for name in ("x-ratelimit-reset-requests", "x-ratelimit-reset-tokens"):
        value = lowered.get(name)
        parsed = _go_duration(value) if value is not None else None
        if parsed is not None:
            waits.append(parsed)
    return max(waits) if waits else None


def provider_codes(body_sample: bytes) -> set[str]:
    """Error codes a JSON error body names, lowercased: error.code, error.type, code, type."""
    try:
        document: object = json.loads(body_sample.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return set()
    if not isinstance(document, dict):
        return set()
    top = cast("dict[str, object]", document)
    codes: set[str] = set()
    sources = [top]
    error = top.get("error")
    if isinstance(error, dict):
        sources.append(cast("dict[str, object]", error))
    elif isinstance(error, str):
        codes.add(error.lower())
    for source in sources:
        for key in ("code", "type"):
            value = source.get(key)
            if isinstance(value, str | int) and not isinstance(value, bool):
                codes.add(str(value).lower())
    return codes


def _from_mapping(mapping: ClassMapping, snapshot: RunSnapshot, detail: str) -> Classification:
    disposition, scope = DEFAULT_DISPOSITION[mapping.as_class]
    disposition = mapping.as_disposition or disposition
    retry_after = mapping.retry_after
    remaining = snapshot.retry_seconds_remaining
    if disposition is Disposition.WAIT and retry_after is not None and retry_after > remaining:
        return Classification(
            mapping.as_class,
            Disposition.NEVER,
            scope,
            f"configured wait {_seconds(retry_after)} exceeds remaining run budget"
            f" {_seconds(remaining)}",
        )
    return Classification(
        mapping.as_class,
        disposition,
        scope,
        f"configured mapping: {detail}",
        retry_after_s=retry_after if disposition is Disposition.WAIT else None,
        attempt_cap=ATTEMPT_CAPS.get(mapping.as_class),
    )


def _mapped(
    policy: ResolvedPolicy,
    snapshot: RunSnapshot,
    *,
    status: int | None = None,
    body: bytes = b"",
    codes: set[str] | None = None,
) -> Classification | None:
    """The first configured mapping whose every condition holds, rule mappings first."""
    text = body.decode("utf-8", "replace") if body else ""
    for mapping in policy.class_mappings:
        if mapping.when_status is not None and mapping.when_status != status:
            continue
        if mapping.when_body_matches is not None and not re.search(mapping.when_body_matches, text):
            continue
        if mapping.when_error_code is not None and mapping.when_error_code.lower() not in (
            codes or set()
        ):
            continue
        return _from_mapping(mapping, snapshot, f"{mapping.as_class} for status {status}")
    return None


def _wait_or_never(
    failure_class: FailureClass, wait: float, snapshot: RunSnapshot, *, quota_class: bool
) -> Classification:
    """WAIT when the run can afford the wait, otherwise NEVER for this run."""
    remaining = snapshot.retry_seconds_remaining
    scope = DEFAULT_DISPOSITION[failure_class][1]
    if wait <= remaining:
        return Classification(
            failure_class,
            Disposition.WAIT,
            scope,
            f"Retry-After {_seconds(wait)} fits remaining run budget {_seconds(remaining)}",
            retry_after_s=wait,
        )
    return Classification(
        FailureClass.QUOTA_EXHAUSTED if quota_class else failure_class,
        Disposition.NEVER,
        FailureScope.RUN,
        f"Retry-After {_seconds(wait)} exceeds remaining run budget {_seconds(remaining)}",
    )


def _response(evidence: Response, policy: ResolvedPolicy, snapshot: RunSnapshot) -> Classification:
    status = evidence.status
    needs_codes = status >= 400 or bool(policy.class_mappings)
    codes = provider_codes(evidence.body_sample) if needs_codes else set[str]()
    if policy.class_mappings:
        mapped = _mapped(policy, snapshot, status=status, body=evidence.body_sample, codes=codes)
        if mapped is not None:
            return mapped
    if 100 <= status < 400:
        return OK
    if codes & QUOTA_CODES or status == 402:
        return Classification(
            FailureClass.QUOTA_EXHAUSTED,
            Disposition.NEVER,
            FailureScope.RUN,
            "the provider reports exhausted quota or credit" if codes & QUOTA_CODES else "402",
        )
    wait = wait_hint_s(evidence.headers, snapshot.now)
    if status == 429:
        if wait is None:
            return Classification(
                FailureClass.RATE_LIMITED,
                Disposition.TRANSIENT,
                FailureScope.RUN,
                "429 without Retry-After or a reset header",
            )
        return _wait_or_never(FailureClass.RATE_LIMITED, wait, snapshot, quota_class=True)
    if status in (401, 403, 407):
        return Classification(
            FailureClass.AUTH_FAILURE, Disposition.NEVER, FailureScope.RUN, f"{status}"
        )
    if status in (404, 410, 451):
        return Classification(
            FailureClass.NOT_FOUND, Disposition.NEVER, FailureScope.REQUEST, f"{status}"
        )
    if status in (408, 421, 423, 425):
        cls = FailureClass.READ_TIMEOUT if status == 408 else FailureClass.SERVER_ERROR
        return Classification(cls, Disposition.TRANSIENT, FailureScope.ENDPOINT, f"{status}")
    if status in (501, 505):
        return Classification(
            FailureClass.INVALID_REQUEST, Disposition.NEVER, FailureScope.ENDPOINT, f"{status}"
        )
    if status >= 500:
        if wait is not None:
            return _wait_or_never(FailureClass.SERVER_ERROR, wait, snapshot, quota_class=False)
        return Classification(
            FailureClass.SERVER_ERROR,
            Disposition.TRANSIENT,
            FailureScope.ENDPOINT,
            f"{status}",
            attempt_cap=ATTEMPT_CAPS[FailureClass.SERVER_ERROR],
        )
    return Classification(
        FailureClass.INVALID_REQUEST, Disposition.NEVER, FailureScope.REQUEST, f"{status}"
    )


def _resolution(evidence: ResolutionFailed) -> Classification:
    if evidence.rcode in (DNS_RCODE_NXDOMAIN, DNS_RCODE_NOERROR) and not evidence.resolved_before:
        reason = (
            "the resolver answered NXDOMAIN (RCODE 3)"
            if evidence.rcode == DNS_RCODE_NXDOMAIN
            else "the name exists but has no address records"
        )
        return Classification(
            FailureClass.DNS_NXDOMAIN, Disposition.NEVER, FailureScope.HOST, reason
        )
    if evidence.resolved_before:
        reason = "a name that resolved earlier does not resolve now"
    elif evidence.rcode is None:
        reason = "no resolver answered"
    else:
        reason = f"the resolver failed (RCODE {evidence.rcode})"
    return Classification(
        FailureClass.DNS_FAILURE, Disposition.TRANSIENT, FailureScope.HOST, reason
    )


def _tls(evidence: TlsRejected, snapshot: RunSnapshot) -> Classification:
    if evidence.verify_code in X509_VALIDITY_CODES and snapshot.clock is not ClockTrust.TRUSTED:
        state = (
            "is skewed"
            if snapshot.clock is ClockTrust.SKEWED
            else "has not been checked against another source"
        )
        return Classification(
            FailureClass.TLS_CLOCK_SKEW,
            Disposition.NEVER,
            FailureScope.HOST,
            f"certificate validity failed while this machine's clock {state}; fix the clock",
        )
    code = "" if evidence.verify_code is None else f" (verify code {evidence.verify_code})"
    return Classification(
        FailureClass.TLS_OTHER, Disposition.NEVER, FailureScope.HOST, f"TLS handshake failed{code}"
    )


def _wedged(deadline_s: float, snapshot: RunSnapshot, *, injected: bool = False) -> Classification:
    if snapshot.wedged_before >= 1:
        return Classification(
            FailureClass.WEDGED,
            Disposition.NEVER,
            FailureScope.ENDPOINT,
            "hung again: an endpoint that hangs twice in a run will hang again",
            injected=injected,
        )
    return Classification(
        FailureClass.WEDGED,
        Disposition.TRANSIENT,
        FailureScope.ENDPOINT,
        f"no completion within the {_seconds(deadline_s)} hard deadline, connection open",
        injected=injected,
    )


def _tool_error(
    evidence: ToolError, policy: ResolvedPolicy, snapshot: RunSnapshot
) -> Classification:
    mapped = _mapped(policy, snapshot, codes={str(evidence.code)})
    if mapped is not None:
        return mapped
    code = evidence.code
    if code == JSONRPC_INVALID_PARAMS and _UNKNOWN_TOOL.search(evidence.message):
        if evidence.listed_before:
            return Classification(
                FailureClass.TOOL_GONE,
                Disposition.NEVER,
                FailureScope.ENDPOINT,
                "the server no longer knows a tool it listed earlier",
            )
        return Classification(
            FailureClass.NOT_FOUND, Disposition.NEVER, FailureScope.ENDPOINT, "unknown tool"
        )
    if code == JSONRPC_METHOD_NOT_FOUND:
        return Classification(
            FailureClass.NOT_FOUND, Disposition.NEVER, FailureScope.ENDPOINT, "method not found"
        )
    if code in (JSONRPC_INVALID_PARAMS, JSONRPC_INVALID_REQUEST):
        return Classification(
            FailureClass.INVALID_REQUEST,
            Disposition.NEVER,
            FailureScope.REQUEST,
            f"JSON-RPC {code}",
        )
    if code == JSONRPC_PARSE_ERROR:
        return Classification(
            FailureClass.PROTOCOL_ERROR,
            Disposition.TRANSIENT,
            FailureScope.ENDPOINT,
            "the server could not parse the request",
            attempt_cap=ATTEMPT_CAPS[FailureClass.PROTOCOL_ERROR],
        )
    if code == JSONRPC_INTERNAL_ERROR or code in JSONRPC_SERVER_ERRORS:
        return Classification(
            FailureClass.SERVER_ERROR,
            Disposition.TRANSIENT,
            FailureScope.ENDPOINT,
            f"JSON-RPC {code}",
            attempt_cap=ATTEMPT_CAPS[FailureClass.SERVER_ERROR],
        )
    return Classification(
        FailureClass.SERVER_ERROR, Disposition.UNKNOWN, FailureScope.REQUEST, f"JSON-RPC {code}"
    )


def _injected(evidence: Injected, policy: ResolvedPolicy, snapshot: RunSnapshot) -> Classification:
    armed = evidence.failure_class
    if armed is FailureClass.WEDGED:
        return _wedged(policy.hard_deadline_s, snapshot, injected=True)
    if armed in (FailureClass.RATE_LIMITED, FailureClass.SERVER_ERROR) and evidence.retry_after_s:
        derived = _wait_or_never(
            armed, evidence.retry_after_s, snapshot, quota_class=armed is FailureClass.RATE_LIMITED
        )
        return Classification(
            derived.failure_class,
            derived.disposition,
            derived.scope,
            f"injected: {derived.reason}",
            retry_after_s=derived.retry_after_s,
            injected=True,
        )
    disposition, scope = DEFAULT_DISPOSITION[armed]
    return Classification(
        armed,
        disposition,
        scope,
        "injected by leeward chaos",
        attempt_cap=ATTEMPT_CAPS.get(armed),
        injected=True,
    )


def classify(evidence: Evidence, policy: ResolvedPolicy, snapshot: RunSnapshot) -> Classification:
    """The class, disposition and scope of one attempt."""
    match evidence:
        case Response():
            return _response(evidence, policy, snapshot)
        case ResolutionFailed():
            return _resolution(evidence)
        case ConnectRefused():
            return Classification(
                FailureClass.CONNECT_REFUSED,
                Disposition.TRANSIENT,
                FailureScope.HOST,
                "nothing is listening",
            )
        case ConnectTimedOut():
            return Classification(
                FailureClass.CONNECT_TIMEOUT,
                Disposition.TRANSIENT,
                FailureScope.HOST,
                "no connection within the connect timeout",
            )
        case TlsRejected():
            return _tls(evidence, snapshot)
        case ReadTimedOut():
            return Classification(
                FailureClass.READ_TIMEOUT,
                Disposition.TRANSIENT,
                FailureScope.ENDPOINT,
                f"connected, then silence after {human_bytes(evidence.bytes_received)}",
            )
        case DeadlineReached(connected=True):
            return _wedged(evidence.deadline_s, snapshot)
        case DeadlineReached():
            return Classification(
                FailureClass.CONNECT_TIMEOUT,
                Disposition.TRANSIENT,
                FailureScope.HOST,
                f"still connecting at the {_seconds(evidence.deadline_s)} hard deadline",
            )
        case Malformed():
            return Classification(
                FailureClass.PROTOCOL_ERROR,
                Disposition.TRANSIENT,
                FailureScope.ENDPOINT,
                evidence.detail,
                attempt_cap=ATTEMPT_CAPS[FailureClass.PROTOCOL_ERROR],
            )
        case TooLarge():
            return Classification(
                FailureClass.CONTENT_TOO_LARGE,
                Disposition.NEVER,
                FailureScope.REQUEST,
                f"response exceeds the {human_bytes(evidence.limit_bytes)} cap",
            )
        case ToolError():
            return _tool_error(evidence, policy, snapshot)
        case ToolAbsent():
            return Classification(
                FailureClass.TOOL_GONE,
                Disposition.NEVER,
                FailureScope.ENDPOINT,
                {
                    "delisted": "the tool is gone from a tools/list that contained it",
                    "server_exited": "the MCP server process exited",
                    "session_closed": "the MCP server closed the session",
                }[evidence.reason],
            )
        case Injected():
            return _injected(evidence, policy, snapshot)
        case _:
            assert_never(evidence)


def refused(
    failure_class: Literal[FailureClass.BREAKER_OPEN, FailureClass.BUDGET_EXHAUSTED],
    behind: Classification | None,
    reason: str,
    *,
    retry_after_s: float | None = None,
) -> Classification:
    """A call leeward refused without an attempt, keeping the class of what caused it.

    A short-circuit that said only "circuit open" would tell the agent nothing it
    could act on, so the underlying class and its disposition travel with it.
    """
    if failure_class is FailureClass.BUDGET_EXHAUSTED:
        disposition, scope = Disposition.NEVER, FailureScope.RUN
    else:
        disposition = behind.disposition if behind is not None else Disposition.UNKNOWN
        scope = behind.scope if behind is not None else FailureScope.ENDPOINT
    return Classification(
        failure_class,
        disposition,
        scope,
        reason,
        retry_after_s=retry_after_s,
        underlying_class=behind.failure_class if behind is not None else None,
        injected=behind.injected if behind is not None else False,
    )
