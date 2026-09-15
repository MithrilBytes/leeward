# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import email.utils

import pytest
from hypothesis import given
from hypothesis import strategies as st

from leeward.classify import (
    Classification,
    ConnectRefused,
    ConnectTimedOut,
    DeadlineReached,
    Evidence,
    Injected,
    Malformed,
    ReadTimedOut,
    ResolutionFailed,
    Response,
    RunSnapshot,
    TlsRejected,
    ToolAbsent,
    TooLarge,
    ToolError,
    classify,
    provider_codes,
    refused,
    wait_hint_s,
)
from leeward.config import Config, parse_config
from leeward.policy import CallTarget, resolve
from leeward.vocab import ClockTrust, Disposition, FailureClass, FailureScope

NOW = 1_789_000_000.0
POLICY = resolve(Config(), CallTarget.http("https://api.example.com/items"))
PLENTY = RunSnapshot(now=NOW, retry_seconds_remaining=300.0)

C = FailureClass
D = Disposition
S = FailureScope

CASES: list[tuple[Evidence, FailureClass, Disposition | None, FailureScope | None]] = [
    (Response(200, {}), C.OK, None, None),
    (Response(304, {}), C.OK, None, None),
    (ResolutionFailed(rcode=3), C.DNS_NXDOMAIN, D.NEVER, S.HOST),
    (ResolutionFailed(rcode=0), C.DNS_NXDOMAIN, D.NEVER, S.HOST),
    (ResolutionFailed(rcode=3, resolved_before=True), C.DNS_FAILURE, D.TRANSIENT, S.HOST),
    (ResolutionFailed(rcode=None), C.DNS_FAILURE, D.TRANSIENT, S.HOST),
    (ResolutionFailed(rcode=2), C.DNS_FAILURE, D.TRANSIENT, S.HOST),
    (ConnectRefused(), C.CONNECT_REFUSED, D.TRANSIENT, S.HOST),
    (ConnectTimedOut(), C.CONNECT_TIMEOUT, D.TRANSIENT, S.HOST),
    (DeadlineReached(connected=False, deadline_s=30), C.CONNECT_TIMEOUT, D.TRANSIENT, S.HOST),
    (TlsRejected(verify_code=10), C.TLS_CLOCK_SKEW, D.NEVER, S.HOST),
    (TlsRejected(verify_code=62), C.TLS_OTHER, D.NEVER, S.HOST),
    (TlsRejected(verify_code=None), C.TLS_OTHER, D.NEVER, S.HOST),
    (ReadTimedOut(bytes_received=512), C.READ_TIMEOUT, D.TRANSIENT, S.ENDPOINT),
    (Response(408, {}), C.READ_TIMEOUT, D.TRANSIENT, S.ENDPOINT),
    (DeadlineReached(connected=True, deadline_s=30), C.WEDGED, D.TRANSIENT, S.ENDPOINT),
    (Response(401, {}), C.AUTH_FAILURE, D.NEVER, S.RUN),
    (Response(403, {}), C.AUTH_FAILURE, D.NEVER, S.RUN),
    (Response(404, {}), C.NOT_FOUND, D.NEVER, S.REQUEST),
    (Response(410, {}), C.NOT_FOUND, D.NEVER, S.REQUEST),
    (Response(400, {}), C.INVALID_REQUEST, D.NEVER, S.REQUEST),
    (Response(422, {}), C.INVALID_REQUEST, D.NEVER, S.REQUEST),
    (Response(501, {}), C.INVALID_REQUEST, D.NEVER, S.ENDPOINT),
    (Response(429, {"Retry-After": "5"}), C.RATE_LIMITED, D.WAIT, S.RUN),
    (Response(429, {}), C.RATE_LIMITED, D.TRANSIENT, S.RUN),
    (Response(402, {}), C.QUOTA_EXHAUSTED, D.NEVER, S.RUN),
    (Response(429, {"Retry-After": "3600"}), C.QUOTA_EXHAUSTED, D.NEVER, S.RUN),
    (
        Response(429, {}, b'{"error": {"code": "insufficient_quota"}}'),
        C.QUOTA_EXHAUSTED,
        D.NEVER,
        S.RUN,
    ),
    (Response(500, {}), C.SERVER_ERROR, D.TRANSIENT, S.ENDPOINT),
    (Response(502, {}), C.SERVER_ERROR, D.TRANSIENT, S.ENDPOINT),
    (Response(503, {}), C.SERVER_ERROR, D.TRANSIENT, S.ENDPOINT),
    (Response(504, {}), C.SERVER_ERROR, D.TRANSIENT, S.ENDPOINT),
    (ToolAbsent("delisted"), C.TOOL_GONE, D.NEVER, S.ENDPOINT),
    (ToolAbsent("server_exited"), C.TOOL_GONE, D.NEVER, S.ENDPOINT),
    (
        ToolError(-32602, "Unknown tool: threat_intel_lookup", True),
        C.TOOL_GONE,
        D.NEVER,
        S.ENDPOINT,
    ),
    (ToolError(-32602, "Unknown tool: lookup", False), C.NOT_FOUND, D.NEVER, S.ENDPOINT),
    (ToolError(-32601, "Method not found", False), C.NOT_FOUND, D.NEVER, S.ENDPOINT),
    (ToolError(-32602, "Invalid arguments", True), C.INVALID_REQUEST, D.NEVER, S.REQUEST),
    (ToolError(-32603, "internal", True), C.SERVER_ERROR, D.TRANSIENT, S.ENDPOINT),
    (ToolError(-32700, "parse error", True), C.PROTOCOL_ERROR, D.TRANSIENT, S.ENDPOINT),
    (Malformed("truncated JSON"), C.PROTOCOL_ERROR, D.TRANSIENT, S.ENDPOINT),
    (TooLarge(limit_bytes=10_000_000), C.CONTENT_TOO_LARGE, D.NEVER, S.REQUEST),
]


@pytest.mark.parametrize(("evidence", "failure_class", "disposition", "scope"), CASES)
def test_evidence_is_classified(
    evidence: Evidence,
    failure_class: FailureClass,
    disposition: Disposition | None,
    scope: FailureScope | None,
) -> None:
    result = classify(evidence, POLICY, PLENTY)
    assert (result.failure_class, result.disposition, result.scope) == (
        failure_class,
        disposition,
        scope,
    )
    assert result.reason


def test_the_table_covers_every_class() -> None:
    produced = {case[1] for case in CASES}
    behind = classify(ConnectTimedOut(), POLICY, PLENTY)
    produced.add(refused(C.BREAKER_OPEN, behind, "open").failure_class)
    produced.add(refused(C.BUDGET_EXHAUSTED, behind, "spent").failure_class)
    assert produced == set(FailureClass)


def test_a_short_wait_the_run_can_afford_is_wait() -> None:
    result = classify(Response(429, {"Retry-After": "5"}), POLICY, PLENTY)
    assert (result.disposition, result.retry_after_s) == (D.WAIT, 5.0)
    assert result.reason == "Retry-After 5s fits remaining run budget 300s"


def test_a_wait_longer_than_the_remaining_run_is_quota_exhausted() -> None:
    snapshot = RunSnapshot(now=NOW, retry_seconds_remaining=118.0)
    result = classify(Response(429, {"Retry-After": "3600"}), POLICY, snapshot)
    assert (result.failure_class, result.disposition) == (C.QUOTA_EXHAUSTED, D.NEVER)
    assert result.retry_after_s is None
    assert result.reason == "Retry-After 3600s exceeds remaining run budget 118s"


@given(
    wait=st.integers(min_value=0, max_value=100_000),
    remaining=st.floats(min_value=0, max_value=100_000, allow_nan=False),
)
def test_retry_after_is_judged_against_the_remaining_run_budget(
    wait: int, remaining: float
) -> None:
    snapshot = RunSnapshot(now=NOW, retry_seconds_remaining=remaining)
    result = classify(Response(429, {"Retry-After": str(wait)}), POLICY, snapshot)
    if wait <= remaining:
        assert (result.failure_class, result.disposition) == (C.RATE_LIMITED, D.WAIT)
        assert result.retry_after_s == wait
    else:
        assert (result.failure_class, result.disposition) == (C.QUOTA_EXHAUSTED, D.NEVER)
        assert result.retry_after_s is None


@pytest.mark.parametrize(
    ("headers", "seconds"),
    [
        ({"Retry-After": "120"}, 120.0),
        ({"Retry-After": email.utils.formatdate(NOW + 90, usegmt=True)}, 90.0),
        ({"Retry-After": email.utils.formatdate(NOW - 90, usegmt=True)}, 0.0),
        ({"X-RateLimit-Reset": str(int(NOW) + 30)}, 30.0),
        ({"X-RateLimit-Reset": "30"}, 30.0),
        ({"RateLimit-Reset": "50"}, 50.0),
        ({"RateLimit": '"default";r=0;t=50'}, 50.0),
        ({"x-ratelimit-reset-requests": "6m0s"}, 360.0),
        ({"x-ratelimit-reset-tokens": "20ms"}, 0.02),
        ({"Retry-After": "5", "x-ratelimit-reset-tokens": "90s"}, 90.0),
        ({"Retry-After": "soon"}, None),
        ({}, None),
    ],
)
def test_wait_hints_are_read_from_every_rate_limit_header(
    headers: dict[str, str], seconds: float | None
) -> None:
    assert wait_hint_s(headers, NOW) == (None if seconds is None else pytest.approx(seconds, abs=1))


def test_a_server_error_with_retry_after_waits_or_gives_up_for_the_run() -> None:
    short = classify(Response(503, {"Retry-After": "10"}), POLICY, PLENTY)
    assert (short.failure_class, short.disposition, short.retry_after_s) == (
        C.SERVER_ERROR,
        D.WAIT,
        10.0,
    )
    long = classify(Response(503, {"Retry-After": "1000"}), POLICY, PLENTY)
    assert (long.failure_class, long.disposition, long.scope) == (C.SERVER_ERROR, D.NEVER, S.RUN)


def test_server_and_protocol_errors_carry_their_attempt_caps() -> None:
    assert classify(Response(500, {}), POLICY, PLENTY).attempt_cap == 2
    assert classify(Malformed("bad json"), POLICY, PLENTY).attempt_cap == 2


def test_a_second_hang_in_the_run_is_never() -> None:
    evidence = DeadlineReached(connected=True, deadline_s=30)
    again = RunSnapshot(now=NOW, retry_seconds_remaining=300, wedged_before=1)
    result = classify(evidence, POLICY, again)
    assert (result.failure_class, result.disposition) == (C.WEDGED, D.NEVER)
    assert "hangs twice" in result.reason


@pytest.mark.parametrize(
    ("clock", "code", "failure_class"),
    [
        (ClockTrust.TRUSTED, 10, C.TLS_OTHER),
        (ClockTrust.UNCHECKED, 9, C.TLS_CLOCK_SKEW),
        (ClockTrust.SKEWED, 10, C.TLS_CLOCK_SKEW),
        (ClockTrust.SKEWED, 62, C.TLS_OTHER),
    ],
)
def test_a_certificate_date_error_blames_the_clock_only_when_the_clock_is_in_doubt(
    clock: ClockTrust, code: int, failure_class: FailureClass
) -> None:
    snapshot = RunSnapshot(now=NOW, retry_seconds_remaining=300, clock=clock)
    result = classify(TlsRejected(verify_code=code), POLICY, snapshot)
    assert result.failure_class is failure_class
    if failure_class is C.TLS_CLOCK_SKEW:
        assert "clock" in result.reason


MAPPED = resolve(
    parse_config(
        """
rules:
  - match: {host: "api.example.com"}
    classes:
      - {when_status: 200, when_body_matches: '"status":\\s*"overloaded"', as_class: SERVER_ERROR}
      - {when_status: 403, when_error_code: over_budget, as_class: QUOTA_EXHAUSTED}
      - {when_status: 418, as_class: RATE_LIMITED, as_disposition: WAIT, retry_after: 10s}
"""
    ).config,
    CallTarget.http("https://api.example.com/items"),
)


def test_configured_mappings_teach_leeward_an_upstream_s_own_failures() -> None:
    overloaded = classify(Response(200, {}, b'{"status": "overloaded"}'), MAPPED, PLENTY)
    assert (overloaded.failure_class, overloaded.disposition) == (C.SERVER_ERROR, D.TRANSIENT)
    assert overloaded.reason.startswith("configured mapping")

    fine = classify(Response(200, {}, b'{"status": "ok"}'), MAPPED, PLENTY)
    assert fine.ok

    budget = classify(Response(403, {}, b'{"error": {"code": "over_budget"}}'), MAPPED, PLENTY)
    assert (budget.failure_class, budget.disposition) == (C.QUOTA_EXHAUSTED, D.NEVER)

    teapot = classify(Response(418, {}), MAPPED, PLENTY)
    assert (teapot.disposition, teapot.retry_after_s) == (D.WAIT, 10.0)
    short_run = RunSnapshot(now=NOW, retry_seconds_remaining=5)
    assert classify(Response(418, {}), MAPPED, short_run).disposition is D.NEVER


def test_injected_faults_are_marked_and_still_derived() -> None:
    dns = classify(Injected(C.DNS_FAILURE), POLICY, PLENTY)
    assert (dns.failure_class, dns.disposition, dns.injected) == (C.DNS_FAILURE, D.TRANSIENT, True)

    again = RunSnapshot(now=NOW, retry_seconds_remaining=300, wedged_before=1)
    wedged = classify(Injected(C.WEDGED), POLICY, again)
    assert (wedged.disposition, wedged.injected) == (D.NEVER, True)

    hour = classify(Injected(C.RATE_LIMITED, retry_after_s=3600), POLICY, PLENTY)
    assert (hour.failure_class, hour.disposition, hour.injected) == (
        C.QUOTA_EXHAUSTED,
        D.NEVER,
        True,
    )


def test_a_refusal_keeps_the_class_and_disposition_of_what_caused_it() -> None:
    gone = classify(ToolAbsent("delisted"), POLICY, PLENTY)
    short = refused(C.BREAKER_OPEN, gone, "breaker open since the tool vanished")
    assert (short.failure_class, short.underlying_class, short.disposition) == (
        C.BREAKER_OPEN,
        C.TOOL_GONE,
        D.NEVER,
    )
    timeout: Classification = classify(ConnectTimedOut(), POLICY, PLENTY)
    probe = refused(C.BREAKER_OPEN, timeout, "host breaker open", retry_after_s=5)
    assert (probe.disposition, probe.retry_after_s) == (D.TRANSIENT, 5)
    spent = refused(C.BUDGET_EXHAUSTED, timeout, "run budget spent")
    assert (spent.disposition, spent.scope, spent.underlying_class) == (
        D.NEVER,
        S.RUN,
        C.CONNECT_TIMEOUT,
    )


@pytest.mark.parametrize(
    ("body", "codes"),
    [
        (
            b'{"error": {"code": "insufficient_quota", "type": "insufficient_quota"}}',
            {"insufficient_quota"},
        ),
        (b'{"error": {"type": "rate_limit_error"}}', {"rate_limit_error"}),
        (b'{"error": "Rate_Limited"}', {"rate_limited"}),
        (b'{"code": 429}', {"429"}),
        (b"<html>busy</html>", set[str]()),
        (b"\xff\xfe", set[str]()),
    ],
)
def test_provider_error_codes_are_read_from_json_bodies(body: bytes, codes: set[str]) -> None:
    assert provider_codes(body) == codes
