# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from leeward.attempt import AttemptRecord, CallReport
from leeward.breaker import Breaker
from leeward.budget import BudgetLimits, RunLedger
from leeward.cache.freshness import ServeStale, StaleReason, StoredResponse, Withhold
from leeward.classify import (
    Classification,
    ConnectTimedOut,
    Response,
    RunSnapshot,
    ToolAbsent,
    classify,
    refused,
)
from leeward.config import parse_config
from leeward.deadlines import CallDeadlines
from leeward.events import RunRef
from leeward.outcome import advice_for, build, stale_outcome_guard
from leeward.policy import CallTarget, ResolvedPolicy, resolve
from leeward.vocab import (
    Advice,
    BreakerState,
    Disposition,
    FailureClass,
    Outcome,
    RunResolution,
    Volatility,
    WithheldReason,
)
from tests.support import assert_valid

NOW = 1_789_000_000.0
SNAPSHOT = RunSnapshot(now=NOW, retry_seconds_remaining=118.0)

LIVE = resolve(
    parse_config("rules:\n  - match: {url: '*/status*'}\n    class: live\n").config,
    CallTarget.http("https://ops.example.com/status"),
)
STATIC = resolve(
    parse_config(
        "rules:\n  - match: {url: '*/wiki/*'}\n    class: static\n    stale_on_error: 30d\n"
    ).config,
    CallTarget.http("https://en.wikipedia.org/wiki/Foo"),
)


def judged(evidence: object, policy: ResolvedPolicy = LIVE) -> Classification:
    return classify(evidence, policy, SNAPSHOT)  # pyright: ignore[reportArgumentType]


def report_for(
    classification: Classification,
    *,
    attempts: int = 2,
    elapsed: float = 30.0,
    policy: ResolvedPolicy = LIVE,
) -> CallReport:
    records = tuple(
        AttemptRecord(index=index + 1, classification=classification, latency_ms=100)
        for index in range(attempts)
    )
    return CallReport(
        classification=classification,
        attempts=records,
        deadlines=CallDeadlines.start(policy, 0.0),
        deadline_hit="hard",
        elapsed_s=elapsed,
    )


def ledger() -> RunLedger:
    return RunLedger(
        run=RunRef("run-x", RunResolution.HEADER),
        limits=BudgetLimits(),
        started_at=NOW,
        last_seen_at=NOW,
    )


def entry(volatility: Volatility = Volatility.STATIC) -> StoredResponse:
    return StoredResponse(
        key="k",
        url="https://en.wikipedia.org/wiki/Foo",
        method="GET",
        endpoint="https://en.wikipedia.org/wiki/Foo",
        status=200,
        headers=(("Cache-Control", "max-age=60"),),
        body_sha256="a" * 64,
        body_bytes=40_000,
        requested_at=NOW - 2460,
        received_at=NOW - 2460,
        stored_at=NOW - 2460,
        volatility=volatility,
    )


def test_a_call_that_worked_proceeds_with_no_note() -> None:
    outcome = build(Outcome.FRESH, STATIC, ledger=ledger(), now=NOW)
    assert outcome.advice is Advice.PROCEED
    assert outcome.note == ""
    assert_valid("outcome", outcome.as_dict())


def test_a_stale_outcome_carries_its_age_provenance_and_caution() -> None:
    served = ServeStale(entry(), 2460.0, StaleReason.ERROR, Volatility.STATIC)
    outcome = build(
        Outcome.STALE,
        STATIC,
        report=report_for(judged(ConnectTimedOut(), STATIC), policy=STATIC),
        served_stale=served,
        ledger=ledger(),
        now=NOW,
    )
    assert outcome.advice is Advice.PROCEED_WITH_CAUTION
    assert outcome.age_s == 2460
    assert outcome.stored_at is not None and outcome.stored_at.endswith("Z")
    assert outcome.content_sha256 == "a" * 64
    assert outcome.note.startswith("[leeward] STALE: served a copy stored 41m ago")
    assert_valid("outcome", outcome.as_dict())


def test_a_live_endpoint_down_treats_the_value_as_unknown_and_says_what_is_withheld() -> None:
    outcome = build(
        Outcome.DOWN,
        LIVE,
        report=report_for(judged(ConnectTimedOut())),
        withheld=Withhold(WithheldReason.VOLATILITY_LIVE, 2460, entry(Volatility.LIVE)),
        ledger=ledger(),
        now=NOW,
    )
    assert outcome.advice is Advice.TREAT_AS_UNKNOWN
    assert outcome.withheld is not None
    assert outcome.withheld.reason is WithheldReason.VOLATILITY_LIVE
    assert outcome.withheld.available_via is None
    assert "classified `live`" in outcome.note
    assert "Treat this value as unknown" in outcome.note
    assert outcome.failure is not None
    assert outcome.failure.failure_class is FailureClass.CONNECT_TIMEOUT
    assert outcome.failure.attempts == 2
    assert_valid("outcome", outcome.as_dict())


def test_a_withheld_older_copy_is_offered_only_where_it_may_be() -> None:
    withheld = Withhold(WithheldReason.BEYOND_STALE_ALLOWANCE, 260_000, entry())
    offered = build(
        Outcome.DOWN,
        STATIC,
        report=report_for(judged(ConnectTimedOut(), STATIC), policy=STATIC),
        withheld=withheld,
        ledger=ledger(),
        accept_stale_via="header",
        now=NOW,
    )
    assert offered.withheld is not None
    assert offered.withheld.available_via == "X-Leeward-Accept-Stale: 1"
    assert "X-Leeward-Accept-Stale: 1" in offered.note
    assert_valid("outcome", offered.as_dict())

    live_withheld = build(
        Outcome.DOWN,
        LIVE,
        report=report_for(judged(ConnectTimedOut())),
        withheld=Withhold(WithheldReason.VOLATILITY_LIVE, 60, entry(Volatility.LIVE)),
        ledger=ledger(),
        accept_stale_via="header",
        now=NOW,
    )
    assert live_withheld.withheld is not None
    assert live_withheld.withheld.available_via is None


def test_a_rate_limit_says_retry_after_and_carries_the_time() -> None:
    limited = judged(Response(429, {"Retry-After": "90"}), STATIC)
    outcome = build(
        Outcome.DOWN,
        STATIC,
        report=report_for(limited, attempts=1, policy=STATIC),
        ledger=ledger(),
        now=NOW,
    )
    assert outcome.advice is Advice.RETRY_AFTER
    assert outcome.failure is not None and outcome.failure.retry_after_s == 90.0
    assert "It can be retried in 1m" in outcome.note
    assert_valid("outcome", outcome.as_dict())


def test_a_transient_failure_with_attempts_left_still_names_a_time_to_come_back() -> None:
    breaker = Breaker(key=STATIC.endpoint, scope="endpoint", state=BreakerState.OPEN)
    transient = judged(Response(500, {}), STATIC)
    outcome = build(
        Outcome.DOWN,
        STATIC,
        report=report_for(transient, attempts=1, policy=STATIC),
        ledger=ledger(),
        breaker=breaker,
        now=NOW,
    )
    assert outcome.advice is Advice.RETRY_AFTER
    assert outcome.failure is not None and outcome.failure.retry_after_s
    assert_valid("outcome", outcome.as_dict())


def test_a_vanished_tool_is_final_for_the_run() -> None:
    tool_policy = resolve(
        parse_config("rules:\n  - match: {tool: 'notes/*'}\n    pure: true\n").config,
        CallTarget.tool("notes", "threat_intel_lookup"),
    )
    gone = classify(ToolAbsent("delisted"), tool_policy, SNAPSHOT)
    outcome = build(
        Outcome.DOWN,
        tool_policy,
        report=report_for(gone, attempts=1, policy=tool_policy),
        ledger=ledger(),
        now=NOW,
    )
    assert outcome.advice is Advice.DO_NOT_RETRY
    assert "`threat_intel_lookup` is gone from its MCP server (notes)" in outcome.note
    assert outcome.endpoint == "notes/threat_intel_lookup"
    assert_valid("outcome", outcome.as_dict())


def test_a_refusal_reports_the_class_behind_it_and_the_breaker_state() -> None:
    behind = judged(ConnectTimedOut())
    short = refused(FailureClass.BREAKER_OPEN, behind, "the host breaker is open", retry_after_s=5)
    breaker = Breaker(
        key=LIVE.endpoint,
        scope="host",
        state=BreakerState.OPEN,
        opened_by=behind,
        next_probe_at=NOW + 5,
    )
    outcome = build(
        Outcome.DOWN,
        LIVE,
        report=report_for(short, attempts=1),
        ledger=ledger(),
        breaker=breaker,
        now=NOW,
    )
    assert outcome.failure is not None
    assert outcome.failure.failure_class is FailureClass.BREAKER_OPEN
    assert outcome.failure.underlying_class is FailureClass.CONNECT_TIMEOUT
    assert outcome.breaker is not None
    assert outcome.breaker.state is BreakerState.OPEN
    assert outcome.breaker.opened_by_class is FailureClass.CONNECT_TIMEOUT
    assert outcome.breaker.next_probe_in_s == 5
    assert_valid("outcome", outcome.as_dict())


def test_the_budget_travels_with_every_outcome() -> None:
    spent = ledger()
    spent.spend_retry(STATIC.endpoint)
    spent.spend_seconds(20.0)
    outcome = build(Outcome.FRESH, STATIC, ledger=spent, now=NOW)
    assert outcome.budget is not None
    assert outcome.budget.run_id == "run-x"
    assert outcome.budget.retry_attempts_remaining == 19
    assert outcome.budget.retry_seconds_remaining == 100.0
    assert outcome.budget.endpoint_attempts_remaining == 3


@pytest.mark.parametrize(
    ("outcome", "volatility", "disposition", "withheld", "exhausted", "advice"),
    [
        (Outcome.FRESH, Volatility.LIVE, None, None, False, Advice.PROCEED),
        (Outcome.STALE, Volatility.STATIC, None, None, False, Advice.PROCEED_WITH_CAUTION),
        (Outcome.STALE, Volatility.VOLATILE, None, None, False, Advice.PROCEED_WITH_CAUTION),
        (Outcome.DOWN, Volatility.VOLATILE, Disposition.WAIT, None, False, Advice.RETRY_AFTER),
        (Outcome.DOWN, Volatility.LIVE, Disposition.WAIT, None, False, Advice.RETRY_AFTER),
        (
            Outcome.DOWN,
            Volatility.LIVE,
            Disposition.TRANSIENT,
            None,
            False,
            Advice.TREAT_AS_UNKNOWN,
        ),
        (
            Outcome.DOWN,
            Volatility.STATIC,
            Disposition.TRANSIENT,
            WithheldReason.VOLATILITY_LIVE,
            False,
            Advice.TREAT_AS_UNKNOWN,
        ),
        (Outcome.DOWN, Volatility.STATIC, Disposition.NEVER, None, False, Advice.DO_NOT_RETRY),
        (Outcome.DOWN, Volatility.STATIC, Disposition.TRANSIENT, None, True, Advice.DO_NOT_RETRY),
        (
            Outcome.DOWN,
            Volatility.STATIC,
            Disposition.UNKNOWN,
            None,
            False,
            Advice.TREAT_AS_UNKNOWN,
        ),
        (Outcome.DOWN, Volatility.STATIC, Disposition.TRANSIENT, None, False, Advice.RETRY_AFTER),
    ],
)
def test_the_advice_table(
    outcome: Outcome,
    volatility: Volatility,
    disposition: Disposition | None,
    withheld: WithheldReason | None,
    exhausted: bool,
    advice: Advice,
) -> None:
    failure = (
        None
        if disposition is None
        else Classification(FailureClass.CONNECT_TIMEOUT, disposition, None, "because")
    )
    assert (
        advice_for(outcome, volatility, failure, withheld, attempts_exhausted=exhausted) is advice
    )


def test_a_spent_budget_is_do_not_retry_whatever_its_disposition() -> None:
    spent = Classification(FailureClass.BUDGET_EXHAUSTED, Disposition.NEVER, None, "spent")
    assert (
        advice_for(Outcome.DOWN, Volatility.STATIC, spent, None, attempts_exhausted=False)
        is Advice.DO_NOT_RETRY
    )


def test_an_outcome_for_a_live_endpoint_can_never_be_stale() -> None:
    built = build(Outcome.FRESH, LIVE, ledger=ledger(), now=NOW)
    stale_outcome_guard(built)
    pretend = build(Outcome.FRESH, LIVE, ledger=ledger(), now=NOW)
    object.__setattr__(pretend, "outcome", Outcome.STALE)
    with pytest.raises(AssertionError, match="cannot be STALE"):
        stale_outcome_guard(pretend)
