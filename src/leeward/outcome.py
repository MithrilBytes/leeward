# SPDX-License-Identifier: Apache-2.0
"""Outcomes: the one shape every surface reports, and the advice that sums it up.

FRESH, STALE or DOWN, carrying the class, whether waiting can help, what was
withheld and why, what the run has left, and the note the model reads. The surfaces
differ in how they carry this (a header, a content block, an error message) and
never in what it says.

`advice` is the machine-readable summary of the note. TREAT_AS_UNKNOWN is the value
that matters: it is leeward saying that the right output here is an explicit gap,
not an estimate. It is the only honest answer when the only meaningful value is the
current one and nobody has it.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from leeward.attempt import CallReport
from leeward.breaker import Breaker
from leeward.budget import RunLedger
from leeward.cache.freshness import ServeStale, StoredResponse, Withhold
from leeward.classify import Classification
from leeward.events import rfc3339
from leeward.notes import NoteFacts, compose
from leeward.policy import ResolvedPolicy
from leeward.templates import template_set_sha256
from leeward.vocab import (
    Advice,
    BreakerState,
    Disposition,
    FailureClass,
    Outcome,
    Volatility,
    WithheldReason,
)


def advice_for(
    outcome: Outcome,
    volatility: Volatility,
    failure: Classification | None,
    withheld_reason: WithheldReason | None,
    *,
    attempts_exhausted: bool,
) -> Advice:
    """The advice table, read top to bottom: the first row that fits wins.

    A rate limit that lifts in five seconds is worth waiting for even on a live
    endpoint, which is why WAIT is asked about before the live case.
    """
    if outcome is Outcome.FRESH:
        return Advice.PROCEED
    if outcome is Outcome.STALE:
        return Advice.PROCEED_WITH_CAUTION
    disposition = failure.disposition if failure is not None else None
    if disposition is Disposition.WAIT:
        return Advice.RETRY_AFTER
    if volatility is Volatility.LIVE or withheld_reason is WithheldReason.VOLATILITY_LIVE:
        return Advice.TREAT_AS_UNKNOWN
    if disposition is Disposition.NEVER or (
        failure is not None and failure.failure_class is FailureClass.BUDGET_EXHAUSTED
    ):
        return Advice.DO_NOT_RETRY
    if disposition is Disposition.UNKNOWN:
        return Advice.TREAT_AS_UNKNOWN
    if disposition is Disposition.TRANSIENT and attempts_exhausted:
        return Advice.DO_NOT_RETRY
    # Transient with attempts still to come: worth another try, and the failure
    # detail says when.
    return Advice.RETRY_AFTER


@dataclass(frozen=True, slots=True)
class FailureDetail:
    failure_class: FailureClass
    disposition: Disposition
    reason: str
    attempts: int
    retry_after_s: float | None = None
    origin_status: int | None = None
    underlying_class: FailureClass | None = None
    scope: str | None = None
    injected: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "class": str(self.failure_class),
            "disposition": str(self.disposition),
            "disposition_reason": self.reason,
            "retry_after_s": self.retry_after_s,
            "attempts": self.attempts,
            "origin_status": self.origin_status,
            "underlying_class": (
                str(self.underlying_class) if self.underlying_class is not None else None
            ),
            "scope": self.scope,
            "injected": self.injected,
        }


@dataclass(frozen=True, slots=True)
class WithheldDetail:
    age_s: int
    reason: WithheldReason
    available_via: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "age_s": self.age_s,
            "reason": str(self.reason),
            "available_via": self.available_via,
        }


@dataclass(frozen=True, slots=True)
class BudgetDetail:
    run_id: str
    retry_attempts_remaining: int
    retry_seconds_remaining: float
    endpoint_attempts_remaining: int

    def as_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "retry_attempts_remaining": self.retry_attempts_remaining,
            "retry_seconds_remaining": self.retry_seconds_remaining,
            "endpoint_attempts_remaining": self.endpoint_attempts_remaining,
        }


@dataclass(frozen=True, slots=True)
class BreakerDetail:
    state: BreakerState
    opened_by_class: FailureClass | None = None
    next_probe_in_s: float | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "state": str(self.state),
            "opened_by_class": (
                str(self.opened_by_class) if self.opened_by_class is not None else None
            ),
            "next_probe_in_s": self.next_probe_in_s,
        }


@dataclass(frozen=True, slots=True)
class CallOutcome:
    """What the agent is told, in the shape the schema describes."""

    outcome: Outcome
    endpoint: str
    volatility: Volatility
    advice: Advice
    note: str
    rule_index: int | None = None
    age_s: int | None = None
    stored_at: str | None = None
    content_sha256: str | None = None
    failure: FailureDetail | None = None
    withheld: WithheldDetail | None = None
    budget: BudgetDetail | None = None
    breaker: BreakerDetail | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "outcome": str(self.outcome),
            "endpoint": self.endpoint,
            "volatility": str(self.volatility),
            "rule_index": self.rule_index,
            "note": self.note,
            "advice": str(self.advice),
            "age_s": self.age_s,
            "stored_at": self.stored_at,
            "content_sha256": self.content_sha256,
            "failure": self.failure.as_dict() if self.failure else None,
            "withheld_cache": self.withheld.as_dict() if self.withheld else None,
            "budget": self.budget.as_dict() if self.budget else None,
            "breaker": self.breaker.as_dict() if self.breaker else None,
            "template_set_sha256": template_set_sha256(),
        }


def host_or_tool(policy: ResolvedPolicy) -> str:
    """What to call this endpoint in a sentence a person or a model reads."""
    target = policy.target
    if target.kind == "http":
        return urlsplit(target.name).hostname or target.name
    return target.name


def build(
    outcome: Outcome,
    policy: ResolvedPolicy,
    *,
    report: CallReport | None = None,
    served: StoredResponse | None = None,
    served_stale: ServeStale | None = None,
    withheld: Withhold | None = None,
    ledger: RunLedger | None = None,
    breaker: Breaker | None = None,
    accept_stale_via: str | None = None,
    known_failure: FailureClass | None = None,
    now: float = 0.0,
    clock_is_wrong: bool = False,
) -> CallOutcome:
    """Assemble an outcome from what the engine did and what the cache decided."""
    classification = report.classification if report is not None and not report.ok else None
    attempts = report.attempt_count if report is not None else 0
    remaining = ledger.remaining(policy.endpoint) if ledger is not None else None
    exhausted = bool(report is not None and attempts >= policy.max_attempts) or bool(
        remaining is not None and remaining.exhausted
    )

    withheld_detail = (
        WithheldDetail(
            age_s=int(withheld.age_s),
            reason=withheld.reason,
            available_via=_available_via(withheld.reason, accept_stale_via),
        )
        if withheld is not None
        else None
    )
    failure_detail = _failure_detail(classification, attempts, report) if classification else None
    advice = advice_for(
        outcome,
        policy.volatility,
        classification,
        withheld.reason if withheld is not None else None,
        attempts_exhausted=exhausted,
    )
    if (
        advice is Advice.RETRY_AFTER
        and failure_detail is not None
        and not failure_detail.retry_after_s
    ):
        wait = breaker.next_probe_in_s(now) if breaker is not None else None
        failure_detail = _with_retry_after(failure_detail, wait if wait else policy.soft_deadline_s)

    entry = served_stale.entry if served_stale is not None else served
    age = served_stale.age_s if served_stale is not None else None
    note = compose(
        NoteFacts(
            outcome=outcome,
            host_or_tool=host_or_tool(policy),
            volatility=policy.volatility,
            failure_class=classification.failure_class if classification else known_failure,
            disposition=classification.disposition if classification else None,
            attempts=attempts,
            elapsed_s=report.elapsed_s if report is not None else 0.0,
            age_s=age,
            stale_reason=served_stale.reason if served_stale is not None else None,
            withheld_age_s=withheld.age_s if withheld is not None else None,
            withheld_reason=withheld.reason if withheld is not None else None,
            retry_after_s=failure_detail.retry_after_s if failure_detail else None,
            retry_attempts_remaining=remaining.retry_attempts if remaining else None,
            accept_stale_via=accept_stale_via,
            tool_name=_tool_name(policy),
            server_name=_server_name(policy),
            soft_deadline_s=policy.soft_deadline_s,
            clock_is_wrong=clock_is_wrong,
        )
    )
    return CallOutcome(
        outcome=outcome,
        endpoint=policy.endpoint,
        volatility=policy.volatility,
        advice=advice,
        note=note,
        rule_index=policy.rule_index,
        age_s=int(age) if age is not None else None,
        stored_at=rfc3339(entry.received_at) if entry is not None and age is not None else None,
        content_sha256=entry.body_sha256 if entry is not None and age is not None else None,
        failure=failure_detail,
        withheld=withheld_detail,
        budget=(
            BudgetDetail(
                run_id=ledger.run.id,
                retry_attempts_remaining=remaining.retry_attempts,
                retry_seconds_remaining=remaining.retry_seconds,
                endpoint_attempts_remaining=remaining.endpoint_attempts,
            )
            if ledger is not None and remaining is not None
            else None
        ),
        breaker=(
            BreakerDetail(
                state=breaker.state,
                opened_by_class=(
                    breaker.opened_by.failure_class if breaker.opened_by is not None else None
                ),
                next_probe_in_s=breaker.next_probe_in_s(now),
            )
            if breaker is not None
            else None
        ),
    )


def _available_via(reason: WithheldReason, accept_stale_via: str | None) -> str | None:
    """A withheld copy is offered only where offering it is safe to do."""
    if reason is not WithheldReason.BEYOND_STALE_ALLOWANCE or accept_stale_via is None:
        return None
    return {
        "header": "X-Leeward-Accept-Stale: 1",
        "argument": "accept_stale: true",
    }.get(accept_stale_via)


def _failure_detail(
    classification: Classification, attempts: int, report: CallReport | None
) -> FailureDetail:
    status = None
    if report is not None and report.fetched is not None:
        status = report.fetched.status
    return FailureDetail(
        failure_class=classification.failure_class,
        disposition=classification.disposition or Disposition.UNKNOWN,
        reason=classification.reason,
        attempts=max(attempts, 1),
        retry_after_s=classification.retry_after_s,
        origin_status=status,
        underlying_class=classification.underlying_class,
        scope=str(classification.scope) if classification.scope is not None else None,
        injected=classification.injected,
    )


def _with_retry_after(detail: FailureDetail, seconds: float) -> FailureDetail:
    return FailureDetail(
        failure_class=detail.failure_class,
        disposition=detail.disposition,
        reason=detail.reason,
        attempts=detail.attempts,
        retry_after_s=seconds,
        origin_status=detail.origin_status,
        underlying_class=detail.underlying_class,
        scope=detail.scope,
        injected=detail.injected,
    )


def _tool_name(policy: ResolvedPolicy) -> str | None:
    if policy.target.kind != "tool":
        return None
    return policy.target.name.split("/", 1)[1]


def _server_name(policy: ResolvedPolicy) -> str | None:
    if policy.target.kind != "tool":
        return None
    return policy.target.name.split("/", 1)[0]


def stale_outcome_guard(outcome: CallOutcome) -> None:
    """The last gate before an outcome leaves: a live endpoint is never STALE.

    freshness.py already makes the stale decision unbuildable for this class, and
    the event log refuses to record it. This is the third place, because the cost of
    being wrong once is the whole point of the tool.
    """
    if outcome.outcome is Outcome.STALE and outcome.volatility in (
        Volatility.LIVE,
        Volatility.NEVER,
    ):
        raise AssertionError(f"{outcome.endpoint} is {outcome.volatility} and cannot be STALE")
