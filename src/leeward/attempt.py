# SPDX-License-Identifier: Apache-2.0
"""The attempt engine: how many times to try, when to stop, and what to report.

One call becomes a short sequence of attempts bounded by three things at once. The
class of failure ends it, since nothing retries a name that does not exist. The
run's retry budget ends it. The hard deadline ends it. Whichever arrives first
wins, and what comes back says which it was.

Waiting between attempts is exponential with decorrelated jitter: each wait is
drawn between the base and three times the previous one, which spreads retries
without the long tail full jitter leaves. Marc Brooker, "Exponential Backoff And
Jitter" (AWS Architecture Blog, 2015).

At the soft deadline a call with an older copy to fall back on stops waiting, and
leaves its request running so the copy can be refreshed. A call with nothing to
serve opens a second attempt on a fresh connection instead: the usual reason one
request hangs is the connection it is on, and two connections hung at once is far
better evidence that the endpoint itself is wedged.

Nothing here writes an event or composes a note. It reports what happened, and a
surface turns that into an outcome the agent can act on.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Callable, Coroutine, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from leeward.breaker import Admission, Breakers, Transition
from leeward.budget import RunLedger
from leeward.chaos import FaultInjector
from leeward.classify import (
    Classification,
    DeadlineReached,
    Injected,
    Response,
    RunSnapshot,
    classify,
    refused,
)
from leeward.deadlines import CallDeadlines, Deadline, DeadlineHit, LatencyEstimator
from leeward.policy import ResolvedPolicy
from leeward.transport import Call, Counters, Fetched
from leeward.vocab import ClockTrust, Disposition, FailureClass, FailureScope

BACKOFF_BASE_S = 0.1
BACKOFF_CAP_S = 5.0

_SEVERITY = {
    Disposition.NEVER: 3,
    Disposition.WAIT: 2,
    Disposition.UNKNOWN: 1,
    Disposition.TRANSIENT: 0,
}
"""Which attempt in a round speaks for the call: the one that closes the most doors."""


class Caller(Protocol):
    """Whatever performs one attempt: the HTTP transport, or an MCP tool call.

    The engine does not care which. It counts attempts, watches deadlines and reads
    the evidence that comes back, and that is the same work either way.
    """

    async def fetch(
        self,
        call: Call,
        policy: ResolvedPolicy,
        deadline: Deadline,
        *,
        fresh: bool = False,
        idle_s: float | None = None,
        counters: Counters | None = None,
    ) -> Fetched: ...


def decorrelated_jitter(previous_s: float, rng: random.Random) -> float:
    """The next wait, drawn between the base and three times the last one."""
    return min(BACKOFF_CAP_S, rng.uniform(BACKOFF_BASE_S, max(previous_s * 3, BACKOFF_BASE_S)))


def _unchecked_clock() -> ClockTrust:
    return ClockTrust.UNCHECKED


def decide(judged: Sequence[Classification]) -> Classification:
    """A success if there was one, otherwise the failure that rules out the most."""
    for classification in judged:
        if classification.ok:
            return classification
    return max(judged, key=lambda item: _SEVERITY.get(item.disposition or Disposition.TRANSIENT, 0))


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    index: int
    classification: Classification
    latency_ms: int
    hedge: bool = False


@dataclass(frozen=True, slots=True)
class CallReport:
    """What the engine did, in the terms the surfaces and the event log need."""

    classification: Classification
    attempts: tuple[AttemptRecord, ...]
    deadlines: CallDeadlines
    deadline_hit: DeadlineHit
    elapsed_s: float
    fetched: Fetched | None = None
    transitions: tuple[Transition, ...] = ()
    short_circuited: bool = False
    abandoned_at_soft: bool = False
    background: asyncio.Task[Fetched] | None = None

    @property
    def ok(self) -> bool:
        return self.classification.ok

    @property
    def attempt_count(self) -> int:
        return len(self.attempts)

    @property
    def latencies_ms(self) -> list[int]:
        return [record.latency_ms for record in self.attempts]


@dataclass
class AttemptEngine:
    """Runs one call to completion, or to the first good reason to stop."""

    transport: Caller
    breakers: Breakers
    injector: FaultInjector | None = None
    estimator: LatencyEstimator = field(default_factory=LatencyEstimator)
    clock: Callable[[], float] = time.monotonic
    wall_clock: Callable[[], float] = time.time
    sleep: Callable[[float], Coroutine[Any, Any, None]] = asyncio.sleep
    rng: random.Random = field(default_factory=random.Random)
    clock_trust: Callable[[], ClockTrust] = _unchecked_clock

    async def call(
        self,
        call: Call,
        policy: ResolvedPolicy,
        ledger: RunLedger,
        *,
        request_key: str | None = None,
        stale_available: bool = False,
        allow_hedge: bool = True,
        caller: Caller | None = None,
    ) -> CallReport:
        started = self.clock()
        deadlines = CallDeadlines.start(policy, started)
        endpoint = policy.endpoint
        origin = policy.target.origin
        transitions: list[Transition] = []

        early = self._refusal(policy, ledger, deadlines, started, request_key, transitions)
        if early is not None:
            return early

        records: list[AttemptRecord] = []
        fetched: Fetched | None = None
        backoff = 0.0
        hedged = False
        round_index = 0

        while True:
            round_index += 1
            hedging = (
                allow_hedge
                and policy.idempotent
                and not stale_available
                and not hedged
                and ledger.may_retry(endpoint)
            )
            round_started = self.clock()
            results, abandoned, background = await self._round(
                call,
                policy,
                deadlines,
                hedging=hedging,
                stale_available=stale_available,
                caller=caller or self.transport,
            )
            if abandoned:
                return CallReport(
                    classification=Classification(
                        FailureClass.OK, None, None, "still waiting at the soft deadline"
                    ),
                    attempts=tuple(records),
                    deadlines=deadlines,
                    deadline_hit="soft",
                    elapsed_s=self.clock() - started,
                    transitions=tuple(transitions),
                    abandoned_at_soft=True,
                    background=background,
                )

            judged: list[Classification] = []
            for result, is_hedge in results:
                if is_hedge:
                    hedged = True
                    ledger.spend_retry(endpoint)
                    if round_index == 1:
                        ledger.spend_seconds(result.elapsed_s)
                classification = self._judge(result, policy, ledger, endpoint)
                judged.append(classification)
                records.append(
                    AttemptRecord(
                        index=len(records) + 1,
                        classification=classification,
                        latency_ms=int(result.elapsed_s * 1000),
                        hedge=is_hedge,
                    )
                )
                transitions += self.breakers.record(origin, endpoint, classification, self.clock())
                if classification.ok:
                    fetched = result
                    self.estimator.observe(endpoint, result.elapsed_s)
            if round_index > 1:
                ledger.spend_seconds(self.clock() - round_started)

            decisive = decide(judged)
            now = self.clock()
            if decisive.ok:
                break
            sent = any(result.bytes_sent for result, _hedge in results)
            stop = self._stop_reason(decisive, policy, ledger, deadlines, records, now, sent=sent)
            if stop is not None:
                decisive = stop
                break
            wait = (
                decisive.retry_after_s
                if decisive.disposition is Disposition.WAIT and decisive.retry_after_s
                else decorrelated_jitter(backoff, self.rng)
            )
            backoff = wait
            if now + wait >= deadlines.hard.at:
                break
            await self.sleep(wait)
            ledger.spend_seconds(wait)
            ledger.spend_retry(endpoint)

        finished = self.clock()
        self._remember(decisive, ledger, endpoint, request_key, finished)
        return CallReport(
            classification=decisive,
            attempts=tuple(records),
            deadlines=deadlines,
            deadline_hit=deadlines.hit(finished),
            elapsed_s=finished - started,
            fetched=fetched,
            transitions=tuple(transitions),
        )

    def _refusal(
        self,
        policy: ResolvedPolicy,
        ledger: RunLedger,
        deadlines: CallDeadlines,
        started: float,
        request_key: str | None,
        transitions: list[Transition],
    ) -> CallReport | None:
        """What this run already knows, before it spends a connection learning it again."""
        endpoint = policy.endpoint
        for key in (endpoint, request_key):
            remembered = ledger.recall(key, started) if key is not None else None
            if remembered is None:
                continue
            behind = remembered.classification
            return self._refused_report(
                refused(
                    FailureClass.BREAKER_OPEN,
                    behind,
                    f"this run already saw {behind.failure_class} here",
                    retry_after_s=(
                        None if remembered.until is None else max(remembered.until - started, 0.0)
                    ),
                ),
                deadlines,
                started,
                transitions,
            )
        verdict, opened = self.breakers.admit(policy.target.origin, endpoint, started)
        transitions += opened
        if verdict.admission is Admission.REFUSE and verdict.refused_by is not None:
            breaker = verdict.refused_by
            return self._refused_report(
                refused(
                    FailureClass.BREAKER_OPEN,
                    breaker.opened_by,
                    f"the {breaker.scope} breaker is open",
                    retry_after_s=breaker.next_probe_in_s(started),
                ),
                deadlines,
                started,
                transitions,
            )
        endpoint_breaker = self.breakers.get("endpoint", endpoint)
        if not ledger.may_retry(endpoint) and endpoint_breaker.failures:
            return self._refused_report(
                refused(
                    FailureClass.BUDGET_EXHAUSTED,
                    endpoint_breaker.opened_by,
                    "this run has spent its retry allowance here",
                ),
                deadlines,
                started,
                transitions,
            )
        return None

    def _refused_report(
        self,
        classification: Classification,
        deadlines: CallDeadlines,
        started: float,
        transitions: list[Transition],
    ) -> CallReport:
        return CallReport(
            classification=classification,
            attempts=(),
            deadlines=deadlines,
            deadline_hit="none",
            elapsed_s=self.clock() - started,
            transitions=tuple(transitions),
            short_circuited=True,
        )

    async def _round(
        self,
        call: Call,
        policy: ResolvedPolicy,
        deadlines: CallDeadlines,
        *,
        hedging: bool,
        stale_available: bool,
        caller: Caller,
    ) -> tuple[list[tuple[Fetched, bool]], bool, asyncio.Task[Fetched] | None]:
        """One attempt, plus a hedge when the wait goes on with nothing to show for it."""
        results: list[tuple[Fetched, bool]] = []
        counters = Counters()
        first = asyncio.create_task(self._attempt(call, policy, deadlines.hard, counters, caller))
        attempts: dict[asyncio.Task[Fetched], tuple[bool, Counters]] = {first: (False, counters)}
        hedge_started = False
        try:
            while attempts:
                now = self.clock()
                if deadlines.hard.passed(now):
                    results += self._cut_off(attempts, policy, deadlines, now)
                    await asyncio.gather(*attempts, return_exceptions=True)
                    attempts.clear()
                    break
                wake = deadlines.hard.at
                if stale_available:
                    wake = min(wake, deadlines.soft.at)
                elif hedging and not hedge_started:
                    wake = min(wake, deadlines.hedge_at(self.estimator.typical(policy.endpoint)).at)
                done, _still = await asyncio.wait(
                    set(attempts), timeout=max(wake - now, 0.0), return_when=asyncio.FIRST_COMPLETED
                )
                for task in done:
                    is_hedge, _counters = attempts.pop(task)
                    results.append((task.result(), is_hedge))
                if any(isinstance(result.evidence, Response) for result, _hedge in results):
                    break
                if results and not attempts:
                    break
                now = self.clock()
                if stale_available and deadlines.soft.passed(now) and not results:
                    attempts.pop(first, None)
                    return [], True, first
                if hedging and not hedge_started and not results:
                    hedge_counters = Counters()
                    hedge = asyncio.create_task(
                        self._attempt(
                            call, policy, deadlines.hard, hedge_counters, caller, fresh=True
                        )
                    )
                    attempts[hedge] = (True, hedge_counters)
                    hedge_started = True
        finally:
            for task in attempts:
                task.cancel()
            if attempts:
                await asyncio.gather(*attempts, return_exceptions=True)
        return results, False, None

    def _cut_off(
        self,
        attempts: dict[asyncio.Task[Fetched], tuple[bool, Counters]],
        policy: ResolvedPolicy,
        deadlines: CallDeadlines,
        now: float,
    ) -> list[tuple[Fetched, bool]]:
        """The hard deadline arrived: every attempt still open becomes evidence of that."""
        cut: list[tuple[Fetched, bool]] = []
        for task, (is_hedge, counters) in attempts.items():
            task.cancel()
            cut.append(
                (
                    Fetched(
                        evidence=DeadlineReached(
                            connected=counters.connected, deadline_s=policy.hard_deadline_s
                        ),
                        elapsed_s=deadlines.elapsed(now),
                        connected=counters.connected,
                        bytes_sent=counters.sent > 0,
                    ),
                    is_hedge,
                )
            )
        return cut

    async def _attempt(
        self,
        call: Call,
        policy: ResolvedPolicy,
        deadline: Deadline,
        counters: Counters,
        caller: Caller,
        *,
        fresh: bool = False,
    ) -> Fetched:
        """One attempt, with an armed fault standing in for the origin when there is one."""
        injector = self.injector
        fault = (
            injector.armed(policy.endpoint, policy.target.origin, self.wall_clock())
            if injector is not None
            else None
        )
        if injector is None or fault is None:
            return await caller.fetch(call, policy, deadline, fresh=fresh, counters=counters)
        started = self.clock()
        wait = injector.with_deadline(fault, policy.soft_deadline_s, policy.hard_deadline_s)
        if wait:
            await self.sleep(min(wait, deadline.remaining(started)))
        if fault.failure_class is None:
            return await caller.fetch(call, policy, deadline, fresh=fresh, counters=counters)
        connected = fault.failure_class is FailureClass.WEDGED
        counters.connected = connected
        return Fetched(
            evidence=Injected(fault.failure_class, retry_after_s=fault.retry_after_s),
            elapsed_s=self.clock() - started,
            connected=connected,
        )

    def _judge(
        self, result: Fetched, policy: ResolvedPolicy, ledger: RunLedger, endpoint: str
    ) -> Classification:
        """Name one attempt, counting a hang so that a second one in the run is final."""
        evidence = result.evidence
        hung = (isinstance(evidence, DeadlineReached) and evidence.connected) or (
            isinstance(evidence, Injected) and evidence.failure_class is FailureClass.WEDGED
        )
        wedged_before = ledger.note_wedge(endpoint) if hung else 0
        snapshot = RunSnapshot(
            now=self.wall_clock(),
            retry_seconds_remaining=ledger.remaining(endpoint).retry_seconds,
            wedged_before=wedged_before,
            clock=self.clock_trust(),
        )
        return classify(evidence, policy, snapshot)

    def _stop_reason(
        self,
        decisive: Classification,
        policy: ResolvedPolicy,
        ledger: RunLedger,
        deadlines: CallDeadlines,
        records: list[AttemptRecord],
        now: float,
        *,
        sent: bool,
    ) -> Classification | None:
        """Why this call stops trying, or None to go round again."""
        if decisive.disposition is Disposition.NEVER or deadlines.hard.passed(now):
            return decisive
        if not policy.idempotent and sent:
            # Bytes have left for something that is not safe to repeat.
            return decisive
        # A class cap such as "server errors get two attempts" is a default: a rule
        # that names max_attempts has already answered the question for this endpoint.
        cap = policy.max_attempts
        if not policy.max_attempts_explicit and decisive.attempt_cap is not None:
            cap = min(cap, decisive.attempt_cap)
        if len(records) >= cap:
            return decisive
        if not ledger.may_retry(policy.endpoint):
            return refused(
                FailureClass.BUDGET_EXHAUSTED, decisive, "this run has spent its retry allowance"
            )
        return None

    def _remember(
        self,
        decisive: Classification,
        ledger: RunLedger,
        endpoint: str,
        request_key: str | None,
        now: float,
    ) -> None:
        """Keep what this run should not have to learn twice."""
        if decisive.ok or decisive.scope not in (FailureScope.RUN, FailureScope.REQUEST):
            return
        key = endpoint if decisive.scope is FailureScope.RUN else (request_key or endpoint)
        if decisive.disposition is Disposition.NEVER:
            ledger.remember(key, decisive, until=None)
        elif decisive.disposition is Disposition.WAIT and decisive.retry_after_s:
            ledger.remember(key, decisive, until=now + decisive.retry_after_s)
