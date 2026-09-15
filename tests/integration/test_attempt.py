# SPDX-License-Identifier: Apache-2.0
"""The engine against a real origin: what a call costs, when it stops, and what it says.

The deadlines here are tenths of what an operator would set, so the suite stays
quick, but nothing else is scaled: real sockets, real cancellation, real timing.
"""

from __future__ import annotations

import asyncio
import os
import random
import time
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from fakes.origin import FakeOrigin, Reply, constant, document, flaky, rate_limited

from leeward.attempt import AttemptEngine, CallReport
from leeward.breaker import BreakerPolicy, Breakers
from leeward.budget import BudgetLimits, RunLedger
from leeward.chaos import FaultInjector
from leeward.config import parse_config
from leeward.events import RunRef
from leeward.policy import CallTarget, ResolvedPolicy, resolve
from leeward.transport import Call, Transport
from leeward.vocab import BreakerState, Disposition, FailureClass, RunResolution

RUN = RunRef("run-a", RunResolution.HEADER)

SLACK_S = 0.5 if os.environ.get("CI") else 0.2
"""How far past a deadline a return may land. A shared runner is not a quiet laptop,
and what is under test is the deadline, not the scheduler's punctuality."""


def policy_for(
    url: str, *, soft: str = "200ms", hard: str = "1s", attempts: int = 2
) -> ResolvedPolicy:
    config = parse_config(
        "rules:\n"
        "  - match: {url: '*'}\n"
        f"    soft_deadline: {soft}\n"
        f"    hard_deadline: {hard}\n"
        f"    max_attempts: {attempts}\n"
    ).config
    return resolve(config, CallTarget.http(url))


def ledger_with(limits: BudgetLimits | None = None) -> RunLedger:
    return RunLedger(run=RUN, limits=limits or BudgetLimits(), started_at=0.0, last_seen_at=0.0)


@pytest.fixture
async def origin() -> AsyncIterator[FakeOrigin]:
    async with FakeOrigin() as running:
        yield running


@pytest.fixture
async def transport() -> AsyncIterator[Transport]:
    made = Transport()
    yield made
    await made.aclose()


class Waits:
    """Stands in for sleeping, so a test can see what the engine asked to wait."""

    def __init__(self) -> None:
        self.seconds: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.seconds.append(seconds)


def engine_with(transport: Transport, waits: Waits | None = None, **extra: object) -> AttemptEngine:
    return AttemptEngine(
        transport=transport,
        breakers=Breakers(BreakerPolicy()),
        rng=random.Random(7),
        sleep=(waits or Waits()),
        **extra,  # pyright: ignore[reportArgumentType]
    )


async def until_closed(origin: FakeOrigin) -> None:
    for _ in range(100):
        if origin.open_connections == 0:
            return
        await asyncio.sleep(0.02)


async def test_a_hang_ends_at_the_hard_deadline_and_the_next_call_returns_at_once(
    origin: FakeOrigin, transport: Transport
) -> None:
    origin.route("/slow", constant(Reply(hang=True)))
    engine = engine_with(transport)
    ledger = ledger_with()
    policy = policy_for(f"{origin.base_url}/slow", soft="200ms", hard="1s")
    call = Call("GET", f"{origin.base_url}/slow")

    started = time.monotonic()
    first = await engine.call(call, policy, ledger)
    elapsed = time.monotonic() - started

    assert first.classification.failure_class is FailureClass.WEDGED
    assert 1.0 <= elapsed <= 1.0 + SLACK_S
    assert first.deadline_hit == "hard"
    assert [record.hedge for record in first.attempts] == [False, True]
    assert first.classification.disposition is Disposition.NEVER
    assert "hangs twice" in first.classification.reason

    await until_closed(origin)
    assert origin.open_connections == 0
    assert origin.accepted == 2

    started = time.monotonic()
    second = await engine.call(call, policy, ledger)
    assert time.monotonic() - started < 0.1
    assert second.short_circuited
    assert second.classification.failure_class is FailureClass.BREAKER_OPEN
    assert second.classification.underlying_class is FailureClass.WEDGED
    assert second.classification.disposition is Disposition.NEVER
    assert origin.accepted == 2


async def test_a_call_with_an_older_copy_stops_waiting_at_the_soft_deadline(
    origin: FakeOrigin, transport: Transport
) -> None:
    origin.route("/slow", constant(Reply(hang=True)))
    engine = engine_with(transport)
    policy = policy_for(f"{origin.base_url}/slow", soft="200ms", hard="5s")

    started = time.monotonic()
    report = await engine.call(
        Call("GET", f"{origin.base_url}/slow"), policy, ledger_with(), stale_available=True
    )
    elapsed = time.monotonic() - started

    assert report.abandoned_at_soft
    assert report.deadline_hit == "soft"
    assert 0.2 <= elapsed <= 0.2 + SLACK_S
    assert report.background is not None and not report.background.done()
    assert origin.accepted == 1
    report.background.cancel()
    await asyncio.gather(report.background, return_exceptions=True)


async def test_a_transient_failure_is_retried_with_decorrelated_backoff(
    origin: FakeOrigin, transport: Transport
) -> None:
    origin.route("/flaky", flaky(failures=2, body=b"recovered"))
    waits = Waits()
    engine = engine_with(transport, waits)
    policy = policy_for(f"{origin.base_url}/flaky", attempts=3)

    report = await engine.call(Call("GET", f"{origin.base_url}/flaky"), policy, ledger_with())

    assert report.ok
    assert report.attempt_count == 3
    assert report.fetched is not None and report.fetched.body == b"recovered"
    assert len(waits.seconds) == 2
    assert all(0.1 <= wait <= 0.9 for wait in waits.seconds)
    assert origin.hits["/flaky"] == 3


async def test_a_rate_limit_longer_than_the_run_costs_exactly_one_attempt(
    origin: FakeOrigin, transport: Transport
) -> None:
    origin.route("/search", rate_limited(retry_after_s=3600))
    engine = engine_with(transport)
    ledger = ledger_with()
    policy = policy_for(f"{origin.base_url}/search")
    call = Call("GET", f"{origin.base_url}/search")

    first = await engine.call(call, policy, ledger)
    assert first.attempt_count == 1
    assert first.classification.failure_class is FailureClass.QUOTA_EXHAUSTED
    assert first.classification.disposition is Disposition.NEVER
    assert "exceeds remaining run budget" in first.classification.reason

    second = await engine.call(call, policy, ledger)
    assert second.short_circuited
    assert second.classification.underlying_class is FailureClass.QUOTA_EXHAUSTED
    assert origin.hits["/search"] == 1


async def test_a_rate_limit_the_run_can_afford_is_waited_out(
    origin: FakeOrigin, transport: Transport
) -> None:
    replies = [Reply(status=429, headers={"Retry-After": "1"}), Reply(status=200, body=b"late")]

    async def limited_once(_request: object) -> Reply:
        return replies.pop(0) if len(replies) > 1 else replies[0]

    origin.route("/search", limited_once)  # pyright: ignore[reportArgumentType]
    waits = Waits()
    engine = engine_with(transport, waits)

    report = await engine.call(
        Call("GET", f"{origin.base_url}/search"),
        policy_for(f"{origin.base_url}/search", hard="10s"),
        ledger_with(),
    )

    assert report.ok
    assert report.attempt_count == 2
    assert waits.seconds == [1.0]


async def test_an_injected_fault_takes_the_same_path_and_is_marked_injected(
    origin: FakeOrigin, transport: Transport, tmp_path: Path
) -> None:
    origin.route("/doc", document(b"hello"))
    injector = FaultInjector(tmp_path / "chaos.json", enabled=True, profile="dev")
    injector.arm("*", now=time.time(), failure_class=FailureClass.DNS_FAILURE)
    engine = engine_with(transport, injector=injector)

    report = await engine.call(
        Call("GET", f"{origin.base_url}/doc"),
        policy_for(f"{origin.base_url}/doc"),
        ledger_with(),
    )

    assert report.classification.failure_class is FailureClass.DNS_FAILURE
    assert report.classification.injected
    assert report.classification.disposition is Disposition.TRANSIENT
    assert origin.accepted == 0


async def test_an_injected_hang_waits_as_long_as_a_real_one_would(
    origin: FakeOrigin, transport: Transport, tmp_path: Path
) -> None:
    origin.route("/doc", document(b"hello"))
    injector = FaultInjector(tmp_path / "chaos.json", enabled=True, profile="dev")
    injector.hang("*", now=time.time())
    waits = Waits()
    engine = engine_with(transport, waits, injector=injector)

    report = await engine.call(
        Call("GET", f"{origin.base_url}/doc"),
        policy_for(f"{origin.base_url}/doc", hard="30s"),
        ledger_with(),
    )

    assert report.classification.failure_class is FailureClass.WEDGED
    assert report.classification.injected
    assert waits.seconds and waits.seconds[0] == pytest.approx(30.0, abs=0.5)


async def test_a_run_that_has_spent_its_allowance_is_refused_without_an_attempt(
    origin: FakeOrigin, transport: Transport
) -> None:
    origin.route("/broken", constant(Reply(status=500, body=b"boom")))
    engine = engine_with(transport)
    ledger = ledger_with(BudgetLimits(retry_attempts=1, retry_seconds=60.0, endpoint_attempts=1))
    policy = policy_for(f"{origin.base_url}/broken", attempts=2)
    call = Call("GET", f"{origin.base_url}/broken")

    first = await engine.call(call, policy, ledger)
    assert first.attempt_count == 2
    assert first.classification.failure_class is FailureClass.SERVER_ERROR

    second = await engine.call(call, policy, ledger)
    assert second.classification.failure_class in (
        FailureClass.BUDGET_EXHAUSTED,
        FailureClass.BREAKER_OPEN,
    )
    assert ledger.retry_attempts <= ledger.limits.retry_attempts
    assert ledger.endpoint_retries[policy.endpoint] <= ledger.limits.endpoint_attempts


async def test_three_server_errors_open_the_breaker_and_it_says_which_class(
    origin: FakeOrigin, transport: Transport
) -> None:
    origin.route("/broken", constant(Reply(status=502, body=b"bad gateway")))
    engine = engine_with(transport)
    policy = policy_for(f"{origin.base_url}/broken", attempts=1)
    call = Call("GET", f"{origin.base_url}/broken")

    reports: list[CallReport] = []
    for _ in range(4):
        reports.append(await engine.call(call, policy, ledger_with()))

    assert engine.breakers.get("endpoint", policy.endpoint).state is BreakerState.OPEN
    assert reports[-1].short_circuited
    assert reports[-1].classification.underlying_class is FailureClass.SERVER_ERROR
    assert origin.hits["/broken"] == 3
