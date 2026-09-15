# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from leeward.breaker import (
    CLEARED_ONLY_BY_EVENT,
    HOST_OPEN_AFTER_CONNECTIONS,
    Admission,
    Breaker,
    BreakerPolicy,
    Breakers,
    admit,
    observe,
)
from leeward.classify import (
    Classification,
    ConnectTimedOut,
    DeadlineReached,
    Evidence,
    Response,
    RunSnapshot,
    TlsRejected,
    ToolAbsent,
    classify,
)
from leeward.config import BreakerSettings, Config
from leeward.policy import CallTarget, resolve
from leeward.vocab import BreakerState, ClockTrust, FailureClass

RESOLVED = resolve(Config(), CallTarget.http("https://api.example.com/items"))
FRESH_RUN = RunSnapshot(now=0, retry_seconds_remaining=300, clock=ClockTrust.TRUSTED)


def judged(evidence: Evidence, snapshot: RunSnapshot = FRESH_RUN) -> Classification:
    return classify(evidence, RESOLVED, snapshot)


SUCCESS = judged(Response(200, {}))
SERVER = judged(Response(500, {}))
OVERLOADED = judged(Response(503, {"Retry-After": "40"}))
TIMEOUT = judged(ConnectTimedOut())
TLS = judged(TlsRejected(verify_code=62))
GONE = judged(ToolAbsent("delisted"))
MISSING = judged(Response(404, {}))
LIMITED = judged(Response(429, {"Retry-After": "5"}))
HUNG_TWICE = judged(
    DeadlineReached(connected=True, deadline_s=30),
    RunSnapshot(now=0, retry_seconds_remaining=300, wedged_before=1),
)

ORIGIN = "https://api.example.com:443"
ENDPOINT = "https://api.example.com/items"


def state(breakers: Breakers, scope: str = "endpoint", key: str = ENDPOINT) -> BreakerState:
    return breakers.get("host" if scope == "host" else "endpoint", key).state


def test_three_transient_failures_open_the_endpoint_breaker() -> None:
    breakers = Breakers(BreakerPolicy())
    assert breakers.record(ORIGIN, ENDPOINT, SERVER, now=0) == []
    assert breakers.record(ORIGIN, ENDPOINT, SERVER, now=1) == []
    (transition,) = breakers.record(ORIGIN, ENDPOINT, SERVER, now=2)
    assert (transition.before.state, transition.after.state) == (
        BreakerState.CLOSED,
        BreakerState.OPEN,
    )
    opened = breakers.get("endpoint", ENDPOINT)
    assert opened.opened_by is SERVER
    assert opened.next_probe_at == 2 + 5
    assert state(breakers, "host", ORIGIN) is BreakerState.CLOSED


def test_a_vanished_tool_opens_at_once_and_stays_open_until_it_returns() -> None:
    breakers = Breakers(BreakerPolicy())
    (transition,) = breakers.record(None, "notes/threat_intel_lookup", GONE, now=0)
    assert transition.after.state is BreakerState.OPEN
    verdict, _ = breakers.admit(None, "notes/threat_intel_lookup", now=10_000)
    assert verdict.admission is Admission.REFUSE
    assert verdict.refused_by is not None and verdict.refused_by.opened_by is GONE
    assert GONE.failure_class in CLEARED_ONLY_BY_EVENT
    breakers.record(None, "notes/threat_intel_lookup", SUCCESS, now=10_001)
    assert state(breakers, key="notes/threat_intel_lookup") is BreakerState.OPEN
    cleared = breakers.clear("endpoint", "notes/threat_intel_lookup")
    assert cleared is not None and cleared.after.state is BreakerState.CLOSED


def test_a_second_hang_opens_at_once_with_the_longest_backoff() -> None:
    breakers = Breakers(BreakerPolicy())
    breakers.record(ORIGIN, ENDPOINT, HUNG_TWICE, now=100)
    opened = breakers.get("endpoint", ENDPOINT)
    assert (opened.state, opened.next_probe_at) == (BreakerState.OPEN, 100 + 120)


def test_the_host_breaker_opens_after_two_connections_and_is_consulted_first() -> None:
    breakers = Breakers(BreakerPolicy())
    assert HOST_OPEN_AFTER_CONNECTIONS == 2
    breakers.record(ORIGIN, ENDPOINT, TIMEOUT, now=0)
    (transition,) = breakers.record(ORIGIN, ENDPOINT, TIMEOUT, now=1)
    assert transition.after.scope == "host"
    verdict, _ = breakers.admit(ORIGIN, "https://api.example.com/other", now=2)
    assert verdict.admission is Admission.REFUSE
    assert verdict.refused_by is not None
    assert verdict.refused_by.scope == "host"
    assert verdict.refused_by.opened_by is TIMEOUT
    assert state(breakers) is BreakerState.CLOSED


def test_a_certificate_failure_opens_the_host_at_once() -> None:
    breakers = Breakers(BreakerPolicy())
    breakers.record(ORIGIN, ENDPOINT, TLS, now=0)
    assert state(breakers, "host", ORIGIN) is BreakerState.OPEN


def test_a_success_between_connection_failures_resets_the_count() -> None:
    breakers = Breakers(BreakerPolicy())
    for classification in (TIMEOUT, SUCCESS, TIMEOUT):
        breakers.record(ORIGIN, ENDPOINT, classification, now=0)
    assert state(breakers, "host", ORIGIN) is BreakerState.CLOSED


def test_failures_about_one_scope_do_not_move_the_other() -> None:
    breakers = Breakers(BreakerPolicy())
    for now in range(3):
        breakers.record(ORIGIN, ENDPOINT, SERVER, now=now)
    assert state(breakers) is BreakerState.OPEN
    assert state(breakers, "host", ORIGIN) is BreakerState.CLOSED
    breakers.record(ORIGIN, "https://api.example.com/other", TIMEOUT, now=4)
    assert breakers.get("endpoint", "https://api.example.com/other").failures == 0


def test_request_and_run_scoped_failures_count_as_the_endpoint_answering() -> None:
    breakers = Breakers(BreakerPolicy())
    for now, classification in enumerate([SERVER, SERVER, MISSING, LIMITED, SERVER, SERVER]):
        breakers.record(ORIGIN, ENDPOINT, classification, now=now)
    assert state(breakers) is BreakerState.CLOSED


def test_half_open_lets_one_probe_through_and_closes_after_two_successes() -> None:
    breakers = Breakers(BreakerPolicy())
    for _ in range(3):
        breakers.record(ORIGIN, ENDPOINT, SERVER, now=0)
    assert breakers.admit(ORIGIN, ENDPOINT, now=4)[0].admission is Admission.REFUSE
    verdict, (transition,) = breakers.admit(ORIGIN, ENDPOINT, now=5)
    assert verdict.admission is Admission.PROBE
    assert transition.after.state is BreakerState.HALF_OPEN
    assert breakers.admit(ORIGIN, ENDPOINT, now=5)[0].admission is Admission.REFUSE
    assert breakers.record(ORIGIN, ENDPOINT, SUCCESS, now=6) == []
    assert breakers.admit(ORIGIN, ENDPOINT, now=6)[0].admission is Admission.PROBE
    (closing,) = breakers.record(ORIGIN, ENDPOINT, SUCCESS, now=7)
    assert closing.after == Breaker(ENDPOINT, "endpoint")


def test_a_failed_probe_reopens_with_doubled_backoff_up_to_the_cap() -> None:
    breakers = Breakers(BreakerPolicy())
    for _ in range(3):
        breakers.record(ORIGIN, ENDPOINT, SERVER, now=0)
    backoffs: list[float] = []
    now = 0.0
    for _ in range(8):
        record = breakers.get("endpoint", ENDPOINT)
        assert record.next_probe_at is not None
        now = record.next_probe_at
        assert breakers.admit(ORIGIN, ENDPOINT, now=now)[0].admission is Admission.PROBE
        breakers.record(ORIGIN, ENDPOINT, SERVER, now=now)
        backoffs.append(breakers.get("endpoint", ENDPOINT).backoff_s)
    assert backoffs == [10, 20, 40, 80, 120, 120, 120, 120]


def test_failures_that_land_after_opening_do_not_stack_the_backoff() -> None:
    breakers = Breakers(BreakerPolicy())
    for _ in range(3):
        breakers.record(ORIGIN, ENDPOINT, SERVER, now=0)
    breakers.record(ORIGIN, ENDPOINT, SERVER, now=1)
    opened = breakers.get("endpoint", ENDPOINT)
    assert (opened.backoff_s, opened.next_probe_at) == (5, 5)


def test_a_never_failure_upgrades_a_breaker_that_is_already_open() -> None:
    breakers = Breakers(BreakerPolicy())
    for _ in range(3):
        breakers.record(None, "notes/lookup", SERVER, now=0)
    breakers.record(None, "notes/lookup", GONE, now=1)
    upgraded = breakers.get("endpoint", "notes/lookup")
    assert (upgraded.opened_by, upgraded.next_probe_at) == (GONE, None)


def test_retry_after_on_an_overloaded_endpoint_delays_the_probe() -> None:
    breakers = Breakers(BreakerPolicy())
    for _ in range(3):
        breakers.record(ORIGIN, ENDPOINT, OVERLOADED, now=0)
    assert breakers.get("endpoint", ENDPOINT).next_probe_at == 40


def test_a_refusal_leaves_no_probe_half_claimed() -> None:
    breakers = Breakers(BreakerPolicy())
    for _ in range(3):
        breakers.record(ORIGIN, ENDPOINT, SERVER, now=0)
    breakers.record(ORIGIN, ENDPOINT, TIMEOUT, now=5)
    breakers.record(ORIGIN, ENDPOINT, TIMEOUT, now=5)
    verdict, transitions = breakers.admit(ORIGIN, ENDPOINT, now=5)
    assert (verdict.admission, transitions) == (Admission.REFUSE, [])
    assert not breakers.get("endpoint", ENDPOINT).probing


def test_a_probe_cut_short_by_the_host_is_withdrawn() -> None:
    breakers = Breakers(BreakerPolicy())
    for _ in range(3):
        breakers.record(ORIGIN, ENDPOINT, SERVER, now=0)
    assert breakers.admit(ORIGIN, ENDPOINT, now=5)[0].admission is Admission.PROBE
    breakers.record(ORIGIN, ENDPOINT, TIMEOUT, now=6)
    withdrawn = breakers.get("endpoint", ENDPOINT)
    assert (withdrawn.state, withdrawn.probing, withdrawn.next_probe_at) == (
        BreakerState.OPEN,
        False,
        6,
    )


def test_policy_reads_configuration_and_hosts_open_sooner() -> None:
    policy = BreakerPolicy.from_settings(BreakerSettings())
    assert policy == BreakerPolicy()
    assert policy.for_scope("host").open_after_failures == HOST_OPEN_AFTER_CONNECTIONS
    assert policy.for_scope("endpoint").open_after_failures == 3


OUTCOMES = [SUCCESS, SERVER, OVERLOADED, TIMEOUT, TLS, GONE, MISSING, LIMITED, HUNG_TWICE]


@given(
    steps=st.lists(
        st.tuples(
            st.sampled_from(OUTCOMES),
            st.floats(min_value=0, max_value=200, allow_nan=False),
            st.booleans(),
        ),
        max_size=60,
    ),
    scope=st.sampled_from(["host", "endpoint"]),
)
def test_breaker_invariants_hold_for_any_sequence(
    steps: list[tuple[Classification, float, bool]], scope: str
) -> None:
    breaker = Breaker("k", "host" if scope == "host" else "endpoint")
    policy = BreakerPolicy().for_scope(breaker.scope)
    now = 0.0
    for classification, gap, try_admission in steps:
        now += gap
        if try_admission:
            before = breaker
            admission, breaker = admit(breaker, now)
            if before.probing:
                assert admission is Admission.REFUSE
            if admission is not Admission.ALLOW or before.state is not BreakerState.CLOSED:
                assert admission is not Admission.ALLOW
        breaker = observe(breaker, classification, now, policy)
        if breaker.state is BreakerState.CLOSED:
            assert breaker.opened_by is None and breaker.next_probe_at is None
            assert not breaker.probing
        if breaker.probing:
            assert breaker.state is BreakerState.HALF_OPEN
        if breaker.state is BreakerState.OPEN and breaker.next_probe_at is None:
            assert breaker.opened_by is not None
            assert breaker.opened_by.failure_class in CLEARED_ONLY_BY_EVENT
        assert 0 <= breaker.backoff_s <= policy.backoff_max_s
        probe_in = breaker.next_probe_in_s(now)
        assert probe_in is None or probe_in >= 0


def test_the_outcomes_cover_every_breaker_relevant_class() -> None:
    classes = {outcome.failure_class for outcome in OUTCOMES}
    assert {FailureClass.TOOL_GONE, FailureClass.CONNECT_TIMEOUT, FailureClass.WEDGED} <= classes
