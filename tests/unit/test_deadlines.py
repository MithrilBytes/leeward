# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from leeward.config import parse_config
from leeward.deadlines import CallDeadlines, LatencyEstimator
from leeward.policy import CallTarget, ResolvedPolicy, resolve

ENDPOINT = "https://api.example.com/items"


def policy(soft: str, hard: str) -> ResolvedPolicy:
    config = parse_config(
        f"rules:\n  - match: {{url: '*'}}\n    soft_deadline: {soft}\n    hard_deadline: {hard}\n"
    ).config
    return resolve(config, CallTarget.http(ENDPOINT))


def test_deadlines_start_from_the_policy_and_run_on_the_given_clock() -> None:
    deadlines = CallDeadlines.start(policy("5s", "30s"), now=100.0)
    assert (deadlines.soft.at, deadlines.hard.at) == (105.0, 130.0)
    assert deadlines.elapsed(now=110.0) == 10.0
    assert deadlines.soft.remaining(now=110.0) == 0.0
    assert deadlines.hard.remaining(now=110.0) == 20.0


@pytest.mark.parametrize(
    ("now", "hit"),
    [(100.0, "none"), (104.9, "none"), (105.0, "soft"), (129.9, "soft"), (130.0, "hard")],
)
def test_the_deadline_reached_is_reported(now: float, hit: str) -> None:
    assert CallDeadlines.start(policy("5s", "30s"), now=100.0).hit(now) == hit


def test_a_hedge_waits_for_the_soft_deadline_when_nothing_is_known() -> None:
    deadlines = CallDeadlines.start(policy("5s", "30s"), now=100.0)
    assert deadlines.hedge_at(None).at == 105.0


def test_a_hedge_waits_longer_for_an_endpoint_that_is_usually_slow() -> None:
    deadlines = CallDeadlines.start(policy("5s", "30s"), now=100.0)
    assert deadlines.hedge_at(8.0).at == 108.0
    assert deadlines.hedge_at(2.0).at == 105.0


def test_a_hedge_never_starts_so_late_that_it_cannot_help() -> None:
    deadlines = CallDeadlines.start(policy("5s", "30s"), now=100.0)
    assert deadlines.hedge_at(40.0).at == 115.0
    late_soft = CallDeadlines.start(policy("20s", "30s"), now=100.0)
    assert late_soft.hedge_at(None).at == 115.0


def test_the_first_measurement_makes_a_threshold_of_three_times_it() -> None:
    """RFC 6298 §2.2: with one sample, srtt is the sample and rttvar is half of it."""
    estimator = LatencyEstimator()
    assert estimator.typical(ENDPOINT) is None
    estimator.observe(ENDPOINT, 0.4)
    assert estimator.typical(ENDPOINT) == pytest.approx(1.2)


def test_repeated_measurements_settle_on_what_the_endpoint_takes() -> None:
    estimator = LatencyEstimator()
    for _ in range(60):
        estimator.observe(ENDPOINT, 0.2)
    assert estimator.typical(ENDPOINT) == pytest.approx(0.2, abs=0.01)


def test_one_slow_answer_raises_the_threshold_and_normal_ones_bring_it_back() -> None:
    estimator = LatencyEstimator()
    for _ in range(60):
        estimator.observe(ENDPOINT, 0.2)
    settled = estimator.typical(ENDPOINT)
    estimator.observe(ENDPOINT, 3.0)
    raised = estimator.typical(ENDPOINT)
    assert settled is not None and raised is not None and raised > settled
    for _ in range(20):
        estimator.observe(ENDPOINT, 0.2)
    recovered = estimator.typical(ENDPOINT)
    assert recovered is not None and recovered < raised / 3


def test_each_endpoint_is_measured_on_its_own_and_can_be_forgotten() -> None:
    estimator = LatencyEstimator()
    estimator.observe(ENDPOINT, 0.4)
    estimator.observe("https://api.example.com/other", 4.0)
    assert estimator.typical(ENDPOINT) != estimator.typical("https://api.example.com/other")
    estimator.forget(ENDPOINT)
    assert estimator.typical(ENDPOINT) is None
