# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import pytest

from leeward.chaos import ChaosDisabledError, Fault, FaultInjector
from leeward.vocab import FailureClass

WIKI = "https://en.wikipedia.org/wiki/Foo"
WIKI_ORIGIN = "https://en.wikipedia.org:443"


def injector(tmp_path: Path, *, enabled: bool = True, profile: str = "dev") -> FaultInjector:
    return FaultInjector(tmp_path / "chaos.json", enabled=enabled, profile=profile)


def test_fault_injection_cannot_be_enabled_under_a_production_profile(tmp_path: Path) -> None:
    with pytest.raises(ChaosDisabledError, match="production"):
        FaultInjector(tmp_path / "chaos.json", enabled=True, profile="production")
    quiet = FaultInjector(tmp_path / "chaos.json", enabled=False, profile="production")
    assert not quiet.enabled


def test_an_injector_that_is_off_arms_nothing_and_finds_nothing(tmp_path: Path) -> None:
    off = injector(tmp_path, enabled=False)
    with pytest.raises(ChaosDisabledError, match=r"chaos\.enabled"):
        off.arm("*/status*", now=0, failure_class=FailureClass.CONNECT_TIMEOUT)
    assert off.armed("https://ops.example.com/status", None, now=0) is None
    assert off.all(now=0) == []


def test_the_classes_leeward_produces_itself_cannot_be_injected(tmp_path: Path) -> None:
    with pytest.raises(ChaosDisabledError, match="leeward's own"):
        injector(tmp_path).arm("*", now=0, failure_class=FailureClass.BREAKER_OPEN)
    with pytest.raises(ChaosDisabledError, match="leeward's own"):
        injector(tmp_path).arm("*", now=0, failure_class=FailureClass.OK)
    with pytest.raises(ChaosDisabledError, match="nothing to do"):
        injector(tmp_path).arm("*", now=0)


def test_a_fault_matches_the_endpoints_its_glob_names(tmp_path: Path) -> None:
    faults = injector(tmp_path)
    faults.arm("*/status*", now=0, failure_class=FailureClass.CONNECT_TIMEOUT)
    hit = faults.armed("http://127.0.0.1:8900/status", "http://127.0.0.1:8900", now=0)
    assert hit is not None and hit.failure_class is FailureClass.CONNECT_TIMEOUT
    assert faults.armed("http://127.0.0.1:8900/search", "http://127.0.0.1:8900", now=0) is None


def test_a_host_fault_is_found_before_an_endpoint_fault(tmp_path: Path) -> None:
    faults = injector(tmp_path)
    faults.arm("*/wiki/*", now=0, failure_class=FailureClass.SERVER_ERROR)
    faults.arm(WIKI_ORIGIN, now=0, scope="host", failure_class=FailureClass.DNS_FAILURE)
    found = faults.armed(WIKI, WIKI_ORIGIN, now=0)
    assert found is not None and found.failure_class is FailureClass.DNS_FAILURE
    assert faults.armed(WIKI, None, now=0) is not None


def test_a_fault_given_a_lifetime_stops_matching_when_it_runs_out(tmp_path: Path) -> None:
    faults = injector(tmp_path)
    faults.arm("*", now=100, failure_class=FailureClass.DNS_FAILURE, for_seconds=30)
    assert faults.armed(WIKI, None, now=129) is not None
    assert faults.armed(WIKI, None, now=130) is None
    assert [fault.target for fault in faults.expire(now=130)] == ["*"]
    assert faults.all(now=130) == []


def test_restoring_lifts_what_it_names_and_reports_it(tmp_path: Path) -> None:
    faults = injector(tmp_path)
    faults.arm("*/status*", now=0, failure_class=FailureClass.CONNECT_TIMEOUT)
    faults.arm("*/search*", now=0, failure_class=FailureClass.RATE_LIMITED, retry_after_s=3600)
    assert [fault.target for fault in faults.restore("*/status*")] == ["*/status*"]
    assert [fault.target for fault in faults.all(now=0)] == ["*/search*"]
    assert len(faults.restore_all()) == 1
    assert faults.all(now=0) == []
    assert faults.restore("*/nothing*") == []


def test_arming_the_same_target_again_replaces_it(tmp_path: Path) -> None:
    faults = injector(tmp_path)
    faults.arm("*/status*", now=0, failure_class=FailureClass.CONNECT_TIMEOUT)
    faults.arm("*/status*", now=0, failure_class=FailureClass.SERVER_ERROR)
    armed = faults.all(now=0)
    assert len(armed) == 1
    assert armed[0].failure_class is FailureClass.SERVER_ERROR


def test_a_fault_armed_in_one_process_is_seen_by_another(tmp_path: Path) -> None:
    arming = injector(tmp_path)
    reading = injector(tmp_path)
    assert reading.armed("https://ops.example.com/status", None, now=0) is None

    arming.arm("*/status*", now=0, failure_class=FailureClass.CONNECT_TIMEOUT)
    found = reading.armed("https://ops.example.com/status", None, now=0)
    assert found is not None and found.failure_class is FailureClass.CONNECT_TIMEOUT

    arming.restore_all()
    assert reading.armed("https://ops.example.com/status", None, now=0) is None


def test_an_injected_timeout_takes_as_long_as_the_real_one_would(tmp_path: Path) -> None:
    faults = injector(tmp_path)
    wedge = faults.hang("*/slow*", now=0)
    assert wedge.failure_class is FailureClass.WEDGED
    assert faults.with_deadline(wedge, connect_timeout_s=10, hard_deadline_s=30) == 30

    blackhole = faults.arm("*/status*", now=0, failure_class=FailureClass.CONNECT_TIMEOUT)
    assert faults.with_deadline(blackhole, connect_timeout_s=10, hard_deadline_s=30) == 10

    refused = faults.arm("*/other*", now=0, failure_class=FailureClass.RATE_LIMITED)
    assert faults.with_deadline(refused, connect_timeout_s=10, hard_deadline_s=30) == 0
    slow = faults.arm("*/slowly*", now=0, latency_s=0.25)
    assert faults.with_deadline(slow, connect_timeout_s=10, hard_deadline_s=30) == 0.25


def test_a_fault_survives_the_trip_through_the_file(tmp_path: Path) -> None:
    fault = Fault(
        target="*/search*",
        scope="endpoint",
        failure_class=FailureClass.RATE_LIMITED,
        latency_s=0.5,
        retry_after_s=3600.0,
        until=1_789_000_000.0,
    )
    assert Fault.from_dict(fault.as_dict()) == fault
    bare = Fault(target="*")
    assert Fault.from_dict(bare.as_dict()) == bare


def test_remaining_time_is_reported_from_now(tmp_path: Path) -> None:
    faults = injector(tmp_path)
    fault = faults.arm("*", now=100, failure_class=FailureClass.DNS_FAILURE, for_seconds=30)
    assert faults.retimed(fault, now=110).until == 20
    assert faults.retimed(fault, now=200).until == 0
    assert faults.retimed(Fault(target="*"), now=110).until is None
