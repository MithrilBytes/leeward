# SPDX-License-Identifier: Apache-2.0
"""Whether the clock can be believed, decided by the origins that answer."""

from __future__ import annotations

from leeward.clock import ClockCheck, offset_of
from leeward.vocab import ClockTrust

NOW = 1_789_000_000.0


def dated(offset_s: float) -> dict[str, str]:
    """A Date header from an origin whose clock is `offset_s` ahead of ours."""
    from email.utils import formatdate

    return {"Date": formatdate(NOW + offset_s, usegmt=True)}


def test_an_origin_that_agrees_says_nothing_until_a_second_one_does() -> None:
    check = ClockCheck(threshold_s=300.0)
    assert check.trust() is ClockTrust.UNCHECKED

    check.observe("one.test", dated(2), NOW)
    assert check.trust() is ClockTrust.UNCHECKED, "one host is not a quorum"

    check.observe("two.test", dated(-3), NOW)
    assert check.trust() is ClockTrust.TRUSTED


def test_one_host_with_a_wrong_clock_is_that_host_s_problem() -> None:
    check = ClockCheck(threshold_s=300.0)
    check.observe("wrong.test", dated(4000), NOW)
    check.observe("right.test", dated(1), NOW)
    assert check.trust() is ClockTrust.TRUSTED


def test_every_host_disagreeing_the_same_way_is_ours() -> None:
    check = ClockCheck(threshold_s=300.0)
    for host in ("one.test", "two.test", "three.test"):
        check.observe(host, dated(-3600), NOW)
    assert check.trust() is ClockTrust.SKEWED


def test_hosts_disagreeing_in_opposite_directions_are_not_evidence_about_us() -> None:
    check = ClockCheck(threshold_s=300.0)
    check.observe("fast.test", dated(3600), NOW)
    check.observe("slow.test", dated(-3600), NOW)
    assert check.trust() is ClockTrust.TRUSTED


def test_a_chatty_host_cannot_outvote_the_others() -> None:
    check = ClockCheck(threshold_s=300.0)
    for _ in range(20):
        check.observe("chatty.test", dated(9999), NOW)
    check.observe("quiet.test", dated(1), NOW)
    assert check.trust() is ClockTrust.TRUSTED


def test_a_date_that_is_not_a_date_is_ignored() -> None:
    check = ClockCheck(threshold_s=300.0)
    check.observe("odd.test", {"Date": "sometime on Tuesday"}, NOW)
    check.observe("also.test", {}, NOW)
    assert check.offsets == {}
    assert offset_of("sometime on Tuesday", NOW) is None
