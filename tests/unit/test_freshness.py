# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import email.utils

import pytest
from hypothesis import given
from hypothesis import strategies as st

from leeward.cache.freshness import (
    NeverStaleError,
    NoEntry,
    ServeFresh,
    ServeStale,
    Situation,
    StaleAllowance,
    StaleReason,
    StoredResponse,
    Withhold,
    current_age,
    decide,
    freshness,
    freshness_lifetime,
    may_store,
    vary_matches,
)
from leeward.config import DEFAULT_REDACT_HEADERS
from leeward.vocab import STALE_SERVABLE, Volatility, WithheldReason

NOW = 1_789_000_000.0
CREDENTIALS = frozenset(DEFAULT_REDACT_HEADERS)
THIRTY_DAYS = 30 * 86400.0


def stored(
    *,
    headers: dict[str, str] | None = None,
    received_ago: float = 0.0,
    status: int = 200,
    volatility: Volatility = Volatility.STATIC,
    vary: tuple[tuple[str, str], ...] = (),
    request_delay: float = 0.0,
) -> StoredResponse:
    received_at = NOW - received_ago
    supplied = dict(headers or {})
    supplied.setdefault("Date", email.utils.formatdate(received_at, usegmt=True))
    return StoredResponse(
        key="k",
        url="https://en.wikipedia.org/wiki/Foo",
        method="GET",
        endpoint="https://en.wikipedia.org/wiki/Foo",
        status=status,
        headers=tuple(supplied.items()),
        vary=vary,
        body_sha256="0" * 64,
        body_bytes=10,
        requested_at=received_at - request_delay,
        received_at=received_at,
        stored_at=received_at,
        volatility=volatility,
    )


def test_age_follows_the_arithmetic_in_the_specification() -> None:
    """RFC 9111 §4.2.3: the greater of what the Date implies and what Age plus delay does."""
    entry = stored(
        headers={
            "Date": email.utils.formatdate(NOW - 110, usegmt=True),
            "Age": "5",
            "Cache-Control": "max-age=60",
        },
        received_ago=100,
        request_delay=2,
    )
    # Date is 10s before the response arrived, Age says 5, the exchange took 2, and
    # the entry has been resident for 100.
    assert current_age(entry, NOW) == pytest.approx(110.0, abs=1.0)


@pytest.mark.parametrize(
    ("headers", "lifetime", "source"),
    [
        ({"Cache-Control": "max-age=3600"}, 3600.0, "max-age"),
        (
            {"Cache-Control": "max-age=3600", "Expires": email.utils.formatdate(NOW + 10)},
            3600.0,
            "max-age",
        ),
        ({"Expires": email.utils.formatdate(NOW + 120, usegmt=True)}, 120.0, "Expires"),
        ({"Last-Modified": email.utils.formatdate(NOW - 1000, usegmt=True)}, 100.0, "heuristic"),
        ({"Last-Modified": email.utils.formatdate(NOW - 10**9, usegmt=True)}, 86400.0, "heuristic"),
        ({}, 0.0, "none"),
    ],
)
def test_freshness_lifetime_reads_the_origin_then_falls_back_to_a_tenth(
    headers: dict[str, str], lifetime: float, source: str
) -> None:
    computed, from_where = freshness_lifetime(stored(headers=headers))
    assert from_where == source
    assert computed == pytest.approx(lifetime, abs=2.0)


def test_a_fresh_copy_is_served_whatever_its_class() -> None:
    for volatility in Volatility:
        entry = stored(
            headers={"Cache-Control": "max-age=600"}, received_ago=10, volatility=volatility
        )
        decision = decide(entry, StaleAllowance(volatility), Situation.START, NOW)
        assert isinstance(decision, ServeFresh)
        assert decision.age_s == pytest.approx(10, abs=1)


def test_a_live_endpoint_past_freshness_is_withheld_and_says_a_copy_exists() -> None:
    entry = stored(
        headers={"Cache-Control": "max-age=5"}, received_ago=2400, volatility=Volatility.LIVE
    )
    allowance = StaleAllowance(Volatility.LIVE)
    for situation in Situation:
        decision = decide(entry, allowance, situation, NOW)
        assert isinstance(decision, Withhold)
        assert decision.reason is WithheldReason.VOLATILITY_LIVE
        assert decision.age_s == pytest.approx(2400, abs=2)
        assert decision.entry is entry


def test_asking_for_a_live_copy_anyway_changes_nothing() -> None:
    entry = stored(
        headers={"Cache-Control": "max-age=5"}, received_ago=60, volatility=Volatility.LIVE
    )
    decision = decide(
        entry, StaleAllowance(Volatility.LIVE), Situation.ORIGIN_FAILED, NOW, accept_stale=True
    )
    assert isinstance(decision, Withhold)
    assert decision.reason is WithheldReason.VOLATILITY_LIVE


def test_a_stale_serve_cannot_even_be_built_for_a_class_that_forbids_it() -> None:
    entry = stored(received_ago=60, volatility=Volatility.LIVE)
    for volatility in (Volatility.LIVE, Volatility.NEVER):
        with pytest.raises(NeverStaleError, match="never served stale"):
            ServeStale(entry, 60.0, StaleReason.ERROR, volatility)


@pytest.mark.parametrize(
    ("situation", "reason"),
    [
        (Situation.ORIGIN_FAILED, StaleReason.ERROR),
        (Situation.SOFT_DEADLINE, StaleReason.SLOW),
    ],
)
def test_a_static_copy_is_served_when_the_origin_fails_or_drags(
    situation: Situation, reason: StaleReason
) -> None:
    entry = stored(headers={"Cache-Control": "max-age=60"}, received_ago=3600)
    allowance = StaleAllowance(Volatility.STATIC, on_error_s=THIRTY_DAYS)
    decision = decide(entry, allowance, situation, NOW)
    assert isinstance(decision, ServeStale)
    assert decision.reason is reason
    assert decision.age_s == pytest.approx(3600, abs=2)


def test_a_copy_older_than_the_class_allows_is_withheld() -> None:
    entry = stored(headers={"Cache-Control": "max-age=60"}, received_ago=7200)
    allowance = StaleAllowance(Volatility.VOLATILE, on_error_s=3600)
    decision = decide(entry, allowance, Situation.ORIGIN_FAILED, NOW)
    assert isinstance(decision, Withhold)
    assert decision.reason is WithheldReason.BEYOND_STALE_ALLOWANCE
    accepted = decide(entry, allowance, Situation.ORIGIN_FAILED, NOW, accept_stale=True)
    assert isinstance(accepted, ServeStale)
    assert accepted.reason is StaleReason.ACCEPTED


def test_revalidating_in_the_background_has_its_own_window() -> None:
    entry = stored(headers={"Cache-Control": "max-age=60"}, received_ago=1800)
    inside = StaleAllowance(Volatility.STATIC, on_error_s=THIRTY_DAYS, while_revalidating_s=3600)
    decision = decide(entry, inside, Situation.START, NOW)
    assert isinstance(decision, ServeStale)
    assert decision.reason is StaleReason.REVALIDATING
    outside = StaleAllowance(Volatility.VOLATILE, on_error_s=THIRTY_DAYS, while_revalidating_s=0)
    assert isinstance(decide(entry, outside, Situation.START, NOW), Withhold)


def test_must_revalidate_is_obeyed_unless_a_rule_has_already_answered() -> None:
    entry = stored(headers={"Cache-Control": "max-age=60, must-revalidate"}, received_ago=600)
    from_headers = StaleAllowance(Volatility.STATIC, on_error_s=THIRTY_DAYS)
    assert isinstance(decide(entry, from_headers, Situation.ORIGIN_FAILED, NOW), Withhold)
    from_rule = StaleAllowance(Volatility.STATIC, on_error_s=THIRTY_DAYS, operator_set=True)
    assert isinstance(decide(entry, from_rule, Situation.ORIGIN_FAILED, NOW), ServeStale)


def test_a_request_that_refuses_the_cache_gets_no_copy() -> None:
    entry = stored(headers={"Cache-Control": "max-age=600"}, received_ago=10)
    allowance = StaleAllowance(Volatility.STATIC, on_error_s=THIRTY_DAYS)
    for directive in ("no-cache", "no-store"):
        decision = decide(
            entry,
            allowance,
            Situation.ORIGIN_FAILED,
            NOW,
            request_headers={"Cache-Control": directive},
        )
        assert isinstance(decision, NoEntry)


def test_a_copy_stored_for_other_headers_is_withheld() -> None:
    entry = stored(received_ago=10, vary=(("accept-language", "en"),))
    allowance = StaleAllowance(Volatility.STATIC, on_error_s=THIRTY_DAYS)
    assert vary_matches(entry, {"Accept-Language": "en"})
    assert not vary_matches(entry, {"Accept-Language": "fr"})
    decision = decide(
        entry, allowance, Situation.START, NOW, request_headers={"Accept-Language": "fr"}
    )
    assert isinstance(decision, Withhold)
    assert decision.reason is WithheldReason.VARY_MISMATCH
    assert not vary_matches(stored(vary=(("*", ""),)), {})


def test_nothing_stored_means_nothing_to_decide() -> None:
    assert isinstance(
        decide(None, StaleAllowance(Volatility.STATIC), Situation.START, NOW), NoEntry
    )


@pytest.mark.parametrize(
    ("status", "sent_back", "asked_with", "vary_on", "allowed", "because"),
    [
        (200, {"Cache-Control": "max-age=60"}, {}, [], True, ""),
        (200, {"Cache-Control": "no-store"}, {}, [], False, "no-store"),
        (
            200,
            {"Cache-Control": "max-age=60"},
            {"Cache-Control": "no-store"},
            [],
            False,
            "no-store",
        ),
        (200, {"Cache-Control": "max-age=60"}, {"Authorization": "Bearer x"}, [], False, "carried"),
        (
            200,
            {"Cache-Control": "max-age=60"},
            {"Authorization": "Bearer x"},
            ["authorization"],
            True,
            "",
        ),
        (404, {}, {}, [], True, ""),
        (500, {}, {}, [], False, "not cacheable by default"),
    ],
)
def test_what_may_be_written_down(
    status: int,
    sent_back: dict[str, str],
    asked_with: dict[str, str],
    vary_on: list[str],
    allowed: bool,
    because: str,
) -> None:
    ok, reason = may_store(
        status,
        sent_back,
        asked_with,
        StaleAllowance(Volatility.STATIC),
        vary_on,
        CREDENTIALS,
    )
    assert ok is allowed
    assert because in reason


def test_a_never_class_endpoint_is_not_written_down() -> None:
    ok, reason = may_store(
        200, {"Cache-Control": "max-age=60"}, {}, StaleAllowance(Volatility.NEVER), [], CREDENTIALS
    )
    assert not ok
    assert "classified never" in reason


@given(
    max_age=st.integers(min_value=0, max_value=100_000),
    age_header=st.integers(min_value=0, max_value=10_000),
    received_ago=st.floats(min_value=0, max_value=5_000_000, allow_nan=False),
    volatility=st.sampled_from(list(Volatility)),
    on_error=st.floats(min_value=0, max_value=3_000_000, allow_nan=False),
    revalidating=st.floats(min_value=0, max_value=3_000_000, allow_nan=False),
    situation=st.sampled_from(list(Situation)),
    accept_stale=st.booleans(),
    must_revalidate=st.booleans(),
    operator_set=st.booleans(),
)
def test_nothing_is_served_older_than_its_class_permits(
    max_age: int,
    age_header: int,
    received_ago: float,
    volatility: Volatility,
    on_error: float,
    revalidating: float,
    situation: Situation,
    accept_stale: bool,
    must_revalidate: bool,
    operator_set: bool,
) -> None:
    """The guarantee, over any entry and any policy: live is never served stale, and
    nothing else is served past the window its class allows."""
    control = f"max-age={max_age}" + (", must-revalidate" if must_revalidate else "")
    entry = stored(
        headers={"Cache-Control": control, "Age": str(age_header)},
        received_ago=received_ago,
        volatility=volatility,
    )
    allowance = StaleAllowance(volatility, on_error, revalidating, operator_set)
    decision = decide(entry, allowance, situation, NOW, accept_stale=accept_stale)

    if isinstance(decision, ServeStale):
        assert volatility in STALE_SERVABLE
        assert not freshness(entry, NOW).fresh
        if not accept_stale:
            window = revalidating if situation is Situation.START else on_error
            assert decision.age_s <= window
    if isinstance(decision, ServeFresh):
        assert freshness(entry, NOW).fresh
    if volatility is Volatility.LIVE and not freshness(entry, NOW).fresh:
        assert isinstance(decision, Withhold)
        assert decision.reason is WithheldReason.VOLATILITY_LIVE
