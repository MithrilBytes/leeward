# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from leeward.budget import (
    BudgetLimits,
    Remaining,
    RunLedger,
    Runs,
    conversation_hash,
    resolve_run,
)
from leeward.canonical import canonical_json, canonical_sha256
from leeward.classify import ConnectTimedOut, Response, RunSnapshot, classify
from leeward.config import Config, RunBudget
from leeward.events import RunRef
from leeward.policy import CallTarget, resolve
from leeward.vocab import RunResolution

RESOLVED = resolve(Config(), CallTarget.http("https://api.example.com/items"))
SNAPSHOT = RunSnapshot(now=0, retry_seconds_remaining=300)
MISSING = classify(Response(404, {}), RESOLVED, SNAPSHOT)
TIMEOUT = classify(ConnectTimedOut(), RESOLVED, SNAPSHOT)
ENDPOINT = "https://api.example.com/items"


@pytest.mark.parametrize(
    ("value", "text"),
    [
        ({"b": 1, "a": 2}, '{"a":2,"b":1}'),
        ({"a": {"d": [1, 2]}, "c": None}, '{"a":{"d":[1,2]},"c":null}'),
        ([True, False, None], "[true,false,null]"),
        (0, "0"),
        (-0.0, "0"),
        (100.0, "100"),
        (1.5, "1.5"),
        (-1.5, "-1.5"),
        (9007199254740992, "9007199254740992"),
        (1e21, "1e+21"),
        (1e23, "1e+23"),
        (1e-7, "1e-7"),
        (0.000001, "0.000001"),
        (333333333.3333332, "333333333.3333332"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        ('a"\\\n\x1f', '"a\\"\\\\\\n\\u001f"'),
        ("café", '"café"'),
    ],
)
def test_canonical_json_follows_the_scheme(value: object, text: str) -> None:
    assert canonical_json(value) == text


def test_keys_sort_by_utf16_code_units_not_code_points() -> None:
    """A non-BMP key is two surrogate units starting at 0xD800, so it sorts before 0xFFFF."""
    assert canonical_json({"￿": 1, "\U00010330": 2}) == '{"\U00010330":2,"￿":1}'


@pytest.mark.parametrize("value", [math.inf, -math.inf, math.nan])
def test_numbers_json_cannot_represent_are_refused(value: float) -> None:
    with pytest.raises(ValueError, match="NaN or infinity"):
        canonical_json(value)


@pytest.mark.parametrize("value", [{1: "int key"}, b"bytes", {"ok": object()}])
def test_values_outside_json_are_refused(value: object) -> None:
    with pytest.raises(TypeError):
        canonical_json(value)


def test_hashing_does_not_depend_on_key_order() -> None:
    first = canonical_sha256({"tool": "notes", "args": {"q": "blackout", "limit": 5}})
    second = canonical_sha256({"args": {"limit": 5, "q": "blackout"}, "tool": "notes"})
    assert first == second
    assert first != canonical_sha256({"tool": "notes", "args": {"q": "blackout", "limit": 6}})


def test_run_identity_prefers_the_strongest_signal() -> None:
    messages = [{"role": "user", "content": "hello"}]
    every = resolve_run(
        header="run-7",
        mcp_meta="meta-run",
        mcp_session="session-9",
        llm_messages=messages,
        connection="127.0.0.1:52344",
    )
    assert every == RunRef("run-7", RunResolution.HEADER)
    without_header = resolve_run(
        mcp_meta="meta-run",
        mcp_session="session-9",
        llm_messages=messages,
        connection="127.0.0.1:52344",
    )
    assert without_header.resolved_by is RunResolution.MCP_META
    session = resolve_run(mcp_session="session-9", connection="127.0.0.1:52344")
    assert session == RunRef("mcp-session-9", RunResolution.MCP_SESSION)
    llm = resolve_run(llm_messages=messages, connection="127.0.0.1:52344")
    assert llm.resolved_by is RunResolution.LLM_CONVERSATION_HASH
    assert resolve_run(connection="127.0.0.1:52344").id == "conn-127.0.0.1:52344"
    assert resolve_run() == RunRef("conn-unknown", RunResolution.CONNECTION)


def test_an_awkward_run_header_is_hashed_rather_than_logged() -> None:
    run = resolve_run(header="Bearer abc.def ghi\nX")
    assert run.id.startswith("h-")
    assert len(run.id) == 18
    assert "Bearer" not in run.id


def test_a_conversation_keeps_its_identity_as_it_grows() -> None:
    first_turn = [
        {"role": "system", "content": "You are a briefing assistant."},
        {"role": "user", "content": "Write about the 2003 blackout."},
    ]
    later = [
        *first_turn,
        {"role": "assistant", "content": "Looking it up."},
        {"role": "user", "content": "Add the cause."},
    ]
    assert conversation_hash(first_turn) == conversation_hash(later)
    other = [first_turn[0], {"role": "user", "content": "Write about tides."}]
    assert conversation_hash(first_turn) != conversation_hash(other)


def ledger(limits: BudgetLimits | None = None) -> RunLedger:
    return RunLedger(
        run=resolve_run(header="run-1"),
        limits=limits or BudgetLimits(),
        started_at=0.0,
        last_seen_at=0.0,
    )


def test_limits_come_from_configuration() -> None:
    assert BudgetLimits.from_settings(RunBudget()) == BudgetLimits(20, 120.0, 4)


def test_only_retries_are_counted_and_each_endpoint_has_its_own_allowance() -> None:
    run = ledger(BudgetLimits(retry_attempts=3, retry_seconds=10.0, endpoint_attempts=2))
    other = "https://api.example.com/other"
    assert run.remaining(ENDPOINT) == Remaining(3, 10.0, 2)

    run.spend_retry(ENDPOINT)
    assert run.remaining(ENDPOINT) == Remaining(2, 10.0, 1)
    assert run.remaining(other) == Remaining(2, 10.0, 2)

    run.spend_retry(ENDPOINT)
    assert not run.may_retry(ENDPOINT)
    assert run.may_retry(other)

    run.spend_seconds(10.0)
    assert not run.may_retry(other)
    assert run.remaining(other).retry_seconds == 0.0


def test_spending_never_reports_a_negative_allowance() -> None:
    run = ledger(BudgetLimits(retry_attempts=1, retry_seconds=1.0, endpoint_attempts=1))
    run.spend_retry(ENDPOINT)
    run.spend_retry(ENDPOINT)
    run.spend_seconds(5.0)
    remaining = run.remaining(ENDPOINT)
    assert (remaining.retry_attempts, remaining.retry_seconds, remaining.endpoint_attempts) == (
        0,
        0.0,
        0,
    )
    assert remaining.exhausted


def test_a_run_counts_hangs_per_endpoint() -> None:
    run = ledger()
    assert run.note_wedge(ENDPOINT) == 0
    assert run.note_wedge(ENDPOINT) == 1
    assert run.note_wedge("https://api.example.com/other") == 0


def test_a_run_remembers_a_refusal_until_it_expires() -> None:
    run = ledger()
    run.remember("key", MISSING, until=None)
    remembered = run.recall("key", now=10_000)
    assert remembered is not None and remembered.classification is MISSING

    run.remember("limited", TIMEOUT, until=100.0)
    assert run.recall("limited", now=99.0) is not None
    assert run.recall("limited", now=100.0) is None
    assert "limited" not in run.remembered


def test_a_warning_that_should_not_repeat_is_given_once_per_endpoint() -> None:
    run = ledger()
    assert run.first_tunnel_warning(ENDPOINT)
    assert not run.first_tunnel_warning(ENDPOINT)
    assert run.first_tunnel_warning("https://other.example.com/x")


def test_ledgers_are_reused_expire_when_idle_and_stay_bounded() -> None:
    runs = Runs(BudgetLimits(), max_runs=2, idle_expiry_s=100.0)
    first = resolve_run(header="run-1")
    assert runs.ledger(first, now=0.0) is runs.ledger(first, now=1.0)

    runs.ledger(resolve_run(header="run-2"), now=1.0)
    runs.ledger(resolve_run(header="run-3"), now=1.0)
    assert [led.run.id for led in runs.active()] == ["run-2", "run-3"]

    runs.ledger(resolve_run(header="run-4"), now=200.0)
    assert [led.run.id for led in runs.active()] == ["run-4"]
    assert runs.get("run-2") is None


@given(
    attempts=st.integers(min_value=0, max_value=40),
    limits=st.tuples(
        st.integers(min_value=0, max_value=10),
        st.floats(min_value=0, max_value=60),
        st.integers(min_value=0, max_value=5),
    ),
    durations=st.lists(st.floats(min_value=0, max_value=30), min_size=1, max_size=40),
)
def test_a_caller_that_asks_before_retrying_never_exceeds_its_budget(
    attempts: int, limits: tuple[int, float, int], durations: list[float]
) -> None:
    """The engine spends only what remaining() offers, so no limit is ever passed."""
    run = ledger(BudgetLimits(*limits))
    for index in range(attempts):
        if not run.may_retry(ENDPOINT):
            break
        allowed = run.remaining(ENDPOINT).retry_seconds
        run.spend_retry(ENDPOINT)
        run.spend_seconds(min(durations[index % len(durations)], allowed))
    assert run.retry_attempts <= run.limits.retry_attempts
    assert run.endpoint_retries.get(ENDPOINT, 0) <= run.limits.endpoint_attempts
    assert run.retry_seconds <= run.limits.retry_seconds
