# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import replace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from leeward.cache.freshness import StaleReason
from leeward.notes import (
    NOTE_LIMIT,
    PREFIX,
    MissingNoteValueError,
    NoteFacts,
    clauses,
    compose,
    render,
    status_line,
)
from leeward.templates import TEMPLATE_NAMES, template_set_sha256, template_texts
from leeward.vocab import Advice, Disposition, FailureClass, Outcome, Volatility, WithheldReason


def facts(**extra: object) -> NoteFacts:
    base: dict[str, object] = {
        "outcome": Outcome.DOWN,
        "host_or_tool": "api.weather.gov",
        "volatility": Volatility.LIVE,
        "failure_class": FailureClass.CONNECT_TIMEOUT,
        "disposition": Disposition.NEVER,
        "attempts": 2,
        "elapsed_s": 30.0,
    }
    base.update(extra)
    return NoteFacts(**base)  # pyright: ignore[reportArgumentType]


def test_a_template_refuses_to_leave_a_hole() -> None:
    with pytest.raises(MissingNoteValueError, match="age_human"):
        render(template_texts()["stale"], {"volatility": "static"})


def test_the_clause_file_parses_into_sentence_parts() -> None:
    parts = clauses()
    assert parts["accuracy.static"] == "the copy is very likely still accurate"
    assert "{{host_or_tool}}" in parts["because.unreachable"]


def test_a_stale_note_gives_the_age_the_reason_and_what_to_expect() -> None:
    note = compose(
        facts(
            outcome=Outcome.STALE,
            volatility=Volatility.STATIC,
            failure_class=FailureClass.DNS_FAILURE,
            disposition=Disposition.TRANSIENT,
            host_or_tool="en.wikipedia.org",
            age_s=2460,
            stale_reason=StaleReason.ERROR,
            attempts=1,
        )
    )
    assert note.startswith(f"{PREFIX} STALE: served a copy stored 41m ago")
    assert "en.wikipedia.org is unreachable (DNS_FAILURE)" in note
    assert "classified `static`" in note
    assert "very likely still accurate" in note
    assert "Retrying will not help until connectivity returns." in note
    assert len(note) <= NOTE_LIMIT


def test_a_tool_that_hangs_once_is_not_told_that_retrying_will_not_help() -> None:
    first = facts(
        volatility=Volatility.VOLATILE,
        failure_class=FailureClass.WEDGED,
        disposition=Disposition.TRANSIENT,
        attempts=1,
        host_or_tool="notes/incident_notes",
        tool_name="incident_notes",
        advice=Advice.RETRY_AFTER,
    )
    note = compose(first)
    assert "will not help" not in note
    assert note.endswith("Calling again shortly may return a fresh copy.")
    waited = compose(replace(first, retry_after_s=5.0))
    assert waited.endswith("It may succeed if called again in 5s.")


def test_a_tool_that_hangs_again_is_refused_without_talk_of_connectivity() -> None:
    note = compose(
        facts(
            volatility=Volatility.VOLATILE,
            failure_class=FailureClass.WEDGED,
            attempts=1,
            host_or_tool="notes/incident_notes",
            tool_name="incident_notes",
            advice=Advice.DO_NOT_RETRY,
        )
    )
    assert note.endswith("Retrying will not help.")
    assert "connectivity" not in note


def test_a_host_that_refuses_connections_still_says_to_wait_for_connectivity() -> None:
    note = compose(
        facts(
            volatility=Volatility.VOLATILE,
            failure_class=FailureClass.CONNECT_REFUSED,
            advice=Advice.DO_NOT_RETRY,
        )
    )
    assert note.endswith("Retrying will not help until connectivity returns.")


def test_a_stale_note_while_revalidating_does_not_claim_anything_is_broken() -> None:
    note = compose(
        facts(
            outcome=Outcome.STALE,
            volatility=Volatility.SLOW,
            failure_class=None,
            disposition=None,
            age_s=3600,
            stale_reason=StaleReason.REVALIDATING,
            attempts=0,
        )
    )
    assert "while a fresh copy is fetched in the background" in note
    assert "unreachable" not in note


def test_a_live_endpoint_note_says_a_copy_exists_and_is_being_withheld() -> None:
    note = compose(
        facts(withheld_reason=WithheldReason.VOLATILITY_LIVE, withheld_age_s=2460, attempts=2)
    )
    assert note.startswith(f"{PREFIX} DOWN: api.weather.gov returned nothing")
    assert "CONNECT_TIMEOUT after 30s, 2 attempts" in note
    assert "classified `live`" in note
    assert "a cached value from 41m ago exists but is not being served" in note
    assert "Treat this value as unknown" in note
    assert len(note) <= NOTE_LIMIT


def test_a_vanished_tool_note_names_the_tool_and_the_server() -> None:
    note = compose(
        facts(
            host_or_tool="notes/threat_intel_lookup",
            volatility=Volatility.VOLATILE,
            failure_class=FailureClass.TOOL_GONE,
            tool_name="threat_intel_lookup",
            server_name="notes",
            attempts=1,
        )
    )
    assert "`threat_intel_lookup` is gone from its MCP server (notes)" in note
    assert "permanent for this run" in note
    assert "Other tools on this server are unaffected." in note


def test_a_rate_limit_note_says_when_it_may_be_tried_again() -> None:
    note = compose(
        facts(
            host_or_tool="api.example.com",
            volatility=Volatility.VOLATILE,
            failure_class=FailureClass.RATE_LIMITED,
            disposition=Disposition.WAIT,
            retry_after_s=90,
            retry_attempts_remaining=12,
            attempts=1,
        )
    )
    assert "is rate limited (RATE_LIMITED)" in note
    assert "It can be retried in 1m" in note
    assert "12 retries left" in note
    assert "Do other work first" in note


def test_a_spent_budget_note_says_to_carry_on_without_the_source() -> None:
    note = compose(
        facts(
            volatility=Volatility.VOLATILE,
            failure_class=FailureClass.BUDGET_EXHAUSTED,
            attempts=4,
        )
    )
    assert "spent its retry allowance on api.weather.gov (4 attempts)" in note
    assert "for the rest of this run" in note
    assert "state what you could not obtain" in note


def test_a_withheld_older_copy_is_offered_where_it_is_safe_to_offer_it() -> None:
    common = {
        "volatility": Volatility.VOLATILE,
        "failure_class": FailureClass.DNS_FAILURE,
        "disposition": Disposition.TRANSIENT,
        "withheld_reason": WithheldReason.BEYOND_STALE_ALLOWANCE,
        "withheld_age_s": 260000,
        "attempts": 1,
    }
    over_http = compose(facts(**common, accept_stale_via="header"))
    assert "A copy from 3d ago exists but is older than this endpoint allows." in over_http
    assert "X-Leeward-Accept-Stale: 1" in over_http
    over_mcp = compose(facts(**common, accept_stale_via="argument"))
    assert "accept_stale set to true" in over_mcp
    silent = compose(facts(**common))
    assert "older than this endpoint allows" in silent
    assert "Accept-Stale" not in silent


def test_a_clock_that_looks_wrong_is_named_as_the_thing_to_fix() -> None:
    note = compose(
        facts(
            failure_class=FailureClass.TLS_CLOCK_SKEW,
            volatility=Volatility.STATIC,
            clock_is_wrong=True,
        )
    )
    assert "This machine's clock looks wrong" in note


def test_a_call_that_worked_needs_no_note() -> None:
    assert compose(facts(outcome=Outcome.FRESH)) == ""


def test_the_status_line_is_one_short_line_and_only_when_degraded() -> None:
    assert status_line([], []) == ""
    line = status_line(["api.weather.gov"], ["en.wikipedia.org"])
    assert line.startswith(PREFIX)
    assert "\n" not in line
    assert len(line) < 200
    assert "unknown, not zero" in line


def test_the_template_set_hash_changes_when_the_wording_does() -> None:
    first = template_set_sha256()
    assert len(first) == 64
    assert set(template_texts()) == set(TEMPLATE_NAMES)


@given(
    host=st.text(min_size=1, max_size=300).filter(lambda value: value.strip()),
    attempts=st.integers(min_value=0, max_value=99),
    elapsed=st.floats(min_value=0, max_value=100_000, allow_nan=False),
    age=st.floats(min_value=0, max_value=10_000_000, allow_nan=False),
    failure_class=st.sampled_from(list(FailureClass)),
    disposition=st.sampled_from([*list(Disposition), None]),
    outcome=st.sampled_from([Outcome.STALE, Outcome.DOWN]),
    volatility=st.sampled_from([Volatility.STATIC, Volatility.SLOW, Volatility.VOLATILE]),
    withheld=st.sampled_from([*list(WithheldReason), None]),
)
def test_every_note_fits_and_says_who_is_speaking(
    host: str,
    attempts: int,
    elapsed: float,
    age: float,
    failure_class: FailureClass,
    disposition: Disposition | None,
    outcome: Outcome,
    volatility: Volatility,
    withheld: WithheldReason | None,
) -> None:
    note = compose(
        NoteFacts(
            outcome=outcome,
            host_or_tool=host,
            volatility=volatility,
            failure_class=failure_class,
            disposition=disposition,
            attempts=attempts,
            elapsed_s=elapsed,
            age_s=age,
            stale_reason=StaleReason.ERROR,
            withheld_reason=withheld,
            withheld_age_s=age,
            retry_after_s=elapsed,
            tool_name="tool",
            server_name="server",
            soft_deadline_s=5.0,
        )
    )
    assert len(note) <= NOTE_LIMIT
    assert note.startswith(PREFIX)
    assert "\n" not in note
