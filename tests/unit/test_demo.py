# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest
from scripts.demo import duration, fill, result_text


def test_fill_replaces_each_region_and_leaves_the_rest_alone() -> None:
    text = "intro\n<!-- demo:suite -->\nold words\n<!-- /demo:suite -->\noutro\n"
    assert fill(text, {"suite": "The suite is 1 test.", "unused": "x"}) == (
        "intro\n<!-- demo:suite -->\n\nThe suite is 1 test.\n\n<!-- /demo:suite -->\noutro\n"
    )


def test_fill_refuses_a_region_it_has_nothing_for() -> None:
    with pytest.raises(ValueError, match="demo:numbers"):
        fill("<!-- demo:numbers -->\nold\n<!-- /demo:numbers -->\n", {"suite": "x"})


def test_fill_refuses_text_without_regions() -> None:
    with pytest.raises(ValueError, match="no <!-- demo:NAME --> regions"):
        fill("nothing marked here\n", {"suite": "x"})


@pytest.mark.parametrize(
    ("seconds", "shown"), [(30.0123, "30.01 s"), (0.0081, "8.1 ms"), (0.0125, "12 ms")]
)
def test_durations_read_at_a_glance(seconds: float, shown: str) -> None:
    assert duration(seconds) == shown


def test_a_result_names_the_class_what_it_carries_and_the_advice() -> None:
    shown = result_text("DOWN", "BREAKER_OPEN", "WEDGED", "504", "DO_NOT_RETRY")
    assert shown == "`DOWN{BREAKER_OPEN}` carrying `WEDGED`, 504, `DO_NOT_RETRY`"
    assert result_text("STALE", None, None, "200", "PROCEED") == "`STALE`, 200, `PROCEED`"
