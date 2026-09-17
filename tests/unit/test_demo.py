# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest
from scripts.demo import duration, fill, result_text


def test_fill_replaces_the_region_it_was_given() -> None:
    text = "intro\n<!-- demo:suite -->\nold words\n<!-- /demo:suite -->\noutro\n"
    assert fill(text, {"suite": "The suite is 1 test."}) == (
        "intro\n<!-- demo:suite -->\n\nThe suite is 1 test.\n\n<!-- /demo:suite -->\noutro\n"
    )


def test_fill_refuses_a_region_the_file_does_not_have() -> None:
    with pytest.raises(ValueError, match="no such region in the file: numbers"):
        fill("<!-- demo:suite -->\nold\n<!-- /demo:suite -->\n", {"numbers": "x"})


def test_fill_refuses_text_without_regions() -> None:
    with pytest.raises(ValueError, match="no such region in the file: suite"):
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


def test_a_region_a_script_does_not_own_is_left_alone() -> None:
    from scripts.demo import fill

    text = (
        "<!-- demo:measured -->\nold numbers\n<!-- /demo:measured -->\n"
        "<!-- demo:overhead -->\nold cost\n<!-- /demo:overhead -->\n"
    )
    written = fill(text, {"overhead": "new cost"})
    assert "old numbers" in written
    assert "new cost" in written
    assert "old cost" not in written


def test_filling_a_region_that_is_not_there_is_an_error() -> None:
    import pytest
    from scripts.demo import fill

    with pytest.raises(ValueError, match="no such region"):
        fill("<!-- demo:measured -->\nx\n<!-- /demo:measured -->\n", {"nowhere": "y"})


def test_the_overhead_table_reports_what_leeward_added() -> None:
    from scripts.overhead import Timing, table

    printed = table(
        [
            Timing("straight to the origin, no leeward", [0.001] * 10),
            Timing("through leeward, to the origin", [0.0015] * 10),
            Timing("through leeward, answered from cache", [0.0002] * 10),
        ]
    )
    assert "| straight to the origin, no leeward | 1.00 ms | 1.00 ms |" in printed
    assert "leeward adds about 0.50 ms" in printed
    assert "answers from its own cache in 0.20 ms" in printed


def test_only_the_note_regions_a_readme_asks_for_are_offered() -> None:
    from scripts.demo import offered

    text = "".join(
        f"<!-- demo:{name} -->\nold\n<!-- /demo:{name} -->\n"
        for name in ("measured", "notes", "suite", "note-gone")
    )
    filled = {"measured": "m", "notes": "n", "suite": "s", "note-gone": "g", "note-quota": "q"}
    assert set(offered(filled, text)) == {"measured", "notes", "suite", "note-gone"}


def test_a_readme_without_the_regions_that_carry_the_argument_is_an_error() -> None:
    import pytest
    from scripts.demo import offered

    with pytest.raises(ValueError, match="missing required regions: measured, notes"):
        offered({"suite": "s"}, "<!-- demo:suite -->\nold\n<!-- /demo:suite -->\n")
