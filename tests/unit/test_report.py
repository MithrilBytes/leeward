# SPDX-License-Identifier: Apache-2.0
"""The report is arithmetic over the log, so the tests state the arithmetic."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from typer.testing import CliRunner

from leeward.cli import app
from leeward.report import headline, percentile, summarize

runner = CliRunner()


def call(
    endpoint: str,
    outcome: str,
    *,
    attempts: int = 1,
    latency_ms: float = 10.0,
    failure: str | None = None,
    cached_bytes: int = 0,
    run: str = "run-1",
    ts: str = "2026-09-17T12:00:00Z",
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "ts": ts,
        "event": "call",
        "run": {"id": run, "resolved_by": "connection"},
        "endpoint": endpoint,
        "outcome": outcome,
        "attempts": attempts,
        "total_latency_ms": latency_ms,
    }
    if failure is not None:
        event["failure_class"] = failure
    if cached_bytes:
        event["cache"] = {"hit": True, "bytes_served": cached_bytes}
    return event


def test_a_report_counts_outcomes_attempts_and_calls_that_cost_nothing() -> None:
    summary = summarize(
        [
            call("wiki/{id}", "FRESH", latency_ms=100.0),
            call("wiki/{id}", "STALE", attempts=0, latency_ms=1.0, cached_bytes=2048),
            call("wiki/{id}", "DOWN", attempts=2, latency_ms=30000.0, failure="WEDGED"),
            call("notes/search", "DOWN", attempts=0, failure="BREAKER_OPEN", run="run-2"),
            {"event": "breaker", "ts": "2026-09-17T12:00:01Z", "endpoint": "wiki/{id}"},
        ]
    )
    totals = summary["totals"]
    assert isinstance(totals, dict)
    assert totals["calls"] == 4
    assert totals["attempts"] == 3
    assert totals["answered_without_network"] == 2
    assert totals["bytes_served_from_cache"] == 2048
    assert totals["refused_before_calling"] == 1
    assert totals["runs"] == 2
    assert totals["outcomes"] == {"DOWN": 2, "FRESH": 1, "STALE": 1}

    rows = cast("list[dict[str, Any]]", summary["endpoints"])
    busiest = rows[0]
    assert busiest["endpoint"] == "wiki/{id}"
    assert busiest["calls"] == 3
    assert busiest["failure_classes"] == {"WEDGED": 1}
    assert busiest["p50_ms"] == 100.0
    assert busiest["p95_ms"] == 30000.0


def test_an_empty_log_reports_nothing_rather_than_dividing_by_it() -> None:
    summary = summarize([])
    totals = summary["totals"]
    assert isinstance(totals, dict)
    assert totals["calls"] == 0
    assert totals["from"] is None
    assert summary["endpoints"] == []
    assert headline(summary) == "no calls recorded yet"


@pytest.mark.parametrize(
    ("values", "fraction", "expected"),
    [([], 0.5, 0.0), ([5.0], 0.95, 5.0), ([1.0, 2.0, 3.0, 4.0], 0.5, 2.0)],
)
def test_percentiles_use_the_nearest_rank(
    values: list[float], fraction: float, expected: float
) -> None:
    assert percentile(values, fraction) == expected


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def test_report_reads_the_log_on_disk_and_prints_a_table(workdir: Path) -> None:
    assert runner.invoke(app, ["init"]).exit_code == 0
    events = workdir / ".leeward" / "events"
    events.mkdir(parents=True, exist_ok=True)
    lines = [call("wiki/{id}", "FRESH"), call("wiki/{id}", "STALE", attempts=0, cached_bytes=99)]
    (events / "2026-09-17.jsonl").write_text(
        "".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8"
    )

    printed = runner.invoke(app, ["report"])
    assert printed.exit_code == 0, printed.output
    assert "2 calls, 2 answered, 0 down, 1 without reaching anyone" in printed.output
    assert "wiki/{id}" in printed.output

    parsed = json.loads(runner.invoke(app, ["report", "--json"]).output)
    assert parsed["totals"]["calls"] == 2
    assert parsed["endpoints"][0]["bytes_served_from_cache"] == 99


def test_doctor_reports_the_wiring_and_fails_on_a_broken_config(workdir: Path) -> None:
    assert runner.invoke(app, ["init"]).exit_code == 0
    healthy = runner.invoke(app, ["doctor"])
    assert healthy.exit_code == 0, healthy.output
    assert "ok   configuration" in healthy.output
    assert "note templates" in healthy.output
    assert "no MCP client configuration mentions leeward wrap" in healthy.output

    (workdir / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "notes": {"command": "/opt/leeward", "args": ["wrap", "--", "python"]},
                    "plain": {"command": "python", "args": ["-m", "server"]},
                }
            }
        ),
        encoding="utf-8",
    )
    wired = json.loads(runner.invoke(app, ["doctor", "--json"]).output)
    assert wired["ok"] is True
    clients = [check for check in wired["checks"] if check["check"] == "client"]
    assert clients and "notes" in clients[0]["detail"]
    assert "plain" not in clients[0]["detail"]

    (workdir / "leeward.yaml").write_text("profile: nonsense\n", encoding="utf-8")
    broken = runner.invoke(app, ["doctor"])
    assert broken.exit_code == 1
    assert "FAIL configuration" in broken.output
