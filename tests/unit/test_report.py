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
from tests.conftest import EgressLog

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


def test_cache_commands_list_pin_and_forget_what_is_stored(workdir: Path) -> None:
    from leeward.cache.store import CacheStore, cache_key
    from leeward.vocab import Volatility

    assert runner.invoke(app, ["init"]).exit_code == 0
    key = cache_key("GET", "https://example.test/wiki/Foo")
    with CacheStore(workdir / ".leeward" / "cache") as store:
        store.put(
            key=key,
            url="https://example.test/wiki/Foo",
            method="GET",
            endpoint="example.test/wiki/{id}",
            status=200,
            headers=(("Cache-Control", "max-age=60"),),
            body=b"a stored page",
            requested_at=0.0,
            received_at=0.0,
            volatility=Volatility.STATIC,
            now=0.0,
        )

    listed = runner.invoke(app, ["cache", "ls"])
    assert listed.exit_code == 0, listed.output
    assert "example.test/wiki/{id}" in listed.output

    stats = json.loads(runner.invoke(app, ["cache", "stats", "--json"]).output)
    assert (stats["entries"], stats["bytes"], stats["pinned"]) == (1, len(b"a stored page"), 0)

    assert runner.invoke(app, ["cache", "pin", "*wiki*"]).exit_code == 0
    assert json.loads(runner.invoke(app, ["cache", "stats", "--json"]).output)["pinned"] == 1

    assert json.loads(runner.invoke(app, ["cache", "rm", "--json", "*"]).output)["removed"] == 1
    assert json.loads(runner.invoke(app, ["cache", "stats", "--json"]).output)["entries"] == 0
    assert "nothing stored" in runner.invoke(app, ["cache", "ls"]).output


def test_chaos_arms_lists_and_lifts_faults(workdir: Path) -> None:
    assert runner.invoke(app, ["init"]).exit_code == 0
    (workdir / "leeward.yaml").write_text(
        "profile: dev\ndata_dir: ./.leeward\nchaos:\n  enabled: true\n", encoding="utf-8"
    )

    armed = runner.invoke(app, ["chaos", "arm", "*/wiki/*", "--fail", "dns_failure"])
    assert armed.exit_code == 0, armed.output
    assert "DNS_FAILURE" in armed.output

    listed = json.loads(runner.invoke(app, ["chaos", "ls", "--json"]).output)
    assert listed[0]["target"] == "*/wiki/*"
    assert listed[0]["failure_class"] == "DNS_FAILURE"

    refused = runner.invoke(app, ["chaos", "arm", "*", "--fail", "not_a_class"])
    assert refused.exit_code == 2
    assert "use one of" in refused.output

    lifted = json.loads(runner.invoke(app, ["chaos", "clear", "--json"]).output)
    assert len(lifted["lifted"]) == 1
    assert "nothing armed" in runner.invoke(app, ["chaos", "ls"]).output


def test_chaos_refuses_to_arm_anything_in_production(workdir: Path) -> None:
    assert runner.invoke(app, ["init"]).exit_code == 0
    (workdir / "leeward.yaml").write_text(
        "profile: production\nchaos:\n  enabled: true\n", encoding="utf-8"
    )
    refused = runner.invoke(app, ["chaos", "arm", "*", "--fail", "dns_failure"])
    assert refused.exit_code == 2


def test_status_and_forecast_answer_from_local_state_without_a_network(
    workdir: Path, egress_guard: EgressLog
) -> None:
    assert runner.invoke(app, ["init"]).exit_code == 0

    empty = runner.invoke(app, ["status"])
    assert empty.exit_code == 0, empty.output
    assert "0 entries" in empty.output
    assert "nothing has been called yet" in empty.output

    known = json.loads(runner.invoke(app, ["status", "--json"]).output)
    assert known["cache"]["entries"] == 0
    assert known["breakers"] == []

    # Nothing is stored and nothing is known to be failing, so the honest prediction is
    # that the call would go out and work.
    predicted = runner.invoke(app, ["forecast", "https://en.wikipedia.org/wiki/Foo"])
    assert predicted.exit_code == 0, predicted.output
    assert predicted.output.splitlines()[0] == "FRESH  PROCEED"
    assert predicted.output.splitlines()[1]

    parsed = json.loads(
        runner.invoke(app, ["forecast", "--json", "https://en.wikipedia.org/wiki/Foo"]).output
    )
    assert parsed["volatility"] == "static"
    assert parsed["predicted"] in ("DOWN", "STALE", "FRESH")
    assert not egress_guard.attempts


def test_forecast_refuses_a_target_it_cannot_parse(workdir: Path) -> None:
    assert runner.invoke(app, ["init"]).exit_code == 0
    refused = runner.invoke(app, ["forecast", "not a url"])
    assert refused.exit_code == 2
