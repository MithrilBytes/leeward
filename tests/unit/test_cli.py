# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from leeward import __version__
from leeward.cli import app
from leeward.config import DEFAULT_REDACT_HEADERS
from leeward.events import EventLog, RunRef
from leeward.vocab import RunResolution
from tests.conftest import EgressLog

runner = CliRunner()


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def test_classify_names_class_deadlines_and_deciding_rule_without_network(
    workdir: Path, egress_guard: EgressLog
) -> None:
    assert runner.invoke(app, ["init"]).exit_code == 0
    result = runner.invoke(app, ["classify", "https://en.wikipedia.org/wiki/Foo"])
    assert result.exit_code == 0, result.output
    assert result.output.splitlines()[0] == "static  decided by rules[0] (wikipedia-articles)"
    assert "soft 5s, hard 30s" in result.output

    parsed = json.loads(
        runner.invoke(app, ["classify", "--json", "https://en.wikipedia.org/wiki/Foo"]).output
    )
    assert (parsed["class"], parsed["rule_index"], parsed["hard_deadline_s"]) == ("static", 0, 30.0)
    assert parsed["decided_by"]["class"] == "rules[0] (wikipedia-articles)"
    assert egress_guard.attempts == []


def test_classify_without_a_config_file_reports_the_defaults(workdir: Path) -> None:
    result = runner.invoke(app, ["classify", "https://api.example.com/items"])
    assert result.exit_code == 0, result.output
    assert result.output.splitlines()[0] == "volatile  decided by defaults.class"
    assert "built-in defaults applied" in result.output


def test_classify_rejects_a_target_it_cannot_read(workdir: Path) -> None:
    result = runner.invoke(app, ["classify", "justaword"])
    assert result.exit_code == 2
    assert "not a URL" in result.output


def test_an_invalid_config_exits_with_the_key_and_reason(workdir: Path) -> None:
    (workdir / "leeward.yaml").write_text("defaults:\n  hard_deadlne: 30s\n")
    result = runner.invoke(app, ["classify", "https://x.example/"])
    assert result.exit_code == 2
    assert "defaults.hard_deadlne: Extra inputs are not permitted" in result.output


def test_init_writes_config_and_data_dirs_and_refuses_to_overwrite(workdir: Path) -> None:
    result = runner.invoke(app, ["init", "--json"])
    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert Path(report["config"]) == (workdir / "leeward.yaml").resolve()
    assert (Path(report["data_dir"]) / "events").is_dir()
    assert (Path(report["data_dir"]) / "cache").is_dir()
    again = runner.invoke(app, ["init"])
    assert again.exit_code == 1
    assert "already exists" in again.output


def test_events_prints_the_log_filtered_by_run(workdir: Path) -> None:
    assert runner.invoke(app, ["init"]).exit_code == 0
    log = EventLog(workdir / ".leeward" / "events", frozenset(DEFAULT_REDACT_HEADERS))
    log.emit("startup", RunRef("r1", RunResolution.HEADER), {"message": "one"})
    log.emit("startup", RunRef("r2", RunResolution.HEADER), {"message": "two"})
    log.close()
    result = runner.invoke(app, ["events", "--json", "--run", "r1"])
    assert result.exit_code == 0, result.output
    assert [json.loads(line)["message"] for line in result.output.splitlines()] == ["one"]
    text = runner.invoke(app, ["events"]).output
    assert "one" in text and "run=r2" in text


def test_version_prints_the_package_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert (result.exit_code, result.output.strip()) == (0, __version__)


def test_events_without_a_config_file_reads_the_log_wrap_writes(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = EventLog(workdir / ".leeward" / "events", frozenset(DEFAULT_REDACT_HEADERS))
    log.emit("startup", RunRef("wrapped", RunResolution.CONNECTION), {"message": "from wrap"})
    log.close()
    elsewhere = workdir / "some" / "project"
    elsewhere.mkdir(parents=True)
    monkeypatch.chdir(elsewhere)
    result = runner.invoke(app, ["events", "--json"])
    assert result.exit_code == 0, result.output
    assert [json.loads(line)["message"] for line in result.output.splitlines()] == ["from wrap"]


def test_wrap_needs_the_command_it_wraps(workdir: Path) -> None:
    result = runner.invoke(app, ["wrap"])
    assert result.exit_code == 2
    assert "COMMAND" in result.output


def test_wrap_refuses_a_name_that_cannot_name_an_endpoint(workdir: Path) -> None:
    result = runner.invoke(app, ["wrap", "--name", "two words", "--", "server"])
    assert result.exit_code == 2
    assert "--name 'two words'" in result.output


def test_serve_refuses_an_invalid_config_before_listening(workdir: Path) -> None:
    (workdir / "leeward.yaml").write_text("surfaces:\n  fetch:\n    listen: nowhere\n")
    result = runner.invoke(app, ["serve"])
    assert result.exit_code == 2
    assert "is not host:port" in result.output
