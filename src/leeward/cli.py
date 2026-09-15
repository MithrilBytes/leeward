# SPDX-License-Identifier: Apache-2.0
"""The leeward command line.

Every command takes --json. The commands that only read local state (classify and
events here, and status, forecast and report once the proxy has state to show)
open no network connection, so they still answer during the outage they describe.
"""

from __future__ import annotations

import datetime
import json
import re
import sys
from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from leeward import __version__
from leeward.config import ConfigError, LoadedConfig, load_config, parse_config
from leeward.events import follow, read_events, run_id
from leeward.policy import CallTarget, resolve
from leeward.units import parse_duration

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="A proxy between an agent and everything it calls.",
)
_out = Console(highlight=False, soft_wrap=True)
_err = Console(stderr=True, highlight=False, soft_wrap=True)

ConfigOption = Annotated[
    Path | None, typer.Option("--config", "-c", help="Configuration file (default ./leeward.yaml).")
]
JsonOption = Annotated[bool, typer.Option("--json", help="Print JSON instead of text.")]

MCP_CLIENT_CONFIGS = (
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    "~/.cursor/mcp.json",
    "~/.codeium/windsurf/mcp_config.json",
    ".mcp.json",
    ".vscode/mcp.json",
)
"""Where common MCP clients keep their server lists. init only reports what it finds."""

_DURATION = re.compile(r"^[0-9]+(ms|s|m|h|d)$")


def _fail(message: str, code: int = 2) -> typer.Exit:
    _err.print(message, markup=False, style="red")
    return typer.Exit(code)


def _load(path: Path | None) -> LoadedConfig:
    try:
        return load_config(path)
    except ConfigError as exc:
        raise _fail(str(exc)) from exc


def _print_json(value: object, *, compact: bool = False) -> None:
    indent = None if compact else 2
    separators = (",", ":") if compact else None
    sys.stdout.write(json.dumps(value, ensure_ascii=False, indent=indent, separators=separators))
    sys.stdout.write("\n")


def _show_version(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_show_version, is_eager=True, help="Print the version."),
    ] = False,
) -> None:
    """A proxy between an agent and everything it calls."""


@app.command()
def init(
    path: Annotated[Path, typer.Argument(help="Where to write the configuration.")] = Path(
        "leeward.yaml"
    ),
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing file.")] = False,
    json_output: JsonOption = False,
) -> None:
    """Write a starter leeward.yaml and create its data directory."""
    if path.exists() and not force:
        raise _fail(f"{path} already exists; pass --force to overwrite it", 1)
    text = files("leeward").joinpath("starter.yaml").read_text(encoding="utf-8")
    loaded = parse_config(text, path.resolve())
    path.write_text(text, encoding="utf-8")
    for sub in ("cache", "events"):
        (loaded.data_dir / sub).mkdir(parents=True, exist_ok=True)
    found = [
        str(candidate)
        for candidate in (Path(item).expanduser() for item in MCP_CLIENT_CONFIGS)
        if candidate.is_file()
    ]
    if json_output:
        _print_json(
            {"config": str(path.resolve()), "data_dir": str(loaded.data_dir), "mcp_clients": found}
        )
        return
    _out.print(f"wrote {path}", markup=False)
    _out.print(f"data directory {loaded.data_dir}", markup=False)
    for item in found:
        _out.print(f"MCP client configuration found at {item}", markup=False)


@app.command()
def classify(
    target: Annotated[str, typer.Argument(help="A URL, a server/tool name, or tier:name.")],
    method: Annotated[str, typer.Option("--method", "-X", help="HTTP method for a URL.")] = "GET",
    config_path: ConfigOption = None,
    json_output: JsonOption = False,
) -> None:
    """Show the policy for a call, and which rule or default decided each part."""
    loaded = _load(config_path)
    try:
        call = CallTarget.parse(target)
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    if call.kind == "http":
        call = CallTarget.http(call.name, method)
    policy = resolve(loaded.config, call)
    if json_output:
        _print_json(
            {
                "target": target,
                "kind": call.kind,
                "method": call.method,
                "endpoint": policy.endpoint,
                "class": str(policy.volatility),
                "rule_index": policy.rule_index,
                "rule_name": policy.rule_name,
                "soft_deadline_s": policy.soft_deadline_s,
                "hard_deadline_s": policy.hard_deadline_s,
                "stale_on_error_s": policy.stale_on_error_s,
                "stale_while_revalidate_s": policy.stale_while_revalidate_s,
                "cacheable": policy.cacheable,
                "idempotent": policy.idempotent,
                "max_attempts": policy.max_attempts,
                "max_body_bytes": policy.max_body_bytes,
                "decided_by": {
                    "class": policy.volatility_source,
                    "deadlines": policy.deadline_source,
                    "stale": policy.stale_source,
                    "cacheable": policy.cacheable_reason,
                },
                "config": str(loaded.source) if loaded.source is not None else None,
            }
        )
        return
    _out.print(f"{policy.volatility}  decided by {policy.volatility_source}", markup=False)
    table = Table(box=None, show_header=True, header_style="bold", pad_edge=False)
    table.add_column("field", no_wrap=True)
    table.add_column("value", overflow="fold")
    table.add_column("decided by", overflow="fold")
    for row in policy.explain():
        table.add_row(*row)
    _out.print(table)
    if loaded.source is None:
        _out.print("no leeward.yaml found; built-in defaults applied", markup=False)


def _parse_since(text: str | None) -> datetime.datetime | None:
    """A duration back from now (30m, 2h) or an ISO 8601 date-time, read as UTC if naive."""
    if text is None:
        return None
    if _DURATION.match(text):
        return datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(
            seconds=parse_duration(text)
        )
    moment = datetime.datetime.fromisoformat(text)
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=datetime.UTC)


def _summary(event: Mapping[str, object]) -> str:
    parts = [str(event.get("ts", ""))[11:23], str(event.get("event", ""))]
    for key in ("outcome", "failure_class", "disposition", "endpoint", "message"):
        value = event.get(key)
        if value:
            parts.append(str(value))
    latency = event.get("total_latency_ms")
    if isinstance(latency, int):
        parts.append(f"{latency}ms")
    identity = run_id(event)
    if identity:
        parts.append(f"run={identity}")
    return "  ".join(parts)


@app.command()
def events(
    run: Annotated[str | None, typer.Option("--run", help="Only events from this run.")] = None,
    since: Annotated[
        str | None, typer.Option("--since", help="A duration such as 30m, or a date-time.")
    ] = None,
    follow_log: Annotated[
        bool, typer.Option("--follow", "-f", help="Keep printing events as they arrive.")
    ] = False,
    config_path: ConfigOption = None,
    json_output: JsonOption = False,
) -> None:
    """Print the event log, or follow it as it grows."""
    loaded = _load(config_path)
    directory = loaded.data_dir / "events"
    try:
        cutoff = _parse_since(since)
    except ValueError as exc:
        raise _fail(f"--since: {exc}") from exc
    stream = (
        follow(directory, run=run) if follow_log else read_events(directory, run=run, since=cutoff)
    )
    try:
        for event in stream:
            if json_output:
                _print_json(event, compact=True)
            else:
                _out.print(_summary(event), markup=False)
    except KeyboardInterrupt:
        raise typer.Exit(0) from None


def main() -> None:
    app()
