# SPDX-License-Identifier: Apache-2.0
"""The leeward command line.

Every command takes --json. The commands that only read local state (classify and
events here, and status, forecast and report once the proxy has state to show) open no
network connection, so they still answer during the outage they describe. serve and
wrap run until they are stopped. serve reports its start on stdout; wrap writes only to
stderr, which is not a courtesy: its stdout is the MCP stream.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import json
import os
import platform
import re
import shutil
import sys
from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path
from typing import Annotated, cast

import typer
from rich.console import Console
from rich.table import Table

from leeward import __version__
from leeward.config import (
    NAME,
    Config,
    ConfigError,
    LoadedConfig,
    load_config,
    parse_config,
)
from leeward.events import follow, read_events, run_id
from leeward.policy import CallTarget, resolve
from leeward.templates import template_set_sha256
from leeward.units import human_bytes, parse_duration

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


@app.command()
def serve(config_path: ConfigOption = None, json_output: JsonOption = False) -> None:
    """Run the proxy on the address in leeward.yaml until it is stopped."""
    # Imported here rather than at the top, where it would double the start time of
    # every other command.
    from leeward.policy import policy_warnings
    from leeward.serve import listen_address, run

    loaded = _load(config_path)
    surfaces = loaded.config.surfaces
    host, port = listen_address(loaded)
    enabled = [
        label
        for label, surface in (
            ("mcp", surfaces.mcp),
            ("fetch", surfaces.fetch),
            ("llm", surfaces.llm),
        )
        if surface.enabled
    ]
    warnings = policy_warnings(loaded.config)
    if not enabled:
        warnings.insert(
            0, "no surface is enabled, so only /leeward/status and /leeward/forecast answer"
        )
    url = f"http://{host}:{port}"
    if json_output:
        report = {
            "leeward": __version__,
            "listening": url,
            "surfaces": enabled,
            "warnings": warnings,
        }
        _print_json(report, compact=True)
        sys.stdout.flush()
    else:
        _err.print(f"leeward {__version__} listening on {url}", markup=False)
        for warning in warnings:
            _err.print(f"warning: {warning}", markup=False)
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(run(loaded))


@app.command(context_settings={"allow_interspersed_args": False})
def wrap(
    command: Annotated[
        list[str],
        typer.Argument(
            help="The server's command line. Put -- before it when it has flags of its own.",
            metavar="COMMAND...",
            show_default=False,
        ),
    ],
    name: Annotated[
        str | None,
        typer.Option(
            "--name",
            "-n",
            help="The server's name in events and rules (default: from the command).",
        ),
    ] = None,
    cache: Annotated[
        list[str] | None,
        typer.Option(
            "--cache",
            help="Keep this tool's results and answer from them when the server fails."
            " Only for tools that are safe to call twice. Repeatable.",
        ),
    ] = None,
    data_dir: Annotated[
        Path | None,
        typer.Option("--data-dir", help="Where the cache and event log live (default ~/.leeward)."),
    ] = None,
    config_path: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c", help="A leeward.yaml for defaults and rules; read only if named."
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json", help="Write startup warnings as JSON lines on stderr; stdout carries MCP."
        ),
    ] = False,
) -> None:
    """Front one stdio MCP server: put `leeward wrap --` before the command that starts it."""
    from leeward.wrap import cache_warnings, run, server_name, wrap_config

    if name is not None and not NAME.match(name):
        raise _fail(f"--name {name!r}: use letters, digits, '.', '_' and '-'")
    server = name or server_name(command)
    base = _load(config_path) if config_path is not None else LoadedConfig(Config(), None)
    loaded = wrap_config(base, server, cache or [], data_dir)
    for warning in cache_warnings(loaded, server, cache or []):
        if json_output:
            sys.stderr.write(json.dumps({"warning": warning}, ensure_ascii=False) + "\n")
        else:
            _err.print(f"leeward: {warning}", markup=False)
    sys.stderr.flush()
    loop = asyncio.new_event_loop()
    with contextlib.suppress(KeyboardInterrupt):
        if loop.run_until_complete(run(loaded, server, command)):
            # Stopped by a signal, with the cleanup done. Closing the loop would wait on
            # the worker thread still blocked reading stdin, since shutting a loop down
            # waits on its default executor.
            # https://anyio.readthedocs.io/en/stable/fileio.html
            # https://docs.python.org/3/library/asyncio-runner.html#asyncio.Runner.close
            os._exit(0)
    loop.close()


@app.command()
def report(
    since: Annotated[
        str | None, typer.Option("--since", help="A duration such as 24h, or a date-time.")
    ] = None,
    run: Annotated[str | None, typer.Option("--run", help="Only events from this run.")] = None,
    config_path: ConfigOption = None,
    json_output: JsonOption = False,
) -> None:
    """Add up the event log: what was served, what failed, and what cost nothing."""
    from leeward.report import headline, summarize

    loaded = _load(config_path)
    try:
        cutoff = _parse_since(since)
    except ValueError as exc:
        raise _fail(f"--since: {exc}") from exc
    events = read_events(loaded.data_dir / "events", run=run, since=cutoff)
    summary = summarize(events)
    if json_output:
        _print_json(summary)
        return
    totals = cast("Mapping[str, object]", summary["totals"])
    _out.print(headline(summary), markup=False)
    rows = cast("list[Mapping[str, object]]", summary["endpoints"])
    if not rows:
        return
    table = Table(box=None, pad_edge=False)
    for column in ("endpoint", "calls", "fresh", "stale", "down", "free", "p50", "p95", "worst"):
        table.add_column(column, justify="left" if column in ("endpoint", "worst") else "right")
    for row in rows:
        outcomes = cast("Mapping[str, int]", row["outcomes"])
        classes = cast("Mapping[str, int]", row["failure_classes"])
        worst = max(classes.items(), key=lambda item: item[1])[0] if classes else ""
        table.add_row(
            str(row["endpoint"]),
            str(row["calls"]),
            str(outcomes.get("FRESH", 0)),
            str(outcomes.get("STALE", 0)),
            str(outcomes.get("DOWN", 0)),
            str(row["answered_without_network"]),
            f"{row['p50_ms']}ms",
            f"{row['p95_ms']}ms",
            worst,
        )
    _out.print(table)
    served = _bytes_from(totals)
    if served:
        _out.print(f"{served} served from cache", markup=False)


def _bytes_from(totals: Mapping[str, object]) -> str:
    from leeward.units import human_bytes

    count = totals.get("bytes_served_from_cache")
    return human_bytes(count) if isinstance(count, int) and count else ""


@app.command()
def doctor(config_path: ConfigOption = None, json_output: JsonOption = False) -> None:
    """Check the wiring: configuration, data directory, event log and MCP clients."""
    from leeward.policy import policy_warnings

    checks: list[dict[str, object]] = []

    def record(name: str, ok: bool, detail: str, *, warn: bool = False) -> None:
        state = "warn" if warn and not ok else ("ok" if ok else "fail")
        checks.append({"check": name, "state": state, "detail": detail})

    record("version", True, f"leeward {__version__} on Python {platform.python_version()}")

    try:
        loaded = load_config(config_path)
        source = str(loaded.source) if loaded.source is not None else "built-in defaults"
        record("configuration", True, source)
        for warning in policy_warnings(loaded.config):
            record("rules", False, warning, warn=True)
    except ConfigError as exc:
        record("configuration", False, str(exc).splitlines()[0])
        _finish(checks, json_output)
        return

    data = loaded.data_dir
    try:
        data.mkdir(parents=True, exist_ok=True)
        probe = data / ".doctor"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
        free = shutil.disk_usage(data).free
        record("data directory", True, f"{data} is writable, {human_bytes(free)} free")
    except OSError as exc:
        record("data directory", False, f"{data}: {exc}")

    record("note templates", bool(template_set_sha256()), f"set {template_set_sha256()[:12]}")

    events_dir = data / "events"
    newest = _newest_event(events_dir)
    if newest is None:
        record("event log", True, "no events yet", warn=False)
    else:
        record("event log", True, f"newest event {newest}")

    wired = _wrapped_servers()
    if wired:
        for client, servers in wired:
            record("client", True, f"{client}: {', '.join(servers)}")
    else:
        record(
            "client",
            False,
            "no MCP client configuration mentions leeward wrap; see the README for the one line",
            warn=True,
        )
    _finish(checks, json_output)


def _finish(checks: list[dict[str, object]], json_output: bool) -> None:
    failed = [check for check in checks if check["state"] == "fail"]
    if json_output:
        _print_json({"ok": not failed, "checks": checks})
    else:
        marks = {"ok": "ok  ", "warn": "warn", "fail": "FAIL"}
        for check in checks:
            _out.print(
                f"{marks[str(check['state'])]} {check['check']}: {check['detail']}", markup=False
            )
    if failed:
        raise typer.Exit(1)


def _newest_event(directory: Path) -> str | None:
    newest: str | None = None
    for event in read_events(directory):
        stamp = event.get("ts")
        if isinstance(stamp, str) and (newest is None or stamp > newest):
            newest = stamp
    return newest


def _wrapped_servers() -> list[tuple[str, list[str]]]:
    """Which MCP client configurations already start a server through leeward."""
    found: list[tuple[str, list[str]]] = []
    for item in MCP_CLIENT_CONFIGS:
        candidate = Path(item).expanduser()
        if not candidate.is_file():
            continue
        try:
            parsed = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        servers = _mapping(parsed).get("mcpServers")
        named = [name for name, entry in _mapping(servers).items() if _through_leeward(entry)]
        if named:
            found.append((str(candidate), sorted(named)))
    return found


def _mapping(value: object) -> Mapping[str, object]:
    """An object read out of someone else's JSON, with its shape stated once."""
    return cast("Mapping[str, object]", value) if isinstance(value, dict) else {}


def _through_leeward(entry: object) -> bool:
    spec = _mapping(entry)
    command = spec.get("command")
    arguments = spec.get("args")
    listed = cast("list[object]", arguments) if isinstance(arguments, list) else []
    first = listed[0] if listed else None
    return isinstance(command, str) and Path(command).name == "leeward" and first == "wrap"


def main() -> None:
    app()
