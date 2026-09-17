# SPDX-License-Identifier: Apache-2.0
"""Arm each failure leeward is for, and write down what came back.

`make demo` runs this and rewrites the regions of README.md that sit between
`<!-- demo:NAME -->` and `<!-- /demo:NAME -->`, so the numbers and the notes there
come from a run and not from prose. Without --readme it prints them instead.

The HTTP cases run in process through leeward's application, against a fake origin
on a real socket, so a hang is a real hang and the 30 second deadline is the real
default. The MCP cases run the way a client runs leeward: `leeward wrap` as a process
over stdio, in front of the fake MCP server as another process, which drops a tool
or is killed with SIGKILL partway through.

Attempts come from leeward's event log. Calls that reached the upstream are counted
by the fakes themselves: requests the origin read, and tool calls the server ran.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import os
import platform
import re
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from fakes.origin import FakeOrigin, Reply, constant, document
from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters
from mcp_types import CallToolResult
from tests.support import AsgiReply, asgi_call

from leeward import __version__
from leeward.config import parse_config
from leeward.events import read_events
from leeward.proxy import Proxy
from leeward.serve import build_app
from leeward.surfaces.upstream import describe

REPO_ROOT = Path(__file__).resolve().parents[1]
REGION = re.compile(r"(<!-- demo:(?P<name>[a-z-]+) -->\n).*?(<!-- /demo:(?P=name) -->)", re.S)
NOTE_WIDTH = 88

HTTP_CONFIG = """
data_dir: {data}
surfaces:
  fetch:
    enabled: true
    mounts:
      origin: {origin}
rules:
  - name: articles
    match: {{url: "*/wiki/*"}}
    class: static
  - name: weather
    match: {{url: "*/weather"}}
    class: live
"""


@dataclass(frozen=True, slots=True)
class Row:
    case: str
    result: str
    seconds: float
    attempts: int
    reached: int


@dataclass
class Measured:
    rows: list[Row]
    notes: dict[str, str]


def result_text(
    outcome: str, failure: str | None, underlying: str | None, marker: str | None, advice: str
) -> str:
    """`DOWN{CLASS}` carrying `UNDERLYING`, then the status or isError, then the advice."""
    head = f"`{outcome}{{{failure}}}`" if failure and outcome == "DOWN" else f"`{outcome}`"
    parts = [f"{head} carrying `{underlying}`" if underlying else head]
    if marker is not None:
        parts.append(marker)
    parts.append(f"`{advice}`")
    return ", ".join(parts)


def duration(seconds: float) -> str:
    if seconds >= 1:
        return f"{seconds:.2f} s"
    milliseconds = seconds * 1000
    return f"{milliseconds:.0f} ms" if milliseconds >= 10 else f"{milliseconds:.1f} ms"


@dataclass
class HttpFront:
    """A leeward of its own over the shared origin, so the failures one case causes
    cannot open the breakers another case is measuring."""

    proxy: Proxy
    app: object
    calls: list[Mapping[str, object]]

    @classmethod
    def over(cls, origin: FakeOrigin, scratch: Path, label: str) -> HttpFront:
        text = HTTP_CONFIG.format(data=scratch / label, origin=origin.base_url)
        proxy = Proxy(parse_config(text, scratch / f"{label}.yaml"))
        calls: list[Mapping[str, object]] = []

        def keep(event: Mapping[str, object]) -> None:
            if event["event"] == "call":
                calls.append(event)

        proxy.events.observe(keep)
        return cls(proxy, build_app(proxy, close_with_app=False), calls)

    async def get(self, origin: FakeOrigin, measured: Measured, case: str, path: str) -> AsgiReply:
        """One call, measured and recorded as a row."""
        before = sum(origin.hits.values())
        started = time.monotonic()
        reply = await asgi_call(self.app, "GET", f"/origin{path}")
        elapsed = time.monotonic() - started
        if reply.header("X-Leeward-Outcome") in ("STALE", "FRESH"):
            result = result_text(
                str(reply.header("X-Leeward-Outcome")),
                reply.header("X-Leeward-Class"),
                None,
                str(reply.status),
                str(reply.header("X-Leeward-Advice")),
            )
        else:
            body = cast("dict[str, Any]", reply.json())
            failure = cast("dict[str, Any]", body["failure"])
            result = result_text(
                str(body["outcome"]),
                failure["class"],
                failure.get("underlying_class"),
                str(reply.status),
                str(body["advice"]),
            )
        reached = sum(origin.hits.values()) - before
        attempts = cast("int", self.calls[-1]["attempts"])
        measured.rows.append(Row(case, result, elapsed, attempts, reached))
        return reply


async def http_cases(scratch: Path, measured: Measured) -> None:
    async with FakeOrigin() as origin:
        page = document(b"<h1>Northeast blackout of 2003</h1>", cache_control="max-age=0")
        origin.route("/wiki/*", page)
        wind = Reply(headers={"Cache-Control": "no-cache"}, body=b'{"wind_kt": 34}')
        origin.route("/weather", constant(wind))
        origin.route("/hang", constant(Reply(hang=True)))
        limited = Reply(status=429, headers={"Retry-After": "3600"}, body=b"slow down")
        origin.route("/limited", constant(limited))
        fronts = {
            label: HttpFront.over(origin, scratch, label)
            for label in ("wedged", "quota", "static", "live")
        }

        front = fronts["wedged"]
        wedged = await front.get(origin, measured, "Origin hangs after connecting", "/hang")
        measured.notes["wedged"] = str(wedged.json()["note"])
        await front.get(origin, measured, "Same endpoint, next call", "/hang")
        front = fronts["quota"]
        quota = await front.get(origin, measured, "429 with `Retry-After: 3600`", "/limited")
        measured.notes["quota"] = str(quota.json()["note"])

        article = "/origin/wiki/Northeast_blackout_of_2003"
        await asgi_call(fronts["static"].app, "GET", article)
        await asgi_call(fronts["live"].app, "GET", "/origin/weather")
        await origin.stop()
        # The first call after the stop serves the copy and refreshes it in the
        # background. Once that refresh has failed, leeward knows the origin is down,
        # which is the state an outage leaves every later call in.
        front = fronts["static"]
        await asgi_call(front.app, "GET", article)
        await front.proxy.settle()
        stale = await front.get(
            origin, measured, "Static page, origin down", article.removeprefix("/origin")
        )
        measured.notes["stale"] = str(stale.header("X-Leeward-Advice-Note"))
        live = await fronts["live"].get(origin, measured, "Live endpoint, origin down", "/weather")
        measured.notes["live"] = str(live.json()["note"])
        for front in fronts.values():
            await front.proxy.aclose()


@dataclass
class Session:
    client: Client
    journal: Path
    pid_file: Path
    data: Path

    def tool_calls(self) -> int:
        return len(self.journal.read_text().splitlines()) if self.journal.exists() else 0

    def kill_server(self) -> None:
        os.kill(int(self.pid_file.read_text(encoding="utf-8")), signal.SIGKILL)


@asynccontextmanager
async def wrapped(
    scratch: Path, label: str, *options: str, vanish_after: int | None = None
) -> AsyncGenerator[Session]:
    """`leeward wrap` in front of the fake MCP server, both as real processes."""
    base = scratch / label
    base.mkdir()
    env = {
        "LEEWARD_FAKE_PID_FILE": str(base / "server.pid"),
        "LEEWARD_FAKE_JOURNAL": str(base / "journal"),
    }
    if vanish_after is not None:
        env["LEEWARD_FAKE_VANISH_AFTER"] = str(vanish_after)
    command = [*("-m", "leeward", "wrap", "--name", "intel", "--data-dir", str(base / "data"))]
    command += [*options, "--", sys.executable, "-m", "fakes.mcp_server"]
    parameters = StdioServerParameters(command=sys.executable, args=command, env=env, cwd=REPO_ROOT)
    async with asyncio.timeout(120), Client(parameters) as client:
        await client.list_tools()
        yield Session(client, base / "journal", base / "server.pid", base / "data")


async def timed(
    session: Session, tool: str, arguments: dict[str, Any]
) -> tuple[CallToolResult, float, int]:
    before = session.tool_calls()
    started = time.monotonic()
    result = await session.client.call_tool(tool, arguments)
    return result, time.monotonic() - started, session.tool_calls() - before


def record(
    measured: Measured, case: str, called: tuple[CallToolResult, float, int], attempts: int
) -> None:
    result, elapsed, reached = called
    outcome = cast("dict[str, Any]", cast("dict[str, Any]", result.structured_content)["leeward"])
    failure = cast("dict[str, Any] | None", outcome.get("failure"))
    text = result_text(
        str(outcome["outcome"]),
        failure["class"] if failure else None,
        failure.get("underlying_class") if failure else None,
        "`isError`" if result.is_error else None,
        str(outcome["advice"]),
    )
    measured.rows.append(Row(case, text, elapsed, attempts, reached))


def call_attempts(data: Path) -> list[int]:
    return [
        cast("int", event["attempts"])
        for event in read_events(data / "events")
        if event["event"] == "call"
    ]


async def mcp_cases(scratch: Path, measured: Measured) -> None:
    async with wrapped(scratch, "vanish", vanish_after=1) as session:
        await timed(session, "threat_intel_lookup", {"ioc": "198.51.100.4"})
        gone = await timed(session, "threat_intel_lookup", {"ioc": "203.0.113.9"})
        data = session.data
    record(measured, "MCP tool removed mid session", gone, call_attempts(data)[1])
    measured.notes["gone"] = describe(gone[0]).splitlines()[0]

    async with wrapped(scratch, "kill") as session:
        await timed(session, "incident_notes", {"query": "blackout"})
        session.kill_server()
        killed = await timed(session, "incident_notes", {"query": "blackout"})
        again = await timed(session, "incident_notes", {"query": "blackout"})
        other = await timed(session, "threat_intel_lookup", {"ioc": "198.51.100.4"})
        data = session.data
    attempts = call_attempts(data)
    record(measured, "MCP server killed mid session", killed, attempts[1])
    record(measured, "Same tool, next call", again, attempts[2])
    record(measured, "Another tool on it, next call", other, attempts[3])

    async with wrapped(scratch, "cache", "--cache", "incident_notes") as session:
        await timed(session, "incident_notes", {"query": "blackout"})
        session.kill_server()
        cached = await timed(session, "incident_notes", {"query": "blackout"})
        data = session.data
    record(measured, "`--cache` tool, server killed", cached, call_attempts(data)[1])
    measured.notes["stale_tool"] = describe(cached[0]).splitlines()[0]


def suite() -> str:
    """The test suite's size and time on this machine, from running it."""
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    found = re.search(r"(\d+) passed in ([\d.]+)s", completed.stdout)
    if completed.returncode != 0 or found is None:
        raise SystemExit(f"the test suite did not pass:\n{completed.stdout[-3000:]}")
    return f"{found[1]} tests, {float(found[2]):.0f} seconds on the machine above"


def machine() -> str:
    system = platform.system()
    name = f"macOS {platform.mac_ver()[0]}" if system == "Darwin" else system
    return (
        f"{name} on {platform.machine()} with {os.cpu_count()} cores, Python"
        f" {platform.python_version()}, leeward {__version__}, {datetime.date.today()}"
    )


def blocks(measured: Measured, tests: str) -> dict[str, str]:
    """The README regions, by name."""
    table = [
        "| Case | Result | Time | Attempts | Reached upstream |",
        "| --- | --- | --- | --- | --- |",
        *(
            f"| {row.case} | {row.result} | {duration(row.seconds)} | {row.attempts} |"
            f" {row.reached} |"
            for row in measured.rows
        ),
    ]

    def fenced(*names: str) -> str:
        wrapped_notes = [
            textwrap.fill(
                measured.notes[name],
                NOTE_WIDTH,
                break_long_words=False,
                break_on_hyphens=False,
            )
            for name in names
        ]
        return "```text\n" + "\n\n".join(wrapped_notes) + "\n```"

    return {
        "measured": f"Measured on {machine()}.\n\n" + "\n".join(table),
        "notes": fenced("stale_tool", "gone", "wedged"),
        **{f"note-{name.replace('_', '-')}": fenced(name) for name in measured.notes},
        "suite": f"The suite is {tests}.",
    }


def fill(text: str, filled: Mapping[str, str]) -> str:
    """The text with every demo region replaced, refusing a region nothing fills."""

    def replace(match: re.Match[str]) -> str:
        name = match["name"]
        if name not in filled:
            raise ValueError(f"no content for the region demo:{name}")
        return f"{match[1]}\n{filled[name].strip()}\n\n{match[3]}"

    result, count = REGION.subn(replace, text)
    if count == 0:
        raise ValueError("no <!-- demo:NAME --> regions found")
    return result


async def measure(scratch: Path) -> Measured:
    measured = Measured([], {})
    await http_cases(scratch, measured)
    await mcp_cases(scratch, measured)
    return measured


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the demo cases and report the numbers.")
    parser.add_argument("--readme", type=Path, help="rewrite the demo regions of this file")
    args = parser.parse_args(argv)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="leeward-demo-") as scratch:
        measured = asyncio.run(measure(Path(scratch)))
    filled = blocks(measured, suite())
    readme = cast("Path | None", args.readme)
    if readme is None:
        for name, block in filled.items():
            print(f"<!-- demo:{name} -->\n{block}\n")
    else:
        readme.write_text(fill(readme.read_text(encoding="utf-8"), filled), encoding="utf-8")
        print(f"rewrote the demo regions of {readme}")
    print(f"done in {time.monotonic() - started:.0f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
