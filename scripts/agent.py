# SPDX-License-Identifier: Apache-2.0
"""The same small agent, asked the same thing twice, with its server killed underneath it.

The left run talks to an MCP server directly. The right run talks to the same server
through `leeward wrap`. Both use a local model, so the recording needs no API key and
no network, and both are real: real processes, real tool calls, a real SIGKILL.

What the model says is its own business and will differ between runs. What is being
shown is what the agent had to work with when the server went away.

    ollama serve
    ollama pull qwen2.5:7b-instruct-q4_K_M
    python -m scripts.agent
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import AsyncGenerator, Mapping, Sequence
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters
from mcp_types import CallToolResult, TextContent, Tool

REPO_ROOT = Path(__file__).resolve().parents[1]
MODEL = os.environ.get("LEEWARD_DEMO_MODEL", "qwen2.5:7b-instruct-q4_K_M")
OLLAMA = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
MAX_ROUNDS = 4
TIMEOUT_S = 120.0

SEED = 7
SYSTEM = (
    "You are an incident analyst. Answer in English, in at most two sentences."
    " Use the tools to answer; do not answer from memory. If a tool result carries a"
    " note from leeward, take it at its word and pass on what it says about freshness."
    " If a call fails, say plainly what you could and could not establish."
)
FIRST = "What do the incident notes say about the blackout?"
SECOND = "Check the notes for the blackout once more, and tell me how current your answer is."

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"


def say(text: str = "") -> None:
    print(text, flush=True)


def rule(title: str, colour: str) -> None:
    say()
    say(f"{colour}{BOLD}{'━' * 78}{RESET}")
    say(f"{colour}{BOLD}  {title}{RESET}")
    say(f"{colour}{BOLD}{'━' * 78}{RESET}")


@dataclass
class Turn:
    """One exchange, kept so the two runs can be compared afterwards."""

    tool_calls: int = 0
    tool_failures: int = 0
    answer: str = ""
    outcomes: list[str] = field(default_factory=list[str])


def chat(messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
    """One turn of the local model, through Ollama's own API."""
    payload = json.dumps(
        {
            "model": MODEL,
            "messages": messages,
            "tools": tools,
            "stream": False,
            # A recording people will compare frame by frame should not drift on
            # temperature. Answers still vary between models and machines.
            "options": {"temperature": 0, "seed": SEED},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{OLLAMA}/api/chat", data=payload, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:
        body = cast("dict[str, Any]", json.loads(response.read()))
    return cast("dict[str, Any]", body.get("message") or {})


def _version() -> None:
    with urllib.request.urlopen(f"{OLLAMA}/api/version", timeout=5) as response:
        response.read()


def as_tool(tool: Tool) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description or "",
            "parameters": tool.input_schema or {"type": "object"},
        },
    }


def text_of(result: CallToolResult) -> str:
    parts = [item.text for item in result.content if isinstance(item, TextContent)]
    return "\n".join(parts) or json.dumps(result.structured_content or {}, ensure_ascii=False)


def outcome_of(result: CallToolResult) -> str:
    meta = cast("Mapping[str, Any]", result.meta or {})
    decision = meta.get("io.github.mithrilbytes.leeward/outcome")
    if not isinstance(decision, dict):
        return ""
    known = cast("Mapping[str, Any]", decision)
    failure = known.get("failure")
    klass = cast("Mapping[str, Any]", failure).get("class") if isinstance(failure, dict) else None
    return f"{known.get('outcome')}{f'{{{klass}}}' if klass else ''} {known.get('advice')}"


async def ask(client: Client, tools: list[Tool], question: str, colour: str) -> Turn:
    """One question, and however many tool calls the model decides it needs."""
    turn = Turn()
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": question},
    ]
    say(f"{colour}> {question}{RESET}")
    offered = [as_tool(tool) for tool in tools]
    for _round in range(MAX_ROUNDS):
        message = await asyncio.to_thread(chat, messages, offered)
        calls = cast("list[dict[str, Any]]", message.get("tool_calls") or [])
        if not calls:
            turn.answer = str(message.get("content") or "").strip()
            say(f"  {turn.answer}")
            return turn
        messages.append(message)
        for call in calls:
            function = cast("Mapping[str, Any]", call.get("function") or {})
            name = str(function.get("name"))
            arguments = cast("dict[str, Any]", function.get("arguments") or {})
            say(f"{DIM}  calling {name}({json.dumps(arguments)}){RESET}")
            turn.tool_calls += 1
            try:
                result = await client.call_tool(name, arguments)
            except Exception as error:  # noqa: BLE001
                turn.tool_failures += 1
                detail = f"{type(error).__name__}: {error}"
                say(f"{RED}  the call raised: {detail[:96]}{RESET}")
                messages.append({"role": "tool", "tool_name": name, "content": detail})
                continue
            body = text_of(result)
            outcome = outcome_of(result)
            if outcome:
                turn.outcomes.append(outcome)
                say(f"{DIM}  leeward: {outcome}{RESET}")
            if result.is_error:
                turn.tool_failures += 1
            say(f"{DIM}  {body.splitlines()[0][:96] if body else '(nothing)'}{RESET}")
            messages.append({"role": "tool", "tool_name": name, "content": body})
    turn.answer = "(gave up after four rounds)"
    say(f"{RED}  {turn.answer}{RESET}")
    return turn


@asynccontextmanager
async def session(base: Path, *, through_leeward: bool) -> AsyncGenerator[tuple[Client, Path]]:
    """The fake server as its own process, with or without leeward in front of it."""
    await asyncio.to_thread(base.mkdir, parents=True, exist_ok=True)
    pid_file = base / "server.pid"
    environment = {
        **os.environ,
        "LEEWARD_FAKE_PID_FILE": str(pid_file),
        "LEEWARD_FAKE_JOURNAL": str(base / "journal"),
    }
    if through_leeward:
        args = [
            *("-m", "leeward", "wrap", "--name", "intel"),
            *("--data-dir", str(base / "data"), "--cache", "incident_notes"),
            *("--", sys.executable, "-m", "fakes.mcp_server"),
        ]
    else:
        args = ["-m", "fakes.mcp_server"]
    parameters = StdioServerParameters(
        command=sys.executable, args=args, env=environment, cwd=str(REPO_ROOT)
    )
    async with Client(parameters) as client:
        yield client, pid_file


def kill_server(pid_file: Path) -> None:
    for _ in range(100):
        if pid_file.exists():
            break
    pid = int(pid_file.read_text(encoding="utf-8"))
    say(f"{YELLOW}  [the MCP server is killed here]{RESET}")
    os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))


async def column(title: str, colour: str, base: Path, *, through_leeward: bool) -> list[Turn]:
    rule(title, colour)
    turns: list[Turn] = []
    async with session(base, through_leeward=through_leeward) as (client, pid_file):
        tools = (await client.list_tools()).tools
        turns.append(await ask(client, list(tools), FIRST, colour))
        say()
        kill_server(pid_file)
        await asyncio.sleep(0.2)
        say()
        turns.append(await ask(client, list(tools), SECOND, colour))
    return turns


def verdict(label: str, turns: Sequence[Turn], colour: str) -> None:
    after = turns[-1]
    say(f"{colour}{BOLD}{label}{RESET}")
    say(f"  tool calls after the kill: {after.tool_calls}, failures: {after.tool_failures}")
    if after.outcomes:
        say(f"  leeward said: {', '.join(after.outcomes)}")
    say(f"  final answer: {after.answer or '(none)'}")


async def main() -> None:
    try:
        await asyncio.to_thread(_version)
    except (urllib.error.URLError, TimeoutError):
        say(f"{RED}no model at {OLLAMA}. Start one with: ollama serve{RESET}")
        raise SystemExit(1) from None

    scratch = Path(tempfile.mkdtemp(prefix="leeward-agent-"))
    try:
        say(f"{BOLD}model {MODEL}, MCP server killed mid session in both runs{RESET}")
        bare = await column("WITHOUT leeward", RED, scratch / "bare", through_leeward=False)
        fronted = await column("WITH leeward", GREEN, scratch / "leeward", through_leeward=True)
        rule("AFTER THE SERVER DIED", BOLD)
        verdict("without leeward", bare, RED)
        say()
        verdict("with leeward", fronted, GREEN)
    finally:
        with suppress(OSError):
            shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
