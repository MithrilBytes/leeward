# SPDX-License-Identifier: Apache-2.0
"""Wrapping one stdio MCP server, with no configuration file.

An MCP client starts a stdio server from a command line, and putting `leeward wrap --`
in front of that command line is the whole of the wiring. The client talks to leeward
over stdio, leeward starts the real server and talks to it the same way, and the
tools, prompts and resources the client sees are the server's own.

The server gets leeward's whole environment and working directory, since those are
what the client prepared for it. Nothing is cached unless asked: a tool's name does
not say whether calling it twice is harmless, so results are kept only for the tools
that `--cache` names.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import secrets
import signal
from collections.abc import Sequence
from pathlib import Path

from leeward.config import NAME, LoadedConfig, Match, Rule, StdioServer
from leeward.policy import CallTarget, resolve
from leeward.proxy import Proxy
from leeward.surfaces.mcp import ServerFront
from leeward.surfaces.upstream import Upstream
from leeward.vocab import Volatility

_LAUNCHER = re.compile(
    r"^(npx|npm|pnpm|yarn|bunx?|deno|node|uvx?|pipx|docker|podman|python[0-9.]*"
    r"|run|exec|dlx|x|tool)$"
)
"""Words that start a server rather than name it, skipped when naming one."""

_VARIABLE = re.compile(r"^[A-Z_][0-9A-Z_]*(=.*)?$")
"""An environment variable, as in `docker run -e GITHUB_TOKEN`, which is not a name either."""

_UNNAMEABLE = re.compile(r"[^A-Za-z0-9_.-]+")


def server_name(command: Sequence[str]) -> str:
    """A name for a server, read off its command line.

    `npx -y @modelcontextprotocol/server-github` gives server-github, and
    `python -m notes.server` gives notes.server. The first word that is not a
    launcher, a flag or a variable is taken, less its path, version and tag.
    """
    for word in command:
        leaf = word.rstrip("/").rsplit("/", 1)[-1]
        if word.startswith("-") or _LAUNCHER.match(leaf) or _VARIABLE.match(word):
            continue
        bare = leaf.split("@", 1)[0] if not leaf.startswith("@") else leaf
        cleaned = _UNNAMEABLE.sub("-", bare.split(":", 1)[0]).strip("-._")
        if NAME.match(cleaned):
            return cleaned
    return "server"


def wrap_config(
    loaded: LoadedConfig, name: str, cached: Sequence[str], data_dir: Path | None = None
) -> LoadedConfig:
    """The configuration to wrap with: the file's, if one was named, and a rule per `--cache`.

    The `--cache` rules go after the file's own, so a rule written for the server
    still decides its tools' class and deadlines. `cache_warnings` says when that
    leaves a named tool uncached.
    """
    config = loaded.config
    rules = [
        Rule(name=f"--cache {tool}", match=Match(tool=f"{name}/{tool}"), pure=True)
        for tool in cached
    ]
    update: dict[str, object] = {"rules": [*config.rules, *rules]}
    if data_dir is not None:
        update["data_dir"] = str(data_dir.expanduser().resolve())
    return LoadedConfig(config.model_copy(update=update), loaded.source)


def cache_warnings(loaded: LoadedConfig, name: str, cached: Sequence[str]) -> list[str]:
    """Why a tool that `--cache` names will still not be cached, for each such tool."""
    warnings: list[str] = []
    for tool in cached:
        policy = resolve(loaded.config, CallTarget.tool(name, tool))
        if policy.cacheable:
            continue
        if policy.volatility is Volatility.NEVER:
            why = f"its class is never, decided by {policy.volatility_source}"
        elif policy.rule_index is not None:
            why = f"rules[{policy.rule_index}] matches it first and does not mark it pure"
        else:
            why = policy.cacheable_reason
        warnings.append(f"--cache {tool} has no effect: {why}")
    return warnings


async def run(loaded: LoadedConfig, name: str, command: Sequence[str]) -> bool:
    """Serve the wrapped server over stdio until the client closes the stream or a signal.

    Returns whether a signal ended it. The SDK reads stdin through anyio's file
    wrapper, which blocks a worker thread; a signal handler runs on the main thread and
    does not unblock it, and shutting an event loop down waits for that thread. So after
    a signal the caller should end the process rather than close the loop. By then the
    wrapped server has been stopped and the cache and event log closed.
    https://anyio.readthedocs.io/en/stable/fileio.html
    https://docs.python.org/3/library/signal.html#signals-and-threads
    https://docs.python.org/3/library/asyncio-runner.html#asyncio.Runner.close
    """
    proxy = Proxy(loaded)
    upstream = Upstream(name, StdioServer(transport="stdio", command=list(command), env_from=["*"]))
    # A client starts one process per session, so the process is the run. The token
    # keeps two sessions apart in the event log they share.
    front = ServerFront(proxy, upstream, connection=f"stdio:{name}:{secrets.token_hex(4)}")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        # Windows raises ValueError for a signal its event loop will not take, and
        # NotImplementedError elsewhere. Either way the client's other way of stopping
        # a stdio server, closing its input, still works.
        with contextlib.suppress(NotImplementedError, ValueError):
            # A client stops a stdio server by closing its input, then with SIGTERM, and
            # the server leeward started is in a process group of its own, so leeward
            # has to stop it on the way out.
            # https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle#shutdown
            loop.add_signal_handler(signum, stop.set)
    serving = asyncio.ensure_future(front.run_stdio_async())
    stopping = asyncio.ensure_future(stop.wait())
    try:
        await asyncio.wait({serving, stopping}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        stopping.cancel()
        await upstream.aclose()
        await proxy.aclose()
    if not serving.done():
        return True
    serving.result()
    return False
