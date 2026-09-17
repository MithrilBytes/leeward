# SPDX-License-Identifier: Apache-2.0
"""A fake MCP server whose tool can vanish mid-session.

That is the case leeward exists for: a server is redeployed, a tool it used to offer
is gone, and the agent keeps asking for it because "unknown tool" reads like every
other error. Here it can be made to happen on demand, and the calls it received are
kept so a test can check what actually reached the tool.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

Asked = tuple[str, dict[str, Any]]


@dataclass
class Journal:
    """What the tools were asked, and what they should do about it."""

    calls: list[Asked] = field(default_factory=list["Asked"])
    notes_fail_after: int | None = None
    notes_hang: bool = False
    lookup_vanishes_after: int | None = None
    sink: Path | None = None
    """A file that gets a line per call, for a caller in another process."""

    def record(self, tool: str, arguments: dict[str, Any]) -> int:
        self.calls.append((tool, arguments))
        if self.sink is not None:
            with self.sink.open("a", encoding="utf-8") as lines:
                lines.write(f"{tool}\n")
        return sum(1 for name, _arguments in self.calls if name == tool)

    def hits(self, tool: str) -> int:
        return sum(1 for name, _arguments in self.calls if name == tool)


def build_server(name: str = "notes", journal: Journal | None = None) -> tuple[MCPServer, Journal]:
    """A server with two tools, one that answers and one that can be taken away, and a
    prompt and a resource that a front has to pass through untouched."""
    kept = journal if journal is not None else Journal()
    server = MCPServer(name=name)

    @server.tool()
    async def incident_notes(query: str) -> str:
        """Search the incident notes for a query."""
        seen = kept.record("incident_notes", {"query": query})
        if kept.notes_hang:
            await anyio.sleep_forever()
        if kept.notes_fail_after is not None and seen > kept.notes_fail_after:
            raise RuntimeError("the document store is not answering")
        return f"3 incident notes mention {query}"

    @server.tool()
    def threat_intel_lookup(ioc: str) -> str:
        """Look up an indicator of compromise."""
        seen = kept.record("threat_intel_lookup", {"ioc": ioc})
        if kept.lookup_vanishes_after is not None and seen >= kept.lookup_vanishes_after:
            vanish(server)
        return f"no intelligence on record for {ioc}"

    @server.prompt()
    def summarize_incident(incident: str) -> str:
        """Ask for a summary of one incident."""
        return f"Summarize incident {incident} from its notes."

    @server.resource("notes://index", mime_type="text/plain")
    def notes_index() -> str:
        """Which incidents have notes."""
        return "blackout\nbrownout\nfailover"

    return server, kept


def missing(server: MCPServer) -> None:
    """Add a tool that reports a thing that is not there, as a file server does."""

    @server.tool()
    def read_note(path: str) -> str:
        """Read one note by path."""
        # Reported the way a real file server reports it: an error result carrying the
        # reason, rather than a crash the framework turns into "error executing tool".
        raise ToolError(f"ENOENT: no such file or directory, open '{path}'")


def vanish(server: MCPServer, tool: str = "threat_intel_lookup") -> None:
    """Take a tool away, as a redeployed server does."""
    server.remove_tool(tool)


def redefine(server: MCPServer, tool: str = "incident_notes") -> None:
    """Keep a tool's name and change what it takes, as a breaking redeploy does."""
    server.remove_tool(tool)

    @server.tool(name=tool)
    def replacement(question: str, limit: int = 3) -> str:
        """Search the incident notes, with the arguments this version wants."""
        return f"{limit} incident notes mention {question}"


def main() -> None:
    """Run over stdio, which is how the demo reaches it.

    A caller in another process sets what it needs through the environment:
    LEEWARD_FAKE_PID_FILE gets the process id, so the server can be killed through a
    wrapper; LEEWARD_FAKE_JOURNAL gets a line per tool call;
    LEEWARD_FAKE_VANISH_AFTER takes threat_intel_lookup away after that many calls; and
    LEEWARD_FAKE_HANG makes incident_notes accept a call and never answer it.
    """
    pid_file = os.environ.get("LEEWARD_FAKE_PID_FILE")
    if pid_file:
        Path(pid_file).write_text(str(os.getpid()), encoding="utf-8")
    journal = Journal()
    if sink := os.environ.get("LEEWARD_FAKE_JOURNAL"):
        journal.sink = Path(sink)
    if after := os.environ.get("LEEWARD_FAKE_VANISH_AFTER"):
        journal.lookup_vanishes_after = int(after)
    journal.notes_hang = bool(os.environ.get("LEEWARD_FAKE_HANG"))
    server, _journal = build_server(journal=journal)
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
