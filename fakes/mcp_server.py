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

from mcp.server.mcpserver import MCPServer

Asked = tuple[str, dict[str, Any]]


@dataclass
class Journal:
    """What the tools were asked, and what they should do about it."""

    calls: list[Asked] = field(default_factory=list["Asked"])
    notes_fail_after: int | None = None

    def record(self, tool: str, arguments: dict[str, Any]) -> int:
        self.calls.append((tool, arguments))
        return sum(1 for name, _arguments in self.calls if name == tool)

    def hits(self, tool: str) -> int:
        return sum(1 for name, _arguments in self.calls if name == tool)


def build_server(name: str = "notes", journal: Journal | None = None) -> tuple[MCPServer, Journal]:
    """A server with two tools, one that answers and one that can be taken away, and a
    prompt and a resource that a front has to pass through untouched."""
    kept = journal if journal is not None else Journal()
    server = MCPServer(name=name)

    @server.tool()
    def incident_notes(query: str) -> str:
        """Search the incident notes for a query."""
        seen = kept.record("incident_notes", {"query": query})
        if kept.notes_fail_after is not None and seen > kept.notes_fail_after:
            raise RuntimeError("the document store is not answering")
        return f"3 incident notes mention {query}"

    @server.tool()
    def threat_intel_lookup(ioc: str) -> str:
        """Look up an indicator of compromise."""
        kept.record("threat_intel_lookup", {"ioc": ioc})
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


def vanish(server: MCPServer, tool: str = "threat_intel_lookup") -> None:
    """Take a tool away, as a redeployed server does."""
    server.remove_tool(tool)


def main() -> None:
    """Run over stdio, which is how the demo's agent reaches it.

    With LEEWARD_FAKE_PID_FILE set, the process id is written there first, so a test
    talking to this server through a wrapper can still kill it.
    """
    pid_file = os.environ.get("LEEWARD_FAKE_PID_FILE")
    if pid_file:
        Path(pid_file).write_text(str(os.getpid()), encoding="utf-8")
    server, _journal = build_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
