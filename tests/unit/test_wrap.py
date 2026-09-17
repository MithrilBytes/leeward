# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import pytest
from mcp.client.stdio import StdioServerParameters

from leeward.config import Config, LoadedConfig, StdioServer, parse_config
from leeward.policy import CallTarget, resolve
from leeward.surfaces.upstream import Upstream
from leeward.wrap import cache_warnings, server_name, wrap_config

BARE = LoadedConfig(Config(), None)


@pytest.mark.parametrize(
    ("command", "name"),
    [
        (["npx", "-y", "@modelcontextprotocol/server-github"], "server-github"),
        (
            ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me"],
            "server-filesystem",
        ),
        (["uvx", "mcp-server-fetch@2025.4.7"], "mcp-server-fetch"),
        (["/usr/bin/python3.13", "-m", "notes.server"], "notes.server"),
        (
            [
                "docker",
                "run",
                "-i",
                "--rm",
                "-e",
                "GITHUB_TOKEN",
                "ghcr.io/github/github-mcp-server:v1",
            ],
            "github-mcp-server",
        ),
        (["node", "build/index.js"], "index.js"),
        (["npx", "-y"], "server"),
    ],
)
def test_a_server_is_named_after_what_its_command_starts(command: list[str], name: str) -> None:
    assert server_name(command) == name


def test_without_a_file_state_lives_in_the_home_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir("/")
    assert wrap_config(BARE, "notes", []).data_dir == (tmp_path / ".leeward").resolve()
    chosen = wrap_config(BARE, "notes", [], tmp_path / "elsewhere")
    assert chosen.data_dir == (tmp_path / "elsewhere").resolve()


def test_only_the_tools_named_by_cache_are_cached() -> None:
    loaded = wrap_config(BARE, "notes", ["incident_notes"])
    named = resolve(loaded.config, CallTarget.tool("notes", "incident_notes"))
    other = resolve(loaded.config, CallTarget.tool("notes", "threat_intel_lookup"))
    assert named.cacheable
    assert named.cacheable_reason == "rules[0] (--cache incident_notes) marks it pure"
    assert not other.cacheable
    assert cache_warnings(loaded, "notes", ["incident_notes"]) == []


def test_rules_from_a_named_file_still_decide_first(tmp_path: Path) -> None:
    text = 'rules:\n  - match: {tool: "notes/*"}\n    class: slow\n    hard_deadline: 60s\n'
    loaded = wrap_config(parse_config(text, tmp_path / "leeward.yaml"), "notes", ["incident_notes"])
    policy = resolve(loaded.config, CallTarget.tool("notes", "incident_notes"))
    assert (str(policy.volatility), policy.hard_deadline_s, policy.cacheable) == (
        "slow",
        60.0,
        False,
    )
    assert cache_warnings(loaded, "notes", ["incident_notes"]) == [
        "--cache incident_notes has no effect: rules[0] matches it first and does not mark it pure"
    ]


def test_a_tool_that_looks_like_a_write_is_not_cached_and_says_why() -> None:
    loaded = wrap_config(BARE, "github", ["create_issue"])
    assert cache_warnings(loaded, "github", ["create_issue"]) == [
        "--cache create_issue has no effect: its class is never, decided by tool name matches"
        " defaults.write_tool_pattern"
    ]


def test_environment_patterns_pass_variables_and_written_values_win() -> None:
    spec = StdioServer(
        transport="stdio", command=["server"], env={"MODE": "configured"}, env_from=["GH_*", "MODE"]
    )
    environment = {"GH_TOKEN": "t", "GH_HOST": "h", "MODE": "inherited", "HOME": "/home/me"}
    target = Upstream("github", spec, environment=environment)._target()  # pyright: ignore[reportPrivateUsage]
    assert isinstance(target, StdioServerParameters)
    assert target.env == {"GH_TOKEN": "t", "GH_HOST": "h", "MODE": "configured"}
