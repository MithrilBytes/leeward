# SPDX-License-Identifier: Apache-2.0
"""Build the sdist and wheel, and prove them from a new virtual environment.

`python -m build` makes the sdist from the working tree and the wheel from the sdist,
so a file the sdist leaves out and the wheel needs fails the build here. Then:

1. Neither artifact carries a file git does not track. A working tree holds more
   than the project, and a build backend only knows what .gitignore tells it.
2. The wheel holds exactly the tracked files under src/leeward, which is how the
   note templates and the starter configuration reach an installed copy.
3. A new virtual environment on the chosen interpreter installs the wheel with the
   pinned dependencies. From a directory outside the repository, with nothing on
   PYTHONPATH, the installed copy prints its version, loads the templates the source
   tree has, runs `init` and `classify`, and wraps a one-tool stdio server that is
   called over MCP.

build: https://build.pypa.io/en/stable/
Binary distribution format: https://packaging.python.org/en/latest/specifications/binary-distribution-format/
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, cast

from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters
from mcp_types import TextContent

from leeward.surfaces.mcp import OUTCOME_META_KEY
from leeward.templates import template_set_sha256

REPO_ROOT = Path(__file__).resolve().parents[1]
CONSTRAINTS = REPO_ROOT / "constraints.txt"
PACKAGE = "leeward"
ENTRY_POINT = "leeward = leeward.cli:main"
COMMAND_LIMIT_S = 120.0
"""Longer than any command below takes, and far short of a hung CI job."""
INSTALL_LIMIT_S = 600.0
"""Installing the pinned dependencies can mean downloading all of them."""

ECHO_SERVER = '''\
from mcp.server.mcpserver import MCPServer

server = MCPServer(name="echo")


@server.tool()
def echo(text: str) -> str:
    """Say the text back."""
    return text


server.run(transport="stdio")
'''


class CheckFailedError(Exception):
    """A check that did not hold, saying what was found instead."""


def tracked_files() -> set[str]:
    listed = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=True
    ).stdout
    return {name for name in listed.decode("utf-8").split("\0") if name}


def uncommitted() -> list[str]:
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [line[3:] for line in status.splitlines()]


def build(outdir: Path) -> tuple[Path, Path]:
    command = [sys.executable, "-m", "build", "--quiet", "--outdir", str(outdir), str(REPO_ROOT)]
    subprocess.run(command, check=True)
    sdists, wheels = sorted(outdir.glob("*.tar.gz")), sorted(outdir.glob("*.whl"))
    if len(sdists) != 1 or len(wheels) != 1:
        found = ", ".join(path.name for path in (*sdists, *wheels))
        raise CheckFailedError(f"expected one sdist and one wheel in {outdir}, found {found}")
    return sdists[0], wheels[0]


def check_sdist(sdist: Path, tracked: set[str]) -> None:
    """Every file in the sdist is tracked, apart from the PKG-INFO the backend writes."""
    with tarfile.open(sdist) as archive:
        names = {member.name.split("/", 1)[1] for member in archive.getmembers() if member.isfile()}
    extra = sorted(names - tracked - {"PKG-INFO"})
    if extra:
        raise CheckFailedError(f"{sdist.name} carries files git does not track: {', '.join(extra)}")


def check_wheel(wheel: Path, tracked: set[str]) -> int:
    """The wheel holds the tracked package files exactly, and metadata that names the
    command and carries the licence. Returns how many package files it holds."""
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        meta = {name.split("/", 1)[0] for name in names if ".dist-info/" in name}
        if len(meta) != 1:
            raise CheckFailedError(f"{wheel.name} has {len(meta)} .dist-info directories")
        info = meta.pop()
        entry_points = archive.read(f"{info}/entry_points.txt").decode("utf-8")
    shipped = {name.removeprefix(f"{PACKAGE}/") for name in names if name.startswith(f"{PACKAGE}/")}
    source = {
        name.removeprefix(f"src/{PACKAGE}/")
        for name in tracked
        if name.startswith(f"src/{PACKAGE}/")
    }
    problems = [
        *(f"missing {name}" for name in sorted(source - shipped)),
        *(f"untracked {name}" for name in sorted(shipped - source)),
        *(
            f"outside the package {name}"
            for name in sorted(names)
            if not name.startswith((f"{PACKAGE}/", f"{info}/"))
        ),
    ]
    if ENTRY_POINT not in entry_points.splitlines():
        problems.append(f"no entry point {ENTRY_POINT!r}")
    problems += [
        f"no {info}/licenses/{name}"
        for name in ("LICENSE", "NOTICE")
        if f"{info}/licenses/{name}" not in names
    ]
    if problems:
        raise CheckFailedError(f"{wheel.name}: {'; '.join(problems)}")
    return len(shipped)


def run(command: list[str], cwd: Path, env: dict[str, str]) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=COMMAND_LIMIT_S,
    )
    if completed.returncode != 0:
        shown = " ".join(Path(part).name if "/" in part else part for part in command)
        raise CheckFailedError(
            f"{shown} exited {completed.returncode}: {completed.stderr.strip()[-2000:]}"
        )
    return completed.stdout


def install(wheel: Path, python: str, venv: Path) -> tuple[Path, str]:
    """A new environment with the wheel and its pinned dependencies, and its version."""
    subprocess.run([python, "-m", "venv", str(venv)], check=True, timeout=COMMAND_LIMIT_S)
    interpreter = venv / "bin" / "python"
    pip = [str(interpreter), "-m", "pip", "install", "--quiet", "--disable-pip-version-check"]
    subprocess.run(
        [*pip, "--constraint", str(CONSTRAINTS), str(wheel)], check=True, timeout=INSTALL_LIMIT_S
    )
    version = subprocess.run(
        [str(interpreter), "-c", "import platform; print(platform.python_version())"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return venv / "bin", version


async def call_through_wrap(bin_dir: Path, work: Path) -> tuple[list[str], list[str], str]:
    """Tool names, result text and outcome from one call through the installed wrap."""
    parameters = StdioServerParameters(
        command=str(bin_dir / "leeward"),
        args=["wrap", "--data-dir", str(work / "data"), "--", str(bin_dir / "python"), "echo.py"],
        env={"HOME": str(work)},
        cwd=work,
    )
    async with asyncio.timeout(COMMAND_LIMIT_S), Client(parameters) as client:
        tools = [tool.name for tool in (await client.list_tools()).tools]
        result = await client.call_tool("echo", {"text": "hello from the wheel"})
    texts = [block.text for block in result.content if isinstance(block, TextContent)]
    meta = result.meta or {}
    return tools, texts, str(cast("dict[str, Any]", meta.get(OUTCOME_META_KEY, {})).get("outcome"))


def check_installed(bin_dir: Path, venv: Path, work: Path, version: str) -> list[str]:
    """Run the installed copy from outside the repository. Returns what was shown."""
    env = {"HOME": str(work), "PATH": f"{bin_dir}:/usr/bin:/bin"}
    shown: list[str] = []

    printed = {
        run([str(bin_dir / "leeward"), "--version"], work, env).strip(),
        run([str(bin_dir / "python"), "-m", "leeward", "--version"], work, env).strip(),
    }
    if printed != {version}:
        raise CheckFailedError(f"the installed commands print {sorted(printed)}, not {version}")
    shown.append(f"leeward --version and python -m leeward --version print {version}")

    probe = "import json, leeward, leeward.templates as t; "
    probe += "print(json.dumps([leeward.__file__, t.template_set_sha256()]))"
    location, digest = json.loads(run([str(bin_dir / "python"), "-I", "-c", probe], work, env))
    if not Path(location).resolve().is_relative_to(venv.resolve()):
        raise CheckFailedError(f"leeward was imported from {location}, outside the environment")
    if digest != template_set_sha256():
        raise CheckFailedError(f"installed templates hash to {digest}, the source tree's do not")
    shown.append(f"the note templates load from the installed copy, set hash {digest[:12]}")

    run([str(bin_dir / "leeward"), "init"], work, env)
    classified = run(
        [str(bin_dir / "leeward"), "classify", "https://en.wikipedia.org/wiki/Foo"], work, env
    ).splitlines()[0]
    if classified != "static  decided by rules[0] (wikipedia-articles)":
        raise CheckFailedError(f"classify after init printed {classified!r}")
    shown.append("init writes the starter configuration, and classify reads it")

    (work / "echo.py").write_text(ECHO_SERVER, encoding="utf-8")
    tools, texts, outcome = asyncio.run(call_through_wrap(bin_dir, work))
    if (tools, texts, outcome) != (["echo"], ["hello from the wheel"], "FRESH"):
        raise CheckFailedError(f"wrap gave tools {tools}, content {texts}, outcome {outcome}")
    events = [
        cast("dict[str, Any]", json.loads(line))
        for path in sorted((work / "data" / "events").glob("*.jsonl"))
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    stamped = {(event["leeward_version"], event["template_set_sha256"]) for event in events}
    if not events or stamped != {(version, digest)}:
        raise CheckFailedError(f"wrap's events are stamped {sorted(stamped)}")
    shown.append(f"wrap served a tool call over MCP and logged {len(events)} events")
    return shown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the sdist and wheel, and check them.")
    parser.add_argument(
        "--outdir",
        type=Path,
        help="copy the artifacts here once every check has passed (default: keep none)",
    )
    parser.add_argument(
        "--python", default=sys.executable, help="the interpreter for the new environment"
    )
    args = parser.parse_args(argv)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="leeward-dist-") as scratch:
        root = Path(scratch)
        work = root / "work"
        work.mkdir()
        try:
            changed = uncommitted()
            if changed:
                print(f"note: uncommitted changes are included: {', '.join(changed)}", flush=True)
            # Built out of the way, so a directory of artifacts only ever holds ones
            # that passed.
            sdist, wheel = build(root / "dist")
            kb = [path.stat().st_size // 1024 for path in (sdist, wheel)]
            print(f"built {sdist.name} ({kb[0]} KB) and {wheel.name} ({kb[1]} KB)", flush=True)
            tracked = tracked_files()
            check_sdist(sdist, tracked)
            count = check_wheel(wheel, tracked)
            print("ok  neither artifact carries a file git does not track", flush=True)
            print(f"ok  the wheel holds all {count} tracked files under src/{PACKAGE}", flush=True)
            bin_dir, python_version = install(wheel, cast("str", args.python), root / "venv")
            print(f"ok  installed with pinned dependencies on Python {python_version}", flush=True)
            wheel_version = wheel.name.split("-")[1]
            for line in check_installed(bin_dir, root / "venv", work, wheel_version):
                print(f"ok  {line}", flush=True)
            if args.outdir is not None:
                outdir = cast("Path", args.outdir)
                outdir.mkdir(parents=True, exist_ok=True)
                for artifact in (sdist, wheel):
                    shutil.copy2(artifact, outdir / artifact.name)
                print(f"kept both in {outdir}", flush=True)
        except (
            CheckFailedError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            TimeoutError,
        ) as error:
            print(f"dist: {error}", file=sys.stderr, flush=True)
            return 1
    print(f"done in {time.monotonic() - started:.1f} s", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
