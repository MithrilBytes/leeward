# SPDX-License-Identifier: Apache-2.0
"""Pin the development environment to exact versions, and check that the pins hold.

pip resolves `.[dev]` in a dry run and writes a report of what it would install.
Every package in that report except this project becomes a `name==version` line
in constraints.txt, which `make install` hands to pip. The check repeats the
resolution under those pins. If pyproject.toml has gained, dropped or tightened a
requirement since the file was written, the result differs from the file or pip
cannot resolve at all, and either way the check fails.

The pins are not a pylock.toml from `pip lock`. That command records only the
wheel it picked for the machine it ran on, so a lock written on macOS arm64 names
a macOS wheel for pydantic-core and gives pip nothing it can install on Linux.
Exact versions install on both. The Python version shapes the resolution as well,
so it goes into the first line of the file and is compared along with the pins.

pip installation report: https://pip.pypa.io/en/stable/reference/installation-report/
Constraints files: https://pip.pypa.io/en/stable/user_guide/#constraints-files
pylock.toml: https://peps.python.org/pep-0751/
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]

CONSTRAINTS = REPO_ROOT / "constraints.txt"


def canonical_name(name: str) -> str:
    """The normalised project name, so pins sort and compare the way pip matches them.

    https://packaging.python.org/en/latest/specifications/name-normalization/
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def render(report: dict[str, Any], python: tuple[int, int]) -> str:
    """The constraints file for one installation report.

    Direct requirements are left out. The only one is this project, installed from
    the working tree, and a pin on it would break the install at the next version
    bump.
    """
    pins = sorted(
        (canonical_name(item["metadata"]["name"]), item["metadata"]["version"])
        for item in report["install"]
        if not item.get("is_direct", False)
    )
    major, minor = python
    header = f"# Exact versions for .[dev] on Python {major}.{minor}. Rewrite with make lock."
    return "\n".join([header, *(f"{name}=={version}" for name, version in pins)]) + "\n"


def resolve(constraints: Path | None) -> dict[str, Any] | None:
    """What pip would install for `.[dev]`, or None when it cannot resolve.

    Nothing is installed, and pip prints its own explanation of a failure.
    --ignore-installed makes the report list every package rather than only the
    ones this environment lacks.
    """
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--dry-run",
        "--ignore-installed",
        "--quiet",
        "--editable",
        ".[dev]",
    ]
    if constraints is not None:
        command += ["--constraint", str(constraints)]
    with tempfile.TemporaryDirectory() as scratch:
        report = Path(scratch) / "report.json"
        completed = subprocess.run([*command, "--report", str(report)], cwd=REPO_ROOT, check=False)
        if completed.returncode != 0:
            return None
        return json.loads(report.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pin or check the development environment.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if constraints.txt no longer matches a resolution of pyproject.toml",
    )
    check: bool = parser.parse_args(argv).check
    report = resolve(CONSTRAINTS if check else None)
    if report is None:
        return 1
    fresh = render(report, (sys.version_info.major, sys.version_info.minor))
    if not check:
        CONSTRAINTS.write_text(fresh, encoding="utf-8")
        return 0
    current = CONSTRAINTS.read_text(encoding="utf-8")
    if fresh == current:
        return 0
    sys.stderr.writelines(
        difflib.unified_diff(
            current.splitlines(keepends=True),
            fresh.splitlines(keepends=True),
            "constraints.txt",
            "fresh resolution",
        )
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
