# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import io
import re
import tarfile
import zipfile
from pathlib import Path

import pytest
from scripts.dist import ENTRY_POINT, CheckFailedError, check_sdist, check_wheel

TRACKED = {"README.md", "src/leeward/__init__.py", "src/leeward/templates/down.txt"}
PACKAGE_FILES = ["leeward/__init__.py", "leeward/templates/down.txt"]


def sdist_with(path: Path, names: list[str]) -> Path:
    with tarfile.open(path, "w:gz") as archive:
        for name in names:
            info = tarfile.TarInfo(f"leeward-0.1.0/{name}")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
    return path


def wheel_with(path: Path, names: list[str], *, entry_points: str | None = None) -> Path:
    info = "leeward-0.1.0.dist-info"
    scripts = f"[console_scripts]\n{ENTRY_POINT}\n" if entry_points is None else entry_points
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, "x")
        archive.writestr(f"{info}/entry_points.txt", scripts)
        for licence in ("LICENSE", "NOTICE"):
            archive.writestr(f"{info}/licenses/{licence}", "x")
    return path


def test_an_sdist_of_tracked_files_passes(tmp_path: Path) -> None:
    names = ["PKG-INFO", "README.md", "src/leeward/__init__.py"]
    check_sdist(sdist_with(tmp_path / "leeward.tar.gz", names), TRACKED)


def test_an_sdist_carrying_an_untracked_file_fails_and_names_it(tmp_path: Path) -> None:
    sdist = sdist_with(tmp_path / "leeward.tar.gz", ["README.md", "notes/todo.md"])
    with pytest.raises(CheckFailedError, match=re.escape("does not track: notes/todo.md")):
        check_sdist(sdist, TRACKED)


def test_a_wheel_holding_exactly_the_tracked_package_passes(tmp_path: Path) -> None:
    assert check_wheel(wheel_with(tmp_path / "leeward.whl", PACKAGE_FILES), TRACKED) == 2


@pytest.mark.parametrize(
    ("names", "problem"),
    [
        (["leeward/__init__.py"], "missing templates/down.txt"),
        ([*PACKAGE_FILES, "leeward/scratch.py"], "untracked scratch.py"),
        ([*PACKAGE_FILES, "fakes/origin.py"], "outside the package fakes/origin.py"),
    ],
)
def test_a_wheel_that_drops_or_adds_a_file_fails(
    tmp_path: Path, names: list[str], problem: str
) -> None:
    with pytest.raises(CheckFailedError, match=re.escape(problem)):
        check_wheel(wheel_with(tmp_path / "leeward.whl", names), TRACKED)


def test_a_wheel_without_the_command_fails(tmp_path: Path) -> None:
    wheel = wheel_with(tmp_path / "leeward.whl", PACKAGE_FILES, entry_points="")
    with pytest.raises(CheckFailedError, match="no entry point"):
        check_wheel(wheel, TRACKED)
