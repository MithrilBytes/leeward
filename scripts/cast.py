# SPDX-License-Identifier: Apache-2.0
"""Re-time a recording, and write it in the format the renderer reads.

The recording is one take of a real run, so its timing is whatever the model and the
network did that day: bursts of output separated by pauses nobody can read at. This
stretches the whole thing by a factor and caps any single pause, which changes how long
a viewer waits and nothing about what happened.

It also converts asciicast v3, which stores the gap before each event, to v2, which
stores the time since the start. That is all `asciinema convert` was doing here, so the
recording pipeline no longer needs asciinema installed to re-render, only to re-record.

    python -m scripts.cast --in demo/leeward.cast --out demo/leeward.v2.cast --slow 1.8
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

DEFAULT_SLOW = 1.8
DEFAULT_CAP_S = 3.0


def read_v3(text: str) -> tuple[dict[str, Any], list[tuple[float, str, str]]]:
    """The header, and every event as (gap before it, kind, data)."""
    lines = [line for line in text.splitlines() if line.strip()]
    header = cast("dict[str, Any]", json.loads(lines[0]))
    events: list[tuple[float, str, str]] = []
    for line in lines[1:]:
        gap, kind, data = cast("list[Any]", json.loads(line))
        events.append((float(gap), str(kind), str(data)))
    return header, events


def retime(
    events: Sequence[tuple[float, str, str]], slow: float, cap_s: float
) -> list[tuple[float, str, str]]:
    """Stretch every gap, and let no single one run past the cap."""
    return [(min(gap, cap_s) * slow, kind, data) for gap, kind, data in events]


def to_v2(header: dict[str, Any], events: Sequence[tuple[float, str, str]]) -> str:
    """asciicast v2: a header, then absolute times."""
    term = cast("dict[str, Any]", header.get("term") or {})
    head = {
        "version": 2,
        "width": term.get("cols", 80),
        "height": term.get("rows", 24),
        "timestamp": header.get("timestamp", 0),
        "env": header.get("env", {}),
    }
    if header.get("command"):
        head["command"] = header["command"]
    lines = [json.dumps(head)]
    at = 0.0
    for gap, kind, data in events:
        at += gap
        lines.append(json.dumps([round(at, 6), kind, data]))
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Re-time a recording and write v2.")
    parser.add_argument("--in", dest="source", type=Path, required=True)
    parser.add_argument("--out", dest="target", type=Path, required=True)
    parser.add_argument("--slow", type=float, default=DEFAULT_SLOW, help="Stretch factor.")
    parser.add_argument("--cap", type=float, default=DEFAULT_CAP_S, help="Longest single pause.")
    arguments = parser.parse_args(argv)

    header, events = read_v3(arguments.source.read_text(encoding="utf-8"))
    timed = retime(events, arguments.slow, arguments.cap)
    arguments.target.write_text(to_v2(header, timed), encoding="utf-8")
    before = sum(gap for gap, _kind, _data in events)
    after = sum(gap for gap, _kind, _data in timed)
    print(f"{arguments.source} {before:.1f}s -> {arguments.target} {after:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
