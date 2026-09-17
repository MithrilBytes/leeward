# SPDX-License-Identifier: Apache-2.0
"""What leeward costs when nothing is wrong.

Every claim in the README is about a call that failed. This measures the other case,
the one that happens all day: a call that works, with leeward in the path. Three
numbers, each against the same fake origin on loopback, so the network is as close to
free as it gets and what is left is leeward's own work.

    python -m scripts.overhead --readme README.md
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import tempfile
import time
from collections.abc import Callable, Coroutine, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpcore2
from fakes.origin import FakeOrigin, document

from leeward.config import parse_config
from leeward.events import RunRef
from leeward.proxy import HttpRequest, Proxy
from leeward.vocab import Outcome

ROUNDS = 200
WARMUP = 20
BODY = b"<h1>the 2003 blackout</h1>" * 8

CONFIG = """
profile: dev
data_dir: {data}
rules:
  - name: article
    match: {{url: "*/wiki/*"}}
    class: static
    stale_on_error: 30d
  - name: live-status
    match: {{url: "*/status*"}}
    class: live
    stale_on_error: 0s
"""


@dataclass(frozen=True, slots=True)
class Timing:
    """One measured path."""

    label: str
    samples: Sequence[float]

    @property
    def p50_ms(self) -> float:
        return statistics.median(self.samples) * 1000

    @property
    def p95_ms(self) -> float:
        ordered = sorted(self.samples)
        return ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))] * 1000


async def repeat(call: Callable[[], Coroutine[Any, Any, None]], label: str) -> Timing:
    for _ in range(WARMUP):
        await call()
    samples: list[float] = []
    for _ in range(ROUNDS):
        started = time.perf_counter()
        await call()
        samples.append(time.perf_counter() - started)
    return Timing(label, samples)


async def measure() -> list[Timing]:
    scratch = Path(tempfile.mkdtemp(prefix="leeward-overhead-"))
    async with FakeOrigin() as origin:
        origin.route("/wiki/*", document(BODY, cache_control="max-age=600"))
        origin.route("/status", document(b'{"alerts": 0}', cache_control="no-cache"))
        loaded = parse_config(CONFIG.format(data=scratch / "data"), scratch / "leeward.yaml")
        proxy = Proxy(loaded)
        run = RunRef.internal("overhead")
        pool = httpcore2.AsyncConnectionPool()
        article = f"{origin.base_url}/wiki/Blackout"
        status = f"{origin.base_url}/status"

        async def direct() -> None:
            response = await pool.request("GET", article)
            assert response.status == 200

        async def through_leeward_uncached() -> None:
            # `live` is never served from cache, so every one of these reaches the origin.
            served = await proxy.fetch(HttpRequest("GET", status), run)
            assert served.outcome.outcome is Outcome.FRESH

        async def from_cache() -> None:
            served = await proxy.fetch(HttpRequest("GET", article), run)
            assert served.from_cache

        # The first call to the article is a miss by definition; prime it so the third
        # measurement is the cache path and not one fetch plus 199 hits.
        await proxy.fetch(HttpRequest("GET", article), run)

        timings = [
            await repeat(direct, "straight to the origin, no leeward"),
            await repeat(through_leeward_uncached, "through leeward, to the origin"),
            await repeat(from_cache, "through leeward, answered from cache"),
        ]
        await pool.aclose()
        await proxy.aclose()
    return timings


def table(timings: Sequence[Timing]) -> str:
    direct, through, cached = timings
    added = through.p50_ms - direct.p50_ms
    lines = [
        "| Path | p50 | p95 |",
        "| --- | --- | --- |",
        *(
            f"| {timing.label} | {timing.p50_ms:.2f} ms | {timing.p95_ms:.2f} ms |"
            for timing in timings
        ),
    ]
    return "\n".join(
        [
            f"Measured over {ROUNDS} calls each against a fake origin on loopback.",
            "",
            *lines,
            "",
            f"leeward adds about {added:.2f} ms to a call it has to make, and answers"
            f" from its own cache in {cached.p50_ms:.2f} ms.",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure what leeward costs per call.")
    parser.add_argument("--readme", type=Path, help="rewrite the overhead region of this file")
    parser.add_argument("--json", action="store_true", help="print the samples as JSON")
    arguments = parser.parse_args(argv)

    timings = asyncio.run(measure())
    if arguments.json:
        print(
            json.dumps(
                [
                    {"label": t.label, "p50_ms": round(t.p50_ms, 3), "p95_ms": round(t.p95_ms, 3)}
                    for t in timings
                ],
                indent=2,
            )
        )
        return 0
    block = table(timings)
    if arguments.readme is None:
        print(block)
        return 0

    from scripts.demo import fill

    text = arguments.readme.read_text(encoding="utf-8")
    arguments.readme.write_text(fill(text, {"overhead": block}), encoding="utf-8")
    print(f"rewrote the overhead region of {arguments.readme}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
