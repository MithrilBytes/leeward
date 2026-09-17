# SPDX-License-Identifier: Apache-2.0
"""When a warm run happens without anyone asking for it.

Two triggers, both configured per corpus. A `schedule` is a cron expression, read the
way cron reads it, so a corpus can be refreshed nightly while the origin is healthy. And
`warm_on_degradation` starts a run when leeward notices something has gone down, on the
theory that the moment one dependency fails is the moment to fill the cache with the
others while they still answer.

Both are deliberately dull: minute granularity, one corpus at a time, and a floor on how
often degradation can retrigger, since a run that is failing will keep looking degraded.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime

from leeward.config import Corpus
from leeward.proxy import Proxy
from leeward.vocab import Outcome
from leeward.warm import Result, Warmer

TICK_S = 30.0
"""How often the scheduler looks at the clock. Cron's own resolution is a minute."""

DEGRADATION_FLOOR_S = 600.0
"""The soonest degradation may start the same corpus again."""

FIELDS = ("minute", "hour", "day", "month", "weekday")
RANGES = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 6))


def _field_matches(expression: str, value: int, low: int, high: int) -> bool:
    for part in expression.split(","):
        step = 1
        text = part
        if "/" in part:
            text, _, divisor = part.partition("/")
            if not divisor.isdigit() or int(divisor) == 0:
                return False
            step = int(divisor)
        if text in ("*", ""):
            start, end = low, high
        elif "-" in text:
            first, _, last = text.partition("-")
            if not (first.isdigit() and last.isdigit()):
                return False
            start, end = int(first), int(last)
        elif text.isdigit():
            start = end = int(text)
        else:
            return False
        if start <= value <= end and (value - start) % step == 0:
            return True
    return False


def cron_matches(expression: str, moment: datetime) -> bool:
    """Whether a five field cron expression covers this minute.

    Supports `*`, `a`, `a-b`, `a,b`, and `*/n` or `a-b/n`, which is the part of cron
    anyone writes by hand. Day of week is 0 to 6 with Sunday at 0, as cron has it, and
    day of month and day of week are both required to match rather than either, which
    is the simpler reading of the two and the one that surprises less.
    https://pubs.opengroup.org/onlinepubs/9699919799/utilities/crontab.html
    """
    parts = expression.split()
    if len(parts) != len(FIELDS):
        return False
    values = (
        moment.minute,
        moment.hour,
        moment.day,
        moment.month,
        (moment.weekday() + 1) % 7,
    )
    return all(
        _field_matches(part, value, low, high)
        for part, value, (low, high) in zip(parts, values, RANGES, strict=True)
    )


@dataclass
class Fired:
    """One triggered run, kept so a caller can see what the scheduler did."""

    corpus: str
    trigger: str
    result: Result | None = None


@dataclass
class Scheduler:
    """Watches the clock and the health table, and warms what they ask for."""

    proxy: Proxy
    clock: Callable[[], float] = time.time
    now: Callable[[], datetime] = datetime.now
    fired: list[Fired] = field(default_factory=list[Fired])
    _last_minute: str = ""
    _last_degraded: dict[str, float] = field(default_factory=dict[str, float])

    def scheduled(self) -> list[Corpus]:
        """Corpora whose cron covers this minute, once per minute however often we look."""
        moment = self.now()
        stamp = moment.strftime("%Y-%m-%dT%H:%M")
        if stamp == self._last_minute:
            return []
        self._last_minute = stamp
        return [
            corpus
            for corpus in self.proxy.config.corpora
            if corpus.schedule and cron_matches(corpus.schedule, moment)
        ]

    def degraded(self) -> list[Corpus]:
        """Corpora to warm because something else is failing, no more than one per floor."""
        if not any(health.last_outcome is Outcome.DOWN for health in self.proxy.health.values()):
            return []
        now = self.clock()
        due: list[Corpus] = []
        for corpus in self.proxy.config.corpora:
            if not corpus.warm_on_degradation:
                continue
            last = self._last_degraded.get(corpus.name)
            if last is not None and now - last < DEGRADATION_FLOOR_S:
                continue
            self._last_degraded[corpus.name] = now
            due.append(corpus)
        return due

    async def tick(self) -> list[Fired]:
        """One pass: whatever the clock and the health table ask for, run one at a time."""
        done: list[Fired] = []
        for corpus in self.scheduled():
            done.append(await self._warm(corpus, "schedule"))
        for corpus in self.degraded():
            done.append(await self._warm(corpus, "degradation"))
        self.fired += done
        return done

    async def _warm(self, corpus: Corpus, trigger: str) -> Fired:
        warmer = Warmer(self.proxy, trigger="schedule" if trigger == "schedule" else "degradation")
        try:
            result = await warmer.warm(corpus)
        except (OSError, ValueError):
            # A warm run that cannot start is not a reason to stop scheduling; the run
            # itself already records every URL that failed.
            return Fired(corpus.name, trigger)
        return Fired(corpus.name, trigger, result)

    async def run_forever(self) -> None:
        while True:
            with contextlib.suppress(Exception):
                await self.tick()
            await asyncio.sleep(TICK_S)


def wanted(corpora: Iterable[Corpus]) -> bool:
    """Whether anything is configured that would ever fire, so serve can skip the task."""
    return any(corpus.schedule or corpus.warm_on_degradation for corpus in corpora)
