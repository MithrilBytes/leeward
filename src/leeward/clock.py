# SPDX-License-Identifier: Apache-2.0
"""Whether this machine's clock can be believed.

A wrong clock is a failure that looks like something else. TLS certificates read as
expired or not yet valid, a freshness lifetime measured against it is nonsense, and no
amount of retrying fixes either. The classifier already knows what to do about it and
says so: `TLS_CLOCK_SKEW` is NEVER at host scope, with a note telling the agent to stop
rather than try again. It just needed something to tell it.

Origins date their responses (RFC 9110 §6.6.1), so every answer carries a second
opinion. One disagreeing host means that host's clock is wrong, which is not leeward's
problem. Several hosts disagreeing the same way means the clock here is wrong, which is.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from statistics import median

from leeward.vocab import ClockTrust

MIN_HOSTS = 2
"""Hosts that have to agree before the local clock is the suspect rather than theirs."""

KEEP = 16
"""Recent observations kept per host. This is a running check, not a history."""


def offset_of(date_header: str, now: float) -> float | None:
    """Seconds the origin's clock is ahead of this one, or nothing if the date is junk."""
    try:
        moment = parsedate_to_datetime(date_header)
    except (TypeError, ValueError):
        return None
    return moment.timestamp() - now


@dataclass
class ClockCheck:
    """A running comparison between this machine's clock and the ones answering it."""

    threshold_s: float
    offsets: dict[str, list[float]] = field(default_factory=dict[str, list[float]])

    def observe(self, host: str, headers: Mapping[str, str], now: float) -> None:
        """Record what one origin thinks the time is."""
        date = headers.get("date") or headers.get("Date")
        if not date:
            return
        offset = offset_of(date, now)
        if offset is None:
            return
        seen = self.offsets.setdefault(host, [])
        seen.append(offset)
        del seen[:-KEEP]

    def trust(self) -> ClockTrust:
        """UNCHECKED until enough hosts have answered, then whether they agree with us.

        Each host is reduced to its median first, so one origin with a broken clock
        cannot outvote the rest by answering more often.
        """
        per_host = [median(offsets) for offsets in self.offsets.values() if offsets]
        if len(per_host) < MIN_HOSTS:
            return ClockTrust.UNCHECKED
        skewed = [offset for offset in per_host if abs(offset) > self.threshold_s]
        if len(skewed) < len(per_host):
            return ClockTrust.TRUSTED
        # Every host disagrees, and in the same direction: the odd one out is this machine.
        return (
            ClockTrust.SKEWED if len({offset > 0 for offset in skewed}) == 1 else ClockTrust.TRUSTED
        )
