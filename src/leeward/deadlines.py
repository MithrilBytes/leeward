# SPDX-License-Identifier: Apache-2.0
"""Deadlines, and when to stop waiting for a slow origin.

Both deadlines are leeward's own. A client that sets no timeout, or a generous one,
must not be able to make a call outlast its policy, so every deadline is measured
on the event loop's monotonic clock: a wall clock that jumps, which is exactly the
machine leeward is written for, cannot lengthen or shorten a call.

At the soft deadline leeward prefers an older copy to more waiting. With nothing to
serve it opens a second attempt on a fresh connection instead, the hedged request of
Dean and Barroso, "The Tail at Scale" (CACM 56(2), 2013). Two connections hung at
once is also far better evidence that an endpoint is wedged than one is.

The hedge waits for the soft deadline or for what this endpoint usually takes,
whichever is longer, so a slow but healthy origin is not doubled up on every call.
The estimate is the round-trip estimator of Jacobson and Karels (SIGCOMM 1988) as
RFC 6298 §2 writes it: srtt + 4 * rttvar.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from leeward.policy import ResolvedPolicy

SRTT_ALPHA = 1 / 8
RTTVAR_BETA = 1 / 4
"""RFC 6298 §2.3 smoothing factors: alpha 1/8 for the estimate, beta 1/4 for the variation."""

HEDGE_SHARE_OF_HARD = 0.5
"""A hedge later than half the hard window has too little time left to help."""

DeadlineHit = Literal["none", "soft", "hard"]


@dataclass(frozen=True, slots=True)
class Deadline:
    """A point on the monotonic clock."""

    at: float

    def remaining(self, now: float) -> float:
        return max(self.at - now, 0.0)

    def passed(self, now: float) -> bool:
        return now >= self.at


@dataclass(frozen=True, slots=True)
class CallDeadlines:
    started_at: float
    soft: Deadline
    hard: Deadline

    @classmethod
    def start(cls, policy: ResolvedPolicy, now: float) -> CallDeadlines:
        return cls(
            started_at=now,
            soft=Deadline(now + policy.soft_deadline_s),
            hard=Deadline(now + policy.hard_deadline_s),
        )

    def elapsed(self, now: float) -> float:
        return max(now - self.started_at, 0.0)

    def hit(self, now: float) -> DeadlineHit:
        if self.hard.passed(now):
            return "hard"
        return "soft" if self.soft.passed(now) else "none"

    def hedge_at(self, typical_s: float | None) -> Deadline:
        """When to open a second attempt: the soft deadline, or later for a slow endpoint."""
        latest = self.started_at + (self.hard.at - self.started_at) * HEDGE_SHARE_OF_HARD
        if typical_s is None:
            return Deadline(min(self.soft.at, latest))
        return Deadline(min(max(self.soft.at, self.started_at + typical_s), latest))


class LatencyEstimator:
    """What each endpoint usually takes, smoothed, so one slow call does not move it far."""

    def __init__(self) -> None:
        self._srtt: dict[str, float] = {}
        self._rttvar: dict[str, float] = {}

    def observe(self, endpoint: str, sample_s: float) -> None:
        sample_s = max(sample_s, 0.0)
        srtt = self._srtt.get(endpoint)
        if srtt is None:
            self._srtt[endpoint] = sample_s
            self._rttvar[endpoint] = sample_s / 2
            return
        rttvar = self._rttvar.get(endpoint, sample_s / 2)
        self._rttvar[endpoint] = (1 - RTTVAR_BETA) * rttvar + RTTVAR_BETA * abs(srtt - sample_s)
        self._srtt[endpoint] = (1 - SRTT_ALPHA) * srtt + SRTT_ALPHA * sample_s

    def typical(self, endpoint: str) -> float | None:
        """srtt + 4 * rttvar, the point past which a response is unusually late."""
        srtt = self._srtt.get(endpoint)
        if srtt is None:
            return None
        return srtt + 4 * self._rttvar.get(endpoint, 0.0)

    def forget(self, endpoint: str) -> None:
        self._srtt.pop(endpoint, None)
        self._rttvar.pop(endpoint, None)
