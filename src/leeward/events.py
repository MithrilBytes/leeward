# SPDX-License-Identifier: Apache-2.0
"""The event log: one JSON line per call, per attempt, and per change of state.

Every number leeward reports is computed from this log, so it has to be complete
and it has to be safe to hand to someone else. Bodies stay out unless recording is
switched on for debugging, and credential headers are removed unconditionally,
recording or not.

Each line reaches the file in one write to a descriptor opened with O_APPEND. POSIX
specifies that such a write moves to the end of the file with no intervening
modification (IEEE Std 1003.1-2017, write()), so the proxy and a CLI command
appending at the same moment cannot interleave inside a line.
"""

from __future__ import annotations

import contextlib
import datetime
import json
import os
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypedDict, cast
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from leeward import __version__
from leeward.config import SECRET_NAME
from leeward.templates import template_set_sha256
from leeward.vocab import Outcome, RunResolution, Volatility

EventKind = Literal[
    "call", "attempt", "breaker", "budget", "warm", "tools_refresh", "chaos", "startup", "warning"
]
RECORDED_BODY_LIMIT = 64 * 1024
FOLLOW_READ_LIMIT = 8 * 1024 * 1024


class LiveServedStaleError(RuntimeError):
    """A live endpoint was about to be recorded as served stale, which must never happen."""


@dataclass(frozen=True, slots=True)
class RunRef:
    id: str
    resolved_by: RunResolution

    @classmethod
    def cli(cls) -> RunRef:
        return cls(f"cli-{uuid.uuid4().hex[:12]}", RunResolution.CLI)

    @classmethod
    def internal(cls, purpose: str) -> RunRef:
        return cls(f"internal-{purpose}", RunResolution.INTERNAL)


class DeadlineInfo(TypedDict, total=False):
    soft_s: float
    hard_s: float
    hit: Literal["none", "soft", "hard"]


class CacheInfo(TypedDict, total=False):
    hit: bool
    age_s: int | None
    revalidated: bool | None
    single_flight_joined: bool | None
    withheld: str | None
    bytes_served: int | None
    pinned: bool | None


class BudgetAfter(TypedDict, total=False):
    retry_attempts_remaining: int
    retry_seconds_remaining: float
    endpoint_attempts_remaining: int


class BreakerChange(TypedDict, total=False):
    scope: Literal["endpoint", "host"]
    from_state: str | None
    to_state: str
    opened_by_class: str | None


class TokenInfo(TypedDict, total=False):
    prompt: int
    completion: int
    spent_on_retries: int


class WarmInfo(TypedDict, total=False):
    corpus: str
    trigger: Literal["cli", "schedule", "degradation", "link_prefetch"]
    fetched: int
    already_fresh: int
    failed: int
    bytes: int
    robots_skipped: bool
    dry_run: bool


class DebugInfo(TypedDict, total=False):
    url: str
    request_headers: dict[str, str]
    response_headers: dict[str, str]
    request_body: str
    response_body: str
    truncated: bool


class EventFields(TypedDict, total=False):
    surface: str
    endpoint: str
    method: str | None
    volatility: str | None
    rule_index: int | None
    outcome: str | None
    advice: str | None
    failure_class: str | None
    underlying_class: str | None
    failure_scope: str | None
    disposition: str | None
    disposition_reason: str | None
    injected: bool
    hedge: bool
    attempts: int | None
    attempt_latencies_ms: list[int] | None
    total_latency_ms: int | None
    deadline: DeadlineInfo | None
    cache: CacheInfo | None
    budget_after: BudgetAfter | None
    breaker: BreakerChange | None
    tokens: TokenInfo | None
    warm: WarmInfo | None
    message: str | None
    debug: DebugInfo | None


def rfc3339(epoch_s: float) -> str:
    """A UTC date-time in RFC 3339 form with millisecond precision."""
    moment = datetime.datetime.fromtimestamp(epoch_s, tz=datetime.UTC)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def strip_headers(headers: Mapping[str, str], redacted: frozenset[str]) -> dict[str, str]:
    return {name: value for name, value in headers.items() if name.lower() not in redacted}


def redact_url(url: str) -> str:
    """The URL without user info, and with secret-looking query values replaced."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    host = f"[{host}]" if ":" in host else host
    netloc = f"{host}:{parts.port}" if parts.port else host
    query = urlencode(
        [
            (key, "redacted" if SECRET_NAME.search(key) else value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
        ]
    )
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


DEFAULT_KEEP_DAYS = 14
DAY_SECONDS = 86_400


class EventLog:
    """Appends events under a directory, one file per UTC day."""

    def __init__(
        self,
        directory: Path,
        redact: frozenset[str],
        *,
        record_bodies: bool = False,
        keep_days: int = DEFAULT_KEEP_DAYS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.directory = directory
        self.record_bodies = record_bodies
        self.keep_days = keep_days
        self._redact = redact
        self._clock = clock
        self._fd: int | None = None
        self._fd_day: str | None = None
        self._observers: list[Callable[[Mapping[str, object]], None]] = []

    def observe(self, observer: Callable[[Mapping[str, object]], None]) -> None:
        """Call `observer` with every event after it is written."""
        self._observers.append(observer)

    def emit(
        self, kind: EventKind, run: RunRef, fields: EventFields | None = None
    ) -> dict[str, object]:
        body: dict[str, object] = dict(fields or {})
        if body.get("outcome") == Outcome.STALE and body.get("volatility") == Volatility.LIVE:
            raise LiveServedStaleError(
                f"refusing to record a stale serve of live endpoint {body.get('endpoint')}"
            )
        debug = body.pop("debug", None)
        if debug is not None and self.record_bodies:
            body["debug"] = self._clean_debug(cast("DebugInfo", debug))
        now = self._clock()
        event: dict[str, object] = {
            "ts": rfc3339(now),
            "event": kind,
            "run": {"id": run.id, "resolved_by": str(run.resolved_by)},
            **{key: value for key, value in body.items() if value is not None},
            "template_set_sha256": template_set_sha256(),
            "leeward_version": __version__,
        }
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
        self._append(now, line.encode("utf-8"))
        for observer in self._observers:
            observer(event)
        return event

    def _clean_debug(self, debug: DebugInfo) -> DebugInfo:
        cleaned: DebugInfo = {}
        if "url" in debug:
            cleaned["url"] = redact_url(debug["url"])
        if "request_headers" in debug:
            cleaned["request_headers"] = strip_headers(debug["request_headers"], self._redact)
        if "response_headers" in debug:
            cleaned["response_headers"] = strip_headers(debug["response_headers"], self._redact)
        request_body = debug.get("request_body", "")
        response_body = debug.get("response_body", "")
        if request_body:
            cleaned["request_body"] = request_body[:RECORDED_BODY_LIMIT]
        if response_body:
            cleaned["response_body"] = response_body[:RECORDED_BODY_LIMIT]
        cleaned["truncated"] = max(len(request_body), len(response_body)) > RECORDED_BODY_LIMIT
        return cleaned

    def _append(self, now: float, data: bytes) -> None:
        day = rfc3339(now)[:10]
        if self._fd is None or day != self._fd_day:
            self.close()
            self.directory.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
            self._fd = os.open(self.directory / f"{day}.jsonl", flags, 0o600)
            self._fd_day = day
            self.prune(now)
        view = memoryview(data)
        while view:
            view = view[os.write(self._fd, view) :]

    def prune(self, now: float | None = None) -> list[Path]:
        """Remove day files older than the window, as the log rolls over to a new one.

        The log is the record of what leeward did, and a record nobody deletes becomes a
        disk that fills. Rotation is the natural moment: it happens once a day, off the
        path of any call, and the file being written is never a candidate.
        """
        moment = now if now is not None else self._clock()
        oldest = rfc3339(moment - self.keep_days * DAY_SECONDS)[:10]
        removed: list[Path] = []
        for path in event_files(self.directory):
            if path.stem >= oldest or path.stem == self._fd_day:
                continue
            with contextlib.suppress(OSError):
                path.unlink()
                removed.append(path)
        return removed

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
            self._fd_day = None


def event_files(directory: Path) -> list[Path]:
    return sorted(directory.glob("*.jsonl")) if directory.is_dir() else []


def _parse(line: bytes | str) -> dict[str, object] | None:
    """One event, or None for a blank or torn line such as a crash leaves at the end."""
    try:
        value: object = json.loads(line)
    except json.JSONDecodeError:
        return None
    return cast("dict[str, object]", value) if isinstance(value, dict) else None


def run_id(event: Mapping[str, object]) -> str | None:
    run = event.get("run")
    if isinstance(run, dict):
        value = cast("dict[str, object]", run).get("id")
        return value if isinstance(value, str) else None
    return None


def read_events(
    directory: Path, *, run: str | None = None, since: datetime.datetime | None = None
) -> Iterator[dict[str, object]]:
    """Events in order, streamed line by line so memory stays flat on a long log."""
    since_ts = rfc3339(since.timestamp()) if since is not None else None
    for path in event_files(directory):
        if since_ts is not None and path.stem < since_ts[:10]:
            continue
        with path.open("rb") as handle:
            for line in handle:
                event = _parse(line)
                if event is None or (run is not None and run_id(event) != run):
                    continue
                if since_ts is not None and str(event.get("ts", "")) < since_ts:
                    continue
                yield event


def follow(
    directory: Path,
    *,
    run: str | None = None,
    poll_s: float = 0.5,
    stop: Callable[[], bool] = lambda: False,
    sleep: Callable[[float], None] = time.sleep,
) -> Iterator[dict[str, object]]:
    """Events appended after this starts, across day files, until `stop` returns true."""
    offsets = {path: path.stat().st_size for path in event_files(directory)}
    while not stop():
        for path in event_files(directory):
            start = offsets.get(path, 0)
            size = path.stat().st_size
            if size <= start:
                continue
            with path.open("rb") as handle:
                handle.seek(start)
                chunk = handle.read(min(size - start, FOLLOW_READ_LIMIT))
            complete, newline, _partial = chunk.rpartition(b"\n")
            if not newline:
                continue
            offsets[path] = start + len(complete) + 1
            for line in complete.split(b"\n"):
                event = _parse(line)
                if event is not None and (run is None or run_id(event) == run):
                    yield event
        sleep(poll_s)
