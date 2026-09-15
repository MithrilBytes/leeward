# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

from leeward.config import DEFAULT_REDACT_HEADERS
from leeward.events import (
    RECORDED_BODY_LIMIT,
    EventFields,
    EventKind,
    EventLog,
    LiveServedStaleError,
    RunRef,
    follow,
    read_events,
    redact_url,
    rfc3339,
)
from leeward.templates import template_set_sha256
from leeward.vocab import RunResolution
from tests.support import assert_valid

REDACT = frozenset(DEFAULT_REDACT_HEADERS)
RUN = RunRef("run-1", RunResolution.HEADER)
MOMENT = 1_789_000_000.0

CALL: EventFields = {
    "surface": "fetch",
    "endpoint": "https://en.wikipedia.org/wiki/Foo",
    "method": "GET",
    "volatility": "static",
    "rule_index": 0,
    "outcome": "STALE",
    "advice": "PROCEED_WITH_CAUTION",
    "failure_class": "DNS_FAILURE",
    "disposition": "TRANSIENT",
    "attempts": 1,
    "attempt_latencies_ms": [2],
    "total_latency_ms": 3,
    "cache": {"hit": True, "age_s": 120},
    "deadline": {"soft_s": 5, "hard_s": 30, "hit": "none"},
}


def test_a_call_event_is_valid_and_carries_versioning(tmp_path: Path) -> None:
    log = EventLog(tmp_path, REDACT, clock=lambda: MOMENT)
    event = log.emit("call", RUN, CALL)
    assert_valid("event", event)
    assert event["template_set_sha256"] == template_set_sha256()
    written = (tmp_path / f"{rfc3339(MOMENT)[:10]}.jsonl").read_text().splitlines()
    assert [json.loads(line) for line in written] == [event]


@pytest.mark.parametrize(
    ("kind", "fields"),
    [
        (
            "breaker",
            {
                "endpoint": "notes/threat_intel_lookup",
                "breaker": {"scope": "endpoint", "from_state": "CLOSED", "to_state": "OPEN"},
            },
        ),
        ("warning", {"message": "cache_unavailable_in_tunnel", "endpoint": "https://x.example/"}),
        ("startup", {"message": "listening on 127.0.0.1:8787"}),
        ("warm", {"warm": {"corpus": "refs", "trigger": "cli", "fetched": 11, "bytes": 3_100_000}}),
        ("tools_refresh", {"endpoint": "notes", "message": "tools/list refreshed"}),
        ("chaos", {"endpoint": "*/status*", "failure_class": "CONNECT_TIMEOUT", "injected": True}),
        (
            "attempt",
            {
                "endpoint": "https://x.example/slow",
                "attempts": 2,
                "hedge": True,
                "failure_class": "WEDGED",
            },
        ),
    ],
)
def test_every_kind_of_event_validates(
    tmp_path: Path, kind: EventKind, fields: EventFields
) -> None:
    assert_valid("event", EventLog(tmp_path, REDACT).emit(kind, RunRef.internal("test"), fields))


def test_a_live_endpoint_is_never_recorded_as_served_stale(tmp_path: Path) -> None:
    log = EventLog(tmp_path, REDACT)
    with pytest.raises(LiveServedStaleError):
        log.emit("call", RUN, {**CALL, "volatility": "live"})
    assert list(read_events(tmp_path)) == []


def test_credential_headers_are_stripped_even_when_recording_bodies(tmp_path: Path) -> None:
    log = EventLog(tmp_path, REDACT, record_bodies=True)
    secret = "Bearer never-in-the-log"
    event = log.emit(
        "call",
        RUN,
        {
            **CALL,
            "debug": {
                "url": "https://user:pw@api.example.com/p?api_key=never-in-the-log&q=blackout",
                "request_headers": {
                    "Authorization": secret,
                    "Accept": "text/html",
                    "COOKIE": "a=b",
                },
                "response_headers": {"X-Api-Key": secret, "Proxy-Authorization": secret},
                "response_body": "x" * (RECORDED_BODY_LIMIT + 1),
            },
        },
    )
    assert_valid("event", event)
    log.close()
    text = next(tmp_path.glob("*.jsonl")).read_text()
    assert "never-in-the-log" not in text
    assert "pw@" not in text
    debug = json.loads(text)["debug"]
    assert debug["request_headers"] == {"Accept": "text/html"}
    assert debug["response_headers"] == {}
    assert debug["truncated"] is True


def test_debug_detail_is_dropped_unless_recording_is_on(tmp_path: Path) -> None:
    event = EventLog(tmp_path, REDACT).emit("call", RUN, {**CALL, "debug": {"url": "https://x/"}})
    assert "debug" not in event


def test_urls_lose_user_info_and_secret_query_values() -> None:
    url = "https://user:pw@api.example.com:8443/p?token=abc&q=blackout"
    assert redact_url(url) == "https://api.example.com:8443/p?token=redacted&q=blackout"


def test_reading_skips_a_torn_last_line_and_filters_by_run(tmp_path: Path) -> None:
    log = EventLog(tmp_path, REDACT, clock=lambda: MOMENT)
    log.emit("call", RUN, CALL)
    log.emit("call", RunRef("run-2", RunResolution.CONNECTION), CALL)
    log.emit("call", RUN, CALL)
    log.close()
    path = next(tmp_path.glob("*.jsonl"))
    with path.open("a") as handle:
        handle.write('{"ts": "2026-09-')
    assert len(list(read_events(tmp_path))) == 3
    assert len(list(read_events(tmp_path, run="run-1"))) == 2


def test_reading_since_a_moment_leaves_out_earlier_events(tmp_path: Path) -> None:
    moments = iter([MOMENT, MOMENT + 60, MOMENT + 120])
    log = EventLog(tmp_path, REDACT, clock=lambda: next(moments))
    for _ in range(3):
        log.emit("startup", RUN, {"message": "tick"})
    since = datetime.datetime.fromtimestamp(MOMENT + 30, tz=datetime.UTC)
    assert len(list(read_events(tmp_path, since=since))) == 2


def test_following_yields_only_events_appended_after_it_starts(tmp_path: Path) -> None:
    log = EventLog(tmp_path, REDACT)
    log.emit("startup", RUN, {"message": "before"})
    polls: list[float] = []

    def sleep(seconds: float) -> None:
        polls.append(seconds)
        if len(polls) == 1:
            log.emit("warning", RUN, {"message": "after"})

    stream = follow(tmp_path, poll_s=0, stop=lambda: len(polls) >= 2, sleep=sleep)
    assert [event["message"] for event in stream] == ["after"]
