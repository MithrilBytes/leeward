# SPDX-License-Identifier: Apache-2.0
"""Cron reading, and the two things that start a warm run without anyone asking."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path

import pytest
from fakes.origin import FakeOrigin, document

from leeward.config import parse_config
from leeward.proxy import EndpointHealth, Proxy
from leeward.schedule import DEGRADATION_FLOOR_S, Scheduler, cron_matches, wanted
from leeward.vocab import Outcome, Volatility

CONFIG = """
profile: dev
data_dir: {data}
corpora:
  - name: nightly
    type: url_list
    urls: [{origin}/wiki/Nightly]
    schedule: "0 3 * * *"
    rps: 50
  - name: when-things-break
    type: url_list
    urls: [{origin}/wiki/Reference]
    warm_on_degradation: true
    rps: 50
  - name: on-demand
    type: url_list
    urls: [{origin}/wiki/Other]
    rps: 50
"""


@pytest.mark.parametrize(
    ("expression", "moment", "expected"),
    [
        ("* * * * *", datetime(2026, 9, 17, 3, 0), True),
        ("0 3 * * *", datetime(2026, 9, 17, 3, 0), True),
        ("0 3 * * *", datetime(2026, 9, 17, 3, 1), False),
        ("0 3 * * *", datetime(2026, 9, 17, 4, 0), False),
        ("*/15 * * * *", datetime(2026, 9, 17, 9, 30), True),
        ("*/15 * * * *", datetime(2026, 9, 17, 9, 31), False),
        ("0 9-17 * * 1-5", datetime(2026, 9, 17, 12, 0), True),  # a Thursday
        ("0 9-17 * * 1-5", datetime(2026, 9, 19, 12, 0), False),  # a Saturday
        ("0 0 1,15 * *", datetime(2026, 9, 15, 0, 0), True),
        ("0 0 1,15 * *", datetime(2026, 9, 16, 0, 0), False),
        ("0 0 * * 0", datetime(2026, 9, 20, 0, 0), True),  # Sunday is 0
        ("nonsense", datetime(2026, 9, 17, 3, 0), False),
        ("0 3 * *", datetime(2026, 9, 17, 3, 0), False),
        ("*/0 * * * *", datetime(2026, 9, 17, 3, 0), False),
    ],
)
def test_cron_expressions_are_read_the_way_cron_reads_them(
    expression: str, moment: datetime, expected: bool
) -> None:
    assert cron_matches(expression, moment) is expected


@pytest.fixture
async def origin() -> AsyncIterator[FakeOrigin]:
    async with FakeOrigin() as running:
        # Cacheable for ten minutes, so a second run inside that window finds it fresh
        # rather than revalidating it.
        running.route("/wiki/*", document(b"<h1>a reference</h1>", cache_control="max-age=600"))
        yield running


@pytest.fixture
async def proxy(tmp_path: Path, origin: FakeOrigin) -> AsyncIterator[Proxy]:
    loaded = parse_config(
        CONFIG.format(data=tmp_path / "data", origin=origin.base_url), tmp_path / "leeward.yaml"
    )
    made = Proxy(loaded)
    yield made
    await made.aclose()


def test_a_configuration_with_no_triggers_starts_no_scheduler(proxy: Proxy) -> None:
    assert wanted(proxy.config.corpora) is True
    assert (
        wanted([corpus for corpus in proxy.config.corpora if corpus.name == "on-demand"]) is False
    )


async def test_a_schedule_fires_once_for_its_minute_however_often_we_look(
    proxy: Proxy, origin: FakeOrigin
) -> None:
    minutes = iter(
        [
            datetime(2026, 9, 17, 3, 0),
            datetime(2026, 9, 17, 3, 0),
            datetime(2026, 9, 17, 3, 1),
        ]
    )
    scheduler = Scheduler(proxy, now=lambda: next(minutes))

    assert [fired.corpus for fired in await scheduler.tick()] == ["nightly"]
    assert await scheduler.tick() == []
    assert await scheduler.tick() == []
    assert origin.hits["/wiki/Nightly"] == 1
    assert "/wiki/Other" not in origin.hits


async def test_degradation_warms_the_corpora_that_asked_for_it_and_then_waits(
    proxy: Proxy, origin: FakeOrigin
) -> None:
    quiet = Scheduler(proxy, now=lambda: datetime(2026, 9, 17, 12, 0))
    assert await quiet.tick() == []

    # Something the agent depends on has gone down.
    proxy.health["notes/search"] = EndpointHealth(
        endpoint="notes/search", volatility=Volatility.VOLATILE, last_outcome=Outcome.DOWN
    )
    now = [1000.0]
    scheduler = Scheduler(proxy, clock=lambda: now[0], now=lambda: datetime(2026, 9, 17, 12, 0))
    fired = await scheduler.tick()
    assert [(item.corpus, item.trigger) for item in fired] == [("when-things-break", "degradation")]
    assert origin.hits["/wiki/Reference"] == 1

    # Still degraded a minute later, and it does not run again.
    now[0] += 60.0
    assert await scheduler.tick() == []

    # Past the floor it may run again, and finds everything already fresh.
    now[0] += DEGRADATION_FLOOR_S
    again = await scheduler.tick()
    assert [item.corpus for item in again] == ["when-things-break"]
    assert again[0].result is not None
    assert again[0].result.already_fresh == 1
    assert origin.hits["/wiki/Reference"] == 1
