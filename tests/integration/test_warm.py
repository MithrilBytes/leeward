# SPDX-License-Identifier: Apache-2.0
"""The warmer against a real origin: paced, capped, resumable, and honest about robots."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from fakes.origin import FakeOrigin, Reply, constant, document

from leeward.cache.store import cache_key
from leeward.config import parse_config
from leeward.events import read_events
from leeward.proxy import Proxy
from leeward.vocab import Volatility
from leeward.warm import Warmer, warm_all
from tests.support import assert_valid

CONFIG = """
profile: dev
data_dir: {data}
rules:
  - name: articles
    match: {{url: "*/wiki/*"}}
    class: static
    stale_on_error: 30d
corpora:
  - name: blackout-refs
    type: url_list
    urls:
      - {origin}/wiki/Blackout
      - {origin}/wiki/Grid
    rps: 50
  - name: docs
    type: sitemap
    url: {origin}/sitemap.xml
    rps: 50
    respect_robots: true
"""

SITEMAP = b"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>{origin}/wiki/Sitemapped</loc></url>
  <url><loc>{origin}/private/secret</loc></url>
</urlset>
"""

ROBOTS = b"User-agent: *\nDisallow: /private/\n"


@pytest.fixture
async def origin() -> AsyncIterator[FakeOrigin]:
    async with FakeOrigin() as running:
        running.route("/wiki/*", document(b"<h1>an article</h1>", cache_control="max-age=600"))
        running.route("/private/*", document(b"<h1>not for robots</h1>"))
        running.route(
            "/sitemap.xml",
            constant(
                Reply(
                    status=200,
                    headers={"Content-Type": "application/xml"},
                    body=SITEMAP.replace(b"{origin}", running.base_url.encode()),
                )
            ),
        )
        running.route(
            "/robots.txt",
            constant(Reply(status=200, headers={"Content-Type": "text/plain"}, body=ROBOTS)),
        )
        yield running


@pytest.fixture
async def proxy(tmp_path: Path, origin: FakeOrigin) -> AsyncIterator[Proxy]:
    loaded = parse_config(
        CONFIG.format(data=tmp_path / "data", origin=origin.base_url), tmp_path / "leeward.yaml"
    )
    made = Proxy(loaded)
    yield made
    await made.aclose()


async def test_a_warm_run_fetches_a_list_and_leaves_it_pinned(
    proxy: Proxy, origin: FakeOrigin
) -> None:
    [result] = await warm_all(proxy, ["blackout-refs"])
    assert (result.fetched, result.already_fresh, result.failed) == (2, 0, 0)
    assert result.bytes == 2 * len(b"<h1>an article</h1>")
    # A list an operator wrote is fetched without consulting robots.txt, and says so.
    assert result.robots_skipped is True
    assert origin.hits["/wiki/Blackout"] == 1

    stats = proxy.cache.stats()
    assert (stats.entries, stats.pinned) == (2, 2)


async def test_warming_twice_costs_one_lookup_each_and_no_fetches(
    proxy: Proxy, origin: FakeOrigin
) -> None:
    await warm_all(proxy, ["blackout-refs"])
    [again] = await warm_all(proxy, ["blackout-refs"])
    assert (again.fetched, again.already_fresh) == (0, 2)
    assert origin.hits["/wiki/Blackout"] == 1


async def test_a_dry_run_says_what_it_would_do_and_touches_nothing(
    proxy: Proxy, origin: FakeOrigin
) -> None:
    accepted = origin.accepted
    [planned] = await warm_all(proxy, ["blackout-refs"], dry_run=True)
    assert (planned.fetched, planned.already_fresh, planned.dry_run) == (2, 0, True)
    assert origin.accepted == accepted
    assert proxy.cache.stats().entries == 0


async def test_a_sitemap_corpus_reads_the_map_and_obeys_robots(
    proxy: Proxy, origin: FakeOrigin
) -> None:
    [result] = await warm_all(proxy, ["docs"])
    assert result.robots_skipped is False
    assert result.fetched == 1
    assert origin.hits["/wiki/Sitemapped"] == 1
    assert "/private/secret" not in origin.hits
    assert origin.hits["/robots.txt"] == 1


async def test_a_byte_cap_stops_the_run(proxy: Proxy, origin: FakeOrigin) -> None:
    corpus = next(item for item in proxy.config.corpora if item.name == "blackout-refs")
    capped = corpus.model_copy(update={"max_bytes": 1, "concurrency": 1})
    result = await Warmer(proxy).warm(capped)
    assert result.stopped_at_cap is True
    assert result.fetched == 1


async def test_pacing_holds_a_host_to_its_rate(proxy: Proxy) -> None:
    corpus = next(item for item in proxy.config.corpora if item.name == "blackout-refs")
    slow = corpus.model_copy(update={"rps": 4.0, "concurrency": 2})
    started = time.monotonic()
    result = await Warmer(proxy).warm(slow)
    elapsed = time.monotonic() - started
    assert result.fetched == 2
    # Two requests to one host at four a second: the second waits a quarter of a second.
    assert elapsed >= 0.25


async def test_an_unsupported_corpus_says_so_rather_than_failing(tmp_path: Path) -> None:
    text = """
profile: dev
data_dir: {data}
corpora:
  - name: offline
    type: zim
    kiwix_url: http://127.0.0.1:8080
    maps_host: en.wikipedia.org
"""
    loaded = parse_config(text.format(data=tmp_path / "data"), tmp_path / "leeward.yaml")
    proxy = Proxy(loaded)
    [result] = await warm_all(proxy, [])
    await proxy.aclose()
    assert result.unsupported == "zim"
    assert (result.fetched, result.failed) == (0, 0)


async def test_every_warm_run_is_an_event(proxy: Proxy, tmp_path: Path) -> None:
    await warm_all(proxy, ["blackout-refs"])
    proxy.events.close()
    events = [
        event for event in read_events(tmp_path / "data" / "events") if event["event"] == "warm"
    ]
    assert len(events) == 1
    assert_valid("event", events[0])
    warm = events[0]["warm"]
    assert isinstance(warm, dict)
    assert warm["corpus"] == "blackout-refs"
    assert warm["trigger"] == "cli"
    assert warm["fetched"] == 2


async def test_asking_for_a_corpus_that_is_not_configured_names_it(proxy: Proxy) -> None:
    with pytest.raises(KeyError, match="nothing-here"):
        await warm_all(proxy, ["nothing-here"])


DIRECTORY = """
profile: dev
data_dir: {data}
rules:
  - name: docs
    match: {{url: "*/docs/*"}}
    class: static
    stale_on_error: 30d
corpora:
  - name: handbook
    type: directory
    path: {path}
    maps_to: https://docs.example.test/docs
"""


async def test_a_directory_corpus_puts_local_files_in_the_cache(tmp_path: Path) -> None:
    root = tmp_path / "handbook"
    (root / "runbooks").mkdir(parents=True)
    (root / "index.html").write_text("<h1>the handbook</h1>", encoding="utf-8")
    (root / "runbooks" / "blackout.md").write_text("# what to do", encoding="utf-8")
    (root / "runbooks" / "notes.bin").write_bytes(b"\x00\x01")

    loaded = parse_config(
        DIRECTORY.format(data=tmp_path / "data", path=root), tmp_path / "leeward.yaml"
    )
    proxy = Proxy(loaded)
    [result] = await warm_all(proxy, ["handbook"])

    assert (result.fetched, result.failed) == (3, 0)
    entry = proxy.cache.get(
        cache_key("GET", "https://docs.example.test/docs/runbooks/blackout.md"), proxy.clock()
    )
    assert entry is not None
    assert proxy.cache.read_body(entry) == b"# what to do"
    assert entry.header("Content-Type") == "text/markdown"
    assert entry.pinned is True
    assert entry.volatility is Volatility.STATIC

    # Nothing changed on disk, so a second run stores nothing and says so.
    [again] = await warm_all(proxy, ["handbook"])
    assert (again.fetched, again.already_fresh) == (0, 3)

    # A changed file is stored again.
    (root / "index.html").write_text("<h1>the handbook, revised</h1>", encoding="utf-8")
    [revised] = await warm_all(proxy, ["handbook"])
    await proxy.aclose()
    assert (revised.fetched, revised.already_fresh) == (1, 2)


async def test_a_directory_corpus_stays_inside_the_directory(tmp_path: Path) -> None:
    root = tmp_path / "handbook"
    root.mkdir()
    (root / "inside.txt").write_text("in", encoding="utf-8")
    outside = tmp_path / "secrets.txt"
    outside.write_text("out", encoding="utf-8")
    (root / "escape.txt").symlink_to(outside)

    loaded = parse_config(
        DIRECTORY.format(data=tmp_path / "data", path=root), tmp_path / "leeward.yaml"
    )
    proxy = Proxy(loaded)
    [result] = await warm_all(proxy, ["handbook"])
    escaped = proxy.cache.get(cache_key("GET", "https://docs.example.test/docs/escape.txt"), 0.0)
    await proxy.aclose()

    assert result.fetched == 1
    assert escaped is None
