# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from leeward.cache.freshness import StoredResponse
from leeward.cache.store import (
    CacheStats,
    CacheStore,
    CorruptBodyError,
    SingleFlight,
    cache_key,
    tool_key,
)
from leeward.vocab import Volatility

NOW = 1_789_000_000.0
DOC = "https://en.wikipedia.org/wiki/Foo"


@pytest.fixture
def store(tmp_path: Path) -> Iterator[CacheStore]:
    with CacheStore(tmp_path / "cache") as opened:
        yield opened


def put(
    store: CacheStore,
    *,
    key: str = "k",
    url: str = DOC,
    body: bytes = b"hello",
    volatility: Volatility = Volatility.STATIC,
    now: float = NOW,
    pinned: bool = False,
    headers: tuple[tuple[str, str], ...] = (("Cache-Control", "max-age=60"),),
    vary: tuple[tuple[str, str], ...] = (),
) -> StoredResponse:
    return store.put(
        key=key,
        url=url,
        method="GET",
        endpoint=url,
        status=200,
        headers=headers,
        body=body,
        requested_at=now,
        received_at=now,
        volatility=volatility,
        vary=vary,
        now=now,
        pinned=pinned,
    )


def test_a_stored_response_comes_back_as_it_went_in(store: CacheStore) -> None:
    stored = put(store, vary=(("accept-language", "en"),))
    found = store.get("k", NOW)
    assert found is not None
    assert found == stored
    assert store.read_body(found) == b"hello"
    assert found.header("cache-control") == "max-age=60"
    assert found.volatility is Volatility.STATIC


def test_nothing_is_found_for_a_key_that_was_never_stored(store: CacheStore) -> None:
    assert store.get("missing") is None


def test_one_body_is_kept_for_two_entries_that_hold_the_same_bytes(store: CacheStore) -> None:
    first = put(store, key="a", url=f"{DOC}/a")
    second = put(store, key="b", url=f"{DOC}/b")
    assert first.body_sha256 == second.body_sha256
    assert len(list(store.bodies.rglob("*"))) == 2  # one directory, one file
    store.delete("a")
    assert store.read_body(second) == b"hello"
    store.delete("b")
    assert store.body_path(second.body_sha256).exists() is False


def test_a_body_that_does_not_match_its_hash_is_refused_and_dropped(store: CacheStore) -> None:
    stored = put(store)
    store.body_path(stored.body_sha256).write_bytes(b"something else entirely")
    with pytest.raises(CorruptBodyError, match="does not match its hash"):
        store.read_body(stored)
    assert store.get("k") is None


def test_a_body_that_has_gone_missing_says_so(store: CacheStore) -> None:
    stored = put(store)
    store.body_path(stored.body_sha256).unlink()
    with pytest.raises(CorruptBodyError, match="is gone"):
        store.read_body(stored)


def test_a_revalidation_refreshes_the_entry_without_rewriting_the_body(store: CacheStore) -> None:
    stored = put(store, headers=(("Cache-Control", "max-age=60"), ("ETag", '"v1"')))
    refreshed = store.refresh(
        "k",
        {"Cache-Control": "max-age=600", "Date": "Wed, 10 Sep 2026 00:00:00 GMT"},
        requested_at=NOW + 100,
        received_at=NOW + 101,
    )
    assert refreshed is not None
    assert refreshed.body_sha256 == stored.body_sha256
    assert refreshed.header("cache-control") == "max-age=600"
    assert refreshed.header("etag") == '"v1"'
    assert refreshed.received_at == NOW + 101
    assert store.read_body(refreshed) == b"hello"
    assert store.refresh("gone", {}, requested_at=NOW, received_at=NOW) is None


def test_eviction_takes_the_least_recently_used_and_pinned_entries_last(
    store: CacheStore,
) -> None:
    for index in range(4):
        put(store, key=f"k{index}", url=f"{DOC}/{index}", body=b"x" * 100, now=NOW + index)
    put(store, key="pinned", url=f"{DOC}/pinned", body=b"y" * 100, now=NOW, pinned=True)
    store.get("k3", NOW + 100)

    evicted = store.evict(byte_cap=250)

    # Five entries of 100 bytes against a 250 byte cap: three have to go.
    assert [item.key for item in evicted] == ["k0", "k1", "k2"]
    assert all(not item.pinned for item in evicted)
    assert store.stats().bytes <= 250
    assert store.get("pinned") is not None
    assert store.get("k3") is not None


def test_eviction_reaches_pinned_entries_only_when_it_must(store: CacheStore) -> None:
    put(store, key="pinned", body=b"z" * 100, pinned=True)
    put(store, key="loose", url=f"{DOC}/loose", body=b"w" * 100)
    evicted = store.evict(byte_cap=50)
    assert [(item.key, item.pinned) for item in evicted] == [("loose", False), ("pinned", True)]
    assert store.stats() == CacheStats(entries=0, bytes=0, pinned=0, oldest_stored_at=None)


def test_the_cache_reports_what_it_holds(store: CacheStore) -> None:
    put(store, key="a", body=b"x" * 10, now=NOW)
    put(store, key="b", url=f"{DOC}/b", body=b"y" * 20, now=NOW + 5, pinned=True)
    stats = store.stats()
    assert (stats.entries, stats.bytes, stats.pinned, stats.oldest_stored_at) == (2, 30, 1, NOW)
    assert [entry.key for entry in store.entries()] == ["b", "a"]


def test_a_key_covers_the_method_the_url_and_the_headers_a_rule_varies_on() -> None:
    plain = cache_key("GET", DOC)
    assert plain == cache_key("get", DOC)
    assert plain != cache_key("HEAD", DOC)
    assert plain != cache_key("GET", f"{DOC}?page=2")
    varied = cache_key("GET", DOC, (("Accept-Language", "en"), ("Authorization", "Bearer x")))
    assert varied == cache_key(
        "GET", DOC, (("authorization", "Bearer x"), ("accept-language", "en"))
    )
    assert varied != cache_key(
        "GET", DOC, (("Accept-Language", "fr"), ("Authorization", "Bearer x"))
    )


def test_a_tool_key_does_not_depend_on_how_the_arguments_were_written() -> None:
    first = tool_key("notes", "search", {"query": "blackout", "limit": 5})
    assert first == tool_key("notes", "search", {"limit": 5, "query": "blackout"})
    assert first != tool_key("notes", "search", {"query": "blackout", "limit": 6})
    assert first != tool_key("notes", "lookup", {"query": "blackout", "limit": 5})


async def test_concurrent_callers_collapse_into_one_flight() -> None:
    flight: SingleFlight[str] = SingleFlight()
    calls = 0
    started = asyncio.Event()
    release = asyncio.Event()

    async def work() -> str:
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return "from the origin"

    first = asyncio.create_task(flight.run("key", work))
    await started.wait()
    joiners = [asyncio.create_task(flight.run("key", work)) for _ in range(4)]
    await asyncio.sleep(0)
    release.set()
    results = await asyncio.gather(first, *joiners)

    assert calls == 1
    assert [value for value, _joined in results] == ["from the origin"] * 5
    assert [joined for _value, joined in results] == [False, True, True, True, True]
    assert not flight.in_flight("key")


async def test_a_flight_that_fails_fails_everyone_waiting_on_it() -> None:
    flight: SingleFlight[str] = SingleFlight()
    started = asyncio.Event()
    release = asyncio.Event()

    async def failing() -> str:
        started.set()
        await release.wait()
        raise RuntimeError("the origin refused")

    first = asyncio.create_task(flight.run("key", failing))
    await started.wait()
    joiner = asyncio.create_task(flight.run("key", failing))
    await asyncio.sleep(0)
    release.set()
    outcomes = await asyncio.gather(first, joiner, return_exceptions=True)

    assert all(isinstance(outcome, RuntimeError) for outcome in outcomes)
    assert not flight.in_flight("key")


async def test_a_later_call_starts_a_new_flight() -> None:
    flight: SingleFlight[int] = SingleFlight()
    calls = 0

    async def work() -> int:
        nonlocal calls
        calls += 1
        return calls

    assert await flight.run("key", work) == (1, False)
    assert await flight.run("key", work) == (2, False)


def test_a_stored_body_is_verified_by_its_own_hash(store: CacheStore) -> None:
    stored = put(store, body=b"a body worth checking")
    assert stored.body_sha256 == hashlib.sha256(b"a body worth checking").hexdigest()
