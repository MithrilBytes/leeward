# SPDX-License-Identifier: Apache-2.0
"""Filling the cache before it is needed.

Everything else in leeward answers a call that has already gone wrong. This is the one
part that runs while things are fine, on the theory that the cheapest way to survive an
outage is to have fetched the important things before it started.

A warm run is polite by construction: one host at a time at a rate the operator set, a
byte cap it will not cross, and robots.txt honoured for anything leeward discovered
itself. A list of URLs an operator wrote down is different, and leeward fetches it
without consulting robots.txt, saying so in the log rather than quietly either way.

It is resumable because it has nothing of its own to resume: anything already stored and
still fresh is left alone, so running it twice costs one cache lookup per URL.
"""

from __future__ import annotations

import asyncio
import mimetypes
import re
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Literal
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

from leeward import __version__
from leeward.cache.store import cache_key
from leeward.config import (
    Corpus,
    DirectoryCorpus,
    McpResourcesCorpus,
    SitemapCorpus,
    UrlListCorpus,
    ZimCorpus,
)
from leeward.events import EventFields, RunRef, WarmInfo
from leeward.policy import CallTarget, resolve
from leeward.proxy import HttpRequest, Proxy
from leeward.vocab import Outcome, Surface

Trigger = Literal["cli", "schedule", "degradation", "link_prefetch"]

MAX_SITEMAP_BYTES = 8 * 1024 * 1024
"""A sitemap larger than this is not one leeward is going to read in one piece."""

MAX_URLS = 50_000

KNOWN_TYPES = {
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".rst": "text/x-rst",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
    ".toml": "application/toml",
    ".jsonl": "application/jsonl",
}
"""Types a documentation directory is made of, named here rather than looked up.

The standard library's table differs between Python versions: 3.11 does not know
`.md` and 3.13 does, which is the sort of difference that shows up as a file served
as a download. text/markdown is RFC 7763.
"""
LOCATION = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
"""Sitemaps are read with a pattern rather than an XML parser on purpose: the only thing
needed from the document is its locations, and a parser would also read entity
declarations written by whoever served it.
https://www.sitemaps.org/protocol.html"""


@dataclass(frozen=True, slots=True)
class Plan:
    """What a warm run would do, before it does any of it."""

    corpus: str
    urls: tuple[str, ...]
    robots_skipped: bool = False
    unsupported: str = ""


@dataclass
class Result:
    """What it did."""

    corpus: str
    fetched: int = 0
    already_fresh: int = 0
    failed: int = 0
    bytes: int = 0
    robots_skipped: bool = False
    dry_run: bool = False
    stopped_at_cap: bool = False
    unsupported: str = ""
    failures: list[tuple[str, str]] = field(default_factory=list[tuple[str, str]])

    def as_event(self, trigger: Trigger) -> WarmInfo:
        return WarmInfo(
            corpus=self.corpus,
            trigger=trigger,
            fetched=self.fetched,
            already_fresh=self.already_fresh,
            failed=self.failed,
            bytes=self.bytes,
            robots_skipped=self.robots_skipped,
            dry_run=self.dry_run,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "corpus": self.corpus,
            "fetched": self.fetched,
            "already_fresh": self.already_fresh,
            "failed": self.failed,
            "bytes": self.bytes,
            "robots_skipped": self.robots_skipped,
            "dry_run": self.dry_run,
            "stopped_at_cap": self.stopped_at_cap,
            "unsupported": self.unsupported or None,
            "failures": [{"url": url, "reason": reason} for url, reason in self.failures],
        }


class Pace:
    """One host, one request at a time, no faster than the operator allowed."""

    def __init__(self, rps: float, clock: object = time.monotonic) -> None:
        self._gap = 1.0 / rps
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            delay = max(self._next - now, 0.0)
            self._next = max(now, self._next) + self._gap
        if delay > 0:
            await asyncio.sleep(delay)


class Warmer:
    """Runs corpora against the same proxy every other surface uses."""

    def __init__(self, proxy: Proxy, *, trigger: Trigger = "cli") -> None:
        self.proxy = proxy
        self.trigger: Trigger = trigger
        self.user_agent = proxy.config.warm.user_agent or f"leeward/{__version__}"
        self._pace: dict[str, Pace] = {}
        self._robots: dict[str, RobotFileParser | None] = {}

    def corpora(self, names: Sequence[str] = ()) -> list[Corpus]:
        """The corpora asked for, or all of them, in configuration order."""
        listed = self.proxy.config.corpora
        if not names:
            return list(listed)
        wanted = set(names)
        found = [corpus for corpus in listed if corpus.name in wanted]
        missing = wanted - {corpus.name for corpus in found}
        if missing:
            raise KeyError(", ".join(sorted(missing)))
        return found

    async def plan(self, corpus: Corpus, run: RunRef) -> Plan:
        """The URLs a corpus covers, without fetching any of them."""
        if isinstance(corpus, UrlListCorpus):
            # An operator wrote these down, so they are not leeward's to second guess,
            # and robots.txt does not speak to them. The log says it was not consulted.
            return Plan(corpus.name, self._listed(corpus), robots_skipped=True)
        if isinstance(corpus, SitemapCorpus):
            return await self._from_sitemap(corpus, run)
        if isinstance(corpus, DirectoryCorpus):
            return Plan(corpus.name, self._files(corpus), robots_skipped=True)
        kind = type(corpus).__name__.removesuffix("Corpus").lower()
        return Plan(corpus.name, (), unsupported=kind)

    def _listed(self, corpus: UrlListCorpus) -> tuple[str, ...]:
        urls = list(corpus.urls)
        if corpus.urls_file:
            path = Path(corpus.urls_file)
            if not path.is_absolute() and self.proxy.loaded.source is not None:
                path = self.proxy.loaded.source.parent / path
            text = path.read_text(encoding="utf-8") if path.exists() else ""
            urls += [
                line.strip()
                for line in text.splitlines()
                if line.strip() and not line.startswith("#")
            ]
        return tuple(dict.fromkeys(urls))[:MAX_URLS]

    def _files(self, corpus: DirectoryCorpus) -> tuple[str, ...]:
        """Local files, as the URLs they stand in for.

        A path that leaves the directory, by symlink or otherwise, is not part of the
        corpus: an operator named a directory, not the filesystem.
        """
        root = Path(corpus.path)
        if not root.is_absolute() and self.proxy.loaded.source is not None:
            root = self.proxy.loaded.source.parent / root
        root = root.resolve()
        base = corpus.maps_to.rstrip("/")
        found: list[str] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if not resolved.is_relative_to(root):
                continue
            found.append(f"{base}/{resolved.relative_to(root).as_posix()}")
            if len(found) >= MAX_URLS:
                break
        return tuple(found)

    async def _from_sitemap(self, corpus: SitemapCorpus, run: RunRef) -> Plan:
        found: list[str] = []
        seen: set[str] = set()
        queue = [corpus.url]
        while queue and len(found) < MAX_URLS:
            document = queue.pop(0)
            if document in seen:
                continue
            seen.add(document)
            body = await self._read(document, run)
            for location in LOCATION.findall(body)[:MAX_URLS]:
                if location.rstrip("/").endswith(".xml") and location not in seen:
                    queue.append(location)
                else:
                    found.append(location)
        allowed = [url for url in found if self._within(corpus, url)]
        if corpus.respect_robots:
            permitted: list[str] = []
            for url in allowed:
                if await self._robots_allow(url, run):
                    permitted.append(url)
            allowed = permitted
        return Plan(
            corpus.name, tuple(dict.fromkeys(allowed)), robots_skipped=not corpus.respect_robots
        )

    @staticmethod
    def _within(corpus: SitemapCorpus, url: str) -> bool:
        if not corpus.hosts:
            return urlsplit(url).netloc == urlsplit(corpus.url).netloc
        return urlsplit(url).netloc in set(corpus.hosts)

    async def _read(self, url: str, run: RunRef) -> str:
        served = await self.proxy.fetch(
            HttpRequest("GET", url, headers=(("User-Agent", self.user_agent),)),
            run,
            surface=Surface.CLI,
        )
        if served.outcome.outcome is Outcome.DOWN:
            return ""
        return served.body[:MAX_SITEMAP_BYTES].decode("utf-8", "replace")

    async def _robots_allow(self, url: str, run: RunRef) -> bool:
        origin = urlsplit(url)
        host = f"{origin.scheme}://{origin.netloc}"
        if host not in self._robots:
            text = await self._read(urljoin(host, "/robots.txt"), run)
            parser: RobotFileParser | None = None
            if text:
                parser = RobotFileParser()
                parser.parse(text.splitlines())
            self._robots[host] = parser
        rules = self._robots[host]
        return True if rules is None else rules.can_fetch(self.user_agent, url)

    async def warm(self, corpus: Corpus, *, dry_run: bool = False) -> Result:
        """One corpus, paced, capped, and recorded."""
        run = RunRef.internal(f"warm-{corpus.name}")
        plan = await self.plan(corpus, run)
        result = Result(
            corpus=corpus.name,
            robots_skipped=plan.robots_skipped,
            dry_run=dry_run,
            unsupported=plan.unsupported,
        )
        if plan.unsupported:
            self._record(result, run)
            return result
        if dry_run:
            for url in plan.urls:
                stored = self.proxy.cache.get(cache_key("GET", url), self.proxy.clock())
                if stored is not None:
                    result.already_fresh += 1
                else:
                    result.fetched += 1
            self._record(result, run)
            return result

        cap = corpus.max_bytes
        if isinstance(corpus, DirectoryCorpus):
            self._store_files(corpus, plan, result, cap)
            self._record(result, run)
            return result

        gate = asyncio.Semaphore(corpus.concurrency)
        stop = asyncio.Event()

        async def one(url: str) -> None:
            if stop.is_set():
                return
            async with gate:
                if stop.is_set():
                    return
                await self._pace_for(url, corpus.rps).wait()
                await self._fetch_one(url, run, result)
                if cap is not None and result.bytes >= cap:
                    result.stopped_at_cap = True
                    stop.set()

        await asyncio.gather(*(one(url) for url in plan.urls))
        self._record(result, run)
        return result

    def _store_files(
        self, corpus: DirectoryCorpus, plan: Plan, result: Result, cap: int | None
    ) -> None:
        """Put local files into the cache as though they had been fetched.

        Nothing here touches the network, so there is no pacing and no robots question.
        A file whose stored copy already matches it byte for byte is left alone, which
        is what makes this rerunnable against a directory that mostly has not changed.
        """
        root = Path(corpus.path)
        if not root.is_absolute() and self.proxy.loaded.source is not None:
            root = self.proxy.loaded.source.parent / root
        root = root.resolve()
        base = corpus.maps_to.rstrip("/")
        now = self.proxy.clock()
        for url in plan.urls:
            path = root / url.removeprefix(f"{base}/")
            try:
                body = path.read_bytes()
            except OSError as error:
                result.failed += 1
                result.failures.append((url, f"{type(error).__name__}: {error}"))
                continue
            key = cache_key("GET", url)
            stored = self.proxy.cache.get(key, now)
            if stored is not None and stored.body_sha256 == sha256(body).hexdigest():
                result.already_fresh += 1
                continue
            policy = resolve(self.proxy.config, CallTarget.parse(url))
            self.proxy.cache.put(
                key=key,
                url=url,
                method="GET",
                endpoint=policy.endpoint,
                status=200,
                headers=(("Content-Type", content_type(path)),),
                body=body,
                requested_at=now,
                received_at=now,
                volatility=policy.volatility,
                now=now,
                pinned=True,
            )
            result.fetched += 1
            result.bytes += len(body)
            if cap is not None and result.bytes >= cap:
                result.stopped_at_cap = True
                return

    async def _fetch_one(self, url: str, run: RunRef, result: Result) -> None:
        key = cache_key("GET", url)
        before = self.proxy.cache.get(key, self.proxy.clock())
        try:
            served = await self.proxy.fetch(
                HttpRequest("GET", url, headers=(("User-Agent", self.user_agent),)),
                run,
                surface=Surface.CLI,
            )
        except (OSError, ValueError) as error:
            result.failed += 1
            result.failures.append((url, f"{type(error).__name__}: {error}"))
            return
        if served.outcome.outcome is Outcome.DOWN:
            result.failed += 1
            failure = served.outcome.failure
            result.failures.append((url, str(failure.failure_class) if failure else "DOWN"))
            return
        if before is not None and served.from_cache:
            result.already_fresh += 1
            return
        result.fetched += 1
        result.bytes += len(served.body)
        # Warmed entries are what an operator asked to have on hand, so eviction takes
        # them last.
        self.proxy.cache.pin(key, True)

    def _pace_for(self, url: str, rps: float) -> Pace:
        host = urlsplit(url).netloc
        if host not in self._pace:
            self._pace[host] = Pace(rps)
        return self._pace[host]

    def _record(self, result: Result, run: RunRef) -> None:
        self.proxy.events.emit(
            "warm",
            run,
            EventFields(
                surface=str(Surface.CLI),
                endpoint=result.corpus,
                warm=result.as_event(self.trigger),
                message=(
                    f"unsupported corpus type: {result.unsupported}" if result.unsupported else None
                ),
            ),
        )


async def warm_all(
    proxy: Proxy, names: Sequence[str] = (), *, dry_run: bool = False, trigger: Trigger = "cli"
) -> list[Result]:
    """Every corpus asked for, one after another, so hosts are not warmed in parallel."""
    warmer = Warmer(proxy, trigger=trigger)
    return [await warmer.warm(corpus, dry_run=dry_run) for corpus in warmer.corpora(names)]


def content_type(path: Path) -> str:
    """What a local file would have been served as."""
    suffix = path.suffix.lower()
    if suffix in KNOWN_TYPES:
        return KNOWN_TYPES[suffix]
    kind, _encoding = mimetypes.guess_type(path.name)
    return kind or "application/octet-stream"


def unsupported_kinds(corpora: Iterable[Corpus]) -> list[str]:
    """Corpus types configured but not implemented, so a caller can say so up front."""
    kinds = {ZimCorpus: "zim", McpResourcesCorpus: "mcp_resources"}
    return sorted(
        {name for corpus in corpora for kind, name in kinds.items() if isinstance(corpus, kind)}
    )
