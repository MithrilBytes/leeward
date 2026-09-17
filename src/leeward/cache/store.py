# SPDX-License-Identifier: Apache-2.0
"""The cache: bodies kept by content, metadata in SQLite, one flight per key.

A body is stored under the hash of its own bytes and checked against that hash
before it is served. A poisoned or truncated cache is the one way leeward could
hand an agent something no origin ever sent, so the check is not optional and a
body that fails it is discarded rather than served.

The index is SQLite in WAL mode, so `leeward status` and `leeward cache ls` can
read while the proxy writes, and neither waits for the other.

Nothing here decides whether a copy may be served. It stores, finds and evicts;
freshness.py judges.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import tempfile
from collections.abc import Awaitable, Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Generic, TypeVar, cast

from leeward.cache.freshness import StoredResponse
from leeward.canonical import canonical_sha256
from leeward.vocab import Volatility

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    key TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    status INTEGER NOT NULL,
    headers TEXT NOT NULL,
    vary TEXT NOT NULL,
    body_sha256 TEXT NOT NULL,
    body_bytes INTEGER NOT NULL,
    requested_at REAL NOT NULL,
    received_at REAL NOT NULL,
    stored_at REAL NOT NULL,
    volatility TEXT NOT NULL,
    pinned INTEGER NOT NULL DEFAULT 0,
    last_access REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS entries_eviction ON entries (pinned, last_access);
CREATE INDEX IF NOT EXISTS entries_endpoint ON entries (endpoint);
"""

T = TypeVar("T")


CHECK_EVERY_BYTES = 8 * 1024 * 1024
"""Bytes written between one look at the store's total size and the next."""


def cache_key(method: str, url: str, vary: Sequence[tuple[str, str]] = ()) -> str:
    """The key for one request: its method, its URL, and the headers the rule varies on."""
    material = {
        "method": method.upper(),
        "url": url,
        "vary": [[name.lower(), value] for name, value in sorted(vary)],
    }
    return canonical_sha256(material)


def tool_key(server: str, tool: str, arguments: object) -> str:
    """The key for one tool call: the tool, and its arguments in canonical form."""
    return canonical_sha256({"tool": f"{server}/{tool}", "arguments": arguments})


def resource_key(server: str, uri: str) -> str:
    """The key for one resource read. A resource is read only, so its URI is the whole of it."""
    return canonical_sha256({"resource": f"{server}/{uri}"})


@dataclass(frozen=True, slots=True)
class CacheStats:
    entries: int
    bytes: int
    pinned: int
    oldest_stored_at: float | None


@dataclass(frozen=True, slots=True)
class Evicted:
    key: str
    url: str
    body_bytes: int
    pinned: bool


class CorruptBodyError(RuntimeError):
    """A stored body did not match the hash it was filed under."""


class SingleFlight(Generic[T]):
    """One call per key at a time. Everyone else waits for that one and shares its answer."""

    def __init__(self) -> None:
        self._flights: dict[str, asyncio.Future[T]] = {}

    def in_flight(self, key: str) -> bool:
        return key in self._flights

    async def run(self, key: str, work: Callable[[], Awaitable[T]]) -> tuple[T, bool]:
        """Returns the result and whether this caller joined someone else's flight."""
        running = self._flights.get(key)
        if running is not None:
            return await asyncio.shield(running), True
        loop = asyncio.get_running_loop()
        flight: asyncio.Future[T] = loop.create_future()
        self._flights[key] = flight
        try:
            result = await work()
        except BaseException as error:
            flight.set_exception(error)
            # Nobody is required to await this future, so its exception is not a bug.
            flight.exception()
            raise
        else:
            flight.set_result(result)
            return result, False
        finally:
            self._flights.pop(key, None)


class CacheStore:
    """Stored responses on local disk. Single process, single thread, no server."""

    def __init__(
        self,
        directory: Path,
        *,
        max_bytes: int | None = None,
        on_evict: Callable[[Sequence[Evicted]], None] | None = None,
        check_every_bytes: int = CHECK_EVERY_BYTES,
    ) -> None:
        self.directory = directory
        self.max_bytes = max_bytes
        self.on_evict = on_evict
        self.check_every_bytes = check_every_bytes
        self._since_check = 0
        self.bodies = directory / "bodies"
        self.bodies.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(directory / "index.db", isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(SCHEMA)

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> CacheStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _row_to_entry(self, row: tuple[Any, ...]) -> StoredResponse:
        headers = cast("list[list[str]]", json.loads(row[5]))
        vary = cast("list[list[str]]", json.loads(row[6]))
        return StoredResponse(
            key=row[0],
            url=row[1],
            method=row[2],
            endpoint=row[3],
            status=row[4],
            headers=tuple((name, value) for name, value in headers),
            vary=tuple((name, value) for name, value in vary),
            body_sha256=row[7],
            body_bytes=row[8],
            requested_at=row[9],
            received_at=row[10],
            stored_at=row[11],
            volatility=Volatility(row[12]),
            pinned=bool(row[13]),
        )

    def get(self, key: str, now: float | None = None) -> StoredResponse | None:
        row = self._db.execute("SELECT * FROM entries WHERE key = ?", (key,)).fetchone()
        if row is None:
            return None
        if now is not None:
            self._db.execute("UPDATE entries SET last_access = ? WHERE key = ?", (now, key))
        return self._row_to_entry(cast("tuple[Any, ...]", row))

    def body_path(self, digest: str) -> Path:
        return self.bodies / digest[:2] / digest

    def read_body(self, entry: StoredResponse) -> bytes:
        """The stored bytes, checked against the hash they are filed under."""
        path = self.body_path(entry.body_sha256)
        try:
            body = path.read_bytes()
        except OSError as exc:
            raise CorruptBodyError(f"{entry.url}: the stored body is gone") from exc
        if hashlib.sha256(body).hexdigest() != entry.body_sha256:
            self.delete(entry.key)
            raise CorruptBodyError(f"{entry.url}: the stored body does not match its hash")
        return body

    def _write_body(self, body: bytes) -> str:
        digest = hashlib.sha256(body).hexdigest()
        path = self.body_path(digest)
        if path.exists():
            return digest
        path.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".body-")
        with os.fdopen(handle, "wb") as file:
            file.write(body)
        os.replace(temporary, path)
        return digest

    def put(
        self,
        *,
        key: str,
        url: str,
        method: str,
        endpoint: str,
        status: int,
        headers: Sequence[tuple[str, str]],
        body: bytes,
        requested_at: float,
        received_at: float,
        volatility: Volatility,
        vary: Sequence[tuple[str, str]] = (),
        now: float | None = None,
        pinned: bool = False,
    ) -> StoredResponse:
        stored_at = now if now is not None else received_at
        digest = self._write_body(body)
        entry = StoredResponse(
            key=key,
            url=url,
            method=method.upper(),
            endpoint=endpoint,
            status=status,
            headers=tuple(headers),
            vary=tuple(vary),
            body_sha256=digest,
            body_bytes=len(body),
            requested_at=requested_at,
            received_at=received_at,
            stored_at=stored_at,
            volatility=volatility,
            pinned=pinned,
        )
        self._db.execute(
            "INSERT OR REPLACE INTO entries VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                entry.key,
                entry.url,
                entry.method,
                entry.endpoint,
                entry.status,
                json.dumps([[name, value] for name, value in entry.headers]),
                json.dumps([[name, value] for name, value in entry.vary]),
                entry.body_sha256,
                entry.body_bytes,
                entry.requested_at,
                entry.received_at,
                entry.stored_at,
                str(entry.volatility),
                int(entry.pinned),
                stored_at,
            ),
        )
        self._maybe_evict(len(body))
        return entry

    def _maybe_evict(self, written: int) -> None:
        """Keep the store inside its cap, without counting the whole store every write.

        Eviction reads the total, which is a scan, so it is not worth doing after every
        small body. Bytes written since the last look are counted instead, and the real
        total is consulted once enough has accumulated to be worth the query.
        """
        if self.max_bytes is None:
            return
        self._since_check += written
        if self._since_check < self.check_every_bytes:
            return
        self._since_check = 0
        evicted = self.evict(self.max_bytes)
        if evicted and self.on_evict is not None:
            self.on_evict(evicted)

    def refresh(
        self,
        key: str,
        headers: Mapping[str, str],
        *,
        requested_at: float,
        received_at: float,
    ) -> StoredResponse | None:
        """Apply a 304: new freshness, same body, which is the point of revalidating."""
        entry = self.get(key)
        if entry is None:
            return None
        updated = dict(entry.headers)
        for name, value in headers.items():
            if name.lower() not in {"content-length", "connection", "transfer-encoding"}:
                updated[name] = value
        merged = tuple(updated.items())
        self._db.execute(
            "UPDATE entries SET headers = ?, requested_at = ?, received_at = ?, last_access = ?"
            " WHERE key = ?",
            (
                json.dumps([[name, value] for name, value in merged]),
                requested_at,
                received_at,
                received_at,
                key,
            ),
        )
        entry_after = self.get(key)
        return entry_after

    def pin(self, key: str, pinned: bool = True) -> None:
        self._db.execute("UPDATE entries SET pinned = ? WHERE key = ?", (int(pinned), key))

    def delete(self, key: str) -> None:
        row = self._db.execute("SELECT body_sha256 FROM entries WHERE key = ?", (key,)).fetchone()
        self._db.execute("DELETE FROM entries WHERE key = ?", (key,))
        if row is not None:
            self._drop_body_if_unused(str(cast("tuple[Any, ...]", row)[0]))

    def _drop_body_if_unused(self, digest: str) -> None:
        still = self._db.execute(
            "SELECT 1 FROM entries WHERE body_sha256 = ? LIMIT 1", (digest,)
        ).fetchone()
        if still is None:
            self.body_path(digest).unlink(missing_ok=True)

    def entries(self) -> Iterator[StoredResponse]:
        for row in self._db.execute("SELECT * FROM entries ORDER BY last_access DESC"):
            yield self._row_to_entry(cast("tuple[Any, ...]", row))

    def stats(self) -> CacheStats:
        row = cast(
            "tuple[Any, ...]",
            self._db.execute(
                "SELECT COUNT(*), COALESCE(SUM(body_bytes), 0),"
                " COALESCE(SUM(pinned), 0), MIN(stored_at) FROM entries"
            ).fetchone(),
        )
        return CacheStats(
            entries=int(row[0]), bytes=int(row[1]), pinned=int(row[2]), oldest_stored_at=row[3]
        )

    def evict(self, byte_cap: int) -> list[Evicted]:
        """Least recently used first, pinned entries last. The caller warns about those."""
        total = self.stats().bytes
        if total <= byte_cap:
            return []
        evicted: list[Evicted] = []
        rows = self._db.execute(
            "SELECT key, url, body_bytes, pinned FROM entries ORDER BY pinned ASC, last_access ASC"
        ).fetchall()
        for row in cast("list[tuple[Any, ...]]", rows):
            if total <= byte_cap:
                break
            self.delete(str(row[0]))
            total -= int(row[2])
            evicted.append(
                Evicted(
                    key=str(row[0]), url=str(row[1]), body_bytes=int(row[2]), pinned=bool(row[3])
                )
            )
        return evicted
