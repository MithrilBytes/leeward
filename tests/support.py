# SPDX-License-Identifier: Apache-2.0
"""Helpers shared by the tests: the published schemas as validators."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

REPO_ROOT = Path(__file__).resolve().parents[1]


@cache
def validator(name: str) -> Draft202012Validator:
    path = REPO_ROOT / "schemas" / f"{name}.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def assert_valid(name: str, instance: object) -> None:
    check = cast(
        "Callable[[Any], Iterable[ValidationError]]",
        validator(name).iter_errors,  # pyright: ignore[reportUnknownMemberType]
    )
    errors: list[ValidationError] = list(check(cast("Any", instance)))
    assert not errors, "\n".join(f"{list(error.path)}: {error.message}" for error in errors)


@dataclass(frozen=True, slots=True)
class AsgiReply:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        found = [value for key, value in self.headers if key.lower() == wanted]
        return found[0] if found else None

    def json(self) -> dict[str, object]:
        return cast("dict[str, object]", json.loads(self.body))


async def asgi_call(
    app: object,
    method: str,
    path: str,
    *,
    query: str = "",
    headers: Sequence[tuple[str, str]] = (),
    body: bytes = b"",
) -> AsgiReply:
    """Drive an ASGI application directly, so the tests need no HTTP client of their own."""
    scope: dict[str, object] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": query.encode("utf-8"),
        "root_path": "",
        "headers": [
            (name.lower().encode("latin-1"), value.encode("latin-1")) for name, value in headers
        ],
        "client": ("127.0.0.1", 54321),
        "server": ("127.0.0.1", 8787),
    }
    incoming: list[dict[str, object]] = [{"type": "http.request", "body": body, "more_body": False}]
    sent: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        if incoming:
            return incoming.pop(0)
        # A streaming response races its body against a disconnect, so saying the client
        # has gone the moment the request is read would end every stream at zero bytes.
        # A real client waits here, and so does this one until the response is done.
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    application = cast("Callable[..., Awaitable[None]]", app)
    await application(scope, receive, send)
    start = next(message for message in sent if message["type"] == "http.response.start")
    raw = cast("Sequence[tuple[bytes, bytes]]", start.get("headers", []))
    chunks = [
        cast("bytes", message.get("body", b""))
        for message in sent
        if message["type"] == "http.response.body"
    ]
    return AsgiReply(
        status=cast("int", start["status"]),
        headers=tuple((name.decode("latin-1"), value.decode("latin-1")) for name, value in raw),
        body=b"".join(chunks),
    )


async def asgi_lifespan(app: object) -> None:
    """Run an application's shutdown, so a test closes what it opened."""
    events: list[dict[str, object]] = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]

    async def receive() -> dict[str, object]:
        return events.pop(0) if events else {"type": "lifespan.shutdown"}

    async def send(_message: dict[str, object]) -> None:
        return None

    application = cast("Callable[..., Awaitable[None]]", app)
    await application({"type": "lifespan", "asgi": {"version": "3.0"}}, receive, send)
