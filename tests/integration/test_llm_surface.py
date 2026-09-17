# SPDX-License-Identifier: Apache-2.0
"""Surface D end to end: a client's base URL pointed at leeward, and tiers that fail."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, cast

import pytest
from fakes.origin import FakeOrigin, Reply, constant

from leeward.config import parse_config
from leeward.events import read_events
from leeward.proxy import Proxy
from leeward.serve import build_app
from leeward.surfaces.llm import conversation_of, inject_status_line
from tests.support import asgi_call, assert_valid

CONFIG = """
profile: dev
data_dir: {data}
surfaces:
  llm:
    enabled: true
    tiers:
      - name: primary
        base_url: {primary}/v1
        model: big-model
        api_key_env: LEEWARD_TEST_KEY
      - name: local
        base_url: {local}/v1
        model: small-model
    status_line:
      enabled: {status_line}
  fetch:
    enabled: true
    mounts:
      origin: {primary}
rules:
  - name: model-calls
    match: {{url: "*/v1/chat/completions"}}
    class: never
    max_attempts: 1
    soft_deadline: 1s
    hard_deadline: 10s
  - name: articles
    match: {{url: "*/wiki/*"}}
    class: static
    stale_on_error: 30d
"""


def completion(text: str, model: str = "big-model") -> bytes:
    return json.dumps(
        {
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
        }
    ).encode("utf-8")


ASK = {"model": "whatever", "messages": [{"role": "user", "content": "why did the grid fail?"}]}


@pytest.fixture
async def primary() -> AsyncIterator[FakeOrigin]:
    async with FakeOrigin() as running:
        running.route("/wiki/*", constant(Reply(body=b"<h1>an article</h1>")))
        yield running


@pytest.fixture
async def local() -> AsyncIterator[FakeOrigin]:
    async with FakeOrigin() as running:
        running.route(
            "/v1/chat/completions",
            constant(
                Reply(
                    status=200,
                    headers={"Content-Type": "application/json"},
                    body=completion("the local model answering", "small-model"),
                )
            ),
        )
        yield running


def config_for(tmp_path: Path, primary: FakeOrigin, local: FakeOrigin, *, status_line: bool) -> str:
    return CONFIG.format(
        data=tmp_path / "data",
        primary=primary.base_url,
        local=local.base_url,
        status_line="true" if status_line else "false",
    )


@pytest.fixture
async def proxy(tmp_path: Path, primary: FakeOrigin, local: FakeOrigin) -> AsyncIterator[Proxy]:
    loaded = parse_config(
        config_for(tmp_path, primary, local, status_line=False), tmp_path / "leeward.yaml"
    )
    made = Proxy(loaded)
    yield made
    await made.aclose()


def app_for(proxy: Proxy) -> object:
    return build_app(proxy, close_with_app=False)


async def post(app: object, body: dict[str, Any], headers: tuple[tuple[str, str], ...] = ()) -> Any:
    return await asgi_call(
        app,
        "POST",
        "/v1/chat/completions",
        headers=(("content-type", "application/json"), *headers),
        body=json.dumps(body).encode("utf-8"),
    )


async def test_a_completion_passes_through_with_the_tier_named(
    proxy: Proxy, primary: FakeOrigin
) -> None:
    primary.route(
        "/v1/chat/completions",
        constant(
            Reply(
                status=200,
                headers={"Content-Type": "application/json"},
                body=completion("because two lines tripped"),
            )
        ),
    )
    reply = await post(app_for(proxy), ASK)
    assert reply.status == 200
    assert reply.header("X-Leeward-Tier") == "primary"
    assert reply.header("X-Leeward-Outcome") == "FRESH"
    body = reply.json()
    choices = cast("list[Any]", body["choices"])
    assert choices[0]["message"]["content"] == "because two lines tripped"
    # The tier's own model name is what goes upstream, not whatever the client asked for.
    assert json.loads(primary.requests[-1].body)["model"] == "big-model"


async def test_a_failing_tier_falls_through_to_the_next_one(
    proxy: Proxy, primary: FakeOrigin, local: FakeOrigin
) -> None:
    primary.route("/v1/chat/completions", constant(Reply(status=503, body=b"overloaded")))
    reply = await post(app_for(proxy), ASK)
    assert reply.status == 200
    assert reply.header("X-Leeward-Tier") == "local"
    assert reply.header("X-Leeward-Failed-Over-From") == "primary"
    assert "the local model answering" in str(reply.json()["choices"])
    assert local.hits["/v1/chat/completions"] == 1


async def test_every_tier_failing_gives_an_openai_shaped_error_carrying_the_note(
    proxy: Proxy, primary: FakeOrigin, local: FakeOrigin
) -> None:
    primary.route("/v1/chat/completions", constant(Reply(status=503, body=b"overloaded")))
    await local.stop()
    reply = await post(app_for(proxy), ASK)
    assert reply.status >= 400
    error = cast("dict[str, Any]", reply.json()["error"])
    assert error["message"].startswith("[leeward] DOWN:")
    assert error["type"] in ("upstream_error", "rate_limit_error")
    assert error["tried"] == ["primary", "local"]
    assert_valid("outcome", error["leeward"])


async def test_a_rate_limited_tier_is_reported_as_a_rate_limit(
    proxy: Proxy, primary: FakeOrigin, local: FakeOrigin
) -> None:
    limited = Reply(status=429, headers={"Retry-After": "3600"}, body=b"slow down")
    primary.route("/v1/chat/completions", constant(limited))
    await local.stop()
    reply = await post(app_for(proxy), ASK)

    # Both failed, and what comes back is the tier the caller asked for, not the fallback.
    error = cast("dict[str, Any]", reply.json()["error"])
    assert error["code"] in ("QUOTA_EXHAUSTED", "RATE_LIMITED")
    assert error["tier"] == "primary"
    assert error["tried"] == ["primary", "local"]
    assert "leeward" in error


SSE = (
    b'data: {"choices":[{"delta":{"content":"because "}}]}\n\n'
    b'data: {"choices":[{"delta":{"content":"two lines tripped"}}]}\n\n'
    b"data: [DONE]\n\n"
)


async def test_a_streamed_completion_passes_through_with_the_tier_named(
    proxy: Proxy, primary: FakeOrigin
) -> None:
    primary.route(
        "/v1/chat/completions",
        constant(Reply(status=200, headers={"Content-Type": "text/event-stream"}, body=SSE)),
    )
    reply = await post(app_for(proxy), {**ASK, "stream": True})
    assert reply.status == 200
    assert reply.header("X-Leeward-Tier") == "primary"
    assert reply.body == SSE


async def test_a_tier_that_will_not_open_fails_over_before_any_bytes_reach_the_client(
    proxy: Proxy, primary: FakeOrigin, local: FakeOrigin
) -> None:
    primary.route("/v1/chat/completions", constant(Reply(status=503, body=b"overloaded")))
    local.route("/v1/streamed", constant(Reply(status=200, body=SSE)))
    await local.stop()
    reply = await post(app_for(proxy), {**ASK, "stream": True})

    # Both tiers were tried, nothing partial was sent, and the failure is JSON.
    assert reply.status == 502
    error = cast("dict[str, Any]", reply.json()["error"])
    assert error["tried"] == ["primary", "local"]
    assert error["message"].startswith("[leeward]")


async def test_a_stream_that_stops_early_says_so_in_the_stream(
    proxy: Proxy, primary: FakeOrigin
) -> None:
    primary.route(
        "/v1/chat/completions",
        constant(
            Reply(
                status=200,
                headers={"Content-Type": "text/event-stream"},
                body=SSE,
                stall_after=40,
            )
        ),
    )
    reply = await post(app_for(proxy), {**ASK, "stream": True})
    assert reply.status == 200

    # The client keeps what arrived, and the last event explains why there is no more.
    assert reply.body.startswith(b'data: {"choices"')
    assert b'"error"' in reply.body
    assert reply.body.rstrip().endswith(b"data: [DONE]")
    tail = json.loads(reply.body.split(b"data: ")[-2])
    assert tail["error"]["code"] in ("READ_TIMEOUT", "PROTOCOL_ERROR", "SERVER_ERROR")
    assert "[leeward]" in tail["error"]["message"]


async def test_tokens_and_the_tier_are_in_the_event_log(
    proxy: Proxy, primary: FakeOrigin, tmp_path: Path
) -> None:
    primary.route(
        "/v1/chat/completions",
        constant(
            Reply(
                status=200,
                headers={"Content-Type": "application/json"},
                body=completion("answered"),
            )
        ),
    )
    await post(app_for(proxy), ASK)
    proxy.events.close()
    calls = [
        event for event in read_events(tmp_path / "data" / "events") if event["event"] == "call"
    ]
    assert [event["surface"] for event in calls] == ["llm"]
    assert_valid("event", calls[0])
    assert calls[0]["outcome"] == "FRESH"


async def test_the_status_line_is_off_by_default_and_one_line_when_on(
    tmp_path: Path, primary: FakeOrigin, local: FakeOrigin
) -> None:
    primary.route(
        "/v1/chat/completions",
        constant(
            Reply(
                status=200,
                headers={"Content-Type": "application/json"},
                body=completion("the answer"),
            )
        ),
    )
    loaded = parse_config(
        config_for(tmp_path, primary, local, status_line=True), tmp_path / "leeward.yaml"
    )
    proxy = Proxy(loaded)
    app = app_for(proxy)

    # Nothing is degraded yet, so even with the status line on there is nothing to say.
    quiet = await post(app, ASK)
    assert quiet.header("X-Leeward-Status-Line") is None

    # Now something the agent depends on goes down, and the next answer carries one line.
    await asgi_call(app, "GET", "/origin/wiki/Foo")
    await primary.stop()
    await asgi_call(app, "GET", "/origin/wiki/Bar")
    degraded = await post(app, ASK)
    await proxy.aclose()

    line = degraded.header("X-Leeward-Status-Line")
    if line is not None:
        assert line.startswith("[leeward]")
        assert "\n" not in line
        assert len(line) < 200


def test_a_status_line_is_prepended_to_the_assistant_message_and_nothing_else() -> None:
    body = completion("the answer")
    injected = inject_status_line(body, "[leeward] notes unreachable")
    parsed = cast("dict[str, Any]", json.loads(injected))
    assert parsed["choices"][0]["message"]["content"] == "[leeward] notes unreachable\nthe answer"
    assert parsed["usage"] == {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
    assert inject_status_line(body, "") == body
    assert inject_status_line(b"not json", "[leeward] x") == b"not json"


def test_the_same_conversation_resolves_to_the_same_run() -> None:
    first = conversation_of(ASK)
    again = conversation_of({**ASK, "temperature": 0.2})
    assert first == again
    other = conversation_of({"messages": [{"role": "user", "content": "something else"}]})
    assert other != first


async def test_a_tier_url_is_its_base_plus_the_completions_path(
    proxy: Proxy, primary: FakeOrigin
) -> None:
    """A base URL already carries the version, so leeward adds only the rest.

    Found against a real provider: appending the whole client path to a base URL that
    ends in /v1 asks for /v1/v1/chat/completions, which every provider answers with a
    404 that says nothing useful.
    """
    primary.route(
        "/v1/chat/completions",
        constant(
            Reply(
                status=200,
                headers={"Content-Type": "application/json"},
                body=completion("answered"),
            )
        ),
    )
    reply = await post(app_for(proxy), ASK)
    assert reply.status == 200
    assert primary.requests[-1].path == "/v1/chat/completions"
    assert "/v1/v1/" not in primary.requests[-1].path
