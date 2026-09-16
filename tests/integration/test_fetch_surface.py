# SPDX-License-Identifier: Apache-2.0
"""The HTTP surface end to end: a tool's base URL pointed at leeward, and an origin that dies.

This is where the cache's promise is tested as an agent would meet it. A static page
survives its origin being killed. A live endpoint does not, and says why, with the
copy it is refusing to hand over named in the same breath.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from fakes.origin import FakeOrigin, Reply, constant, document

from leeward.config import parse_config
from leeward.events import read_events
from leeward.proxy import Proxy
from leeward.serve import build_app
from leeward.vocab import FailureClass
from tests.support import asgi_call, assert_valid

CONFIG = """
profile: dev
data_dir: {data}
surfaces:
  fetch:
    enabled: true
    listen: 127.0.0.1:8787
    mounts:
      origin: {origin}
    generic_fetch:
      enabled: true
      allow_hosts: ["127.0.0.1"]
rules:
  - name: wikipedia-articles
    match: {{url: "*/wiki/*"}}
    class: static
    stale_on_error: 30d
  - name: operator-status
    match: {{url: "*/status*"}}
    class: live
    stale_on_error: 0s
  - name: docs-mirror
    match: {{url: "*/docs/*"}}
    class: slow
    stale_on_error: 7d
    stale_while_revalidate: 0s
chaos:
  enabled: true
"""


@pytest.fixture
async def origin() -> AsyncIterator[FakeOrigin]:
    async with FakeOrigin() as running:
        running.route("/wiki/*", document(b"<h1>the 2003 blackout</h1>", cache_control="max-age=0"))
        running.route(
            "/status",
            constant(
                Reply(
                    status=200,
                    headers={"Cache-Control": "no-cache", "Content-Type": "application/json"},
                    body=b'{"alerts": 0}',
                )
            ),
        )
        running.route("/docs/*", document(b"a page of documentation", cache_control="max-age=0"))
        running.route("/slow", constant(Reply(body=b"eventually", delay_s=0.2)))
        yield running


@pytest.fixture
async def proxy(tmp_path: Path, origin: FakeOrigin) -> AsyncIterator[Proxy]:
    loaded = parse_config(
        CONFIG.format(data=tmp_path / "data", origin=origin.base_url), tmp_path / "leeward.yaml"
    )
    made = Proxy(loaded)
    yield made
    await made.aclose()


def app_for(proxy: Proxy) -> object:
    return build_app(proxy, close_with_app=False)


async def test_a_fresh_response_passes_through_with_leeward_headers(
    proxy: Proxy, origin: FakeOrigin
) -> None:
    reply = await asgi_call(app_for(proxy), "GET", "/origin/wiki/Foo")
    assert reply.status == 200
    assert reply.body == b"<h1>the 2003 blackout</h1>"
    assert reply.header("X-Leeward-Outcome") == "FRESH"
    assert reply.header("X-Leeward-Volatility") == "static"
    assert reply.header("X-Leeward-Advice") == "PROCEED"
    assert reply.header("Content-Type") == "text/html"
    assert origin.hits["/wiki/Foo"] == 1


async def test_a_static_page_survives_the_origin_dying_and_a_live_one_does_not(
    proxy: Proxy, origin: FakeOrigin
) -> None:
    app = app_for(proxy)
    assert (await asgi_call(app, "GET", "/origin/wiki/Foo")).status == 200
    assert (await asgi_call(app, "GET", "/origin/status")).status == 200

    await origin.stop()

    survived = await asgi_call(app, "GET", "/origin/wiki/Foo")
    assert survived.status == 200
    assert survived.body == b"<h1>the 2003 blackout</h1>"
    assert survived.header("X-Leeward-Outcome") == "STALE"
    assert survived.header("X-Leeward-Advice") == "PROCEED_WITH_CAUTION"
    assert survived.header("Age") is not None
    assert survived.header("Warning") == '110 leeward "Response is Stale"'
    note = survived.header("X-Leeward-Advice-Note") or ""
    assert note.startswith("[leeward] STALE: served a copy stored")
    assert "fetched in the background" in note

    # That refresh fails, and from then on the note says why the copy is being served.
    await proxy.settle()
    again = await asgi_call(app, "GET", "/origin/wiki/Foo")
    assert again.header("X-Leeward-Outcome") == "STALE"
    informed = again.header("X-Leeward-Advice-Note") or ""
    assert "is unreachable (CONNECT_REFUSED)" in informed
    assert "Retrying will not help until connectivity returns." in informed

    refused = await asgi_call(app, "GET", "/origin/status")
    assert refused.status in (503, 504)
    assert refused.header("X-Leeward-Outcome") == "DOWN"
    assert refused.header("X-Leeward-Advice") == "TREAT_AS_UNKNOWN"
    body = refused.json()
    assert body["outcome"] == "DOWN"
    assert body["volatility"] == "live"
    withheld = body["withheld_cache"]
    assert isinstance(withheld, dict)
    assert withheld["reason"] == "VOLATILITY_LIVE"
    assert withheld["available_via"] is None
    assert "classified `live`" in str(body["note"])
    assert "Treat this value as unknown" in str(body["note"])


async def test_a_copy_is_served_at_once_and_refreshed_behind_it(
    proxy: Proxy, origin: FakeOrigin
) -> None:
    app = app_for(proxy)
    first = await asgi_call(app, "GET", "/origin/wiki/Foo")
    assert first.header("X-Leeward-Outcome") == "FRESH"

    second = await asgi_call(app, "GET", "/origin/wiki/Foo")
    assert second.status == 200
    assert second.body == first.body
    assert second.header("X-Leeward-Outcome") == "STALE"
    assert "fetched in the background" in (second.header("X-Leeward-Advice-Note") or "")

    await proxy.settle()
    assert origin.hits["/wiki/Foo"] == 2
    assert origin.requests[-1].header("if-none-match") is not None


async def test_a_revalidation_returns_the_stored_body_without_downloading_it_again(
    proxy: Proxy, origin: FakeOrigin
) -> None:
    app = app_for(proxy)
    first = await asgi_call(app, "GET", "/origin/docs/guide")
    downloaded = origin.bytes_served

    second = await asgi_call(app, "GET", "/origin/docs/guide")

    assert second.status == 200
    assert second.body == first.body == b"a page of documentation"
    assert second.header("X-Leeward-Outcome") == "FRESH"
    assert second.header("Age") == "0"
    assert origin.hits["/docs/guide"] == 2
    assert origin.requests[-1].header("if-none-match") is not None
    assert origin.bytes_served == downloaded


async def test_identical_requests_in_flight_collapse_into_one_origin_call(
    proxy: Proxy, origin: FakeOrigin
) -> None:
    app = app_for(proxy)
    replies = await asyncio.gather(*(asgi_call(app, "GET", "/origin/slow") for _ in range(5)))
    assert [reply.status for reply in replies] == [200] * 5
    assert all(reply.body == b"eventually" for reply in replies)
    assert origin.hits["/slow"] == 1


async def test_the_generic_fetch_only_serves_hosts_the_operator_allowed(
    proxy: Proxy, origin: FakeOrigin
) -> None:
    app = app_for(proxy)
    allowed = await asgi_call(
        app, "GET", "/fetch", query=f"url={origin.base_url}/wiki/Foo".replace(":", "%3A", 1)
    )
    assert allowed.status == 200
    refused = await asgi_call(app, "GET", "/fetch", query="url=https://example.com/secrets")
    assert refused.status == 403
    assert "allow_hosts" in str(refused.json()["message"])
    assert (await asgi_call(app, "GET", "/fetch")).status == 400


async def test_an_unknown_mount_says_which_mounts_exist(proxy: Proxy) -> None:
    reply = await asgi_call(app_for(proxy), "GET", "/nowhere/x")
    assert reply.status == 404
    assert "origin" in str(reply.json()["message"])


async def test_status_and_forecast_answer_while_the_origin_is_gone(
    proxy: Proxy, origin: FakeOrigin
) -> None:
    app = app_for(proxy)
    await asgi_call(app, "GET", "/origin/wiki/Foo")
    await origin.stop()
    accepted = origin.accepted

    reply = await asgi_call(app, "GET", "/leeward/status")
    assert reply.status == 200
    report = reply.json()
    assert isinstance(report["endpoints"], list)
    cache = report["cache"]
    assert isinstance(cache, dict)
    assert cache["entries"] == 1
    assert cache["bytes"] == len(b"<h1>the 2003 blackout</h1>")
    assert cache["pinned"] == 0

    predicted = await asgi_call(
        app, "GET", "/leeward/forecast", query=f"url={origin.base_url}/wiki/Foo"
    )
    assert predicted.status == 200
    assert predicted.json()["predicted"] in ("FRESH", "STALE")
    assert origin.accepted == accepted


async def test_a_forecast_predicts_what_the_next_call_returns(
    proxy: Proxy, origin: FakeOrigin
) -> None:
    app = app_for(proxy)
    await asgi_call(app, "GET", "/origin/wiki/Foo")
    proxy.injector.arm("*/wiki/*", now=proxy.clock(), failure_class=FailureClass.DNS_FAILURE)
    forecast = await asgi_call(
        app, "GET", "/leeward/forecast", query=f"url={origin.base_url}/wiki/Foo"
    )
    predicted = forecast.json()
    real = await asgi_call(app, "GET", "/origin/wiki/Foo")
    assert predicted["predicted"] == real.header("X-Leeward-Outcome")
    assert predicted["injected"] is True


async def test_every_event_validates_and_no_live_endpoint_is_ever_recorded_stale(
    proxy: Proxy, origin: FakeOrigin, tmp_path: Path
) -> None:
    app = app_for(proxy)
    await asgi_call(app, "GET", "/origin/wiki/Foo")
    await asgi_call(app, "GET", "/origin/status")
    await origin.stop()
    await asgi_call(app, "GET", "/origin/wiki/Foo")
    await asgi_call(app, "GET", "/origin/status")
    proxy.events.close()

    events = list(read_events(tmp_path / "data" / "events"))
    assert events
    for event in events:
        assert_valid("event", event)
        assert not (event.get("volatility") == "live" and event.get("outcome") == "STALE")
    calls = [event for event in events if event["event"] == "call"]
    assert [event["outcome"] for event in calls] == ["FRESH", "FRESH", "STALE", "DOWN"]
    assert json.dumps(events)
