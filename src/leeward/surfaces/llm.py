# SPDX-License-Identifier: Apache-2.0
"""Surface D: an OpenAI compatible endpoint, so model calls fail like everything else.

Point a client's `base_url` at leeward and the calls go out through the same engine as
every other surface: one deadline, one classifier, one set of breakers, one run budget
shared with the agent's tool calls. Tiers are tried in order, so a hosted model that is
rate limiting can fall through to a local one without the agent knowing.

Two things here are not like the other surfaces. A failure has to come back in the
provider's own error shape, since that is what the client library will parse, and the
message it carries is leeward's note. And the status line, off unless an operator turns
it on, prepends one line to the answer while something else the agent depends on is
degraded, because the model is the only part of the system that reads prose.

Model calls are not cached. The same prompt twice is a question about billing, not about
freshness, and answering it from a cache would be leeward inventing content.
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from leeward.attempt import AttemptRecord, CallReport
from leeward.budget import RunLedger, conversation_hash, resolve_run
from leeward.classify import OK, Classification, Evidence, RunSnapshot, classify
from leeward.classify import Response as Response_
from leeward.config import Config, Tier
from leeward.deadlines import CallDeadlines, Deadline
from leeward.events import CacheInfo, RunRef, TokenInfo
from leeward.notes import status_line
from leeward.outcome import CallOutcome, build
from leeward.policy import CallTarget, ResolvedPolicy, resolve
from leeward.proxy import HttpRequest, Proxy, Served
from leeward.transport import Call, EvidenceError, Streamed
from leeward.vocab import Advice, Outcome, Surface, Volatility

RUN_HEADER = "x-leeward-run"
SHOW_INJECTION_HEADER = "x-leeward-show-injection"
CHAT_PATH = "/v1/chat/completions"
"""Where clients call leeward, matching what they would call on a provider."""

UPSTREAM_PATH = "/chat/completions"
"""What leeward appends to a tier's base URL.

By convention a base URL already ends in the version, `https://api.openai.com/v1`, and
the client adds the rest. Appending the whole path instead produces `/v1/v1/chat/...`,
which every provider answers with a 404 and no explanation worth reading.
"""
MAX_BODY_BYTES = 8 * 1024 * 1024

ERROR_TYPES: Mapping[Advice, str] = {
    Advice.RETRY_AFTER: "rate_limit_error",
    Advice.DO_NOT_RETRY: "upstream_error",
    Advice.TREAT_AS_UNKNOWN: "upstream_error",
    Advice.PROCEED: "upstream_error",
    Advice.PROCEED_WITH_CAUTION: "upstream_error",
}
"""OpenAI's error `type`, chosen from what leeward decided rather than from the status."""


@dataclass(frozen=True, slots=True)
class Attempted:
    """One tier's turn."""

    tier: Tier
    served: Served

    @property
    def ok(self) -> bool:
        return self.served.outcome.outcome is not Outcome.DOWN and self.served.status < 500


def tiers_of(proxy: Proxy) -> list[Tier]:
    return list(proxy.config.surfaces.llm.tiers)


def error_body(outcome: CallOutcome, tier: str | None) -> dict[str, object]:
    """A failure in the shape a client library will parse, carrying leeward's note."""
    failure = outcome.failure
    return {
        "error": {
            "message": outcome.note or "leeward could not reach any configured tier",
            "type": ERROR_TYPES.get(outcome.advice, "upstream_error"),
            "param": None,
            "code": str(failure.failure_class) if failure is not None else "LEEWARD_DOWN",
            "leeward": outcome.as_dict(),
            "tier": tier,
        }
    }


def _endpoint(tier: Tier) -> str:
    return f"{tier.base_url.rstrip('/')}{UPSTREAM_PATH}"


def _headers(tier: Tier, request: Request) -> tuple[tuple[str, str], ...]:
    """Only what the upstream needs: its own key, read from the environment, never config."""
    headers: list[tuple[str, str]] = [("Content-Type", "application/json")]
    if tier.api_key_env:
        key = os.environ.get(tier.api_key_env)
        if key:
            headers.append(("Authorization", f"Bearer {key}"))
    accept = request.headers.get("accept")
    if accept:
        headers.append(("Accept", accept))
    return tuple(headers)


def _with_model(payload: Mapping[str, object], tier: Tier) -> bytes:
    """Each tier names its own model, so the body is rewritten for the tier it goes to."""
    return json.dumps({**payload, "model": tier.model}, ensure_ascii=False).encode("utf-8")


def _messages(payload: Mapping[str, object]) -> list[Mapping[str, object]]:
    raw = payload.get("messages")
    if not isinstance(raw, list):
        return []
    return [item for item in cast("list[object]", raw) if isinstance(item, dict)]


def _usage(body: bytes) -> TokenInfo | None:
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    usage = cast("Mapping[str, object]", parsed).get("usage")
    if not isinstance(usage, dict):
        return None
    counted = cast("Mapping[str, object]", usage)
    prompt = counted.get("prompt_tokens")
    completion = counted.get("completion_tokens")
    return TokenInfo(
        prompt=prompt if isinstance(prompt, int) else 0,
        completion=completion if isinstance(completion, int) else 0,
    )


def inject_status_line(body: bytes, line: str) -> bytes:
    """Prepend one line to the assistant's message, and leave everything else alone."""
    if not line:
        return body
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return body
    if not isinstance(parsed, dict):
        return body
    document = cast("dict[str, Any]", parsed)
    choices = document.get("choices")
    if not isinstance(choices, list) or not choices:
        return body
    first = cast("list[Any]", choices)[0]
    if not isinstance(first, dict):
        return body
    message = cast("dict[str, Any]", first).get("message")
    if not isinstance(message, dict):
        return body
    spoken = cast("dict[str, Any]", message)
    content = spoken.get("content")
    if not isinstance(content, str):
        return body
    spoken["content"] = f"{line}\n{content}"
    return json.dumps(document, ensure_ascii=False).encode("utf-8")


def _one_attempt(classification: Classification, policy: ResolvedPolicy, now: float) -> CallReport:
    """One attempt that has already happened, in the shape the outcome builder reads."""
    return CallReport(
        classification=classification,
        attempts=(AttemptRecord(index=1, classification=classification, latency_ms=0),),
        deadlines=CallDeadlines.start(policy, now),
        deadline_hit="none",
        elapsed_s=0.0,
    )


def _no_outcome() -> CallOutcome:
    """Nothing was tried, which only happens when no tier is configured."""
    from leeward.outcome import CallOutcome as Built

    return Built(
        outcome=Outcome.DOWN,
        endpoint="(no tier)",
        volatility=Volatility.NEVER,
        advice=Advice.TREAT_AS_UNKNOWN,
        note="[leeward] DOWN: no tier answered.",
    )


def _stream_error(outcome: CallOutcome, tier: str) -> bytes:
    """One more SSE event, so a stream that stopped early says why in its own channel."""
    body = error_body(outcome, tier)
    return (
        b"data: " + json.dumps(body, ensure_ascii=False).encode("utf-8") + b"\n\ndata: [DONE]\n\n"
    )


class ModelSurface:
    """The chat endpoint, and the tier ladder behind it."""

    def __init__(self, proxy: Proxy) -> None:
        self.proxy = proxy

    async def chat(self, request: Request) -> Response:
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            return self._refusal(413, "the request body is larger than leeward will forward")
        try:
            parsed: object = json.loads(raw) if raw else {}
        except json.JSONDecodeError as error:
            return self._refusal(400, f"the request body is not JSON: {error}")
        if not isinstance(parsed, dict):
            return self._refusal(400, "the request body must be a JSON object")
        payload = cast("Mapping[str, object]", parsed)
        tiers = tiers_of(self.proxy)
        if not tiers:
            return self._refusal(503, "no tiers are configured for the model surface")

        run = self._run_of(request, payload)
        if payload.get("stream"):
            return await self._stream(request, payload, tiers, run)
        ledger = self.proxy.runs.ledger(run, self.proxy.clock())
        attempted: list[Attempted] = []
        for tier in tiers:
            served = await self.proxy.fetch(
                HttpRequest(
                    "POST",
                    _endpoint(tier),
                    headers=_headers(tier, request),
                    body=_with_model(payload, tier),
                ),
                run,
                surface=Surface.LLM,
            )
            attempted.append(Attempted(tier, served))
            if Attempted(tier, served).ok:
                return self._answer(attempted[-1], attempted, ledger, request)
        return self._exhausted(attempted)

    def _answer(
        self,
        chosen: Attempted,
        attempted: Sequence[Attempted],
        ledger: RunLedger,
        request: Request,
    ) -> Response:
        body = chosen.served.body
        usage = _usage(body)
        if usage is not None:
            ledger.tokens_prompt += usage.get("prompt", 0)
            ledger.tokens_completion += usage.get("completion", 0)
        line = self._status_line(request)
        if line:
            body = inject_status_line(body, line)
        headers = {
            "X-Leeward-Outcome": str(chosen.served.outcome.outcome),
            "X-Leeward-Advice": str(chosen.served.outcome.advice),
            "X-Leeward-Tier": chosen.tier.name,
            "Content-Type": "application/json",
        }
        if len(attempted) > 1:
            headers["X-Leeward-Failed-Over-From"] = ", ".join(
                item.tier.name for item in attempted[:-1]
            )
        if line:
            headers["X-Leeward-Status-Line"] = line
        return Response(content=body, status_code=chosen.served.status, headers=headers)

    def _status_line(self, request: Request) -> str:
        """One line, only while something is degraded, and only if it was turned on."""
        asked = request.headers.get(SHOW_INJECTION_HEADER) == "1"
        if not (self.proxy.config.surfaces.llm.status_line.enabled or asked):
            return ""
        from leeward.api import degraded

        report = degraded(self.proxy)
        return status_line(report.down, report.stale)

    def _exhausted(self, attempted: Sequence[Attempted]) -> Response:
        """Every tier failed. The caller hears about the tier it asked for.

        Reporting the last one would mean the answer changes depending on how many
        fallbacks an operator happens to have configured, and the failure of a fallback
        the caller never named is not the one to act on.
        """
        asked = attempted[0]
        body = error_body(asked.served.outcome, asked.tier.name)
        error = cast("dict[str, object]", body["error"])
        error["tried"] = [item.tier.name for item in attempted]
        return JSONResponse(
            body,
            status_code=asked.served.status if asked.served.status >= 400 else 502,
            headers={
                "X-Leeward-Outcome": str(asked.served.outcome.outcome),
                "X-Leeward-Advice": str(asked.served.outcome.advice),
                "X-Leeward-Tier": asked.tier.name,
            },
        )

    async def _stream(
        self,
        request: Request,
        payload: Mapping[str, object],
        tiers: Sequence[Tier],
        run: RunRef,
    ) -> Response:
        """A streamed completion: fail over before the first byte, explain after it.

        Once a token has reached the client there is no failing over, because the client
        has half an answer already. What leeward can still do is notice the stream has
        stopped early and say so in the stream itself, as one more event, so the model's
        caller sees why the text ends where it does.
        """
        opened: Streamed | None = None
        tried: list[str] = []
        chosen: Tier | None = None
        failure: CallOutcome | None = None
        for tier in tiers:
            tried.append(tier.name)
            call = Call(
                "POST",
                _endpoint(tier),
                headers=_headers(tier, request),
                body=_with_model(payload, tier),
            )
            policy = resolve(self.proxy.config, CallTarget.parse(call.url))
            try:
                started = await self.proxy.transport.open(
                    call, policy, Deadline(self.proxy.clock() + policy.hard_deadline_s)
                )
            except EvidenceError as error:
                failure = self._stream_failure(tier, policy, run, error.evidence)
                continue
            if started.status >= 400:
                await started.aclose()
                failure = self._stream_failure(
                    tier, policy, run, Response_(started.status, dict(started.headers), b"")
                )
                continue
            opened, chosen = started, tier
            break

        if opened is None or chosen is None:
            body = error_body(failure or _no_outcome(), tried[0] if tried else None)
            cast("dict[str, object]", body["error"])["tried"] = tried
            return JSONResponse(body, status_code=502)

        return StreamingResponse(
            self._chunks(opened, chosen, run),
            status_code=opened.status,
            media_type=dict(opened.headers).get("Content-Type", "text/event-stream"),
            headers={"X-Leeward-Tier": chosen.name, "X-Leeward-Stream": "passthrough"},
        )

    async def _chunks(self, opened: Streamed, tier: Tier, run: RunRef) -> AsyncIterator[bytes]:
        policy = resolve(self.proxy.config, CallTarget.parse(_endpoint(tier)))
        try:
            async for chunk in opened.chunks():
                yield chunk
        except EvidenceError as error:
            outcome = self._stream_failure(tier, policy, run, error.evidence)
            yield _stream_error(outcome, tier.name)
        else:
            self._stream_ok(tier, policy, run, opened.received)
        finally:
            await opened.aclose()

    def _stream_failure(
        self, tier: Tier, policy: ResolvedPolicy, run: RunRef, evidence: Evidence
    ) -> CallOutcome:
        ledger = self.proxy.runs.ledger(run, self.proxy.clock())
        snapshot = RunSnapshot(
            now=self.proxy.engine.wall_clock(),
            retry_seconds_remaining=ledger.remaining(policy.endpoint).retry_seconds,
            clock=self.proxy.engine.clock_trust(),
        )
        classification = classify(evidence, policy, snapshot)
        self.proxy.breakers.record(
            policy.target.origin, policy.endpoint, classification, self.proxy.clock()
        )
        report = _one_attempt(classification, policy, self.proxy.clock())
        outcome = build(Outcome.DOWN, policy, report=report, ledger=ledger, now=self.proxy.clock())
        self.proxy.record(outcome, report, Surface.LLM, run, ledger, cache=CacheInfo(hit=False))
        return outcome

    def _stream_ok(self, tier: Tier, policy: ResolvedPolicy, run: RunRef, received: int) -> None:
        ledger = self.proxy.runs.ledger(run, self.proxy.clock())
        report = _one_attempt(OK, policy, self.proxy.clock())
        outcome = build(Outcome.FRESH, policy, report=report, ledger=ledger, now=self.proxy.clock())
        self.proxy.record(
            outcome,
            report,
            Surface.LLM,
            run,
            ledger,
            cache=CacheInfo(hit=False, bytes_served=received),
        )

    def _refusal(self, status: int, message: str) -> Response:
        return JSONResponse(
            {"error": {"message": f"[leeward] {message}", "type": "invalid_request_error"}},
            status_code=status,
            headers={"X-Leeward-Outcome": "DOWN"},
        )

    def _run_of(self, request: Request, payload: Mapping[str, object]) -> RunRef:
        """A conversation is a run: the same messages coming back means the same agent."""
        client = request.client
        return resolve_run(
            header=request.headers.get(RUN_HEADER),
            llm_messages=_messages(payload) or None,
            connection=f"{client.host}:{client.port}" if client is not None else None,
        )

    async def models(self, _request: Request) -> Response:
        """The tiers, in the shape a client expects a model list to take."""
        return JSONResponse(
            {
                "object": "list",
                "data": [
                    {
                        "id": tier.model,
                        "object": "model",
                        "owned_by": tier.name,
                        "created": 0,
                    }
                    for tier in tiers_of(self.proxy)
                ],
            }
        )


def mount_routes(proxy: Proxy) -> list[Route]:
    surface = ModelSurface(proxy)
    return [
        Route(CHAT_PATH, surface.chat, methods=["POST"]),
        Route("/v1/models", surface.models, methods=["GET"]),
    ]


def tier_warnings(config: Config) -> list[str]:
    """What an operator should hear at startup about the ladder they configured."""
    tiers = config.surfaces.llm.tiers
    warnings = [
        f"tier {tier.name}: {tier.api_key_env} is not set in the environment"
        for tier in tiers
        if tier.api_key_env and not os.environ.get(tier.api_key_env)
    ]
    names = [tier.name for tier in tiers]
    if len(set(names)) != len(names):
        warnings.append("two tiers share a name; the first one wins in the log")
    return warnings


def conversation_of(payload: Mapping[str, object]) -> str:
    """The run identity a conversation would get, for tests and for `leeward classify`."""
    return conversation_hash(_messages(payload))
