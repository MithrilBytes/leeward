# leeward

A proxy that sits between your agent and everything it calls, so that a failure arrives as a usable answer instead of an error string.

An agent that calls a tool and gets back `Error: request failed` cannot tell a timeout worth retrying from a tool that no longer exists. So it retries both, spends its budget on the one that was never coming back, and ends the run with nothing to say. leeward stands in front of the call. It classifies what went wrong, decides whether waiting could possibly help, and answers with the last good copy where that is honest, or with a short note that says what is missing and what to do instead. Nothing in the agent changes: you point it at a different address.

## The three failures it fixes

**The wedged call.** A request that connects and then hangs holds the run open until something else gives up. leeward returns at the hard deadline with the failure classified, and refuses the next call to that endpoint without touching the network.

**The vanished tool.** An MCP server is redeployed and a tool it used to offer is gone. The server reports that the same way it reports a tool that crashed, so agents retry it. leeward confirms the tool has left `tools/list`, answers once with `TOOL_GONE`, and marks it permanent for the run.

**The permanent 429.** `Retry-After: 3600` inside a run with two minutes left is not a wait, it is a no. leeward spends one attempt on it and tells the rest of the run to stop asking.

## Measured

From a real run against a local fake origin and a fake MCP server, on a MacBook Pro with Apple silicon. The script arms each failure and reports what came back.

| Case | Result | Time | Attempts | Calls that reached the origin |
| --- | --- | --- | --- | --- |
| Origin hangs after connecting | `DOWN{WEDGED}`, 504, `DO_NOT_RETRY` | 30.01 s (hard deadline 30 s) | 2 | 2 |
| Same endpoint, next call | `DOWN{BREAKER_OPEN}` carrying `WEDGED` | 1.2 ms | 0 | 0 |
| 429 with `Retry-After: 3600` | `DOWN{QUOTA_EXHAUSTED}`, `DO_NOT_RETRY` | 8 ms | 1 | 1 |
| Static page, origin killed | `STALE`, 200, `PROCEED_WITH_CAUTION` | 0.3 ms | 0 | 0 |
| Live endpoint, origin killed | `DOWN`, 503, `TREAT_AS_UNKNOWN` | 102 ms | 2 | 2 |
| MCP tool removed mid session | `TOOL_GONE`, `isError`, `DO_NOT_RETRY` | 7.6 ms | 1 | 1 |
| Same tool, next call | `BREAKER_OPEN` carrying `TOOL_GONE` | 0.3 ms | 0 | 0 |

The suite is 392 tests, about 5 seconds, on Python 3.11 and 3.13, Linux and macOS.

## What a note looks like

Notes are what the model reads. They are capped at 400 characters, always prefixed, and never contain content from the origin. These three are verbatim from the run above.

```text
[leeward] STALE: served a copy stored 106ms ago because 127.0.0.1 is unreachable
(CONNECT_REFUSED). This endpoint is classified `static`, so the copy is very likely
still accurate. Retrying will not help until connectivity returns.

[leeward] DOWN: the tool `threat_intel_lookup` is gone from its MCP server (intel).
This is permanent for this run; further attempts will not succeed. Other tools on
this server are unaffected.

[leeward] DOWN: 127.0.0.1 returned nothing (WEDGED after 30s, 2 attempts). Retrying
will not help until connectivity returns.
```

Beside every note, machine readers get the same decision as structured data: the outcome, the failure class, the advice, the age of anything served, and what was withheld.

## The live guarantee

Some values are only worth having if they are current. A wind reading from 40 minutes ago is not a wind reading, and an agent that treats it as one is worse than an agent that admits it does not know.

Mark those endpoints `class: live` and leeward will never serve them from cache, however badly the origin is failing. It says so, and it names the copy it is holding back rather than pretending none exists:

```text
[leeward] DOWN: 127.0.0.1 returned nothing (CONNECT_REFUSED after 102ms, 2 attempts).
This endpoint is classified `live`: a cached value from 0s ago exists but is not being
served, because only the current value is meaningful here. Treat this value as unknown
and say so rather than estimating it.
```

No configuration option, request header or tool argument overrides this. Three independent places enforce it: the policy layer refuses to build a stale allowance for a live endpoint, the serving path checks again before it hands anything back, and the event log refuses to record a stale serve of a live endpoint at all. A property test asserts it across generated policies and cache states.

## Wiring

One line of configuration per mode, and the agent is unchanged.

**A. MCP servers.** leeward fronts each configured server at its own path, with the same tool names.

```yaml
surfaces: {mcp: {enabled: true, servers: {notes: {transport: stdio, command: ["python", "-m", "notes_server"]}}}}
```

Point the client at `http://127.0.0.1:8787/mcp/notes`.

**B. HTTP tools.** Give a tool a base URL that leads to a mount.

```yaml
surfaces: {fetch: {enabled: true, mounts: {wiki: "https://en.wikipedia.org"}}}
```

`GET http://127.0.0.1:8787/wiki/wiki/Foo` fetches the article, with `X-Leeward-Outcome`, `Age` and the note on the response.

**C. Everything else over HTTPS** is planned through a forward proxy on its own port, set with `HTTPS_PROXY`. A tunnel cannot see inside TLS, so that mode classifies failures and never caches. Not built yet.

**D. Model calls** are planned as an OpenAI compatible base URL, with tier failover and transport failures shaped like the API's own errors. Not built yet.

`leeward.example.yaml` has the full set of knobs with comments.

## How it decides

Deterministically, and it will show its work. There is no model in the data path.

- **Classification.** Twenty failure classes, each derived from evidence rather than from a string match on the exception: DNS response codes, refused connections, TLS validation with a clock check, deadlines, HTTP status with rate limit headers, JSON-RPC codes, tool listings. `leeward classify <url|tool>` prints the policy and the rule that decided each part, without touching the network.
- **Disposition.** Every failure is `TRANSIENT`, `WAIT`, `NEVER` or `UNKNOWN`, with a scope: this request, this endpoint, this host, this run. A `NEVER` is remembered at its scope, so one refusal answers the rest of the run.
- **Attempts.** Decorrelated jitter backoff, a hedge at the soft deadline for calls that are safe to duplicate, and a per run budget on retries that cannot be exceeded.
- **Cache.** The subset of RFC 9111 that matters here, plus `stale-if-error` and `stale-while-revalidate` from RFC 5861, with per class limits on how old a copy may be. Bodies are content addressed and verified on read. Identical in flight requests collapse into one.
- **Breakers.** Per endpoint and per host, opened immediately by a `NEVER`, with half open backoff. A short circuit reports the original failure class, not a generic one.

Every outcome is an event in a JSONL log with credentials redacted, and `/leeward/status` and `/leeward/forecast` answer from local state, so they still work when everything they describe is unreachable.

## What this is not

It is not a browser cache, not a service mesh, and not a retry library. A caching proxy in front of an agent will happily serve a stale weather reading; leeward's whole point is knowing which values may be stale and which may not. A retry library lives inside the process and has to be wired into every call site; leeward is an address. A mesh does this well for services you own, at an operational cost that a laptop agent will not pay, and it does not speak MCP. If you already run a mesh for your services, the overlap is real and you should weigh it.

## Quickstart

```bash
pip install -e .
leeward init
leeward classify https://en.wikipedia.org/wiki/Northeast_blackout_of_2003
```

Not on PyPI yet.

## Status

Working today: configuration and policy resolution, the classifier, breakers, budgets, deadlines and attempts, the cache and its freshness rules, notes and outcomes, the event log, the MCP surface, the HTTP surface, status and forecast, and fault injection for testing.

Not built yet: the warmer and its corpora, the model surface, the forward proxy, the reporting command, most of the CLI, and the recorded demo. The numbers above will be regenerated by that demo when it lands.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
