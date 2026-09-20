# Cheap safety fixes: three memory and availability bounds

2026-09-20. Three small, independent changes that stop one remote client from
killing or stalling a sensor. No new features, no new event fields beyond two
values of an existing one, **no change to any byte a well-behaved client
receives**. Deployment to the hosts is not part of this plan; that stays with
the operator.

Shared rules for every package

- Edit only the files in your fence. Do not touch anything else, including
  `agent-conversation-queue/`, `AGENTS.md`, `.containerignore`, `docs/`.
  Another agent (Codex) works in this tree at the same time.
- Do **not** commit, stage, branch or stash. Leave the change in the working
  tree; the orchestrator reviews the diff.
- Standard library only. Match the surrounding comment style: comments say
  why, in plain sentences.
- Never read `.env`, `*.local.*`, `*-secrets.json`.
- Finish with a report: what changed (`path:line`), the exact test commands
  run and their result, and **every deviation from this plan with the reason**.

## Package A: `sentinel.py` (model: sonnet)

Fence: `sentinel.py` only.

Read the module header first. `_selftest_wire` / `WIRE_GOLDEN` must pass
unchanged; if your change makes it fail, the change is wrong, not the golden.

### A1. Read POST bodies in chunks (`do_http`, around line 1179-1191)

Today: `length = min(content-length, 1 << 20)` then `reader.readexactly(length)`.
512 connections x 1 MiB against `mem_limit: 256m` is an OOM kill. `TlsStream`
also has no `readexactly`, so the same line silently fails on 443.

Change: keep the `min(..., 1 << 20)` cap and everything after the read as it
is. Replace the single `readexactly` with a loop:

```python
kept, got = b"", 0
deadline = time.monotonic() + TIMEOUTS["http_header"]
with contextlib.suppress(Exception):
    while got < length:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        chunk = await asyncio.wait_for(
            reader.read(min(READ_LIMIT, length - got)), timeout=left)
        if not chunk:
            break
        got += len(chunk)
        if len(kept) < 4096:
            kept += chunk[:4096 - len(kept)]
body = kept
```

`note["bytes_received"]` must add `got`, not `len(body)`. `http_body` and the
`bait_hit` call keep using the first 4096 bytes, which is all they used
before. Peak memory per connection becomes `READ_LIMIT` + 4096.

### A2. Per-address connection cap (`handle`, around line 1454)

New constant next to `MAX_CONCURRENT`:

```python
MAX_PER_ADDRESS = 32       # concurrent connections from one address
```

`self.per_address: dict[str, int] = {}` in `__init__` next to `open_conns`.
In `handle`: increment on entry, and in the existing `finally` decrement and
`pop` the key at zero (the dict must not grow). When the count exceeds
`MAX_PER_ADDRESS`, emit the same event shape as the `shed-load` branch with
`"outcome": "shed-address"` and return. Check it **after** the
`MAX_CONCURRENT` check, before `tracker.note`.

### A3. Total deadline per handler (`handle`, around line 1480)

New table under `TIMEOUTS`, with a comment that these are backstops above
every legitimate flow, not protocol values:

```python
DEADLINES = {
    "ssh": 250.0,     # two 120 s waits plus slack
    "http": 600.0,
    "https": 600.0,
    "smtp": 900.0,
    "mysql": 60.0,
    "other": 120.0,
}
```

Wrap the dispatch in `asyncio.wait_for(<handler coroutine>,
timeout=DEADLINES.get(role, DEADLINES["other"]))`. On `asyncio.TimeoutError`
set `note["outcome"] = "deadline"` and carry on to build the event: `note` is
mutated in place, so what the client said before the deadline is kept. The
existing `contextlib.suppress(Exception)` must still swallow every other
handler error. The `hold` sleep stays outside the deadline.

### Acceptance tests (add to the existing selftest, same style as its neighbours)

1. Body bound: feed `do_http` a `POST / HTTP/1.1` with `Content-Length:
   1048576` and a 1 MiB body whose first bytes are `A=1&` followed by filler.
   Assert `note["http_body"]` is 4096 characters starting `A=1&`,
   `note["bytes_received"] >= 1048576`, and the response bytes equal what the
   same request with a 10-byte body gets (405 today).
2. Short body: `Content-Length: 100`, client sends 10 bytes and closes.
   Assert no exception, `http_body` holds the 10 bytes, an event is produced.
3. Per-address cap: with `MAX_PER_ADDRESS` patched to 2, three concurrent
   connections from one address: the third gets `outcome == "shed-address"`
   and zero bytes; after all close, `per_address` is empty.
4. Deadline: `DEADLINES["ssh"]` patched to 0.2, a client that connects to the
   SSH role and sends nothing: event has `outcome == "deadline"`, handler
   returns in under 2 s.
5. `WIRE_GOLDEN` passes untouched. `python sentinel.py --selftest` exits 0.

### Edge-case matrix

| axis | applies | note |
|---|---|---|
| plain stream / `TlsStream` (443, dormant) | yes | A1 must use only `read`, which both have |
| first contact / returning / sweeping address | yes | cap and deadline are independent of `tracker`; hold unchanged |
| shutdown with connections open | yes | `finally` must still decrement both counters on `CancelledError` |
| IPv6 | no | no listener yet |
| MySQL role | yes | deadline only; not deployed |
| Vector / mappings | no | `outcome` already exists as a field; no new fields |

## Package B: fake SSH output bound (model: sonnet)

Fence: `beelzebub/engine/shell.go`, `beelzebub/engine/shell_test.go`.

Today `cat a a a ...` (input limit 16384 bytes, files up to 16384 bytes each)
builds roughly 128 MiB in a `strings.Builder` before anything trims it; the
engine is OOM-killed and the host key regenerates on restart.

Change:

```go
const maxOutput = 65536 // bytes one exec line may produce
```

1. `builtin`, case `"cat"` (line 343): before `out.WriteString(n.Data)`, if
   `out.Len()+len(n.Data) > maxOutput`, write only what fits and return.
2. `run` (line 486): after a chunk's text has been appended to `out`, if
   `out.Len() >= maxOutput`, stop executing further chunks and return what is
   there, truncated to `maxOutput`. Otherwise `cat a a a a; cat a a a a; ...`
   gets around the per-command bound.
3. Check the other builtins that repeat input into output (`echo`, `ls`,
   `head`/`tail` if present) against the same limit; report what you found
   even if nothing needed changing.

Status code and the virtual filesystem must be what they were for every
command that did run.

### Acceptance tests (`shell_test.go`, names must start `TestVirtual` so the Containerfile gate runs them)

1. `TestVirtualCatOutputBounded`: write a 16000-byte file with the shell's own
   redirection, run `cat f f f ...` with as many arguments as fit in 16000
   bytes of input: `len(output) <= maxOutput`.
2. `TestVirtualChainOutputBounded`: `cat f f f f;` repeated to the input
   limit: `len(output) <= maxOutput`.
3. `TestVirtualCatSmallUnchanged`: `cat a b` on two small files returns the
   exact concatenation, status 0.
4. Existing tests stay green: `go test` with the same `-run
   'TestVirtual|TestTripwire'` filter the Containerfile uses. `go` is
   installed locally; the tests live in an overlay on upstream Beelzebub, so
   read `beelzebub/build-engine.py` and `beelzebub/engine/README.md` for how
   the overlay is assembled and use that path. If the tests can only run
   inside the container build, say so and run that.

### Edge-case matrix

| axis | applies | note |
|---|---|---|
| exec request / interactive PTY | yes | both go through `run` |
| redirection `>` / `>>` of a large `cat` | yes | file quota at `shell.go:218` already bounds the write; do not loosen it |
| model fallback commands | no | reply size is bounded by the gateway |
| `&&` / `\|\|` chains | yes | test 2 covers `;`; the break applies to all separators |

## Package C: one failed lookup must not abort the pass (model: haiku)

Fence: `enrich.py` only.

`fetch()` (line 184) returns HTTP errors but raises on everything else
(`URLError`, timeout, connection reset, bad JSON further up). `cycle()` (line
985) runs `pool.map(self.lookup, ips)`, which re-raises the first exception
and throws away the whole pass.

Change, in `class Enricher`, directly above `cycle`:

```python
def lookup_safe(self, ip_text):
    """One address failing must not cost the others their pass."""
    try:
        return self.lookup(ip_text)
    except Exception as e:
        log.warning("lookup failed for %s: %s", ascii(ip_text), e)
        return None
```

and in `cycle` use `pool.map(self.lookup_safe, ips)`. The existing `if e`
filter already drops `None`. Nothing else changes: do not touch `fetch`, its
callers, or `checked` stamping.

### Acceptance test (add to `selftest()`, line 1031, same style as its neighbours)

Build an `Enricher` the way the selftest already does (or the smallest stub
that works), replace `lookup` with a function that raises `OSError` for one
address and returns `{"ip": ip}` for two others, call the same
`ThreadPoolExecutor` expression `cycle` uses with `lookup_safe`: assert two
entries come back and no exception escapes. `python enrich.py --selftest`
exits 0.

### Edge-case matrix

| axis | applies | note |
|---|---|---|
| OpenSearch down | yes | every lookup fails, pass yields zero entries, loop survives (outer `except` at line 1017-1026 already exists) |
| third-party API timeout | yes | the case this fixes |
| attacker-controlled text in the log line | yes | hence `ascii()` |

## Walkthrough (operator, there is no end-user surface)

- **Discover:** nothing to find until it fires. `CLAUDE.md` gets no new
  section; the constants are self-describing at the top of `sentinel.py`.
- **Feedback when it works:** Discover on `tripwire-sentinel-*`, filter
  `outcome: shed-address` or `outcome: deadline`. A burst of either from one
  address is somebody trying to blind the sensor. Enricher: `podman logs
  tripwire-enricher` shows `lookup failed for ...` and the pass still ends
  with its `pass: N addresses` line.
- **Failure:** fake SSH output that hits the bound is cut mid-file with no
  message, as a real terminal that was closed would. Tweakable knobs:
  `MAX_PER_ADDRESS`, `DEADLINES`, `maxOutput`.

## After landing (orchestrator)

Diff read of each package against this plan; rerun `python sentinel.py
--selftest`, `python enrich.py --selftest`, the Go tests; then the operator
decides on commit and on the two host sittings (sentinel rebuild, enricher
restart).
