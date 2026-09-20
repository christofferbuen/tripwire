# Alert integrity: alerts that cannot be missed by lag or forged by a writer

2026-09-20. Four monitors can stay silent when they should fire, or fire on
data an owned sentinel wrote. No new features: the same alerts, made to hold.
Deployment (copy to the collector, `bootstrap-opensearch.sh`, enricher
restart) is a separate operator sitting, not part of this plan.

## Problems

1. **Lag eats alerts.** Monitors look at the last 5 to 30 minutes of
   `@timestamp` (when the visitor acted). `tripwire-returned`,
   `tripwire-novel-fingerprint` and `tripwire-novel-dropper` only match after
   the enricher has written something, and the enricher can be later than the
   window (slow reverse lookups, 200 sequential updates, a restart). The
   record then appears with an `@timestamp` already outside the window and no
   monitor ever sees it.
2. **The fingerprint scan loses new values.** `Enricher.fingerprints()` asks
   for the 1000 most frequent values over all time. New values are the rarest,
   so past 1000 distinct values they fall off the end. `fingerprint.http`
   hashes header names the client chooses, so its value space is unlimited:
   the book grows without bound and the monitor can fire on every pass.
3. **A writer can forge two alerts.** `tripwire-both` counts distinct
   `event.module`, a field the sender fills in; the sentinel's writer account
   can index a document that claims `receiver`. `first_seen()` in `enrich.py`
   trusts the same field, so a backdated sentinel document carrying the
   collector's own public address makes `tripwire-returned` fire on every
   heartbeat fetch.
4. **Bait reuse on the sentinel has no alert.** `bait.credential_used` is
   shipped and mapped; `tripwire-bait-used` watches the fake VM index only.

## Package (one builder, model: sonnet)

Fence: `alerts.py`, `enrich.py` (only `ensure_book`, `first_seen`,
`fingerprints`, constants, `selftest`), `droppers.py` (only the book mapping,
the entry written by the `_create` call, `selftest`). Nothing else. No commit,
no staging, no branch. Standard library only. Never read `.env`,
`*.local.*`, `*-secrets.json`. Another agent works in this tree: do not touch
`receiver.py`, `analyze.py`, `beelzebub/`, `agent-conversation-queue/`,
`compose*.yaml`, `bootstrap-opensearch.sh`.

### 1. `recorded`: when the book learned it

- `enrich.py` `ensure_book` and the dropper book mapping in `droppers.py:232`:
  add `"recorded": {"type": "date"}`. For a book that already exists, send
  `PUT /<book>/_mapping` with that one property on every start (idempotent;
  log a warning and carry on if it is refused).
- Every `_create` into `fingerprint-book` and `dropper-book` carries
  `"recorded": now_iso()` (the helper both modules already use).
  `@timestamp` keeps its meaning: first sighting.
- `alerts.py`: `tripwire-novel-fingerprint` and `tripwire-novel-dropper` use
  `time_field="recorded"` and gain one filter,
  `{"range": {"@timestamp": {"gte": "{{period_end}}||-24h", "format": "epoch_millis"}}}`,
  so a rebuilt book still stays quiet about last month's sightings. Documents
  written before this change have no `recorded` and never match: correct.
  Fix the two comments above those monitors to say this.
- `tripwire-returned`: `time_field="enrichment.at"` (mapped as `date` in the
  hits template already; the enricher stamps it once, in the same update that
  writes `prior.sentinel_hours`). Verify that in `enrich.py` before relying on
  it; if the two are written in different updates, report it instead of
  guessing.

### 2. `fingerprints()`: recent values, paged, bounded

- Replace the `terms` aggregation with a `composite` aggregation on the
  field, 1000 per page, following `after_key`, at most `FINGERPRINT_PAGES = 20`
  pages per kind per pass (log a warning when the cap is reached). Keep the
  `first` and `earliest` sub-aggregations as they are.
- Add a range filter `@timestamp >= FINGERPRINT_SCAN`, new constant
  `FINGERPRINT_SCAN = "now-6h"` with a comment: long enough to cover an
  enricher outage, short enough that the scan cost does not grow with the
  index. The first pass after start (`self.known_fingerprints` empty) runs
  without the range filter so a fresh or restored book is filled once.
- New constant `MAX_NEW_HTTP_PER_PASS = 50`: for kind `http` only, stop
  creating book entries after that many new ones in a pass and log one
  warning. `hassh` and `ja4` are never capped.
- `alerts.py`: `tripwire-novel-fingerprint` gains
  `{"terms": {"kind": ["hassh", "ja4"]}}`. The digest gets one line, "new
  header orders: N", counting `kind: http` documents with `recorded` in the
  digest period; follow how the digest counts droppers today.

### 3. Key on `_index`, not on `event.module`

- `tripwire-both`: replace the `cardinality` on `event.module` with two
  `filter` sub-aggregations under `by_ip`,
  `{"prefix": {"_index": "tripwire-hits-"}}` and
  `{"prefix": {"_index": "tripwire-sentinel-"}}`, trigger condition
  `params.hits > 0 && params.sentinel > 0` with `buckets_path`
  `{"hits": "hits>_count", "sentinel": "sentinel>_count"}`. (`prefix` on
  `_index` is already used by the digest and works on the live cluster.)
  Add `must_not` `{"term": {"http.user_agent": HEARTBEAT_AGENT}}` to the
  query so the collector's own heartbeat can never be half of a pair.
- `enrich.py` `first_seen`: same idea, a `filters` aggregation with the two
  prefixes named `sentinel` and `receiver`, each with the `min` on
  `@timestamp`. The returned dict keeps its keys (`first_seen_sentinel`,
  `first_seen_receiver`).
- `tripwire-returned`: add the same heartbeat `must_not`. `query_monitor`
  takes `filters` only; give it an optional `must_not=None` parameter rather
  than building this monitor by hand.

### 4. `tripwire-bait-used-sentinel`

New `query_monitor` next to `tripwire-bait-used`: `SENTINEL`,
`[{"term": {"bait.credential_used": True}}]`, severity "1", message lists
`source.ip`, country, `destination.port` or the port field the other sentinel
monitors print. The message must not print the credential or any request
text. Dormant until the bait is switched on; that is expected.

### Acceptance tests (planner-authored; implement exactly these)

`alerts.py` has only `--dump` today. Add `--selftest` (same dummy-env path
`--dump` uses, no network), wired like the other modules' selftests, asserting:

1. Monitor names are unique; every monitor that existed before this change
   still exists (hard-code the eleven names plus the new one).
2. `tripwire-novel-fingerprint`: window range is on `recorded`; filters
   contain the `kind` terms with exactly `hassh` and `ja4`; an `@timestamp`
   range with `-24h` is present. Same window and `-24h` checks for
   `tripwire-novel-dropper`.
3. `tripwire-returned`: window range on `enrichment.at`, sort on
   `enrichment.at`, heartbeat agent in `must_not`.
4. `tripwire-both`: the serialized monitor contains no `event.module`;
   both `_index` prefixes present; heartbeat agent in `must_not`.
5. `tripwire-bait-used-sentinel`: exists, severity "1", indices are the
   sentinel pattern, message template contains none of `http_body`,
   `http_requests`, `smtp_commands`, `payload`.
6. No monitor anywhere references `event.module` (`json.dumps(MONITORS)`).

`enrich.py --selftest` (extend, with the existing `StubOS` style):

7. `fingerprints()` paging: stub answers page one with 2 buckets and an
   `after_key`, page two with 1 bucket and none: three `_create` calls, each
   body has `recorded`, second search body carries the `after` key.
8. First pass has no range filter on `@timestamp`; a second call (known set
   non-empty) has `FINGERPRINT_SCAN`.
9. `http` cap: with `MAX_NEW_HTTP_PER_PASS` patched to 2 and 5 new `http`
   buckets, exactly 2 creates; 5 new `hassh` buckets, 5 creates.
10. `first_seen`: the search body contains no `event.module`; a canned
    `filters` response yields both `first_seen_*` keys.
11. `ensure_book` sends the `_mapping` call containing `recorded` when the
    book already exists.

`droppers.py --selftest` (extend):

12. The entry passed to `_create` has `recorded`, and `@timestamp` is still
    the event's timestamp, not now.

All three selftests, `python dashboards.py --selftest` and `python
sentinel.py --selftest` exit 0.

### Edge-case matrix

| axis | applies | note |
|---|---|---|
| fresh book / existing book without `recorded` | yes | old docs never alert; `_mapping` put on start |
| enricher down for hours, then back | yes | the case this fixes: `recorded` is now, `@timestamp` within 24 h |
| enricher down for more than 24 h | accepted | sightings older than a day stay quiet; they are in the book and the digest |
| book rebuilt from scratch | yes | first pass unfiltered, `-24h` filter keeps old sightings quiet |
| owned sentinel writing forged documents | yes | cannot write to `tripwire-hits-*` (role scope), so `_index` is trustworthy |
| heartbeat traffic | yes | excluded from `both` and `returned` |
| read-only (ISM) indices | no | nothing here updates event documents in a new way |
| bait switched off (today) | yes | new monitor is dormant, must still create cleanly |
| more than 20000 distinct values in 6 h | accepted | page cap logs a warning; that is a flood and the volume monitor's job (later package) |

### Walkthrough (operator)

- **Discover:** `CLAUDE.md` monitor list gains `bait-used-sentinel`
  (orchestrator edits that file after landing). Nothing else changes name.
- **Input:** none; after deploy, `./bootstrap-opensearch.sh` recreates the
  monitors and the enricher restart picks up the rest.
- **Feedback:** `podman logs tripwire-enricher` shows `new fingerprint ...`
  as before; the digest has the new "new header orders" line; Discover on
  `fingerprint-book` shows `recorded` next to `@timestamp`.
- **Failure:** a refused `_mapping` put or a reached page cap is one warning
  line in the enricher log naming the book or the kind. Knobs:
  `FINGERPRINT_SCAN`, `FINGERPRINT_PAGES`, `MAX_NEW_HTTP_PER_PASS`.

### Report

What changed (`path:line`), the exact test commands and results, and every
deviation from this plan with its reason.

## Not in this package

Egress events on their own alias and a volume monitor before the 1 GB cap;
ntfy message size (`*_short` fields from Vector); forward-confirmed PTR;
429 handling in reputation lookups. Each is its own small plan.
