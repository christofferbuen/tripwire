# M: mappings, monitors, dashboards, wiring, docs

Read `2026-09-19-wave1-overview.md` first.

**Owner files:** `bootstrap-opensearch.sh`, `dashboards.py`, `alerts.py`,
`compose.yaml`, `README.md`, `CLAUDE.md`.
**Done by:** the orchestrator, after A1, B1, B2, C and D have landed and
each diff has been read against its plan. These are the shared hot files;
keeping them in one pair of hands is why the other fences could be disjoint.

Order inside this package: mappings first and deployed first. A new field
that reaches the cluster before its mapping is dynamically typed, and a
wrong type cannot be changed without a reindex.

## 1. `bootstrap-opensearch.sh`

Every field below goes in **both** the index template and the live-index
`PUT /tripwire-*/_mapping` block.

| field | mapping |
|---|---|
| `network.rtt_ms`, `network.rttvar_ms`, `network.geo_km`, `network.rtt_floor_ms` | `float` |
| `network.mss` | `integer` |
| `network.rtt_verdict` | `keyword` |
| `proto_mismatch` | `keyword` |
| `smtp.helo` | `keyword`, `ignore_above: 256` |
| `smtp.mail_from`, `smtp.rcpt` | `keyword`, `ignore_above: 320` |
| `smtp.auth_user`, `smtp.auth_pass` | `keyword`, `ignore_above: 128` |
| `smtp.starttls`, `http.host_foreign`, `bait.credential_used`, `threat.proxy_probe`, `threat.tor`, `dropper.scanned` | `boolean` |
| `bait.served`, `threat.exploit`, `threat.fake_crawler`, `source.hosting` | `keyword` |
| `dropper.urls` | `keyword`, `ignore_above: 512` |
| `dropper.hosts` | `keyword`, `ignore_above: 256` |
| `egress.dst_ip` | `ip` |
| `egress.dst_port`, `egress.uid`, `egress.count` | `integer` |
| `egress.proto`, `egress.scope` | `keyword` |
| `reputation.internetdb.ports` | `integer` |
| `reputation.internetdb.tags`, `reputation.internetdb.hostnames` | `keyword` |
| `reputation.internetdb.vulns_count`, `reputation.dshield.count`, `reputation.dshield.attacks`, `reputation.otx.pulses` | `integer` |
| `reputation.dshield.last_seen` | `keyword` (their date format is not ours to trust) |

`dropper-book` is created by `droppers.py` itself, as `address-book` is by
the enricher. The `self` document's `scope` and `honeypot_tagged` fields are
added to `BOOK_MAPPING` by B1; check that they were.

## 2. `alerts.py`

| monitor | index | fires when | channel |
|---|---|---|---|
| `tripwire-egress` | sentinel | any `classification: egress-blocked` in the last 5 min. Message: destination, port, uid, count. No throttle beyond 10 min: this is the one alert that means the VM is owned | high |
| `tripwire-honeypot-tagged` | `address-book` | doc `self` has `honeypot_tagged: true`. Throttle 24 h | high |
| `tripwire-novel-dropper` | `dropper-book` | a doc with `@timestamp` in the last 10 min. Message uses `url_defanged` only. Noisy for the first days, like `novel-fingerprint` | high |

Both book monitors use the existing "skip a monitor whose index does not
exist yet" path.

Digest additions, one line each: new dropper locations in 24 h; events with
`proto_mismatch`; addresses with `network.rtt_verdict: impossible` or
`detour`; top `threat.exploit`.

`python alerts.py --dump` with the dummy env must list the three new
monitors and still exit 0.

## 3. `dashboards.py`

Visualisations: "Spoke the wrong protocol" (terms on `proto_mismatch`, split
by port); "Exploits named" (`threat.exploit`); "RTT verdicts"
(`network.rtt_verdict`); "EHLO names" (`smtp.helo`); "Hosting kind"
(`source.hosting`); "Proxy probes over time".

Saved searches:

- "Droppers": `dropper.urls:*`, columns `source.ip`, `dropper.urls`,
  `threat.exploit`, `source.as.organization_name`.
- "Unlabelled": spoke, and carries no `threat.tool`, no `threat.exploit`, no
  `threat.scanner`. This is the reading list: whatever is in it is either
  new or a gap in the tables.
- "Residents": addresses active on many distinct days. Dashboards cannot
  count distinct days per address in a saved search, so this is a table
  visualisation: terms on `source.ip` ordered by a cardinality of a day
  bucket. If that proves impossible without a scripted field, say so in the
  README and leave it to `campaigns.py` in wave 2.
- "SMTP identities": `smtp.helo:*`, columns `smtp.helo`, `smtp.mail_from`,
  `smtp.rcpt`, `smtp.auth_user`, `smtp.auth_pass` (empty until A2).
- "Egress attempts": `classification:egress-blocked`.

All added to `LAYOUT` below the existing rows; nothing existing moves.

## 4. `compose.yaml`

Enricher service, one line next to the existing single-file mount:
`- ./droppers.py:/app/droppers.py:ro,Z`. Nothing else. No new published
port, no network change.

## 5. Docs

`README.md`: a section per feature, in the README's voice: what it
observes, what it cannot conclude. Must state plainly: RTT tests the GeoIP
claim, not who is behind a proxy; dropper locations are never fetched; the
opt-in lookups send attacker addresses to third parties and are off by
default; what the egress alert means and what to do when it fires (snapshot
the VM from the cloud console, then destroy it; do not log in to look
around first).

`CLAUDE.md`: the payload table gains the new fields; "Changing things"
gains `./test-vector.sh`, `python droppers.py --selftest`,
`harden-sentinel.sh --check` and the `--build-window` step before a
rebuild on the VM; "Monitors" gains the three new ones; the roadmap loses
what is done.

## Deploy order

1. Collector: copy, strip CRLF, `./bootstrap-opensearch.sh`. Verify with
   `GET /tripwire-sentinel-*/_mapping/field/network.rtt_ms` that the type is
   `float` on the live index.
2. Collector: `vector.toml` (C), stop/start Vector. `enrich.py`,
   `droppers.py`, compose change: `podman compose up -d enricher`. Check the
   start-up log lines B1 and B2 specify.
3. VM: D's procedure, in full, with the operator.
4. VM: `vector-sentinel.toml` (C), stop/start. Then `sentinel.py` (A1) with
   A1's before/after `nmap` check, inside a `--build-window`.
5. After an hour: every new field has at least one document, or a known
   reason why not. `python alerts.py --dump` on the collector; trigger the
   egress alert once more end to end.

## Acceptance

- `bash -n bootstrap-opensearch.sh`; `python alerts.py --dump`; `python
  dashboards.py` produces valid NDJSON (each line parses).
- Every field in the overview's contract appears in both mapping blocks
  (a ten-line Python check over the script's text; keep it as
  `--selftest`-style assertion in `dashboards.py` or throw it away, but run
  it).
- Step 5 above.

## Edge-case matrix

| axis | applies | note |
|---|---|---|
| bootstrap rerun | yes | idempotent today; stays so |
| today's index already has a dynamic mapping for a new field | yes | only if deploy order was broken; fix is to wait for the daily rollover, not to reindex |
| monitors on indices that do not exist yet | yes | existing skip path |
| fresh cluster | yes | template covers it |
| Dashboards import overwriting operator edits | yes | same behaviour as today; say so in the README |
