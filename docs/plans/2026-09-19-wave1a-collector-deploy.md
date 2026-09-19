# Wave 1a, sitting 1: the collector

Runbook for one sitting with the operator present. Every step that touches
the host is proposed, approved, then run; nothing here is a script to paste
whole. `<collector>` is the SSH alias from the private notes, the account is
the unprivileged one that owns `~/tripwire`. No hostname, address or secret
belongs in this file.

Code: `main` at the commit that contains "Give an existing book the fields
it has not got", full suite green (see `CLAUDE.md`, "Changing things").

## Why the collector goes first

The sentinel's new fields (`network.*`, `proto_mismatch`, `smtp.*`,
`http.host_foreign`) must have a mapping before the first event that carries
them arrives. A field that reaches an index first is mapped by guess, and a
guess cannot be changed until that day's index rolls over. So: mappings,
then the things that write. The sentinel VM is sitting 2.

## What this sitting does not do

- Nothing on the sentinel VM: no `sentinel.py`, no `vector-sentinel.toml`,
  no `compose.sentinel.yaml`, and `harden-sentinel.sh` stays unapplied.
- No opt-in lookups. `ENRICH_LOOKUPS` stays unset unless the operator
  decides otherwise in step 4.
- No push. `main` is pushed after step 9 agrees with the code.

## What will be visible afterwards, and what will not yet

| visible after this sitting | dormant until sitting 2 |
|---|---|
| `dropper.urls` on stored payloads, `dropper-book`, saved searches "Droppers" and "Dropper ledger: first seen" | panels "Spoke the wrong protocol", "SMTP: EHLO names", "RTT against GeoIP", "Proxy probes": empty |
| `source.hosting`, `threat.tor`, `threat.fake_crawler` on new events; panel "Hosting kind" | `threat.exploit` on sentinel events (that table lives in `vector-sentinel.toml`) |
| `threat.exploit` on receiver hits (collector `vector.toml`) | `tripwire-egress` can never fire: nothing produces egress events |
| monitors `tripwire-novel-dropper`, `tripwire-egress`; three new digest lines | `tripwire-honeypot-tagged` (needs `internetdb` opted in and `SENTINEL_PUBLIC_IP`) |

An empty panel in the right-hand column is correct, not a failure.

## A helper for reading the cluster

Read-only, reads `.env` itself so no secret reaches a command line or the
shell history. Attacker strings come back through `json.dumps`, which
escapes control characters; still, do not paste results anywhere that
renders links.

```bash
cd ~/tripwire
osq() { python3 - "$@" <<'PY'
import base64, json, ssl, sys, urllib.request
env = dict(l.strip().split("=", 1) for l in open(".env") if "=" in l and not l.startswith("#"))
pw = env["OPENSEARCH_INITIAL_ADMIN_PASSWORD"].strip("'\"")
url = "https://%s:9200%s" % (env.get("ADMIN_BIND", "127.0.0.1").strip("'\""), sys.argv[1])
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request(url, headers={
    "Authorization": "Basic " + base64.b64encode(("admin:" + pw).encode()).decode()})
try:
    raw = urllib.request.urlopen(req, context=ctx, timeout=20).read()
except urllib.error.HTTPError as e:  # a 404 is an answer, not a crash
    raw = b'{"http_status": %d, "body": %s}' % (e.code, json.dumps(e.read().decode("ascii", "backslashreplace")[:2000]).encode())
try:
    print(json.dumps(json.loads(raw), indent=1)[:6000])
except ValueError:
    print(raw.decode("ascii", "backslashreplace")[:6000])
PY
}
```

GET only. It is a shell function for this sitting, not a file to keep.

## Steps

### 1. Look before touching (read-only)

```bash
podman ps --format '{{.Names}} {{.Status}}'
df -h ~ | tail -n 1
osq '/_cat/indices/tripwire-*,address-book*,fingerprint-book*,dropper-book*?h=index,docs.count,store.size&s=index'
```

Expect five containers up, `dropper-book` absent (wildcards, so a missing
index is an empty line and not a 404).

Field head-room. The template goes from 250 to 300 fields and maps 147 by
name; what matters is how many fields today's indices already hold:

```bash
osq '/tripwire-sentinel-*/_field_caps?fields=*' | python3 -c "import json,sys; print(len(json.load(sys.stdin)['fields']))"
```

Pass: under 200. Between 200 and 250: go on, note it. Over 250: stop, find
which dynamic fields grew (that is an attacker-driven field explosion and a
finding of its own) before raising any limit.

None of the new fields may exist yet with a guessed type:

```bash
osq '/tripwire-*/_mapping/field/network.rtt_ms,proto_mismatch,smtp.helo,dropper.urls,egress.uid'
```

Pass: every index answers with empty `mappings`. A hit means something
already wrote that field; note index and type, and expect the live
`_mapping` step to warn for that index until it rolls over.

### 2. Make sure the host copy is the one we think it is

The files about to be replaced must be the repo's previous version. From
the workstation, in the repo:

```bash
for f in enrich.py alerts.py dashboards.py bootstrap-opensearch.sh setup-logging.sh compose.yaml vector.toml; do
  printf '%s  %s\n' "$(git show 6b78a71:$f | tr -d '\r' | sha256sum | cut -c1-64)" "$f"
done
```

On the collector: `cd ~/tripwire && sha256sum enrich.py alerts.py dashboards.py bootstrap-opensearch.sh setup-logging.sh compose.yaml vector.toml`.

Any mismatch is an edit made on the host. Stop, `diff` it, carry the edit
into the repo or decide to drop it. `compose.yaml` is the likely one.

### 3. Backup, copy, strip CRLF, verify

```bash
# collector
cd ~/tripwire && mkdir -p ../tripwire-backup-wave1a && cp -a enrich.py alerts.py dashboards.py bootstrap-opensearch.sh setup-logging.sh compose.yaml vector.toml ../tripwire-backup-wave1a/
```

```bash
# workstation
scp enrich.py droppers.py alerts.py dashboards.py bootstrap-opensearch.sh setup-logging.sh compose.yaml vector.toml <collector>:tripwire/
```

```bash
# collector
cd ~/tripwire && sed -i 's/\r$//' enrich.py droppers.py alerts.py dashboards.py bootstrap-opensearch.sh setup-logging.sh compose.yaml vector.toml
chmod +x bootstrap-opensearch.sh setup-logging.sh
python3 enrich.py --selftest && python3 droppers.py --selftest && python3 dashboards.py --selftest && bash -n bootstrap-opensearch.sh && bash -n setup-logging.sh
```

Then the same comparison as step 2, against `main` this time and with
`droppers.py` in the list (`git show main:$f | tr -d '\r' | sha256sum` at
the workstation, `sha256sum` on the host). Every line must agree: that is
what lets step 6 trust the workstation's Vector tests.

Pass: three times `selftest ok`. The enricher selftest prints two "cannot
update mapping" warnings on purpose. Running containers still see the old
files: `sed -i` writes a new inode, a bind mount keeps the old one until the
container is restarted. Nothing has changed for the running system yet.

### 4. `.env`: coordinates, and the lookup decision

Optional, by hand in an editor, never through `echo` on a command line:

- `SENTINEL_LAT`, `SENTINEL_LON`: the data centre's city is precise enough.
  Without them the RTT verdict is skipped and the enricher says so once.
- `ENRICH_LOOKUPS`: leave unset. Each name in it sends every visitor's
  address to that third party.

Then `./setup-logging.sh` (re-renders `vector-secrets.json`, mode 600; it
does not generate a new password when `.env` has one). Check with
`python3 -c "import json; print({k: type(v).__name__ for k, v in json.load(open('vector-secrets.json')).items()})"`:
key names and types only, never values. Pass: every type is `str`. Vector
reads the same file and refuses all of it, password included, if one value
is a number or a list. The first sitting found that the hard way: the
coordinates were written as floats, and Vector did not come back in step 6
until the renderer was fixed (`7395092`; `test-vector.sh` now renders its
secrets with the real `setup-logging.sh`, so this is caught at the
workstation).

### 5. Mappings, dashboards, monitors: first bootstrap

```bash
./bootstrap-opensearch.sh 2>&1 | tee ../bootstrap-wave1a-1.log
```

Pass: "open indices: mappings updated" (a WARNING line there is the case
step 1 predicted, and only that), "dropper-book index not there yet ...
pattern skipped", the dashboards import with exactly one error
(`missing_references` for `tw-search-ledger`, which needs the `dropper-book`
pattern; step 8 brings it in), and the monitor for `dropper-book` reported
as skipped: the index does not exist yet.

```bash
osq '/tripwire-sentinel-*/_mapping/field/network.rtt_ms,egress.uid,egress.dst_ip'
```

Pass: `float`, `long`, `ip`.

### 6. Collector Vector: stop, start

The config was tested at the workstation (`./test-vector.sh` runs Vector's
own unit tests against it), and step 3 proved the host has the same bytes.
It is not validated again here: that needs the secrets file mounted into a
second container, and going back is one `cp`.

```bash
podman stop tripwire-vector && podman start tripwire-vector
podman logs --since 2m tripwire-vector 2>&1 | tail -n 20
```

`restart` is not enough under rootless podman. Pass: no `error` lines, and
within ten minutes the heartbeat arrives:
`osq '/tripwire-hits-*/_count?q=http.user_agent:tripwire-heartbeat%20AND%20@timestamp:>now-15m'`.

### 7. Enricher: recreate, not restart

`compose.yaml` gained a mount (`droppers.py`), and a restart keeps the old
container definition.

```bash
podman compose up -d --no-deps --force-recreate enricher
podman logs -f --since 1m tripwire-enricher
```

`--no-deps` fences the command to the one container: compose recreates a
dependency whose configuration hash has drifted, and the dependency here is
OpenSearch.

Pass, in the log: no traceback; one `lookups:` line reading
`internetdb=off (not enabled) dshield=off (not enabled) otx=off (not
enabled)` and `rtt-geo=on` (or `off (no sentinel_lat)` if step 4 left the
coordinates out); `droppers: on` (`module not found` means the mount did
not take: the container was restarted, not recreated); `created index
dropper-book`; no "cannot update mapping of address-book" warning (one
means an existing field clashes: copy the line, carry on, it is cosmetic).
Then:

```bash
osq '/address-book/_mapping/field/honeypot_tagged,dshield.last_seen'
osq '/_cat/indices/dropper-book?h=index,docs.count'
```

Pass: `boolean`, and `date` with `ignore_malformed`; `dropper-book` exists.

The first scan walks the stored payloads of the lookback window, so the
ledger fills at once. `tripwire-novel-dropper` looks at the last 30 minutes
of event time only: old payloads fill the ledger silently, a burst of
pushes is not expected. One or two are.

### 8. Second bootstrap

`dropper-book` exists now, so its index pattern and its monitor can be
created.

```bash
./bootstrap-opensearch.sh 2>&1 | tee ../bootstrap-wave1a-2.log
osq '/_plugins/_alerting/monitors/_search?source_content_type=application/json&source=%7B%22size%22%3A50%2C%22query%22%3A%7B%22exists%22%3A%7B%22field%22%3A%22monitor%22%7D%7D%7D' | python3 -c "import json,sys; print(sorted(h['_source']['name'] for h in json.load(sys.stdin)['hits']['hits']))"
```

(`_search` on monitors accepts GET, but wants the query, `size` included,
in the `source` parameter: a bare `?size=50` is a 400.) Pass: eleven names, among them
`tripwire-egress`, `tripwire-novel-dropper`, `tripwire-honeypot-tagged`.

### 9. Does the live cluster agree with the code?

Two things could only be checked here. Either in Dashboards as below, or
without executing a monitor at all: take the query from `alerts.py --dump`,
replace `{{period_end}}` with `now`, and send it as a GET `_search` with the
`source` parameter. The first sitting did the latter: `prefix` on `_index`
is accepted, no shard failed.

- **Digest aggregation.** The dropper count uses a `prefix` query on
  `_index`. In Dashboards: Alerting, Monitors, `tripwire-digest`, Edit,
  "Run" on the query (a dry run, sends nothing). Pass: the response has
  `aggregations.droppers.doc_count` and no shard failure. If `prefix` on
  `_index` is refused, the fix is a `wildcard` or a `terms` on the concrete
  name in `alerts.py`; do that at the workstation, not on the host.
- **Dead-man switch.** `tripwire-sentinel-silent`, same dry run. Pass: hit
  count over zero, trigger false.

In Discover: saved search "Dropper ledger: first seen" opens on the
`dropper-book` pattern and shows `hxxp://` forms; "Droppers" shows events.
Do not open anything shown there.

### 10. Close

- `podman ps`: five containers up, none restarting.
- Tomorrow 07:00: the digest carries "exploits:", "wrong protocol:",
  "New dropper locations:" (zeros on the first two until sitting 2).
- Workstation: `git push origin main`, after the operator says so.
- Keep `../tripwire-backup-wave1a` until sitting 2 is done.

## Going back

Per step, smallest first.

| after step | undo |
|---|---|
| 3 | `cp -a ../tripwire-backup-wave1a/* .` and `rm droppers.py`. Nothing was running the new files. |
| 5 | Mappings are additive and unused: leave them. Old dashboards and monitors: restore the backup, run `./bootstrap-opensearch.sh`. New monitors are not deleted by that; delete `tripwire-egress` in the Alerting UI if it matters. |
| 6 | Restore `vector.toml`, stop, start. Events logged meanwhile are in the log volume and are read from the checkpoint. |
| 7 | Restore `enrich.py` and `compose.yaml`, `podman compose up -d --force-recreate enricher`. `dropper-book` and `dropper.*` on events stay; they are inert. Delete the index only on purpose. |

Nothing in this sitting deletes data, so nothing here needs a snapshot
first.

## Edge cases

| case | applies | handling |
|---|---|---|
| host file differs from the repo | yes | step 2 stops the sitting |
| a new field already mapped by guess | possible | step 1 finds it, step 5 warns, gone at rollover |
| field count near the limit | possible | step 1 gate |
| `dropper-book` missing at first bootstrap | always | skipped on purpose, step 8 |
| lookups enabled | no, default off | step 4 |
| sentinel still on old code | always | right-hand column above; nothing breaks, old events just lack the fields |
| enricher mapping update refused | possible | warning, enricher keeps running |
| Windows line endings | always | step 3 `sed` |
| new mount ignored by `restart` | always | step 7 recreates |
