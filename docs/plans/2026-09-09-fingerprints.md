# Fingerprints, campaigns, return correlation

Date 2026-09-09. Three work packages with disjoint file ownership. Everything
stays standard library only, Python 3.12+ syntax (the containers run 3.14).

Mechanism: an address is cheap identity, a protocol stack is expensive
identity. The sentinel already receives the bytes that fingerprint a client's
SSH, TLS and HTTP stack and discards them. Keep them, hash them the way the
industry does (HASSH, JA4), then cluster and alert on them.

## Shared field contract (all packages depend on these exact names)

Sentinel event JSON, written by `sentinel.py` into the `note` dict, flat:

| key | type | when |
|---|---|---|
| `ssh_hassh` | 32 lowercase hex | client KEXINIT parsed |
| `ssh_kex_client` | string ≤512, the raw kex name-list | same |
| `http_header_order` | string ≤1024, comma-joined lowercased header names of the first request, in wire order | any HTTP request with ≥1 header |
| `http_header_hash` | 12 lowercase hex | same |
| `tls_ja4` | JA4 string e.g. `t13d1516h2_8daaf6152771_b186095e22b6` | ClientHello parsed on an https port |
| `tls_sni` | string ≤253 | SNI present |
| `tls_alpn` | first ALPN protocol ≤32 | ALPN present |
| `tls_version` | `13`, `12`, `11`, `10`, `s3` | ClientHello parsed |

`vector-sentinel.toml` moves them to:

```
.fingerprint = { "hassh": .ssh_hassh, "ja4": .tls_ja4, "http": .http_header_hash }
.tls         = { "sni": .tls_sni, "alpn": .tls_alpn, "version": .tls_version }
.http.header_order = .http_header_order
.ssh = { "kex": .ssh_kex_client }
```
and deletes the flat keys. Absent values stay absent (VRL: assigning null to a
key then `compact(.)` is acceptable, or guard each with `if exists(...)`).
`ssh_client`, `mysql_user`, `http_requests`, `smtp_commands` stay where they
are. All these are keyword-mapped by the dynamic template already; the
orchestrator adds explicit mapping lines to `bootstrap-opensearch.sh`.

Address book (`address-book` index, one doc per address, `enrich.py`):

| field | type |
|---|---|
| `first_seen_sentinel` | ISO date, min `@timestamp` of that address in `tripwire-sentinel-*` |
| `first_seen_receiver` | ISO date, same over `tripwire-hits-*` |

Stamped onto events by the enricher's update-by-query, object `prior`:

| field | type | rule |
|---|---|---|
| `prior.sentinel_first_seen` | date | copied from the book when present |
| `prior.receiver_first_seen` | date | same |
| `prior.sentinel_hours` | float | receiver events only: (event `@timestamp` − `first_seen_sentinel`) in hours, only when > 0 |

New index `fingerprint-book`, doc id `<kind>:<value>`:

| field | |
|---|---|
| `@timestamp` | first time this fingerprint was seen (min over all sentinel indices) |
| `kind` | `hassh`, `ja4`, `http` |
| `value` | the fingerprint |
| `first_ip` | address of the earliest event |
| `tool` | `threat.tool` of that event if any |
| `ssh_client` | of that event if any |

## Package A: sentinel fingerprints

Owner files: `sentinel.py`, `vector-sentinel.toml`. Nothing else.

### HASSH (`do_ssh`, `sentinel.py:507`)

After sending KEXINIT the code does one `reader.read(READ_LIMIT)`. Replace
with: read until the full SSH binary packet is present or `TIMEOUTS["ssh"]`
elapses. Packet = uint32 packet_length, byte padding_length, byte msg type
(20 = KEXINIT), 16-byte cookie, then ten name-lists (uint32 len + ASCII):
kex, hostkey, enc c2s, enc s2c, mac c2s, mac s2c, comp c2s, comp s2c,
lang c2s, lang s2c. Total bytes to read = 4 + packet_length. Cap at 64 KiB;
if packet_length is larger or msg type ≠ 20, record `bytes_received` and
stop, no fingerprint.

HASSH = md5 of `kex;enc_c2s;mac_c2s;comp_c2s` (each list as sent, comma
separated, joined with `;`), lowercase hex. Set `ssh_hassh`,
`ssh_kex_client`, keep `ssh_kexinit_received`. Parsing must be in a pure
function `parse_kexinit(data: bytes) -> dict | None` and `hassh(lists) -> str`
so the selftest can hit them.

### HTTP header order (`do_http`, `sentinel.py:538`)

Headers are parsed into a dict; also keep the ordered list of lowercased
names for the first request on the connection. `http_header_order` =
`",".join(names)[:1024]`; `http_header_hash` = sha256 of
`f"{http_version}|{','.join(names)}"`[:12] where http_version is the token
after the target (`HTTP/1.1`, or `HTTP/0.9` when absent). Only set when at
least one header line was read.

### JA4 (https ports)

Today `serve()` passes `ssl=ssl_context` to `asyncio.start_server`, so the
handshake happens before `handle()` sees bytes. Change: https ports listen
plain. In `handle()`, for role `https`, call a new `do_https()` that

1. reads TLS records from `reader` until one full handshake message of type 1
   (ClientHello) is buffered, or 16 KiB / `TIMEOUTS["http_header"]` is hit.
   Records are 5-byte headers (type 22, version, length) and a handshake
   message may span records. Anything else (SSLv2 hello, plain HTTP on 443,
   garbage) is recorded as `payload_hex` like `do_silent` and returned.
2. runs `parse_client_hello(bytes) -> dict | None` and `ja4(parsed) -> str`
   (pure functions) and sets `tls_*`.
3. completes the handshake with `ssl.MemoryBIO` + `ssl_context.wrap_bio()`,
   feeding the already-consumed bytes into the incoming BIO first, then
   pumping between the socket streams and the BIOs until `do_handshake()`
   succeeds. Then serve HTTP through a small `TlsStream` adapter exposing
   `readline()`, `read(n)`, `write(b)`, `drain()`, `close()`,
   `wait_closed()` on top of the SSLObject, and call the existing `do_http`
   with it as both reader and writer. Any TLS failure ends the connection
   quietly; the fingerprint is already recorded.
4. `serve()` no longer passes `ssl=` for https; it still refuses to bind
   https without a certificate. `Sentinel.__init__` takes the ssl_context.

JA4 rules (JA4 spec, TCP variant):
- `t` + version + sni + ciphers + extensions + alpn, `_`, hash b, `_`, hash c.
- version: highest value in `supported_versions` (ext 0x002b) ignoring GREASE,
  else the ClientHello legacy version. 0x0304→`13`, 0x0303→`12`,
  0x0302→`11`, 0x0301→`10`, 0x0300→`s3`.
- sni: `d` if ext 0x0000 present else `i`.
- ciphers: count of cipher suites excluding GREASE, two digits, cap 99.
- extensions: count of extensions excluding GREASE, two digits, cap 99
  (SNI and ALPN are counted here, only excluded from hash c).
- alpn: first and last character of the first ALPN value; `00` when no ALPN.
  If either character is not printable ASCII, use the first hex digit of
  the first byte and the last hex digit of the last byte instead.
- hash b: sha256 of the cipher suites as 4-hex-digit lowercase strings,
  sorted, comma-joined, first 12 hex chars. `000000000000` if none.
- hash c: sha256 of (extensions as 4-hex sorted, comma-joined, excluding
  0x0000 and 0x0010) + `_` + (signature algorithms from ext 0x000d as 4-hex
  in wire order, comma-joined); omit the `_` part when ext 0x000d is
  absent. First 12 hex chars. `000000000000` if no extensions.
- GREASE values: 0x0a0a, 0x1a1a, … 0xfafa (both bytes equal, low nibble a).

### Selftest (`python sentinel.py --selftest`, new flag, no network)

Add `selftest()` following `enrich.py`'s style, exits non-zero on failure:
- `parse_kexinit` on a KEXINIT built by the module's own `ssh_kexinit()`
  returns the four lists equal to `SSH_KEX`, `SSH_CIPHER`, `SSH_MAC`,
  `SSH_COMPRESSION`, and `hassh` of it equals
  `hashlib.md5(f"{SSH_KEX};{SSH_CIPHER};{SSH_MAC};{SSH_COMPRESSION}".encode()).hexdigest()`.
- `parse_kexinit` on truncated bytes and on a type-21 packet returns None.
- `parse_client_hello` on a hand-built ClientHello (TLS 1.2 legacy version,
  supported_versions containing GREASE 0x0a0a and 0x0304, SNI
  `example.com`, ALPN `h2` then `http/1.1`, 3 ciphers including one GREASE,
  signature algorithms 0x0403,0x0804) gives `tls_version` `13`, sni flag
  `d`, cipher count 2, alpn `h2`, and a JA4 matching
  `^t13d02\d\dh2_[0-9a-f]{12}_[0-9a-f]{12}$` with the extension count equal to
  the non-GREASE extensions you built. Assert hash b equals sha256 of the
  two real ciphers sorted, computed inline in the test.
- Same ClientHello split across two TLS records gives the same JA4.
- The same ClientHello without ALPN gives `...00_` and without SNI gives `i`.
- HTTP: assert the header order helper on `["Host: x", "User-Agent: y"]`
  with `HTTP/1.1` gives order `host,user-agent` and a 12-hex hash.
- Integration, loopback: start the sentinel in a thread with
  `--port-offset 40000 --no-hold --host 127.0.0.1 --log <tmp>`, connect to
  the ssh port, send `SSH-2.0-Test\r\n` + the module's `ssh_kexinit()`, close;
  make one HTTP GET with two headers to the http port; stop; assert the
  JSONL has an event with `ssh_hassh` and one with `http_header_order ==
  "host,user-agent"` (or whatever you sent). Skip the https part if no
  certificate is at hand; the unit tests cover the parser.

Edge cases to handle explicitly: ident and KEXINIT in one TCP segment (the
existing `readline` leaves the rest buffered, keep it that way); KEXINIT in
several segments; client closes after ident; non-SSH bytes on 22; HTTP/0.9
request line without version; duplicate header names (keep both in order);
ClientHello fragmented across records and across segments; SSLv2 hello
(first byte ≥ 0x80): no fingerprint, `payload_hex`; extensions with zero
length; ALPN list longer than one value; `supported_versions` with only
GREASE.

Nothing here may change any byte the sentinel sends on 22, 25, 80 or 3306.
The whole point of the file is not looking like a honeypot; read its header.

## Package B: campaign clustering

Owner file: `campaigns.py` (new). Nothing else.

Stdlib CLI in the style of `alerts.py` (env `OS_URL`, `OS_PASS`, same
`call()` and INSECURE context; copy them, do not import alerts.py).

```
python3 campaigns.py [--days 7] [--min-addresses 2] [--json]
```

One search over `tripwire-sentinel-*` for the window, `size 0`, composite
aggregation on `source.ip` (page with `after_key`, size 500) with sub-aggs:
`terms` (size 3) on each of `fingerprint.hassh`, `fingerprint.ja4`,
`fingerprint.http`, `threat.tool`, `ssh_client`, `mysql_user`,
`source.as.organization_name`, `source.geo.country_iso_code`; `terms`
(size 10) on `port`; `min` and `max` of `@timestamp`; `sum` of `held_ms`;
`value_count` of `@timestamp` as the connection count.

Cluster key per address: `(primary, ports)` where primary is the first
present of hassh, ja4, http hash, tool (prefixed `hassh:`, `ja4:`, `http:`,
`tool:`), else `unknown`; ports = tuple of sorted ports touched. Addresses
with `unknown` primary are grouped by ports only and reported at the end as
"unfingerprinted".

Output, sorted by address count desc, only clusters with at least
`--min-addresses`:

```
hassh:8a…  ports 22            37 addresses  6 ASNs  9 countries  2026-09-02 → 2026-09-09
  tool go-ssh (35) libssh (2)   clients SSH-2.0-Go (35) …
  users root (400) admin (120) …      held 41 min
  ASNs DigitalOcean (14) Hetzner (9) …
```
`--json` prints a list of cluster dicts with the same information. Read the
`clean()` helper in `analyze.py` and apply the same idea: every string here
is attacker-controlled, escape non-printables before printing.

Selftest: `--selftest` runs the clustering over a hard-coded list of fake
composite buckets (at least: two addresses sharing hassh and ports, one
sharing hassh but different ports, one with only a tool, one with nothing)
and asserts cluster count, ordering, the unfingerprinted section, and that a
`\x1b` in a fake ssh_client is escaped in the text output. No network.

## Package C: return correlation and novelty

Owner files: `enrich.py`, `alerts.py`. Nothing else.

### enrich.py

- `lookup()` already writes `first_seen`. Add `first_seen_sentinel` and
  `first_seen_receiver` from one search over `EVENT_INDICES` (no LOOKBACK,
  `ignore_unavailable`) filtered on the address: `terms` on `event.module`
  with `min` of `@timestamp`. Refresh these two fields every time an
  address has pending events, not only every RECHECK: split `lookup()` so
  the cheap first-seen query runs on every pass while PTR/lists/APIs keep
  the RECHECK cache.
- `APPLY_SCRIPT` gains `prior`: set `ctx._source.prior` from
  `params.prior` (an object with the two first-seen dates), and when
  `ctx._source.event.module == 'receiver'` and `params.prior.sentinel_first_seen`
  is set, compute `prior.sentinel_hours` from the event's `@timestamp`
  (`ZonedDateTime.parse(...)` handles the `+00:00` form both producers
  write) and only store it when positive.
- Fingerprint book: `ensure_book()` also creates `fingerprint-book`
  (mapping: `@timestamp` date, the rest keyword). Each `cycle()`, for each
  of the three kinds, run a `terms` agg (size 1000) over all
  `tripwire-sentinel-*` on the field with sub-aggs `min @timestamp` and a
  `top_hits` (size 1, sorted asc by `@timestamp`, `_source` limited to
  `source.ip`, `threat.tool`, `ssh_client`). Index each value with
  `op_type=create` (PUT `/fingerprint-book/_create/<kind>:<value>`), so an
  existing doc is never touched and `@timestamp` stays the true first
  sighting. 409 is the normal case; log at debug. Cache the set of known
  ids in memory to avoid re-issuing creates every minute.
- `selftest()` gains: the hours computation in pure Python mirrors the
  painless (implement `hours_between(a, b)` in Python used to build the
  expected value in the test and document that the painless does the same);
  the doc id builder escapes `/` and `:` in values safely (URL-quote the
  value part); `first_seen` merging keeps the earlier date.

### alerts.py

Two monitors appended to `MONITORS`, using the existing `query_monitor`:

- `tripwire-returned`: indices `HITS`, filter `range prior.sentinel_hours gte 1`,
  window 5 min, severity 2, message:
  `Scanned the sentinel first, came to the site later.` then per hit
  `ip country tier_name method path, N h after first sentinel contact`
  (`{{_source.prior.sentinel_hours}}`).
- `tripwire-novel-fingerprint`: indices `["fingerprint-book"]`, no filters,
  window 5 min, severity 3, throttle 5, message listing
  `kind value first_ip tool ssh_client` per hit. Update the module docstring
  table and the README paragraph is the orchestrator's.

Both channels stay as they are. Run `python3 alerts.py` needs a live cluster;
instead add a `--dump` flag that prints `json.dumps(MONITORS)` and exits,
and check locally with dummy env that the two new monitors serialise and
their filters reference the fields named in the contract.

## Validation, every package

- `python -m py_compile <file>` for every owned Python file.
- The package's selftest passes.
- `git add` only owned files; commit with a message in the style of `git log`
  (plain prose, why not what), `Co-Authored-By` and `Claude-Session` trailers
  as in recent commits. Do not touch other files; report deviations from
  this plan with reasons instead of improvising around them.

## Deploy (orchestrator, after all three land)

Bootstrap mapping lines; `alerts.py` rerun on nebula; enricher image
rebuild on nebula; sentinel image rebuild on the VM (`podman compose -f
compose.sentinel.yaml build && up -d`); README. JA4 stays dormant until the
VM has a real certificate for 443, which the persona only opens when one is
supplied.
