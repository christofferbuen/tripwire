# B1: enricher, free intelligence and address-level verdicts

Read `2026-09-19-wave1-overview.md` first.

**Owner files:** `enrich.py`, and in `setup-logging.sh` only the block that
copies optional keys from `.env` into the secrets file. Nothing else.
**Builder model:** sonnet.

Everything here is a lookup about an address. Nothing contacts the address.

## 1. More bulk lists, and lists that are allowed to fail

`firehol:level1` already contains Spamhaus DROP, DShield and Feodo, so those
are not added again. New dict beside `LISTS`:

```python
OPTIONAL_LISTS = {
    "tor:exits": "https://check.torproject.org/torbulkexitlist",
    "et:compromised": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "cins:army": "https://cinsscore.com/list/ci-badguys.txt",
    "x4b:vpn": "https://raw.githubusercontent.com/X4BNET/lists_vpn/main/output/vpn/ipv4.txt",
    "x4b:datacenter": "https://raw.githubusercontent.com/X4BNET/lists_vpn/main/output/datacenter/ipv4.txt",
}
```

`Lists.refresh()` today aborts the whole refresh when any source fails. That
stays true for `OPENFILTERS`, `LISTS` and `IPSUM`. Each `OPTIONAL_LISTS`
entry is fetched inside its own `try`; a failure logs a warning and the
refresh carries on without it. Same `parse_networks`.

`Lists.match()` keeps its three-tuple. Derived in `lookup()`:

- `entry["tor"] = True` when `"tor:exits"` is in the names.
- `entry["hosting"] = "vpn"` when `"x4b:vpn"` is in the names, else
  `"datacenter"` when `"x4b:datacenter"` is. The two `x4b:` names are removed
  from `entry["lists"]`: they describe the network, they are not accusations.

`apply()` sends `threat.tor` inside `threat`, and `hosting` as a new param
that the painless writes to `ctx._source.source.hosting`.

Cloud-provider range files are deliberately not added: `source.as.
organization_name` from the ASN database already answers that.

## 2. Opt-in lookups

Off unless named. Secrets key `lookups`, a list drawn from `internetdb`,
`dshield`, `otx`. `setup-logging.sh` fills it from a comma-separated
`ENRICH_LOOKUPS` in `.env`, and `otx_api_key` from `OTX_API_KEY`, following
the existing GreyNoise pattern.

Add to `Reputation`, same shape as `abuseipdb()` (429 pauses an hour, non-200
returns `None`, 15 s timeout):

| method | request | kept |
|---|---|---|
| `internetdb(ip)` | `GET https://internetdb.shodan.io/<ip>`; 404 means unknown and returns `{"ports": []}` | `ports` (ints, max 64), `tags` (max 16), `vulns_count` (int), `hostnames` (max 8, each max 253) |
| `dshield(ip)` | `GET https://isc.sans.edu/api/ip/<ip>?json` | from the `ip` object: `count`, `attacks` as ints, `maxdate` as `last_seen` |
| `otx(ip)` | `GET https://otx.alienvault.com/api/v1/indicators/IPv4/<ip>/general`, header `X-OTX-API-KEY` | `pulses` = `pulse_info.count` as int |

Every value read from a response is coerced (`int()`, `str()[:n]`) inside a
`try`; a response that does not have the expected shape yields `None`. These
are third-party JSON and get the same distrust as attacker text.

`lookup()` adds them to the loop that already handles `greynoise` and
`abuseipdb`; `apply()` adds them to `reputation`; `BOOK_MAPPING` gets the
properties. IPv6 addresses skip `internetdb` and `otx`.

## 3. RTT against geography

TCP RTT measures the path to the address, so it tests the GeoIP claim. It
does not see through a proxy that terminates TCP.

Secrets keys `sentinel_lat`, `sentinel_lon` (floats; from `SENTINEL_LAT`,
`SENTINEL_LON` in `.env`). Without them this feature is skipped and says so
once at start-up.

```python
RTT_KM_PER_MS = 100.0     # light in fibre: about 200 km per ms one way
DETOUR_FACTOR = 3.0
DETOUR_SLACK_MS = 80.0

def haversine_km(lat1, lon1, lat2, lon2) -> float
def rtt_verdict(rtt_ms: float, km: float) -> tuple[float, str]
```

`rtt_verdict` returns `(floor, verdict)`, `floor = km / RTT_KM_PER_MS`:
`impossible` when `rtt_ms < floor * 0.8`; `detour` when `rtt_ms > floor *
DETOUR_FACTOR + DETOUR_SLACK_MS`; else `plausible`.

`Enricher.network(ip_text)`: one search over `SENTINEL_INDICES` for the
address, `size: 1` with `_source: ["source.geo.location"]`, plus a `min`
aggregation on `network.rtt_ms`. Returns `None` when either half is missing.
`apply()` passes `network = {"geo_km", "rtt_floor_ms", "rtt_verdict"}`; the
painless merges it into `ctx._source.network` without replacing `rtt_ms`.
`source.geo.location` arrives as `{"lat","lon"}` or as a `"lat,lon"` string:
handle both.

`# ponytail:` the verdict is computed once, when the address is first
enriched, from the RTT samples that exist then. Recompute on `RECHECK` if
that proves too early.

## 4. Fake crawlers

```python
CRAWLERS = {
    "googlebot": ("googlebot.com", "google.com"),
    "bingbot": ("search.msn.com",),
    "yandexbot": ("yandex.ru", "yandex.net", "yandex.com"),
    "baiduspider": ("baidu.com", "baidu.jp"),
    "duckduckbot": ("duckduckgo.com",),
    "applebot": ("applebot.apple.com",),
}

def claimed_crawler(user_agents: list[str]) -> str | None
def crawler_verified(name: str, ptr: str | None, ip_text: str, resolve=socket.gethostbyname_ex) -> bool
```

`claimed_crawler`: first key of `CRAWLERS` found, case-insensitively, in any
user agent. `crawler_verified`: PTR ends in one of the suffixes (same
tail-only match as `scanner_from_ptr`) and the forward lookup of the PTR
contains `ip_text`; any resolver error is `False`. `resolve` is a parameter
so the selftest needs no network.

`lookup()` gets the address's user agents with a `terms` aggregation on
`http.user_agent` (size 20) over `EVENT_INDICES`. When a crawler is claimed
and not verified: `entry["fake_crawler"] = name`, sent as
`threat.fake_crawler`.

## 5. Deception audit: what Shodan says about us

Secrets key `sentinel_public_ip` (from `SENTINEL_PUBLIC_IP`). Once per
`LIST_REFRESH`, only when `internetdb` is in `lookups` and the key is set:
call `internetdb()` on it and `PUT /address-book/_doc/self` with
`{"ip": <it>, "scope": "self", "checked": now, "internetdb": {...},
"honeypot_tagged": "honeypot" in tags}`. Package M adds the monitor on
`honeypot_tagged: true`. Log the tags and ports at INFO every time.

## 6. Hook for the dropper ledger (package B2)

`droppers.py` is written in parallel by someone else and may not be mounted
yet. At module level:

```python
try:
    import droppers
except ImportError:
    droppers = None
```

`main()` logs `droppers: on` or `droppers: module not found` once. At the end
of `Enricher.cycle()` (before the early return when nothing is pending, so
it runs every pass): `if droppers: droppers.scan(self.os)` inside its own
`try` that logs and continues. `scan` takes anything with `call(method,
path, body=None) -> (status, doc)`. Nothing else about that module is this
package's business.

## Acceptance tests (implement exactly these in `selftest()`)

1. Optional list failure: `Lists.refresh()` with `fetch` monkeypatched so
   required sources return small valid bodies and `"cins:army"` returns 500:
   `loaded_at` is set, `match()` works, no exception.
2. Required list failure still keeps the previous lists (existing behaviour):
   patched `IPSUM` returning 500 leaves `exact` as it was and sets
   `next_try` about an hour out.
3. Derivation: an address on `tor:exits` and `x4b:vpn` yields `tor is True`,
   `hosting == "vpn"`, and `lists` without any `x4b:` name.
4. `haversine_km(48.86, 2.35, 52.52, 13.40)` is within 5 of 877.
5. `rtt_verdict(1.0, 400)` is `(4.0, "impossible")`; `rtt_verdict(6.0, 400)`
   is `(4.0, "plausible")`; `rtt_verdict(200.0, 400)` is `(4.0, "detour")`;
   `rtt_verdict(5.0, 0)` is `(0.0, "plausible")`.
6. `claimed_crawler(["Mozilla/5.0 (compatible; Googlebot/2.1)"]) ==
   "googlebot"`; `claimed_crawler(["curl/8"]) is None`.
7. `crawler_verified("googlebot", "crawl-1.googlebot.com", "192.0.2.1",
   resolve=lambda h: (h, [], ["192.0.2.1"]))` is `True`; with `["192.0.2.9"]`
   `False`; with PTR `googlebot.com.evil.example` `False`; with a resolver
   that raises `socket.gaierror` `False`; with PTR `None` `False`.
8. Response distrust: `internetdb`, `dshield` and `otx` parsers, fed
   `b"[]"`, `b"{}"`, `b'{"ports":"x","tags":7}'` and 1 MB of `b"a"`, return
   `None` or a well-typed dict and never raise. Split each method so the
   parsing half is a pure function the test can call.
9. With `lookups` absent from secrets, none of the three methods performs a
   request (assert through a patched `fetch` that records calls).
10. The existing selftest assertions all still pass.
11. `cycle()` with module-level `droppers` set to `None` runs; with it set
    to an object whose `scan` raises `RuntimeError`, `cycle()` still returns
    normally and the enrichment half ran first or after, unaffected.

## Edge-case matrix

| axis | applies | note |
|---|---|---|
| no optional keys in `.env` at all | yes | behaviour identical to today except the new bulk lists |
| private or non-global address | yes | no lookups, as today |
| IPv6 | yes | bulk lists are v4 files; no match is fine |
| third party down, slow, or returning HTML | yes | test 8, 15 s timeout, never blocks the pass beyond that |
| receiver events (no RTT, no sentinel geo) | yes | `network()` returns `None`, nothing stamped |
| index frozen by ISM | yes | same `conflicts=proceed` path as today |
| address-book doc `self` | yes | `pending()` never returns it: it is keyed by event addresses |

## Where's the door handle

Operator sets `ENRICH_LOOKUPS=internetdb,dshield` in `.env`, reruns
`setup-logging.sh`, restarts the enricher. Start-up logs one line naming
what is on and what is off and why (`otx=off (no key)`, `rtt-geo=off (no
sentinel_lat)`). A lookup that hits its quota logs the pause. Results show
as columns and filters in Dashboards once M lands.

## Validation

```
python -m py_compile enrich.py
python enrich.py --selftest
bash -n setup-logging.sh
```

`git add enrich.py setup-logging.sh` only. Report deviations with reasons,
including any upstream URL that has moved: say so rather than guessing a
replacement.
