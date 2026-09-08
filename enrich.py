#!/usr/bin/env python3
"""Passive enrichment for tripwire events.

Every address that shows up in the indices is looked up once:

  - reverse DNS, kept as source.domain, and the scanner it names if the PTR
    ends in a known scanner domain (threat.scanner)
  - membership in published scanner and abuser lists (threat.scanner,
    threat.lists, threat.ipsum_score), refreshed daily from their sources
  - GreyNoise and AbuseIPDB verdicts (reputation.*) when API keys are present
    in the secrets file; silently skipped when they are not

Answers are cached in the `address-book` index, one document per address, and
copied onto every event from that address with an update-by-query. Nothing
here contacts the attacker: the lookups go to DNS, GitHub and the two APIs.

Stdlib only. Loops forever; compose.yaml runs it next to Vector.
    python3 enrich.py --selftest   exercises the parsers without a network.
"""

import base64
import io
import ipaddress
import json
import logging
import os
import signal
import socket
import ssl
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

OS_URL = os.environ.get("OPENSEARCH_URL", "https://opensearch:9200")
SECRETS_FILE = os.environ.get("SECRETS_FILE", "/run/secrets/tripwire.json")
EVENT_INDICES = "tripwire-hits-*,tripwire-sentinel-*"
SENTINEL_INDICES = "tripwire-sentinel-*"
BOOK = "address-book"
FINGERPRINT_BOOK = "fingerprint-book"
# The three client fingerprints the sentinel records, and where Vector puts
# them. One document per distinct value, written once: the interesting event
# is a value nobody has ever presented here before.
FINGERPRINT_FIELDS = {"hassh": "fingerprint.hassh",
                      "ja4": "fingerprint.ja4",
                      "http": "fingerprint.http"}
CYCLE = 60                 # seconds between passes over new addresses
RECHECK = 7 * 86400        # re-resolve and re-query an address after this long
LIST_REFRESH = 24 * 3600   # the sources themselves update between 10 min and 1 day
LOOKBACK = "now-3d"        # older events are left alone; ISM may have frozen them
BATCH = 200                # addresses per pass

# Published lists. Any token on a line that parses as an address or network
# counts and the rest of the line is ignored, so nft `define` blocks, plain
# ipsets and ipsum's `ip<TAB>score` rows all work with one parser.
#
# OpenFilters is fetched as a tarball: one download, one file per scanning
# organisation, and organisations added upstream show up here without a
# config change. The file stem is the organisation name.
OPENFILTERS = "https://github.com/OpenFilters/internet-scanners/archive/refs/heads/main.tar.gz"
FIREHOL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/"
LISTS = {
    "firehol:maltrail_scanners": FIREHOL + "maltrail_scanners.ipset",  # mass scanners, daily
    "firehol:level1": FIREHOL + "firehol_level1.netset",               # dshield, spamhaus drop, feodo
    "firehol:blocklist_de": FIREHOL + "blocklist_de.ipset",            # fail2ban reports, 48 h
    "firehol:greensnow": FIREHOL + "greensnow.ipset",                  # brute force and scan harvesters
    "firehol:dshield": FIREHOL + "dshield.netset",                     # top attacking /24s
}
IPSUM = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
IPSUM_MIN = 3  # blocklists that must agree before the score is recorded
# Upstream spelling differs from the company's.
ORG_ALIASES = {"strechoid": "stretchoid"}

# Reverse-DNS suffixes that name the scanner outright. Matched against the
# tail of the name only, so scan-05a.shadowserver.org matches and
# shadowserver.org.example.net does not.
PTR_SCANNERS = {
    "censys-scanner.com": "censys",
    "sfj.corp.censys.io": "censys",
    "shodan.io": "shodan",
    "stretchoid.com": "stretchoid",
    "binaryedge.ninja": "binaryedge",
    "shadowserver.org": "shadowserver",
    "internet-measurement.com": "driftnet",
    "onyphe.net": "onyphe",
    "onyphe.io": "onyphe",
    "leakix.net": "leakix",
    "leakix.org": "leakix",
    "security.ipip.net": "ipip",
    "criminalip.com": "criminalip",
    "netsystemsresearch.com": "netsystemsresearch",
    "alphastrike.io": "alphastrike",
    "rapid7.com": "rapid7",
    "internettl.org": "paloaltonetworks",
    "academyforinternetresearch.org": "academyforinternetresearch",
    "bufferover.run": "bufferoverrun",
    "recyber.net": "recyber",
    "hunter.how": "hunter",
    "fofa.info": "fofa",
    "zoomeye.org": "zoomeye",
    "odin.io": "odin",
    "ipinfo.io": "ipinfo",
    "cyber.casa": "cyber-casa",
    "researchscan.comsys.rwth-aachen.de": "rwth-research",
}

GREYNOISE = "https://api.greynoise.io/v3/community/"
ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress="

log = logging.getLogger("enrich")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(text):
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def hours_between(start, end):
    """Hours from start to end, ISO 8601 with an offset (`+00:00` from the two
    producers, `Z` from an aggregation). The painless in APPLY_SCRIPT computes
    the same number the same way: difference in milliseconds over 3_600_000."""
    a = datetime.fromisoformat(start.replace("Z", "+00:00"))
    b = datetime.fromisoformat(end.replace("Z", "+00:00"))
    return (b - a).total_seconds() / 3600.0


def earlier(a, b):
    """The earlier of two ISO timestamps, either of which may be missing.
    An index the lifecycle policy has dropped takes its events' timestamps
    with it, so the first sighting already in the book outranks a fresh
    aggregation over what is left."""
    if not a or not b:
        return a or b
    return a if hours_between(a, b) >= 0 else b


def book_id(kind, value):
    """Document id for the fingerprint book. The value half is attacker
    controlled, and a raw `/` in it would make the create URL address a
    different index, so it is percent-encoded; the separator stays literal."""
    return kind + ":" + urllib.parse.quote(value, safe="")


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

# The cluster uses the demo self-signed certificate and is only reachable on
# the container network; the external APIs are verified normally.
INSECURE = ssl.create_default_context()
INSECURE.check_hostname = False
INSECURE.verify_mode = ssl.CERT_NONE


def fetch(method, url, body=None, headers=None, timeout=60):
    """Returns (status, bytes). HTTP errors are returned, not raised."""
    data = None
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "tripwire-enrich/1 (+stdlib urllib)")
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    ctx = INSECURE if url.startswith(OS_URL) else None
    try:
        with urllib.request.urlopen(req, data=data, timeout=timeout, context=ctx) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class OpenSearch:
    def __init__(self, url, user, password):
        self.url = url
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {"Authorization": "Basic " + token}

    def call(self, method, path, body=None):
        status, raw = fetch(method, self.url + path, body, self.headers)
        try:
            doc = json.loads(raw) if raw else {}
        except ValueError:
            doc = {"raw": raw[:200].decode("utf-8", "replace")}
        return status, doc


# --------------------------------------------------------------------------
# Lists
# --------------------------------------------------------------------------

def parse_networks(text):
    """Every address or network on non-comment lines, as ip_network objects."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        for tok in line.replace(",", " ").replace("{", " ").replace("}", " ").split():
            try:
                out.append(ipaddress.ip_network(tok, strict=False))
            except ValueError:
                continue
    return out


def parse_ipsum(text, minimum):
    scores = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 2 or line.startswith("#"):
            continue
        try:
            ip, score = ipaddress.ip_address(parts[0]), int(parts[1])
        except ValueError:
            continue
        if score >= minimum:
            scores[int(ip)] = score
    return scores


class Lists:
    """All published lists in one structure. Single addresses go in a dict
    keyed by integer so 100k of them cost one hash lookup; real networks stay
    in a list that is scanned. Both are rebuilt in full on refresh."""

    def __init__(self):
        self.exact = {}      # int(address) -> set of list names
        self.nets = []       # (network, list name)
        self.ipsum = {}      # int(address) -> score
        self.loaded_at = 0
        self.next_try = 0

    def add(self, name, networks):
        n = 0
        for net in networks:
            if net.num_addresses == 1:
                self.exact.setdefault(int(net.network_address), set()).add(name)
            else:
                self.nets.append((net, name))
            n += 1
        log.info("list %s: %d entries", name, n)

    def refresh(self):
        exact, nets, ipsum = self.exact, self.nets, self.ipsum
        self.exact, self.nets, self.ipsum = {}, [], {}
        try:
            status, raw = fetch("GET", OPENFILTERS)
            if status != 200:
                raise RuntimeError(f"openfilters {status}")
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
                for member in tar.getmembers():
                    parts = member.name.split("/")
                    if len(parts) != 3 or parts[1] != "cidr" or not member.isfile():
                        continue
                    stem = parts[2].rsplit(".", 1)[0]
                    org = stem.removesuffix("_v4").removesuffix("_v6")
                    org = ORG_ALIASES.get(org, org)
                    text = tar.extractfile(member).read().decode("utf-8", "replace")
                    self.add("openfilters:" + org, parse_networks(text))
            for name, url in LISTS.items():
                status, raw = fetch("GET", url)
                if status != 200:
                    raise RuntimeError(f"{name} {status}")
                self.add(name, parse_networks(raw.decode("utf-8", "replace")))
            status, raw = fetch("GET", IPSUM)
            if status != 200:
                raise RuntimeError(f"ipsum {status}")
            self.ipsum = parse_ipsum(raw.decode("utf-8", "replace"), IPSUM_MIN)
            log.info("ipsum: %d addresses on %d+ lists", len(self.ipsum), IPSUM_MIN)
        except Exception as e:  # keep the previous lists rather than none
            log.warning("list refresh failed, keeping previous: %s", e)
            self.exact, self.nets, self.ipsum = exact, nets, ipsum
            self.next_try = time.time() + 3600
            return
        self.loaded_at = time.time()
        self.next_try = self.loaded_at + LIST_REFRESH
        log.info("lists loaded: %d exact, %d networks", len(self.exact), len(self.nets))

    def match(self, ip):
        names = set(self.exact.get(int(ip), ()))
        names.update(name for net, name in self.nets if ip in net)
        orgs = sorted(n.split(":", 1)[1] for n in names if n.startswith("openfilters:"))
        return orgs[0] if orgs else None, sorted(names), self.ipsum.get(int(ip))


def scanner_from_ptr(host):
    if not host:
        return None
    for suffix, name in PTR_SCANNERS.items():
        if host == suffix or host.endswith("." + suffix):
            return name
    return None


def reverse_dns(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None
    host = host.rstrip(".").lower()[:253]
    # musl hands the address back as the "name" when there is no PTR.
    return None if not host or host == ip else host


# --------------------------------------------------------------------------
# Reputation APIs (optional)
# --------------------------------------------------------------------------

class Reputation:
    def __init__(self, secrets):
        self.gn_key = secrets.get("greynoise_api_key")
        self.ab_key = secrets.get("abuseipdb_api_key")
        self.paused = {}  # api -> retry after epoch, set on 429

    def _ok(self, name):
        return time.time() >= self.paused.get(name, 0)

    def greynoise(self, ip):
        if not self.gn_key or not self._ok("greynoise"):
            return None
        status, raw = fetch("GET", GREYNOISE + ip,
                            headers={"key": self.gn_key, "Accept": "application/json"}, timeout=15)
        if status == 429:
            log.warning("greynoise quota hit, pausing an hour")
            self.paused["greynoise"] = time.time() + 3600
            return None
        if status == 404:  # not seen scanning and not in RIOT
            return {"noise": False, "riot": False}
        if status != 200:
            log.warning("greynoise %s: %s", ip, status)
            return None
        d = json.loads(raw)
        out = {"noise": bool(d.get("noise")), "riot": bool(d.get("riot"))}
        for k in ("classification", "name", "last_seen"):
            if d.get(k):
                out[k] = d[k]
        return out

    def abuseipdb(self, ip):
        if not self.ab_key or not self._ok("abuseipdb"):
            return None
        status, raw = fetch("GET", ABUSEIPDB + ip,
                            headers={"Key": self.ab_key, "Accept": "application/json"}, timeout=15)
        if status == 429:
            log.warning("abuseipdb quota hit, pausing an hour")
            self.paused["abuseipdb"] = time.time() + 3600
            return None
        if status != 200:
            log.warning("abuseipdb %s: %s", ip, status)
            return None
        d = json.loads(raw).get("data", {})
        out = {"score": d.get("abuseConfidenceScore"), "reports": d.get("totalReports"),
               "is_tor": bool(d.get("isTor"))}
        for k, v in (("usage_type", d.get("usageType")), ("domain", d.get("domain"))):
            if v:
                out[k] = v
        return out


# --------------------------------------------------------------------------
# Enricher
# --------------------------------------------------------------------------

BOOK_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "dynamic_templates": [{"strings_as_keyword": {
            "match_mapping_type": "string", "mapping": {"type": "keyword", "ignore_above": 1024}}}],
        "properties": {
            "ip": {"type": "ip"}, "ptr": {"type": "keyword"}, "scanner": {"type": "keyword"},
            "lists": {"type": "keyword"}, "ipsum_score": {"type": "integer"},
            "scope": {"type": "keyword"},
            "first_seen": {"type": "date"}, "checked": {"type": "date"},
            "first_seen_sentinel": {"type": "date"},
            "first_seen_receiver": {"type": "date"},
            "greynoise": {"properties": {
                "noise": {"type": "boolean"}, "riot": {"type": "boolean"},
                "classification": {"type": "keyword"}, "name": {"type": "keyword"},
                "last_seen": {"type": "date", "ignore_malformed": True}}},
            "abuseipdb": {"properties": {
                "score": {"type": "integer"}, "reports": {"type": "integer"},
                "usage_type": {"type": "keyword"}, "domain": {"type": "keyword"},
                "is_tor": {"type": "boolean"}}},
        },
    },
}

FINGERPRINT_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "dynamic_templates": [{"strings_as_keyword": {
            "match_mapping_type": "string", "mapping": {"type": "keyword", "ignore_above": 1024}}}],
        "properties": {
            "@timestamp": {"type": "date"}, "kind": {"type": "keyword"},
            "value": {"type": "keyword"}, "first_ip": {"type": "keyword"},
            "tool": {"type": "keyword"}, "ssh_client": {"type": "keyword"},
        },
    },
}

# Runs on every event of the address that has no enrichment yet. threat is
# merged rather than replaced because Vector already sets threat.tool from the
# banner or user agent at ingest.
#
# prior carries what the address book knows about when this address was first
# seen by each producer. On a receiver event that also has a sentinel first
# sighting, the gap between the two is stamped as prior.sentinel_hours: the
# number that says "it scanned the honeypot, then N hours later it came to the
# real site". Only a positive gap counts; scanning after the visit is the
# ordinary direction and says nothing. params.prior is shared by every
# document of this update-by-query, so it is copied before the hours go in.
# ZonedDateTime.parse reads both forms written here, `+00:00` from the two
# producers and `Z` from an aggregation. hours_between() above is the same sum.
APPLY_SCRIPT = """
if (ctx._source.source == null) { ctx._source.source = new HashMap(); }
if (params.domain != null) { ctx._source.source.domain = params.domain; }
if (params.threat != null) {
  if (ctx._source.threat == null) { ctx._source.threat = new HashMap(); }
  ctx._source.threat.putAll(params.threat);
}
if (params.reputation != null) { ctx._source.reputation = params.reputation; }
if (params.prior != null) {
  ctx._source.prior = new HashMap(params.prior);
  def module = null;
  if (ctx._source.containsKey('event') && ctx._source.event instanceof Map) {
    module = ctx._source.event.get('module');
  }
  def first = params.prior.get('sentinel_first_seen');
  def stamp = ctx._source.containsKey('@timestamp') ? ctx._source['@timestamp'] : null;
  if ('receiver'.equals(module) && first instanceof String && stamp instanceof String) {
    long gap = ZonedDateTime.parse(stamp).toInstant().toEpochMilli()
             - ZonedDateTime.parse(first).toInstant().toEpochMilli();
    if (gap > 0) { ctx._source.prior.sentinel_hours = gap / 3600000.0; }
  }
}
ctx._source.enrichment = params.enrichment;
"""


class Enricher:
    def __init__(self, os_client, lists, reputation):
        self.os = os_client
        self.lists = lists
        self.rep = reputation
        # ponytail: unbounded set of fingerprint ids, one short string each.
        # A honeypot sees thousands of distinct stacks, not millions; give it
        # an LRU or a periodic reload from the book if that stops being true.
        self.known_fingerprints = set()

    def ensure_book(self):
        for name, mapping in ((BOOK, BOOK_MAPPING), (FINGERPRINT_BOOK, FINGERPRINT_MAPPING)):
            status, doc = self.os.call("PUT", "/" + name, mapping)
            if status == 200:
                log.info("created index %s", name)
            elif status != 400 or "already_exists" not in json.dumps(doc):
                raise RuntimeError(f"cannot create {name}: {status} {doc}")

    def pending(self):
        body = {"size": 0,
                "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": LOOKBACK}}}],
                                   "must_not": [{"exists": {"field": "enrichment.at"}}]}},
                "aggs": {"ips": {"terms": {"field": "source.ip", "size": BATCH}}}}
        status, doc = self.os.call("POST", f"/{EVENT_INDICES}/_search?ignore_unavailable=true", body)
        if status != 200:
            log.warning("pending query %s: %s", status, doc)
            return []
        return [b["key"] for b in doc.get("aggregations", {}).get("ips", {}).get("buckets", [])]

    def first_seen(self, ip_text):
        """Earliest event of this address per producer. One cheap aggregation
        with no lookback, so it runs on every pass: an address that scanned the
        sentinel months ago and shows up on the site today has to be caught the
        moment it does, not whenever its cache entry next expires."""
        body = {"size": 0,
                "query": {"bool": {"filter": [{"term": {"source.ip": ip_text}}]}},
                "aggs": {"modules": {"terms": {"field": "event.module", "size": 5},
                                     "aggs": {"first": {"min": {"field": "@timestamp"}}}}}}
        status, doc = self.os.call("POST", f"/{EVENT_INDICES}/_search?ignore_unavailable=true", body)
        if status != 200:
            log.warning("first-seen %s: %s %s", ip_text, status, doc)
            return {}
        out = {}
        for bucket in doc.get("aggregations", {}).get("modules", {}).get("buckets", []):
            stamp = bucket.get("first", {}).get("value_as_string")
            if stamp and bucket["key"] in ("sentinel", "receiver"):
                out["first_seen_" + bucket["key"]] = stamp
        return out

    def lookup(self, ip_text):
        status, doc = self.os.call("GET", f"/{BOOK}/_doc/{ip_text}")
        cached = doc.get("_source") if status == 200 else None
        found, book = self.first_seen(ip_text), cached or {}
        seen = {k: earlier(found.get(k), book.get(k))
                for k in ("first_seen_sentinel", "first_seen_receiver")
                if found.get(k) or book.get(k)}
        if cached and (datetime.now(timezone.utc) - parse_iso(cached["checked"])).total_seconds() < RECHECK:
            fresh = {k: v for k, v in seen.items() if cached.get(k) != v}
            if fresh:
                cached.update(fresh)
                self.os.call("POST", f"/{BOOK}/_update/{ip_text}", {"doc": fresh})
            return cached
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            return None
        entry = {"ip": ip_text, "checked": now_iso(),
                 "first_seen": (cached or {}).get("first_seen") or now_iso(), **seen}
        if ip.is_global:
            ptr = reverse_dns(ip_text)
            scanner, lists, score = self.lists.match(ip)
            if ptr:
                entry["ptr"] = ptr
            scanner = scanner_from_ptr(ptr) or scanner
            if scanner:
                entry["scanner"] = scanner
            if lists:
                entry["lists"] = lists
            if score is not None:
                entry["ipsum_score"] = score
            for name, result in (("greynoise", self.rep.greynoise(ip_text)),
                                 ("abuseipdb", self.rep.abuseipdb(ip_text))):
                if result:
                    entry[name] = result
        else:
            entry["scope"] = "private"
        self.os.call("PUT", f"/{BOOK}/_doc/{ip_text}", entry)
        log.info("%s ptr=%s scanner=%s lists=%d ipsum=%s", ip_text, entry.get("ptr"),
                 entry.get("scanner"), len(entry.get("lists", [])), entry.get("ipsum_score"))
        return entry

    def apply(self, entry):
        threat = {k: entry[k] for k in ("scanner", "lists", "ipsum_score") if entry.get(k) is not None}
        reputation = {k: entry[k] for k in ("greynoise", "abuseipdb") if entry.get(k)}
        prior = {f"{who}_first_seen": entry[f"first_seen_{who}"]
                 for who in ("sentinel", "receiver") if entry.get(f"first_seen_{who}")}
        params = {"domain": entry.get("ptr"), "threat": threat or None,
                  "reputation": reputation or None, "prior": prior or None,
                  "enrichment": {"at": now_iso()}}
        body = {"query": {"bool": {"filter": [{"term": {"source.ip": entry["ip"]}},
                                              {"range": {"@timestamp": {"gte": LOOKBACK}}}],
                                   "must_not": [{"exists": {"field": "enrichment.at"}}]}},
                "script": {"lang": "painless", "source": APPLY_SCRIPT, "params": params}}
        status, doc = self.os.call(
            "POST", f"/{EVENT_INDICES}/_update_by_query?conflicts=proceed&ignore_unavailable=true", body)
        if status != 200:
            log.warning("apply %s: %s %s", entry["ip"], status, doc)
        return doc.get("updated", 0)

    def fingerprints(self):
        """Fill the fingerprint book from the sentinel indices. Every document
        is written with _create, so the first sighting is never overwritten and
        @timestamp keeps meaning "the first time this stack knocked"."""
        for kind, field in FINGERPRINT_FIELDS.items():
            body = {"size": 0,
                    "query": {"bool": {"filter": [{"exists": {"field": field}}]}},
                    "aggs": {"values": {
                        "terms": {"field": field, "size": 1000},
                        "aggs": {"first": {"min": {"field": "@timestamp"}},
                                 "earliest": {"top_hits": {
                                     "size": 1, "sort": [{"@timestamp": "asc"}],
                                     "_source": ["source.ip", "threat.tool", "ssh_client"]}}}}}}
            status, doc = self.os.call(
                "POST", f"/{SENTINEL_INDICES}/_search?ignore_unavailable=true", body)
            if status != 200:
                log.warning("fingerprints %s: %s %s", kind, status, doc)
                continue
            for bucket in doc.get("aggregations", {}).get("values", {}).get("buckets", []):
                doc_id = book_id(kind, bucket["key"])
                if doc_id in self.known_fingerprints:
                    continue
                hits = bucket.get("earliest", {}).get("hits", {}).get("hits", [])
                src = hits[0].get("_source", {}) if hits else {}
                entry = {"@timestamp": bucket.get("first", {}).get("value_as_string"),
                         "kind": kind, "value": bucket["key"]}
                first_ip = (src.get("source") or {}).get("ip")
                for key, value in (("first_ip", first_ip),
                                   ("tool", (src.get("threat") or {}).get("tool")),
                                   ("ssh_client", src.get("ssh_client"))):
                    if value:
                        entry[key] = value
                status, resp = self.os.call(
                    "PUT", f"/{FINGERPRINT_BOOK}/_create/{doc_id}", entry)
                if status in (200, 201):
                    log.info("new fingerprint %s %s from %s", kind, bucket["key"], first_ip)
                elif status == 409:  # the normal case: seen on an earlier pass
                    log.debug("fingerprint %s already in the book", doc_id)
                else:
                    log.warning("fingerprint %s: %s %s", doc_id, status, resp)
                    continue
                self.known_fingerprints.add(doc_id)

    def cycle(self):
        self.fingerprints()
        ips = self.pending()
        if not ips:
            return
        with ThreadPoolExecutor(max_workers=8) as pool:
            entries = [e for e in pool.map(self.lookup, ips) if e]
        updated = sum(self.apply(e) for e in entries)
        log.info("pass: %d addresses, %d events updated", len(entries), updated)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    # PID 1 in a container gets no default handler, so without this a stop
    # waits ten seconds and then kills.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    with open(SECRETS_FILE, encoding="utf-8") as fh:
        secrets = json.load(fh)
    client = OpenSearch(OS_URL, "admin", secrets["opensearch_password"])
    lists = Lists()
    enricher = Enricher(client, lists, Reputation(secrets))
    log.info("reputation: greynoise=%s abuseipdb=%s",
             bool(secrets.get("greynoise_api_key")), bool(secrets.get("abuseipdb_api_key")))
    while True:
        try:
            enricher.ensure_book()
            break
        except Exception as e:
            log.warning("waiting for OpenSearch: %s", e)
            time.sleep(15)
    while True:
        if time.time() >= lists.next_try:
            lists.refresh()
        if lists.loaded_at:  # no lists, no verdicts: better to wait than to mark events done
            try:
                enricher.cycle()
            except Exception as e:
                log.exception("pass failed: %s", e)
        time.sleep(CYCLE)


def selftest():
    nets = parse_networks("# Censys\ndefine censys_v4 = {\n\t162.142.125.0/24,\n\t1.2.3.4,\n}\n; comment\nbad 999.1.1.1\n")
    assert [str(n) for n in nets] == ["162.142.125.0/24", "1.2.3.4/32"], nets
    scores = parse_ipsum("# IPsum\n1.1.1.1\t2\n2.2.2.2\t5\nbroken\n", 3)
    assert scores == {int(ipaddress.ip_address("2.2.2.2")): 5}, scores
    lists = Lists()
    lists.add("openfilters:censys", nets)
    lists.add("firehol:dshield", parse_networks("1.2.3.0/24"))
    lists.ipsum = scores
    assert lists.match(ipaddress.ip_address("162.142.125.9")) == ("censys", ["openfilters:censys"], None)
    assert lists.match(ipaddress.ip_address("1.2.3.4")) == ("censys", ["firehol:dshield", "openfilters:censys"], None)
    assert lists.match(ipaddress.ip_address("2.2.2.2")) == (None, [], 5)
    assert scanner_from_ptr("scan-05a.shadowserver.org") == "shadowserver"
    assert scanner_from_ptr("shadowserver.org.example.net") is None
    assert scanner_from_ptr(None) is None
    assert not ipaddress.ip_address("10.89.0.4").is_global

    # The gap the painless stamps as prior.sentinel_hours. Both writers emit
    # the +00:00 form; an aggregation hands back the Z form; the two mix,
    # because the book's dates come from aggregations and the event's from
    # the producer.
    assert hours_between("2026-09-01T00:00:00+00:00", "2026-09-01T06:30:00+00:00") == 6.5
    assert hours_between("2026-09-01T00:00:00.000Z", "2026-09-01T01:00:00+00:00") == 1.0
    assert hours_between("2026-09-01T12:00:00Z", "2026-09-01T09:00:00+00:00") == -3.0
    # The sentinel visited first: positive, so it is stored. Reversed it is
    # negative and the painless drops it.
    assert hours_between("2026-09-01T00:00:00+00:00", "2026-09-04T00:00:00+00:00") == 72.0

    # first_seen merging keeps the earlier date whichever side it comes from,
    # and tolerates a missing side.
    assert earlier("2026-09-01T00:00:00Z", "2026-08-01T00:00:00Z") == "2026-08-01T00:00:00Z"
    assert earlier("2026-08-01T00:00:00Z", "2026-09-01T00:00:00Z") == "2026-08-01T00:00:00Z"
    assert earlier(None, "2026-09-01T00:00:00Z") == "2026-09-01T00:00:00Z"
    assert earlier("2026-09-01T00:00:00Z", None) == "2026-09-01T00:00:00Z"
    assert earlier(None, None) is None

    # Fingerprint ids: the value half is attacker text, so a slash cannot be
    # allowed to walk out of the index in the create URL.
    assert book_id("hassh", "06046964c022c6407d15a27b12a6a4fb") == \
        "hassh:06046964c022c6407d15a27b12a6a4fb"
    assert book_id("ja4", "t13d1516h2_8daaf6152771_b186095e22b6") == \
        "ja4:t13d1516h2_8daaf6152771_b186095e22b6"
    assert book_id("http", "a/b:c d") == "http:a%2Fb%3Ac%20d"
    assert "/" not in book_id("http", "../../_all")

    print("selftest ok")


if __name__ == "__main__":
    selftest() if "--selftest" in sys.argv else main()
