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
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

OS_URL = os.environ.get("OPENSEARCH_URL", "https://opensearch:9200")
SECRETS_FILE = os.environ.get("SECRETS_FILE", "/run/secrets/tripwire.json")
EVENT_INDICES = "tripwire-hits-*,tripwire-sentinel-*"
BOOK = "address-book"
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

# Runs on every event of the address that has no enrichment yet. threat is
# merged rather than replaced because Vector already sets threat.tool from the
# banner or user agent at ingest.
APPLY_SCRIPT = """
if (ctx._source.source == null) { ctx._source.source = new HashMap(); }
if (params.domain != null) { ctx._source.source.domain = params.domain; }
if (params.threat != null) {
  if (ctx._source.threat == null) { ctx._source.threat = new HashMap(); }
  ctx._source.threat.putAll(params.threat);
}
if (params.reputation != null) { ctx._source.reputation = params.reputation; }
ctx._source.enrichment = params.enrichment;
"""


class Enricher:
    def __init__(self, os_client, lists, reputation):
        self.os = os_client
        self.lists = lists
        self.rep = reputation

    def ensure_book(self):
        status, doc = self.os.call("PUT", "/" + BOOK, BOOK_MAPPING)
        if status == 200:
            log.info("created index %s", BOOK)
        elif status != 400 or "already_exists" not in json.dumps(doc):
            raise RuntimeError(f"cannot create {BOOK}: {status} {doc}")

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

    def lookup(self, ip_text):
        status, doc = self.os.call("GET", f"/{BOOK}/_doc/{ip_text}")
        cached = doc.get("_source") if status == 200 else None
        if cached and (datetime.now(timezone.utc) - parse_iso(cached["checked"])).total_seconds() < RECHECK:
            return cached
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            return None
        entry = {"ip": ip_text, "checked": now_iso(),
                 "first_seen": (cached or {}).get("first_seen") or now_iso()}
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
        params = {"domain": entry.get("ptr"), "threat": threat or None,
                  "reputation": reputation or None, "enrichment": {"at": now_iso()}}
        body = {"query": {"bool": {"filter": [{"term": {"source.ip": entry["ip"]}},
                                              {"range": {"@timestamp": {"gte": LOOKBACK}}}],
                                   "must_not": [{"exists": {"field": "enrichment.at"}}]}},
                "script": {"lang": "painless", "source": APPLY_SCRIPT, "params": params}}
        status, doc = self.os.call(
            "POST", f"/{EVENT_INDICES}/_update_by_query?conflicts=proceed&ignore_unavailable=true", body)
        if status != 200:
            log.warning("apply %s: %s %s", entry["ip"], status, doc)
        return doc.get("updated", 0)

    def cycle(self):
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
    print("selftest ok")


if __name__ == "__main__":
    selftest() if "--selftest" in sys.argv else main()
