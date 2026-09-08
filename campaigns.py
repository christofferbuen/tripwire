#!/usr/bin/env python3
"""Cluster sentinel addresses by protocol fingerprint into campaigns.

An address is cheap identity: throwaway VPS, next scanner in the botnet.
A SSH/TLS/HTTP stack fingerprint is expensive to change. This groups the
addresses seen on tripwire-sentinel-* by (fingerprint, ports touched) so a
hundred addresses running the same tool on the same port show up as one row
instead of a hundred.

Stdlib only.

    python3 campaigns.py [--days 7] [--min-addresses 2] [--json]
    python3 campaigns.py --selftest   exercises the clustering, no network

Environment: OS_URL, OS_PASS (as alerts.py).
"""

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone

OS_URL = os.environ.get("OS_URL", "https://localhost:9200").rstrip("/")
OS_PASS = os.environ.get("OS_PASS", "")

# Self-signed demo certificates on a loopback or WireGuard address.
INSECURE = ssl.create_default_context()
INSECURE.check_hostname = False
INSECURE.verify_mode = ssl.CERT_NONE
AUTH = "Basic " + base64.b64encode(f"admin:{OS_PASS}".encode()).decode()


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(OS_URL + path, data=data, method=method,
                                 headers={"Authorization": AUTH,
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30, context=INSECURE) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read() or b"{}")


def clean(text):
    """Escape control characters before they reach a terminal.

    Every field here (ssh client banner, mysql user, tool name, ASN org) is
    attacker-controlled. An ANSI sequence must not get to repaint the screen
    it is printed on.
    """
    return "".join(ch if ch.isprintable() else repr(ch)[1:-1]
                   for ch in str(text if text is not None else ""))


# Sub-aggregations run per address (per composite bucket). size 3 on the
# identity fields is enough to see "this address rotated fingerprints" without
# pulling every value; size 10 on port covers a scanner touching several.
SUB_AGGS = {
    "hassh": {"terms": {"field": "fingerprint.hassh", "size": 3}},
    "ja4": {"terms": {"field": "fingerprint.ja4", "size": 3}},
    "http": {"terms": {"field": "fingerprint.http", "size": 3}},
    "tool": {"terms": {"field": "threat.tool", "size": 3}},
    "ssh_client": {"terms": {"field": "ssh_client", "size": 3}},
    "mysql_user": {"terms": {"field": "mysql_user", "size": 3}},
    "asn": {"terms": {"field": "source.as.organization_name", "size": 3}},
    "country": {"terms": {"field": "source.geo.country_iso_code", "size": 3}},
    "ports": {"terms": {"field": "port", "size": 10}},
    "first_seen": {"min": {"field": "@timestamp"}},
    "last_seen": {"max": {"field": "@timestamp"}},
    "held": {"sum": {"field": "held_ms"}},
    "conns": {"value_count": {"field": "@timestamp"}},
}

PAGE_SIZE = 500


def fetch_addresses(days):
    """Page the composite aggregation over tripwire-sentinel-* to completion."""
    addresses = []
    after = None
    while True:
        composite = {"size": PAGE_SIZE, "sources": [{"ip": {"terms": {"field": "source.ip"}}}]}
        if after:
            composite["after"] = after
        body = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
            "aggs": {"by_ip": {"composite": composite, "aggregations": SUB_AGGS}},
        }
        status, resp = call("POST", "/tripwire-sentinel-*/_search", body)
        if status != 200:
            sys.exit(f"search: {status} {resp}")
        by_ip = resp["aggregations"]["by_ip"]
        buckets = by_ip.get("buckets", [])
        addresses.extend(address_summary(b) for b in buckets)
        after = by_ip.get("after_key")
        if not after or len(buckets) < PAGE_SIZE:
            break
    return addresses


def address_summary(bucket):
    """Reduce one composite bucket (one address) to the fields we cluster on."""
    def top(name):
        buckets = bucket.get(name, {}).get("buckets", [])
        return buckets[0]["key"] if buckets else None

    def counts(name):
        return {b["key"]: b["doc_count"] for b in bucket.get(name, {}).get("buckets", [])}

    primary = "unknown"
    for kind, field in (("hassh", "hassh"), ("ja4", "ja4"), ("http", "http"), ("tool", "tool")):
        value = top(field)
        if value:
            primary = f"{kind}:{value}"
            break

    return {
        "ip": bucket["key"]["ip"],
        "primary": primary,
        "ports": tuple(sorted(b["key"] for b in bucket.get("ports", {}).get("buckets", []))),
        "tool": counts("tool"),
        "ssh_client": counts("ssh_client"),
        "mysql_user": counts("mysql_user"),
        "asn": counts("asn"),
        "country": counts("country"),
        "first_seen": (bucket.get("first_seen") or {}).get("value"),
        "last_seen": (bucket.get("last_seen") or {}).get("value"),
        "held_ms": (bucket.get("held") or {}).get("value") or 0,
    }


def merge_counts(addrs, field):
    total = Counter()
    for a in addrs:
        for value, count in a[field].items():
            total[value] += count
    return total


def iso(epoch_ms):
    if epoch_ms is None:
        return None
    return datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc).isoformat()


def make_cluster(key, addrs):
    primary, ports = key
    firsts = [a["first_seen"] for a in addrs if a["first_seen"] is not None]
    lasts = [a["last_seen"] for a in addrs if a["last_seen"] is not None]
    asn = merge_counts(addrs, "asn")
    country = merge_counts(addrs, "country")
    return {
        "primary": primary,
        "unfingerprinted": primary == "unknown",
        "ports": list(ports),
        "addresses": len(addrs),
        "ips": sorted(a["ip"] for a in addrs),
        "asns": len(asn),
        "countries": len(country),
        "first_seen": iso(min(firsts)) if firsts else None,
        "last_seen": iso(max(lasts)) if lasts else None,
        "held_ms": sum(a["held_ms"] for a in addrs),
        "tool": merge_counts(addrs, "tool").most_common(),
        "ssh_client": merge_counts(addrs, "ssh_client").most_common(),
        "mysql_user": merge_counts(addrs, "mysql_user").most_common(),
        "asn": asn.most_common(),
        "country": country.most_common(),
    }


def build_clusters(addrs):
    """Group addresses into campaigns.

    Cluster key is (primary fingerprint, ports touched). An address with no
    fingerprint gets primary "unknown", which collapses the key to ports
    alone -- exactly the "grouped by ports only" rule the plan asks for.
    """
    groups = defaultdict(list)
    for a in addrs:
        groups[(a["primary"], a["ports"])].append(a)
    return [make_cluster(key, members) for key, members in groups.items()]


def report(addrs, min_addresses):
    clusters = build_clusters(addrs)
    fingerprinted = sorted(
        (c for c in clusters if not c["unfingerprinted"] and c["addresses"] >= min_addresses),
        key=lambda c: -c["addresses"])
    unfingerprinted = sorted(
        (c for c in clusters if c["unfingerprinted"] and c["addresses"] >= min_addresses),
        key=lambda c: -c["addresses"])
    return fingerprinted, unfingerprinted


def top_str(pairs, n=5):
    return " ".join(f"{clean(value)} ({count})" for value, count in pairs[:n])


def format_cluster(c):
    ports = ",".join(str(p) for p in c["ports"]) or "-"
    first = (c["first_seen"] or "?")[:10]
    last = (c["last_seen"] or "?")[:10]
    lines = [f"{clean(c['primary'])}  ports {ports}  {c['addresses']} addresses  "
             f"{c['asns']} ASNs  {c['countries']} countries  {first} → {last}"]

    row = []
    if c["tool"]:
        row.append("tool " + top_str(c["tool"]))
    if c["ssh_client"]:
        row.append("clients " + top_str(c["ssh_client"]))
    if row:
        lines.append("  " + "   ".join(row))

    row = []
    if c["mysql_user"]:
        row.append("users " + top_str(c["mysql_user"]))
    if c["held_ms"]:
        row.append(f"held {round(c['held_ms'] / 60000)} min")
    if row:
        lines.append("  " + "   ".join(row))

    if c["asn"]:
        lines.append("  ASNs " + top_str(c["asn"]))
    return "\n".join(lines)


def print_report(fingerprinted, unfingerprinted):
    if not fingerprinted and not unfingerprinted:
        print("no addresses in window")
        return
    for c in fingerprinted:
        print(format_cluster(c))
    if unfingerprinted:
        print("\nunfingerprinted")
        for c in unfingerprinted:
            print(format_cluster(c))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--min-addresses", type=int, default=2)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true", help="run the clustering selftest, no network")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return 0

    addrs = fetch_addresses(args.days)
    fingerprinted, unfingerprinted = report(addrs, args.min_addresses)

    if args.json:
        print(json.dumps(fingerprinted + unfingerprinted))
    else:
        print_report(fingerprinted, unfingerprinted)
    return 0


def selftest():
    def bucket(ip, doc_count, **fields):
        b = {"key": {"ip": ip}, "doc_count": doc_count}
        b.update(fields)
        for name in ("hassh", "ja4", "http", "tool", "ssh_client", "mysql_user", "asn", "country", "ports"):
            b.setdefault(name, {"buckets": []})
        b.setdefault("first_seen", {"value": 1_700_000_000_000})
        b.setdefault("last_seen", {"value": 1_700_000_100_000})
        b.setdefault("held", {"value": 0})
        return b

    def term(*pairs):
        return {"buckets": [{"key": k, "doc_count": n} for k, n in pairs]}

    raw = [
        # Two addresses sharing hassh and ports -> one cluster of 2.
        bucket("1.1.1.1", 10, hassh=term(("aaa", 10)), tool=term(("go-ssh", 10)),
               ssh_client=term(("SSH-2.0-Go", 10)), ports=term((22, 10))),
        bucket("1.1.1.2", 5, hassh=term(("aaa", 5)), tool=term(("go-ssh", 5)),
               ssh_client=term(("SSH-2.0-Go", 5)), ports=term((22, 5))),
        # Same hassh, different ports -> its own cluster of 1.
        bucket("1.1.1.3", 3, hassh=term(("aaa", 3)), ports=term((22, 2), (2222, 1))),
        # Only a tool, no hassh/ja4/http -> primary "tool:..." with an ANSI
        # escape in its ssh_client, which must come out escaped.
        bucket("1.1.1.4", 4, tool=term(("libssh", 4)),
               ssh_client=term(("evil\x1b[31m", 4)), ports=term((2222, 4))),
        # Nothing at all -> unfingerprinted.
        bucket("1.1.1.5", 1, ports=term((80, 1))),
    ]

    addrs = [address_summary(b) for b in raw]
    assert addrs[0]["primary"] == "hassh:aaa", addrs[0]
    assert addrs[2]["ports"] == (22, 2222), addrs[2]
    assert addrs[3]["primary"] == "tool:libssh", addrs[3]
    assert addrs[4]["primary"] == "unknown", addrs[4]

    fingerprinted, unfingerprinted = report(addrs, min_addresses=1)
    assert len(fingerprinted) == 3, fingerprinted
    assert len(unfingerprinted) == 1, unfingerprinted
    assert fingerprinted[0]["addresses"] == 2, fingerprinted[0]
    assert fingerprinted[0]["ports"] == [22], fingerprinted[0]
    assert fingerprinted[0]["primary"] == "hassh:aaa"
    assert unfingerprinted[0]["ips"] == ["1.1.1.5"]

    # --min-addresses filters the singleton clusters back out.
    fingerprinted2, unfingerprinted2 = report(addrs, min_addresses=2)
    assert len(fingerprinted2) == 1, fingerprinted2
    assert not unfingerprinted2

    tool_cluster = next(c for c in fingerprinted if c["primary"] == "tool:libssh")
    text = format_cluster(tool_cluster)
    assert "\x1b" not in text, text
    assert "\\x1b" in text, text

    print("selftest ok")


if __name__ == "__main__":
    sys.exit(main())
