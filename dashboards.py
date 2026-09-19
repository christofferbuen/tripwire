#!/usr/bin/env python3
"""Print the Dashboards saved objects for tripwire as ndjson.

One overview dashboard, the visualisations on it and the saved searches, on
the `tripwire` index pattern that bootstrap-opensearch.sh creates (the
dropper ledger view is on its own `dropper-book` pattern). Stdlib only. bootstrap-opensearch.sh pipes the output into the saved-objects import
API; to load it by hand, redirect to a file and use Stack Management >
Saved objects > Import in Dashboards.

Everything is keyed by a fixed id so re-importing with overwrite=true updates
in place instead of piling up copies. That also means an edit made to one of
these objects in the Dashboards UI is lost on the next bootstrap: copy the
object under a new name before changing it.

`--selftest` checks the output against itself and against the mappings in
bootstrap-opensearch.sh, without a cluster.
"""

import json
import os
import re
import sys

INDEX = {"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
         "type": "index-pattern", "id": "tripwire"}

RECEIVER = "event.module:receiver"
SENTINEL = "event.module:sentinel"


def search_source(query=""):
    return json.dumps({"query": {"query": query, "language": "kuery"},
                       "filter": [], "indexRefName": INDEX["name"]})


def count():
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric",
            "params": {}}


def terms(field, size=15, schema="bucket", agg_id="2"):
    return {"id": agg_id, "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "orderBy": "1", "order": "desc",
                       "size": size, "otherBucket": False,
                       "otherBucketLabel": "Other", "missingBucket": False,
                       "missingBucketLabel": "Missing"}}


def vis(vid, title, vis_type, aggs, params, query=""):
    state = {"title": title, "type": vis_type, "aggs": aggs, "params": params}
    return {"id": vid, "type": "visualization",
            "attributes": {"title": title, "visState": json.dumps(state),
                           "uiStateJSON": "{}", "description": "", "version": 1,
                           "kibanaSavedObjectMeta": {
                               "searchSourceJSON": search_source(query)}},
            "references": [INDEX]}


def table(vid, title, field, query="", size=15, split=None):
    aggs = [count(), terms(field, size)]
    if split:
        aggs.append(terms(split, 5, agg_id="3"))
    return vis(vid, title, "table", aggs,
               {"perPage": 15, "showPartialRows": False,
                "showMetricsAtAllLevels": False, "showTotal": False,
                "totalFunc": "sum", "percentageCol": "",
                "sort": {"columnIndex": None, "direction": None}}, query)


def pie(vid, title, field, query=""):
    return vis(vid, title, "pie", [count(), terms(field, 10, "segment")],
               {"type": "pie", "addTooltip": True, "addLegend": True,
                "legendPosition": "right", "isDonut": True,
                "labels": {"show": False, "values": True, "last_level": True,
                           "truncate": 100}}, query)


def timeline(vid, title, split_field, query=""):
    aggs = [count(),
            {"id": "2", "enabled": True, "type": "date_histogram",
             "schema": "segment",
             "params": {"field": "@timestamp", "interval": "auto",
                        "min_doc_count": 1, "extended_bounds": {},
                        "useNormalizedOpenSearchInterval": True,
                        "scaleMetricValues": False, "drop_partials": False,
                        "timeRange": {"from": "now-7d", "to": "now"}}},
            terms(split_field, 5, "group", "3")]
    params = {
        "type": "histogram", "grid": {"categoryLines": False},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category",
                          "position": "bottom", "show": True, "style": {},
                          "scale": {"type": "linear"},
                          "labels": {"show": True, "filter": True,
                                     "truncate": 100},
                          "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1",
                       "type": "value", "position": "left", "show": True,
                       "style": {}, "scale": {"type": "linear", "mode": "normal"},
                       "labels": {"show": True, "rotate": 0, "filter": False,
                                  "truncate": 100},
                       "title": {"text": "Count"}}],
        "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                          "data": {"label": "Count", "id": "1"},
                          "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                          "lineWidth": 2, "showCircles": True}],
        "addTooltip": True, "addLegend": True, "legendPosition": "right",
        "times": [], "addTimeMarker": False, "labels": {"show": False},
        "thresholdLine": {"show": False, "value": 10, "width": 1,
                          "style": "full", "color": "#E7664C"},
    }
    return vis(vid, title, "histogram", aggs, params, query)


def world_map(vid, title):
    """Coordinate map on source.geo.location. Tiles come from
    maps.opensearch.org, fetched by the browser, so this panel is blank when
    the browser has no route out. Everything else works offline."""
    aggs = [count(),
            {"id": "2", "enabled": True, "type": "geohash_grid", "schema": "segment",
             "params": {"field": "source.geo.location", "autoPrecision": True,
                        "isFilteredByCollar": True, "useGeocentroid": True,
                        "mapZoom": 2, "mapCenter": [20, 0], "precision": 2}}]
    params = {"colorSchema": "Yellow to Red", "mapType": "Scaled Circle Markers",
              "isDesaturated": True, "addTooltip": True, "heatClusterSize": 1.5,
              "legendPosition": "bottomright", "mapZoom": 2, "mapCenter": [20, 0],
              "wms": {"enabled": False, "options": {"format": "image/png",
                                                    "transparent": True}}}
    return vis(vid, title, "tile_map", aggs, params)


def saved_search(sid, title, query, columns, pattern="tripwire"):
    return {"id": sid, "type": "search",
            "attributes": {"title": title, "columns": columns,
                           "sort": [["@timestamp", "desc"]], "version": 1,
                           "description": "",
                           "kibanaSavedObjectMeta": {
                               "searchSourceJSON": search_source(query)}},
            "references": [dict(INDEX, id=pattern)]}


VISUALISATIONS = [
    timeline("tw-timeline", "Events by source", "event.module"),
    table("tw-sources", "Top addresses", "source.ip", size=20),
    pie("tw-tiers", "Receiver: tiers", "tier_name", RECEIVER),
    table("tw-paths", "Receiver: paths", "path", RECEIVER),
    pie("tw-class", "Sentinel: classification", "classification", SENTINEL),
    table("tw-ports", "Sentinel: ports", "port", SENTINEL),
    table("tw-agents", "User agents", "http.user_agent"),
    table("tw-canaries", "Canaries that fired", "canary", RECEIVER),
    world_map("tw-map", "Where from"),
    table("tw-countries", "Countries", "source.geo.country_name"),
    table("tw-orgs", "Networks", "source.as.organization_name"),
    # Filled in by enrich.py after the fact (reverse DNS, published lists)
    # and by Vector at ingest (threat.tool from banners and user agents).
    pie("tw-scanners", "Known scanners", "threat.scanner"),
    pie("tw-tools", "Tools", "threat.tool"),
    table("tw-lists", "On lists", "threat.lists"),
    table("tw-ptr", "Reverse DNS", "source.domain", size=20),
    # What they actually asked for. Request lines carry the exploit paths
    # (/boaform/, /.env, the Mozi dropper in the query string); the
    # fingerprint says which program sent them, across addresses.
    table("tw-requests", "Sentinel: request lines", "http_requests", SENTINEL, size=20),
    table("tw-hassh", "SSH stacks (HASSH)", "fingerprint.hassh", SENTINEL),
    # What the connection gives away without being asked: a client speaking
    # TLS or HTTP to an SSH port, the exploit a request line belongs to, a
    # round trip that cannot be squared with where GeoIP puts the address.
    # The verdict tests the GeoIP claim, not who is behind a proxy.
    table("tw-mismatch", "Spoke the wrong protocol", "proto_mismatch", SENTINEL,
          split="port"),
    table("tw-exploits", "Exploits named", "threat.exploit", SENTINEL, size=20),
    pie("tw-rtt", "RTT against GeoIP", "network.rtt_verdict", SENTINEL),
    table("tw-helo", "SMTP: EHLO names", "smtp.helo", SENTINEL, size=20),
    pie("tw-hosting", "Hosting kind", "source.hosting"),
    timeline("tw-proxy", "Proxy probes", "port", "threat.proxy_probe:true"),
]

SEARCHES = [
    saved_search("tw-search-receiver", "Receiver hits", RECEIVER,
                 ["source.ip", "source.domain", "source.geo.country_iso_code",
                  "source.as.organization_name", "threat.scanner", "threat.tool",
                  "tier_name", "method", "path", "http.user_agent", "canary"]),
    saved_search("tw-search-sentinel", "Sentinel connections", SENTINEL,
                 ["source.ip", "source.domain", "source.geo.country_iso_code",
                  "source.as.organization_name", "threat.scanner", "threat.tool",
                  "port", "role", "classification", "ssh_client",
                  "distinct_ports"]),
    # The payload views: open these in Discover to read what was sent.
    saved_search("tw-search-payloads", "Sentinel payloads",
                 SENTINEL + " and (http_requests:* or http_body:* or smtp_commands:* or mysql_user:* or payload_text:*)",
                 ["source.ip", "port", "threat.tool", "fingerprint.hassh", "fingerprint.http",
                  "http_requests", "http_body", "smtp_commands", "mysql_user", "payload_text"]),
    saved_search("tw-search-bodies", "Receiver: posted bodies and odd paths",
                 RECEIVER + " and (body_excerpt:* or tier_name:(collection-post or instruction-follower or tarpit))",
                 ["source.ip", "tier_name", "method", "path", "http.user_agent", "body_excerpt", "canary"]),
    # dropper.urls is attacker text naming attacker infrastructure: read it,
    # never open it. The ledger view shows the defanged form only.
    saved_search("tw-search-droppers", "Droppers", "dropper.urls:*",
                 ["source.ip", "port", "threat.exploit", "dropper.hosts", "dropper.urls"]),
    saved_search("tw-search-ledger", "Dropper ledger: first seen", "",
                 ["kind", "url_defanged", "host", "port", "first_source_ip", "first_index"],
                 pattern="dropper-book"),
    # Payloads nothing has a name for yet: the raw material for the next
    # needle in vector-sentinel.toml.
    saved_search("tw-search-unlabelled", "Unlabelled payloads",
                 SENTINEL + " and (http_requests:* or http_body:* or payload_text:*)"
                 " and not threat.exploit:* and not threat.tool:* and not threat.scanner:*",
                 ["source.ip", "port", "http.user_agent", "http_requests", "http_body", "payload_text"]),
    saved_search("tw-search-smtp", "SMTP identities",
                 SENTINEL + " and (smtp.helo:* or smtp.mail_from:* or smtp.auth_user:*)",
                 ["source.ip", "smtp.helo", "smtp.mail_from", "smtp.rcpt", "smtp.auth_user",
                  "smtp.starttls", "proto_mismatch"]),
    saved_search("tw-search-egress", "Egress attempts", "classification:egress-blocked",
                 ["egress.scope", "egress.uid", "egress.dst_ip", "egress.dst_port",
                  "egress.proto", "egress.count"]),
]

# (id, x, y, w, h) on a 48-column grid.
LAYOUT = [
    ("tw-timeline", 0, 0, 48, 12),
    ("tw-map", 0, 12, 24, 18),
    ("tw-countries", 24, 12, 12, 18),
    ("tw-orgs", 36, 12, 12, 18),
    ("tw-sources", 0, 30, 16, 16),
    ("tw-tiers", 16, 30, 16, 16),
    ("tw-class", 32, 30, 16, 16),
    ("tw-paths", 0, 46, 16, 16),
    ("tw-ports", 16, 46, 16, 16),
    ("tw-canaries", 32, 46, 16, 16),
    ("tw-scanners", 0, 62, 12, 16),
    ("tw-tools", 12, 62, 12, 16),
    ("tw-lists", 24, 62, 12, 16),
    ("tw-ptr", 36, 62, 12, 16),
    ("tw-agents", 0, 78, 48, 14),
    ("tw-requests", 0, 92, 32, 16),
    ("tw-hassh", 32, 92, 16, 16),
    ("tw-exploits", 0, 108, 16, 16),
    ("tw-mismatch", 16, 108, 16, 16),
    ("tw-helo", 32, 108, 16, 16),
    ("tw-rtt", 0, 124, 12, 16),
    ("tw-hosting", 12, 124, 12, 16),
    ("tw-proxy", 24, 124, 24, 16),
]


def dashboard():
    panels, refs = [], []
    for n, (vid, x, y, w, h) in enumerate(LAYOUT):
        panels.append({"version": "3.8.0", "panelIndex": str(n),
                       "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(n)},
                       "embeddableConfig": {}, "panelRefName": f"panel_{n}"})
        refs.append({"name": f"panel_{n}", "type": "visualization", "id": vid})
    return {"id": "tw-overview", "type": "dashboard",
            "attributes": {"title": "Tripwire overview", "hits": 0,
                           "description": "Receiver hits and sentinel connections",
                           "panelsJSON": json.dumps(panels),
                           "optionsJSON": json.dumps({"useMargins": True,
                                                      "hidePanelTitles": False}),
                           "version": 1, "timeRestore": True,
                           "timeFrom": "now-7d", "timeTo": "now",
                           "refreshInterval": {"pause": False, "value": 60000},
                           "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                               {"query": {"query": "", "language": "kuery"},
                                "filter": []})}},
            "references": refs}


def mapped_fields(text):
    """Dotted names of every field in one mapping JSON blob."""
    found = set()

    def walk(props, prefix):
        for name, spec in props.items():
            found.add(prefix + name)
            walk(spec.get("properties", {}), prefix + name + ".")
    walk(json.loads(text)["properties"], "")
    return found


def selftest():
    objects = VISUALISATIONS + SEARCHES + [dashboard()]
    for obj in objects:
        json.loads(json.dumps(obj))
    ids = [o["id"] for o in objects]
    assert len(ids) == len(set(ids)), "duplicate saved object id"
    placed = [vid for vid, *_ in LAYOUT]
    assert set(placed) == {v["id"] for v in VISUALISATIONS}, "LAYOUT and VISUALISATIONS disagree"
    cells = set()
    for vid, x, y, w, h in LAYOUT:
        assert x + w <= 48, vid
        box = {(cx, cy) for cx in range(x, x + w) for cy in range(y, y + h)}
        assert not box & cells, f"{vid} overlaps another panel"
        cells |= box

    # Every field a panel or a column names has to be in the index template,
    # and the block for already-open indices may not name a field the
    # template lacks: that is how the two drift apart.
    # ponytail: finds the two blobs by the lines around them, not by parsing sh.
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "bootstrap-opensearch.sh"), encoding="utf-8") as fh:
        script = fh.read()
    template = mapped_fields(
        re.search(r'"mappings": (\{.*?\n    \})\n', script, re.S).group(1))
    live = mapped_fields(
        re.search(r"""/_mapping" '(\{.*?\})' \|\| true""", script, re.S).group(1))
    assert not live - template, f"only in the live block: {sorted(live - template)}"
    used = set()
    for v in VISUALISATIONS:
        for agg in json.loads(v["attributes"]["visState"])["aggs"]:
            used.add(agg["params"].get("field"))
    for s in SEARCHES:
        if s["references"][0]["id"] == "tripwire":
            used.update(s["attributes"]["columns"])
    used -= {None}
    assert not used - template, f"not in the template: {sorted(used - template)}"
    print(f"selftest ok: {len(objects)} objects, {len(used)} fields, all mapped")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
        sys.exit(0)
    for obj in VISUALISATIONS + SEARCHES + [dashboard()]:
        print(json.dumps(obj))
