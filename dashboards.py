#!/usr/bin/env python3
"""Print the Dashboards saved objects for tripwire as ndjson.

One overview dashboard, the visualisations on it and two saved searches, all
on the `tripwire` index pattern that bootstrap-opensearch.sh creates. Stdlib
only. bootstrap-opensearch.sh pipes the output into the saved-objects import
API; to load it by hand, redirect to a file and use Stack Management >
Saved objects > Import in Dashboards.

Everything is keyed by a fixed id so re-importing with overwrite=true updates
in place instead of piling up copies.
"""

import json

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


def table(vid, title, field, query="", size=15):
    return vis(vid, title, "table", [count(), terms(field, size)],
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


def timeline(vid, title, split_field):
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
    return vis(vid, title, "histogram", aggs, params)


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


def saved_search(sid, title, query, columns):
    return {"id": sid, "type": "search",
            "attributes": {"title": title, "columns": columns,
                           "sort": [["@timestamp", "desc"]], "version": 1,
                           "description": "",
                           "kibanaSavedObjectMeta": {
                               "searchSourceJSON": search_source(query)}},
            "references": [INDEX]}


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


if __name__ == "__main__":
    for obj in VISUALISATIONS + SEARCHES + [dashboard()]:
        print(json.dumps(obj))
