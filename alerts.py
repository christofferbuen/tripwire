#!/usr/bin/env python3
"""Create the alerting channel and monitors in OpenSearch. Stdlib only.

bootstrap-opensearch.sh runs this when NTFY_TOKEN is set in .env. Everything
is keyed by a fixed name or id, so re-running updates in place.

Two channels, both webhooks to the ntfy server with the token in an
Authorization header and title, priority and tags as ntfy headers so the
message templates stay plain text: one high priority for things that need a
look, one low priority for the daily digest.

  tripwire-canary            a canary token was presented back to the receiver
  tripwire-agent             something followed an embedded instruction or
                             posted to the collection endpoint (tiers 2 and 3)
  tripwire-both              one address touched the sentinel and the receiver
                             within an hour: scanned first, then knocked
  tripwire-returned          a receiver hit from an address whose first
                             sentinel contact is at least an hour older. The
                             same shape as tripwire-both over any distance in
                             time: it scanned the honeypot, then came back to
                             the real site days or weeks later
  tripwire-novel-fingerprint a client stack (HASSH, JA4 or header order) the
                             sentinel has never seen before
  tripwire-egress            something on the sentinel VM tried to connect out
                             and the firewall refused it. Nothing there has
                             a reason to, so this is the alert that means the
                             VM is owned: snapshot it from the cloud console,
                             then destroy it, and do not log in to look first
  tripwire-novel-dropper     a payload named a second-stage location that is
                             not in dropper-book yet. Shown defanged, never
                             fetched
  tripwire-honeypot-tagged   Shodan's InternetDB tags the sentinel's own
                             address as a honeypot: the persona has been seen
                             through. Only with that opt-in lookup enabled
  tripwire-sentinel-silent   no sentinel events for an hour. It sees dozens
                             of connections an hour at its quietest, so an
                             empty hour means the VM, its Vector or WireGuard
                             is down, not that the internet went quiet
  tripwire-receiver-silent   no heartbeat hit for 30 minutes. The receiver
                             can legitimately go hours without a visitor, so
                             a cron job on the collector fetches the public
                             site every 10 minutes with User-Agent
                             tripwire-heartbeat (see README). Missing three
                             in a row means receiver, Vector or tunnel is down
  tripwire-digest            07:00 summary of the last 24 hours, low priority

Everything a message contains is attacker text (paths, user agents). ntfy
shows it as text and nothing more, which is the point of a push channel over
an HTML mail.

Environment: OS_URL, OS_PASS, NTFY_URL (base URL of the ntfy server),
NTFY_TOKEN, NTFY_TOPIC (default tripwire), DIGEST_TZ (default Europe/Oslo).
"""

import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

OS_URL = os.environ["OS_URL"].rstrip("/")
OS_PASS = os.environ["OS_PASS"]
NTFY_URL = os.environ["NTFY_URL"].rstrip("/")
NTFY_TOKEN = os.environ["NTFY_TOKEN"]
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "tripwire")
DIGEST_TZ = os.environ.get("DIGEST_TZ", "Europe/Oslo")

CHANNEL_ID = "tripwire-ntfy"
DIGEST_CHANNEL_ID = "tripwire-ntfy-digest"
HEARTBEAT_AGENT = "tripwire-heartbeat"

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


def window(minutes, field="@timestamp"):
    """Range filter over the monitor's own period end, the documented idiom."""
    return {"range": {field: {"gte": f"{{{{period_end}}}}||-{minutes}m",
                              "lte": "{{period_end}}",
                              "format": "epoch_millis"}}}


def action(message, throttle_minutes=None, per_alert=False, channel_id=CHANNEL_ID):
    act = {"name": "ntfy", "destination_id": channel_id,
           "subject_template": {"source": "Tripwire", "lang": "mustache"},
           "message_template": {"source": message, "lang": "mustache"},
           "throttle_enabled": throttle_minutes is not None}
    if throttle_minutes is not None:
        act["throttle"] = {"value": throttle_minutes, "unit": "MINUTES"}
    if per_alert:
        # One message per new bucket (address), nothing for ones already
        # alerting. Without this a bucket monitor repeats every run.
        act["action_execution_policy"] = {"action_execution_scope": {
            "per_alert": {"actionable_alerts": ["NEW"]}}}
    return act


def query_monitor(name, indices, filters, trigger_name, severity, message,
                  minutes=5, size=5, condition="ctx.results[0].hits.total.value > 0",
                  throttle_minutes=None, aggs=None, schedule=None,
                  channel_id=CHANNEL_ID, time_field="@timestamp", must_not=None):
    query = {"bool": {"filter": filters + [window(minutes, time_field)]}}
    if must_not:
        query["bool"]["must_not"] = must_not
    search = {"size": size, "sort": [{time_field: "desc"}], "query": query}
    if aggs:
        search["aggs"] = aggs
    if throttle_minutes is None:
        # The window is five minutes and the monitor runs every minute,
        # so one event would fire five times without the throttle.
        throttle_minutes = minutes
    return {
        "type": "monitor", "name": name, "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": schedule or {"period": {"interval": 1, "unit": "MINUTES"}},
        "inputs": [{"search": {"indices": indices, "query": search}}],
        "triggers": [{"query_level_trigger": {
            "name": trigger_name, "severity": severity,
            "condition": {"script": {"source": condition, "lang": "painless"}},
            "actions": [action(message, throttle_minutes=throttle_minutes or None,
                               channel_id=channel_id)]}}],
    }


def silent_monitor(name, indices, filters, minutes, message):
    """Dead-man switch: fires on an empty window, repeats every six hours."""
    return query_monitor(name, indices, filters, "silent", "2", message,
                         minutes=minutes, size=0,
                         condition="ctx.results[0].hits.total.value == 0",
                         throttle_minutes=360)


def top(field, size=3):
    return {"terms": {"field": field, "size": size}}


DIGEST_AGGS = {"by": {
    # Keyed on which index wrote the document, not on event.module: that
    # field is sender-filled, and the sentinel's writer account has no scope
    # to put anything in tripwire-hits-* regardless of what it claims.
    "filters": {"filters": {
        "receiver": {"bool": {
            "filter": [{"prefix": {"_index": "tripwire-hits-"}}],
            "must_not": [{"term": {"http.user_agent": HEARTBEAT_AGENT}}]}},
        "sentinel": {"bool": {
            "filter": [{"prefix": {"_index": "tripwire-sentinel-"}}],
            "must_not": [{"term": {"classification": "egress-blocked"}}]}}}},
    "aggs": {"ips": {"cardinality": {"field": "source.ip"}},
             "cc": top("source.geo.country_iso_code"),
             "tiers": top("tier_name", 6),
             "ports": top("port"),
             "exploits": top("threat.exploit"),
             "mismatch": {"filter": {"exists": {"field": "proto_mismatch"}}},
             "rtt_odd": {"filter": {"terms": {"network.rtt_verdict":
                                              ["impossible", "detour"]}},
                         "aggs": {"ips": {"cardinality": {"field": "source.ip"}}}},
             "held": {"sum": {"field": "held_ms"}},
             # Sums come back as doubles; format gives a whole number of
             # minutes as value_as_string for the template.
             "held_min": {"bucket_script": {"buckets_path": {"h": "held"},
                                            "script": "Math.round(params.h/60000)",
                                            "format": "0"}}}},
    # Ledger documents live in their own index, so they land in neither
    # bucket above; their @timestamp is the event that first named the
    # location.
    "droppers": {"filter": {"prefix": {"_index": "dropper-book"}}},
    # Same idea as "new dropper locations" just below: a count of what the
    # fingerprint book recorded today, kind http only (hassh/ja4 already
    # have their own novelty alert; this is the noisy one worth a headline
    # number instead).
    "fingerprints_http": {"filter": {"bool": {"filter": [
        {"prefix": {"_index": "fingerprint-book"}}, {"term": {"kind": "http"}}]}}},
    "fakevm": {"filter": {"prefix": {"_index": "tripwire-fakevm-"}},
               "aggs": {"starts": {"filter": {"term": {"fakevm.status": "start"}}},
                        "interactions": {"filter": {"term": {"fakevm.status": "interaction"}}}}}}

DIGEST_MESSAGE = (
    "Last 24 h\n"
    "{{#ctx.results.0.aggregations.by.buckets.receiver}}"
    "Receiver: {{doc_count}} hits from {{ips.value}} addresses\n"
    " tiers: {{#tiers.buckets}}{{key}}={{doc_count}} {{/tiers.buckets}}\n"
    " countries: {{#cc.buckets}}{{key}}={{doc_count}} {{/cc.buckets}}\n"
    "{{/ctx.results.0.aggregations.by.buckets.receiver}}"
    "{{#ctx.results.0.aggregations.by.buckets.sentinel}}"
    "Sentinel: {{doc_count}} connections from {{ips.value}} addresses, "
    "{{held_min.value_as_string}} min held\n"
    " ports: {{#ports.buckets}}{{key}}={{doc_count}} {{/ports.buckets}}\n"
    " countries: {{#cc.buckets}}{{key}}={{doc_count}} {{/cc.buckets}}\n"
    " exploits: {{#exploits.buckets}}{{key}}={{doc_count}} {{/exploits.buckets}}\n"
    " wrong protocol: {{mismatch.doc_count}}, RTT at odds with GeoIP: "
    "{{rtt_odd.ips.value}} addresses\n"
    "{{/ctx.results.0.aggregations.by.buckets.sentinel}}"
    "New dropper locations: {{ctx.results.0.aggregations.droppers.doc_count}}\n"
    "New header orders: {{ctx.results.0.aggregations.fingerprints_http.doc_count}}\n"
    "Fake VM: {{ctx.results.0.aggregations.fakevm.starts.doc_count}} starts, "
    "{{ctx.results.0.aggregations.fakevm.interactions.doc_count}} interactions")


HITS = ["tripwire-hits-*"]
SENTINEL = ["tripwire-sentinel-*"]
FAKEVM = ["tripwire-fakevm-*"]
FINGERPRINTS = ["fingerprint-book"]
DROPPERS = ["dropper-book"]
ADDRESSES = ["address-book"]
EGRESS = {"term": {"classification": "egress-blocked"}}
# The novelty monitors below key their window on "recorded" (when the book
# learned it, stamped by the enricher) rather than "@timestamp" (first
# sighting). This filter is the second half of that fix: it keeps a rebuilt
# book, which restamps "recorded" for months of old history in one pass,
# from alerting on any of it.
RECENT_24H = {"range": {"@timestamp": {"gte": "{{period_end}}||-24h",
                                       "format": "epoch_millis"}}}

MONITORS = [
    query_monitor(
        "tripwire-bait-used", FAKEVM, [{"term": {"fakevm.status": "start"}}],
        "bait credential used", "1",
        "Bait credential used in the fake SSH service.\n"
        "{{#ctx.results.0.hits.hits}}"
        "{{_source.source.ip}} session={{_source.fakevm.session}}\n"
        "{{/ctx.results.0.hits.hits}}"),
    # Same alert as tripwire-bait-used, on the sentinel's own SSH persona
    # rather than the fake VM. Dormant until the bait is switched on there.
    query_monitor(
        "tripwire-bait-used-sentinel", SENTINEL,
        [{"term": {"bait.credential_used": True}}],
        "bait credential used", "1",
        "Bait credential used on the sentinel.\n"
        "{{#ctx.results.0.hits.hits}}"
        "{{_source.source.ip}} {{_source.source.geo.country_iso_code}} "
        "port {{_source.port}}\n"
        "{{/ctx.results.0.hits.hits}}"),
    query_monitor(
        "tripwire-canary", HITS, [{"exists": {"field": "canary"}}],
        "canary presented", "1",
        "Canary token presented.\n"
        "{{#ctx.results.0.hits.hits}}"
        "{{_source.source.ip}} {{_source.source.geo.country_iso_code}} "
        "{{_source.method}} {{_source.path}} canary={{_source.canary}}\n"
        "{{/ctx.results.0.hits.hits}}"),
    query_monitor(
        "tripwire-agent", HITS, [{"range": {"tier": {"gte": 2, "lte": 3}}}],
        "instruction followed", "2",
        "Something followed an embedded instruction.\n"
        "{{#ctx.results.0.hits.hits}}"
        "{{_source.source.ip}} {{_source.source.geo.country_iso_code}} "
        "{{_source.tier_name}} {{_source.method}} {{_source.path}}\n"
        "agent: {{_source.http.user_agent}}\n"
        "{{/ctx.results.0.hits.hits}}"),
    {
        "type": "monitor", "name": "tripwire-both",
        "monitor_type": "bucket_level_monitor", "enabled": True,
        "schedule": {"period": {"interval": 5, "unit": "MINUTES"}},
        # by_ip's sub-aggregations are keyed on which index each hit came
        # from, not on event.module: that field is sender-filled, and the
        # sentinel's writer account has no scope to put anything in
        # tripwire-hits-* regardless of what it claims. The heartbeat is
        # excluded so the collector's own 10-minute fetch of its own site
        # can never be half of a pair.
        "inputs": [{"search": {"indices": HITS + SENTINEL, "query": {
            "size": 0,
            "query": {"bool": {"filter": [window(60)],
                               "must_not": [{"term": {"http.user_agent": HEARTBEAT_AGENT}}]}},
            "aggregations": {"by_ip": {
                "composite": {"size": 500, "sources": [
                    {"ip": {"terms": {"field": "source.ip"}}}]},
                "aggregations": {
                    "hits": {"filter": {"prefix": {"_index": "tripwire-hits-"}}},
                    "sentinel": {"filter": {"prefix": {"_index": "tripwire-sentinel-"}}}}}}}}}],
        "triggers": [{"bucket_level_trigger": {
            "name": "scanned then knocked", "severity": "2",
            "condition": {"buckets_path": {"hits": "hits>_count", "sentinel": "sentinel>_count"},
                          "parent_bucket_path": "by_ip",
                          "script": {"source": "params.hits > 0 && params.sentinel > 0",
                                     "lang": "painless"}},
            "actions": [action(
                "Scanned the sentinel and hit the receiver within an hour: "
                "{{#ctx.newAlerts}}{{bucket_keys}} {{/ctx.newAlerts}}",
                per_alert=True)]}}],
    },
    # The one alert that means the VM is owned, so severity 1. Both scopes
    # fire: "other" is the host outside the containers, which is worse, not
    # quieter. egress-watch.py already sums a burst into one event.
    query_monitor(
        "tripwire-egress", SENTINEL, [EGRESS],
        "outbound attempt from the sentinel VM", "1",
        "Sentinel VM tried to connect out. Treat it as owned: snapshot it "
        "from the cloud console, then destroy it. Do not log in first.\n"
        "{{#ctx.results.0.hits.hits}}"
        "{{_source.egress.scope}} uid {{_source.egress.uid}} to "
        "{{_source.egress.dst_ip}} port {{_source.egress.dst_port}} "
        "{{_source.egress.proto}} x{{_source.egress.count}}\n"
        "{{/ctx.results.0.hits.hits}}",
        throttle_minutes=10),
    # Egress summaries come from the VM too, but a host that produces only
    # those is not a working sentinel: they are no sign of life.
    silent_monitor(
        "tripwire-sentinel-silent", SENTINEL,
        [{"bool": {"must_not": [EGRESS]}}], 60,
        "Sentinel silent: no events for an hour. It normally sees dozens, "
        "so the VM, its Vector or WireGuard is down."),
    silent_monitor(
        "tripwire-receiver-silent", HITS,
        [{"term": {"http.user_agent": HEARTBEAT_AGENT}}], 30,
        "Receiver heartbeat missing for 30 minutes: three fetches of the "
        "public site failed to arrive. Receiver, its Vector or the tunnel "
        "is down."),
    # prior.sentinel_hours is stamped by the enricher on receiver events only,
    # and only when the sentinel saw the address first; the gte 1 keeps out the
    # same-visit noise tripwire-both already covers. The window keys on
    # enrichment.at (stamped in the same update that writes prior.*) rather
    # than @timestamp, so a slow enricher pass cannot push the record outside
    # the window before this monitor ever runs over it. Heartbeat excluded,
    # same reason as tripwire-both.
    query_monitor(
        "tripwire-returned", HITS,
        [{"range": {"prior.sentinel_hours": {"gte": 1}}}],
        "returned to the site", "2",
        "Scanned the sentinel first, came to the site later.\n"
        "{{#ctx.results.0.hits.hits}}"
        "{{_source.source.ip}} {{_source.source.geo.country_iso_code}} "
        "{{_source.tier_name}} {{_source.method}} {{_source.path}}, "
        "{{_source.prior.sentinel_hours}} h after first sentinel contact\n"
        "{{/ctx.results.0.hits.hits}}",
        time_field="enrichment.at",
        must_not=[{"term": {"http.user_agent": HEARTBEAT_AGENT}}]),
    # recorded is stamped when the enricher writes the book entry; @timestamp
    # stays "the first time this stack knocked". Keying the window on
    # recorded, not @timestamp, means a slow enricher pass (a restart, a
    # backlog) cannot push the record outside this monitor's window before
    # anyone sees it. The added @timestamp range keeps a rebuilt book, which
    # restamps recorded for months of old history in one pass, from alerting
    # on any of it. hassh/ja4 only: fingerprint.http's value space is
    # attacker-chosen and unbounded, so it gets its own count in the digest
    # instead of a per-value alert.
    query_monitor(
        "tripwire-novel-fingerprint", FINGERPRINTS,
        [{"terms": {"kind": ["hassh", "ja4"]}}, RECENT_24H],
        "fingerprint not seen before", "3",
        "New client fingerprint.\n"
        "{{#ctx.results.0.hits.hits}}"
        "{{_source.kind}} {{_source.value}} {{_source.first_ip}} "
        "{{_source.tool}} {{_source.ssh_client}}\n"
        "{{/ctx.results.0.hits.hits}}",
        time_field="recorded", throttle_minutes=5),
    # Same fix as the fingerprint book above: recorded is the window (the
    # throttle keeps that wider window from repeating), and the @timestamp
    # range keeps a rebuilt ledger quiet about old locations. Only the
    # defanged form goes into a message, so nothing downstream turns it into
    # a link.
    query_monitor(
        "tripwire-novel-dropper", DROPPERS, [RECENT_24H],
        "dropper location not seen before", "3",
        "New second-stage location (defanged, never fetch it).\n"
        "{{#ctx.results.0.hits.hits}}"
        "{{_source.kind}} {{_source.url_defanged}} from "
        "{{_source.first_source_ip}}\n"
        "{{/ctx.results.0.hits.hits}}",
        time_field="recorded", minutes=30),
    # The enricher rewrites the address-book document "self" once a day with
    # what InternetDB says about the sentinel's own address, and `checked` is
    # that document's clock. 26 h so one late pass does not open a gap.
    query_monitor(
        "tripwire-honeypot-tagged", ADDRESSES,
        [{"term": {"scope": "self"}}, {"term": {"honeypot_tagged": True}}],
        "sentinel tagged as a honeypot", "2",
        "InternetDB tags the sentinel's own address as a honeypot.\n"
        "{{#ctx.results.0.hits.hits}}"
        "tags: {{#_source.internetdb.tags}}{{.}} {{/_source.internetdb.tags}}\n"
        "{{/ctx.results.0.hits.hits}}",
        minutes=26 * 60, size=1, throttle_minutes=24 * 60, time_field="checked",
        schedule={"period": {"interval": 60, "unit": "MINUTES"}}),
    # dropper-book* and fingerprint-book* rather than the bare names: a
    # wildcard that matches nothing is not an error, a missing index would
    # cost the whole digest.
    query_monitor(
        "tripwire-digest",
        HITS + SENTINEL + FAKEVM + ["dropper-book*", "fingerprint-book*"], [], "daily",
        "5", DIGEST_MESSAGE,
        minutes=24 * 60, size=0, condition="true", throttle_minutes=0,
        aggs=DIGEST_AGGS, channel_id=DIGEST_CHANNEL_ID,
        schedule={"cron": {"expression": "0 7 * * *", "timezone": DIGEST_TZ}}),
]


def channel(channel_id, title, priority, tags):
    config = {"name": channel_id, "description": f"ntfy topic {NTFY_TOPIC}",
              "config_type": "webhook", "is_enabled": True,
              "webhook": {"url": f"{NTFY_URL}/{NTFY_TOPIC}", "method": "POST",
                          "header_params": {
                              "Authorization": f"Bearer {NTFY_TOKEN}",
                              "Title": title,
                              "Priority": priority,
                              "Tags": tags}}}
    status, _ = call("GET", f"/_plugins/_notifications/configs/{channel_id}")
    if status == 200:
        status, body = call("PUT", f"/_plugins/_notifications/configs/{channel_id}",
                            {"config": config})
    else:
        status, body = call("POST", "/_plugins/_notifications/configs",
                            {"config_id": channel_id, "config": config})
    if status != 200:
        sys.exit(f"channel: {status} {body}")
    print(f"  channel {channel_id}: {NTFY_URL}/{NTFY_TOPIC} priority {priority}")


def existing_monitor(name):
    status, body = call("POST", "/_plugins/_alerting/monitors/_search", {
        "query": {"match_phrase": {"monitor.name": name}}})
    if status != 200:
        sys.exit(f"monitor search: {status} {body}")
    for hit in body.get("hits", {}).get("hits", []):
        if hit["_source"]["name"] == name:
            return hit["_id"]
    return None


def monitors():
    for monitor in MONITORS:
        mid = existing_monitor(monitor["name"])
        if mid:
            status, body = call("PUT", f"/_plugins/_alerting/monitors/{mid}", monitor)
        else:
            status, body = call("POST", "/_plugins/_alerting/monitors", monitor)
        if status == 404 and "not found" in json.dumps(body):
            # The enricher creates fingerprint-book on its first pass; on a
            # fresh install the bootstrap can get here first. Same as the
            # address-book pattern: skipped now, created on the next run.
            print(f"  monitor {monitor['name']}: index not there yet, skipped")
            continue
        if status not in (200, 201):
            sys.exit(f"monitor {monitor['name']}: {status} {body}")
        print(f"  monitor {monitor['name']}: {'updated' if mid else 'created'}")


def test_channel():
    status, body = call("GET", f"/_plugins/_notifications/feature/test/{CHANNEL_ID}")
    ok = status == 200 and all(
        d.get("delivery_status", {}).get("status_code") == "200"
        for d in body.get("status_list", []))
    print("  test message delivered" if ok else f"  test message failed: {status} {body}")


def selftest():
    """Everything MONITORS declares is a literal, so all of this is checked
    by reading the structure, no cluster needed -- the same reason --dump
    works without one."""
    dump = json.dumps(MONITORS)

    # 1. Names are unique, and every monitor that existed before this
    # package still exists. tripwire-bait-used is the fake VM's twin of the
    # new tripwire-bait-used-sentinel; CLAUDE.md's monitor list predates it.
    names = [m["name"] for m in MONITORS]
    assert len(names) == len(set(names)), names
    before = {"tripwire-bait-used", "tripwire-canary", "tripwire-agent",
              "tripwire-both", "tripwire-egress", "tripwire-sentinel-silent",
              "tripwire-receiver-silent", "tripwire-returned",
              "tripwire-novel-fingerprint", "tripwire-novel-dropper",
              "tripwire-honeypot-tagged", "tripwire-digest"}
    assert before <= set(names), before - set(names)
    assert "tripwire-bait-used-sentinel" in names

    by_name = {m["name"]: m for m in MONITORS}

    # 2. tripwire-novel-fingerprint: window on recorded, kind in [hassh, ja4],
    # an @timestamp -24h range. Same window and -24h check for the dropper.
    fp = by_name["tripwire-novel-fingerprint"]
    fp_query = fp["inputs"][0]["search"]["query"]
    assert "recorded" in fp_query["query"]["bool"]["filter"][-1]["range"], fp_query
    assert fp_query["sort"] == [{"recorded": "desc"}], fp_query["sort"]
    filters = fp_query["query"]["bool"]["filter"]
    kind_terms = [f["terms"]["kind"] for f in filters if "terms" in f and "kind" in f["terms"]]
    assert kind_terms == [["hassh", "ja4"]], kind_terms
    assert any("@timestamp" in f.get("range", {}) and
              "-24h" in f["range"]["@timestamp"]["gte"] for f in filters), filters

    dr = by_name["tripwire-novel-dropper"]
    dr_query = dr["inputs"][0]["search"]["query"]
    assert "recorded" in dr_query["query"]["bool"]["filter"][-1]["range"], dr_query
    assert dr_query["sort"] == [{"recorded": "desc"}], dr_query["sort"]
    dr_filters = dr_query["query"]["bool"]["filter"]
    assert any("@timestamp" in f.get("range", {}) and
              "-24h" in f["range"]["@timestamp"]["gte"] for f in dr_filters), dr_filters

    # 3. tripwire-returned: window on enrichment.at, sorted the same way,
    # heartbeat excluded.
    ret = by_name["tripwire-returned"]
    ret_query = ret["inputs"][0]["search"]["query"]
    assert ret_query["sort"] == [{"enrichment.at": "desc"}], ret_query["sort"]
    assert any("enrichment.at" in f.get("range", {}) for f in ret_query["query"]["bool"]["filter"]), \
        ret_query
    assert {"term": {"http.user_agent": HEARTBEAT_AGENT}} in ret_query["query"]["bool"]["must_not"]

    # 4. tripwire-both: no event.module anywhere in it, both _index prefixes
    # present, heartbeat excluded.
    both = by_name["tripwire-both"]
    both_dump = json.dumps(both)
    assert "event.module" not in both_dump, both_dump
    assert "tripwire-hits-" in both_dump and "tripwire-sentinel-" in both_dump
    both_query = both["inputs"][0]["search"]["query"]["query"]
    assert {"term": {"http.user_agent": HEARTBEAT_AGENT}} in both_query["bool"]["must_not"]

    # 5. tripwire-bait-used-sentinel exists, severity 1, sentinel indices,
    # and never prints attacker-supplied bodies or commands.
    bait = by_name["tripwire-bait-used-sentinel"]
    assert bait["triggers"][0]["query_level_trigger"]["severity"] == "1", bait
    assert bait["inputs"][0]["search"]["indices"] == SENTINEL, bait
    message = bait["triggers"][0]["query_level_trigger"]["actions"][0]["message_template"]["source"]
    for forbidden in ("http_body", "http_requests", "smtp_commands", "payload"):
        assert forbidden not in message, (forbidden, message)

    # 6. event.module appears nowhere in any monitor, including the digest,
    # which used to key its receiver/sentinel/fakevm split on it.
    assert "event.module" not in dump, "event.module still present in MONITORS"

    print("selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
        sys.exit(0)
    if "--dump" in sys.argv:
        # Everything above is a literal; printing it needs no cluster, so the
        # monitor definitions can be read and diffed away from the deployment.
        print(json.dumps(MONITORS, indent=2))
        sys.exit(0)
    channel(CHANNEL_ID, "Tripwire", "high", "honeypot")
    channel(DIGEST_CHANNEL_ID, "Tripwire digest", "low", "bar_chart")
    monitors()
    if "--test" in sys.argv:
        test_channel()
