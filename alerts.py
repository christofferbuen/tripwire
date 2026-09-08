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


def window(minutes):
    """Range filter over the monitor's own period end, the documented idiom."""
    return {"range": {"@timestamp": {"gte": f"{{{{period_end}}}}||-{minutes}m",
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
                  channel_id=CHANNEL_ID):
    search = {"size": size, "sort": [{"@timestamp": "desc"}],
              "query": {"bool": {"filter": filters + [window(minutes)]}}}
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
    "filters": {"filters": {
        "receiver": {"bool": {
            "filter": [{"term": {"event.module": "receiver"}}],
            "must_not": [{"term": {"http.user_agent": HEARTBEAT_AGENT}}]}},
        "sentinel": {"term": {"event.module": "sentinel"}}}},
    "aggs": {"ips": {"cardinality": {"field": "source.ip"}},
             "cc": top("source.geo.country_iso_code"),
             "tiers": top("tier_name", 6),
             "ports": top("port"),
             "held": {"sum": {"field": "held_ms"}},
             # Sums come back as doubles; format gives a whole number of
             # minutes as value_as_string for the template.
             "held_min": {"bucket_script": {"buckets_path": {"h": "held"},
                                            "script": "Math.round(params.h/60000)",
                                            "format": "0"}}}}}

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
    " countries: {{#cc.buckets}}{{key}}={{doc_count}} {{/cc.buckets}}"
    "{{/ctx.results.0.aggregations.by.buckets.sentinel}}")


HITS = ["tripwire-hits-*"]
SENTINEL = ["tripwire-sentinel-*"]
FINGERPRINTS = ["fingerprint-book"]

MONITORS = [
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
        "inputs": [{"search": {"indices": HITS + SENTINEL, "query": {
            "size": 0,
            "query": {"bool": {"filter": [window(60)]}},
            "aggregations": {"by_ip": {
                "composite": {"size": 500, "sources": [
                    {"ip": {"terms": {"field": "source.ip"}}}]},
                "aggregations": {"modules": {
                    "cardinality": {"field": "event.module"}}}}}}}}],
        "triggers": [{"bucket_level_trigger": {
            "name": "scanned then knocked", "severity": "2",
            "condition": {"buckets_path": {"modules": "modules"},
                          "parent_bucket_path": "by_ip",
                          "script": {"source": "params.modules > 1",
                                     "lang": "painless"}},
            "actions": [action(
                "Scanned the sentinel and hit the receiver within an hour: "
                "{{#ctx.newAlerts}}{{bucket_keys}} {{/ctx.newAlerts}}",
                per_alert=True)]}}],
    },
    silent_monitor(
        "tripwire-sentinel-silent", SENTINEL, [], 60,
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
    # same-visit noise tripwire-both already covers.
    query_monitor(
        "tripwire-returned", HITS,
        [{"range": {"prior.sentinel_hours": {"gte": 1}}}],
        "returned to the site", "2",
        "Scanned the sentinel first, came to the site later.\n"
        "{{#ctx.results.0.hits.hits}}"
        "{{_source.source.ip}} {{_source.source.geo.country_iso_code}} "
        "{{_source.tier_name}} {{_source.method}} {{_source.path}}, "
        "{{_source.prior.sentinel_hours}} h after first sentinel contact\n"
        "{{/ctx.results.0.hits.hits}}"),
    # Every document in the book is a first sighting, and its @timestamp is
    # when that sighting happened, so the window filter alone is the novelty
    # test: a fingerprint indexed today for a stack first seen last month
    # stays quiet, which is what it should do.
    query_monitor(
        "tripwire-novel-fingerprint", FINGERPRINTS, [],
        "fingerprint not seen before", "3",
        "New client fingerprint.\n"
        "{{#ctx.results.0.hits.hits}}"
        "{{_source.kind}} {{_source.value}} {{_source.first_ip}} "
        "{{_source.tool}} {{_source.ssh_client}}\n"
        "{{/ctx.results.0.hits.hits}}",
        throttle_minutes=5),
    query_monitor(
        "tripwire-digest", HITS + SENTINEL, [], "daily", "5", DIGEST_MESSAGE,
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


if __name__ == "__main__":
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
