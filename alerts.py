#!/usr/bin/env python3
"""Create the alerting channel and monitors in OpenSearch. Stdlib only.

bootstrap-opensearch.sh runs this when NTFY_TOKEN is set in .env. Everything
is keyed by a fixed name or id, so re-running updates in place.

One channel: a webhook to the ntfy server, token in an Authorization header,
title and priority as ntfy headers so the message template stays plain text.
Three monitors:

  tripwire-canary   a canary token was presented back to the receiver
  tripwire-agent    something followed an embedded instruction or posted
                    to the collection endpoint (tiers 2 and 3)
  tripwire-both     one address touched the sentinel and the receiver within
                    an hour: scanned first, then knocked

Everything a message contains is attacker text (paths, user agents). ntfy
shows it as text and nothing more, which is the point of a push channel over
an HTML mail.

Environment: OS_URL, OS_PASS, NTFY_URL (base URL of the ntfy server),
NTFY_TOKEN, NTFY_TOPIC (default tripwire).
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

CHANNEL_ID = "tripwire-ntfy"

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


def action(message, throttle_minutes=None, per_alert=False):
    act = {"name": "ntfy", "destination_id": CHANNEL_ID,
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
                  minutes=5, size=5):
    return {
        "type": "monitor", "name": name, "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
        "inputs": [{"search": {"indices": indices, "query": {
            "size": size, "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"filter": filters + [window(minutes)]}}}}}],
        "triggers": [{"query_level_trigger": {
            "name": trigger_name, "severity": severity,
            "condition": {"script": {"source": "ctx.results[0].hits.total.value > 0",
                                     "lang": "painless"}},
            # The window is five minutes and the monitor runs every minute,
            # so one event would fire five times without the throttle.
            "actions": [action(message, throttle_minutes=minutes)]}}],
    }


HITS = ["tripwire-hits-*"]
SENTINEL = ["tripwire-sentinel-*"]

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
]


def channel():
    config = {"name": "ntfy", "description": f"ntfy topic {NTFY_TOPIC}",
              "config_type": "webhook", "is_enabled": True,
              "webhook": {"url": f"{NTFY_URL}/{NTFY_TOPIC}", "method": "POST",
                          "header_params": {
                              "Authorization": f"Bearer {NTFY_TOKEN}",
                              "Title": "Tripwire",
                              "Priority": "high",
                              "Tags": "honeypot"}}}
    status, _ = call("GET", f"/_plugins/_notifications/configs/{CHANNEL_ID}")
    if status == 200:
        status, body = call("PUT", f"/_plugins/_notifications/configs/{CHANNEL_ID}",
                            {"config": config})
    else:
        status, body = call("POST", "/_plugins/_notifications/configs",
                            {"config_id": CHANNEL_ID, "config": config})
    if status != 200:
        sys.exit(f"channel: {status} {body}")
    print(f"  channel {CHANNEL_ID}: {NTFY_URL}/{NTFY_TOPIC}")


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
    channel()
    monitors()
    if "--test" in sys.argv:
        test_channel()
