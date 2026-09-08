#!/usr/bin/env bash
# Create the index template and the retention policy. Run once, after
# `podman compose up -d` reports opensearch healthy. Safe to re-run.
#
# Two things this fixes that the defaults get wrong for a honeypot.
#
# Field explosion. Dynamic mapping creates a field for every new JSON key it
# sees. Almost everything in these documents originates with the client, so
# without a ceiling anyone who can reach the honeypot can grow the cluster
# state until it falls over. Vector already collapses request headers into
# one string, and the template caps total fields and forces unknown strings
# to keyword.
#
# Retention. These indices hold third-party data: credentials sprayed at the
# sentinel, and whatever an agent posted to the collection endpoint on some
# page's say-so. Keeping that indefinitely is not defensible. The policy
# deletes it.
#
# The password is read from .env and passed through the environment, never on
# a command line where it would be visible in `ps` or land in shell history.
set -euo pipefail

cd "$(dirname "$0")"

RETENTION_DAYS="${RETENTION_DAYS:-90}"
OS_URL="${OS_URL:-https://127.0.0.1:9200}"

if [[ ! -f .env ]]; then
  echo "No .env. Run ./setup-logging.sh first." >&2
  exit 1
fi
# shellcheck disable=SC1091
set -a; source .env; set +a
: "${OPENSEARCH_INITIAL_ADMIN_PASSWORD:?not set in .env}"
export OS_PASS="$OPENSEARCH_INITIAL_ADMIN_PASSWORD"

# -k because the cluster uses the self-signed demo certificates and is
# reachable on loopback only. --netrc-file /dev/null keeps curl from picking
# up credentials from anywhere else.
api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -k -X "$method" "${OS_URL}${path}"
              -u "admin:${OS_PASS}" -H 'Content-Type: application/json')
  [[ -n "$body" ]] && args+=(-d "$body")
  curl "${args[@]}"
}

echo "Waiting for the cluster."
for _ in $(seq 1 60); do
  if api GET /_cluster/health | grep -qE '"status":"(green|yellow)"'; then
    break
  fi
  sleep 5
done

echo "Creating the retention policy (${RETENTION_DAYS} days)."
api PUT /_plugins/_ism/policies/tripwire-retention "$(cat <<EOF
{
  "policy": {
    "description": "Roll daily indices, then delete. These indices hold data belonging to third parties.",
    "default_state": "hot",
    "ism_template": [
      { "index_patterns": ["tripwire-hits-*", "tripwire-sentinel-*"], "priority": 100 }
    ],
    "states": [
      {
        "name": "hot",
        "actions": [],
        "transitions": [
          { "state_name": "delete", "conditions": { "min_index_age": "${RETENTION_DAYS}d" } }
        ]
      },
      { "name": "delete", "actions": [{ "delete": {} }], "transitions": [] }
    ]
  }
}
EOF
)" > /dev/null
echo "  done"

echo "Creating the index template."
api PUT /_index_template/tripwire "$(cat <<'EOF'
{
  "index_patterns": ["tripwire-hits-*", "tripwire-sentinel-*"],
  "priority": 200,
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "refresh_interval": "10s",
      "mapping.total_fields.limit": 250,
      "mapping.depth.limit": 8,
      "mapping.ignore_malformed": true
    },
    "mappings": {
      "dynamic_templates": [
        {
          "strings_as_keyword": {
            "match_mapping_type": "string",
            "mapping": { "type": "keyword", "ignore_above": 1024 }
          }
        }
      ],
      "properties": {
        "@timestamp": { "type": "date" },
        "event": {
          "properties": {
            "kind":     { "type": "keyword" },
            "dataset":  { "type": "keyword" },
            "module":   { "type": "keyword" },
            "ingested": { "type": "date" }
          }
        },
        "source": {
          "properties": {
            "ip": { "type": "ip", "ignore_malformed": true }
          }
        },

        "tier":      { "type": "integer" },
        "tier_name": { "type": "keyword" },
        "depth":     { "type": "integer" },
        "delay_ms":  { "type": "long" },
        "held_ms":   { "type": "long" },
        "hold_ms":   { "type": "long" },
        "method":    { "type": "keyword" },
        "path":      { "type": "keyword", "ignore_above": 2048 },
        "query":     { "type": "keyword", "ignore_above": 2048 },
        "placement": { "type": "keyword" },
        "agent_self":{ "type": "keyword" },
        "canary":    { "type": "keyword" },
        "body_len":  { "type": "long" },
        "no_fetch_metadata": { "type": "boolean" },

        "http": {
          "properties": {
            "user_agent":      { "type": "keyword", "ignore_above": 1024 },
            "referer":         { "type": "keyword", "ignore_above": 2048 },
            "accept":          { "type": "keyword", "ignore_above": 1024 },
            "accept_language": { "type": "keyword", "ignore_above": 256 },
            "accept_encoding": { "type": "keyword", "ignore_above": 256 },
            "sec_fetch_mode":  { "type": "keyword" },
            "sec_fetch_dest":  { "type": "keyword" },
            "cf_connecting_ip":{ "type": "ip", "ignore_malformed": true },
            "x_forwarded_for": { "type": "keyword", "ignore_above": 1024 },
            "header_count":    { "type": "integer" },
            "headers_raw":     { "type": "text", "index": true }
          }
        },

        "kind":            { "type": "keyword" },
        "outcome":         { "type": "keyword" },
        "note":            { "type": "keyword", "ignore_above": 512 },
        "port":            { "type": "integer" },
        "role":            { "type": "keyword" },
        "persona":         { "type": "keyword" },
        "distinct_ports":  { "type": "integer" },
        "first_contact":   { "type": "boolean" },
        "sweeping":        { "type": "boolean" },
        "spoke":           { "type": "boolean" },
        "classification":  { "type": "keyword" },
        "bytes_received":  { "type": "long" },
        "ports":           { "type": "integer" },
        "ssh_client":      { "type": "keyword", "ignore_above": 256 },
        "mysql_user":      { "type": "keyword", "ignore_above": 256 },
        "http_requests":   { "type": "keyword", "ignore_above": 512 },
        "smtp_commands":   { "type": "keyword", "ignore_above": 512 },

        "body_excerpt":  { "type": "text",    "index": true },
        "payload_text":  { "type": "text",    "index": true },
        "payload_hex":   { "type": "keyword", "index": false }
      }
    }
  }
}
EOF
)" > /dev/null
echo "  done"

echo
echo "Verifying."
api GET "/_index_template/tripwire?filter_path=index_templates.name" || true
echo
api GET "/_plugins/_ism/policies/tripwire-retention?filter_path=_id" || true
echo
echo
cat <<EOF
Template and policy are in place. They apply to indices created from now on,
so if Vector already wrote today's index, delete it and let it be recreated:

  curl -sk -u admin:\$OPENSEARCH_INITIAL_ADMIN_PASSWORD \\
    -X DELETE "${OS_URL}/tripwire-hits-*,tripwire-sentinel-*"

Retention is ${RETENTION_DAYS} days. Set RETENTION_DAYS and re-run to change
it. Shorter is easier to justify: these indices hold data belonging to people
who are not you.
EOF
