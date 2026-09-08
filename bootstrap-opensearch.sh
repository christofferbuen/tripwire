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
# Sentinel data is noisier and less interesting after a month, and a shorter
# window is also what bounds the write-only user (see below).
SENTINEL_RETENTION_DAYS="${SENTINEL_RETENTION_DAYS:-30}"
# Per-index ceiling for sentinel data. Real load is a few hundred bytes a
# connection; anything near this is a flood, not traffic.
SENTINEL_INDEX_CAP="${SENTINEL_INDEX_CAP:-1gb}"

if [[ ! -f .env ]]; then
  echo "No .env. Run ./setup-logging.sh first." >&2
  exit 1
fi
# shellcheck disable=SC1091
set -a; source .env; set +a
: "${OPENSEARCH_INITIAL_ADMIN_PASSWORD:?not set in .env}"
export OS_PASS="$OPENSEARCH_INITIAL_ADMIN_PASSWORD"
# Follows the bind address compose.yaml publishes 9200 on.
OS_URL="${OS_URL:-https://${ADMIN_BIND:-127.0.0.1}:9200}"

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

echo "Setting absolute disk watermarks."
# Percent watermarks are meaningless on a 1 TB disk shared with everything
# else on the host; absolute free-space floors are what actually protect it.
# At flood_stage OpenSearch makes every index read-only, so the host never
# drops below that much free space because of this cluster. Needs
# enable_for_single_data_node=true in compose.yaml or nothing here applies.
api PUT /_cluster/settings '{"persistent":{
  "cluster.routing.allocation.disk.watermark.low":"150gb",
  "cluster.routing.allocation.disk.watermark.high":"100gb",
  "cluster.routing.allocation.disk.watermark.flood_stage":"50gb"}}' > /dev/null
echo "  done"

echo "Creating the sentinel policy (rollover daily, cap ${SENTINEL_INDEX_CAP}, delete after ${SENTINEL_RETENTION_DAYS} days)."
# The sentinel host is the one assumed to be owned eventually, and its Vector
# holds a write-only credential. OpenSearch has no per-user quota, so the cap
# is built from three pieces: writes go through one alias, ISM rolls it over
# once a day, and an index that reaches SENTINEL_INDEX_CAP is made read-only
# until that rollover. The write-only role cannot create indices, so the
# worst case is one capped index per day for SENTINEL_RETENTION_DAYS days.
api PUT /_plugins/_ism/policies/tripwire-sentinel "$(cat <<EOF
{
  "policy": {
    "description": "Sentinel indices: daily rollover, size cap, short retention.",
    "default_state": "hot",
    "ism_template": [
      { "index_patterns": ["tripwire-sentinel-0*"], "priority": 110 }
    ],
    "states": [
      {
        "name": "hot",
        "actions": [{ "rollover": { "min_index_age": "1d" } }],
        "transitions": [
          { "state_name": "capped", "conditions": { "min_size": "${SENTINEL_INDEX_CAP}" } },
          { "state_name": "delete", "conditions": { "min_index_age": "${SENTINEL_RETENTION_DAYS}d" } }
        ]
      },
      {
        "name": "capped",
        "actions": [{ "read_only": {} }, { "rollover": { "min_index_age": "1d" } }],
        "transitions": [
          { "state_name": "delete", "conditions": { "min_index_age": "${SENTINEL_RETENTION_DAYS}d" } }
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
      "mapping.ignore_malformed": true,
      "plugins.index_state_management.rollover_alias": "tripwire-sentinel"
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

echo "Creating the sentinel write alias."
# Only ever created once; rollover takes it from here. Attaching the policy
# explicitly because ism_template only fires for indices created after it.
if ! api GET "/tripwire-sentinel-000001?filter_path=*.settings.index.uuid" | grep -q uuid; then
  api PUT /tripwire-sentinel-000001 \
    '{"aliases":{"tripwire-sentinel":{"is_write_index":true}}}' > /dev/null
  api POST /_plugins/_ism/add/tripwire-sentinel-000001 \
    '{"policy_id":"tripwire-sentinel"}' > /dev/null
fi
echo "  done"

echo "Creating the write-only role for the sentinel."
# No indices:admin/create and no auto_create: it may write to the alias and
# to indices that already exist under it, and nothing else. mapping/put is
# what a bulk request needs for dynamic fields; the template caps those.
api PUT /_plugins/_security/api/roles/sentinel-writer '{
  "cluster_permissions": ["cluster:monitor/main","cluster:monitor/health","indices:data/write/bulk*"],
  "index_permissions": [{
    "index_patterns": ["tripwire-sentinel*"],
    "allowed_actions": ["indices:data/write/index","indices:data/write/bulk*",
                        "indices:admin/mapping/auto_put","indices:admin/mapping/put"]
  }]}' > /dev/null
if [[ -n "${SENTINEL_WRITER_PASSWORD:-}" ]]; then
  api PUT /_plugins/_security/api/internalusers/sentinel-writer \
    "{\"password\":\"${SENTINEL_WRITER_PASSWORD}\",\"opendistro_security_roles\":[\"sentinel-writer\"],\"description\":\"write-only, sentinel Vector\"}" > /dev/null
  echo "  role and user done"
else
  echo "  role done (set SENTINEL_WRITER_PASSWORD in .env to create/rotate the user)"
fi

echo "Creating the Dashboards index pattern."
# Into the Global tenant: the security plugin puts API calls made with basic
# auth into the caller's private tenant, which a browser session never sees.
DASH_URL="${DASH_URL:-http://${ADMIN_BIND:-127.0.0.1}:5601}"
dash() {
  curl -sS -X "$1" "${DASH_URL}$2" -u "admin:${OS_PASS}" \
    -H 'osd-xsrf: true' -H 'Content-Type: application/json' -H 'securitytenant: global' -d "$3"
}
dash POST '/api/saved_objects/index-pattern/tripwire?overwrite=true' \
  '{"attributes":{"title":"tripwire-*","timeFieldName":"@timestamp"}}' > /dev/null \
  && dash POST /api/opensearch-dashboards/settings '{"changes":{"defaultIndex":"tripwire"}}' > /dev/null \
  && echo "  done" || echo "  skipped (Dashboards not reachable at ${DASH_URL})"

echo
echo "Verifying."
api GET "/_index_template/tripwire?filter_path=index_templates.name" || true
echo
api GET "/_plugins/_ism/policies/tripwire-retention?filter_path=_id" || true
echo
api GET "/_plugins/_ism/explain/tripwire-sentinel-000001?filter_path=*.policy_id" || true
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
