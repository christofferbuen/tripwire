#!/bin/sh
# Build and run the tripwire receiver under rootless podman.
#
# Defaults to publishing on loopback only. Reaching it from the internet is a
# separate, deliberate step: leave this on 127.0.0.1 and point a TLS proxy you
# control at it. Do not change BIND to 0.0.0.0 as a shortcut.
#
# This runs the receiver on its own, with SQLite as the only store. That is
# enough to collect and to run analyze.py against. Use compose.yaml instead
# when you want the events shipped into OpenSearch as well; the JSON lines
# written here are what the shipper reads, so the two are not exclusive.

set -eu

IMAGE=${IMAGE:-localhost/tripwire:latest}
NAME=${NAME:-tripwire}
BIND=${BIND:-127.0.0.1}
PORT=${PORT:-8787}
VOLUME=${VOLUME:-tripwire-data}
LOG_VOLUME=${LOG_VOLUME:-tripwire-logs}

cd "$(dirname "$0")"

echo "==> building $IMAGE"
# --format docker is required: podman's default OCI image format silently
# discards HEALTHCHECK, so the health wait below would never succeed.
podman build --format docker --tag "$IMAGE" --file Containerfile .

echo "==> replacing any existing container"
podman rm --force --ignore "$NAME" >/dev/null

echo "==> starting $NAME on $BIND:$PORT"
# --trust-proxy is deliberately absent. Turn it on only once a proxy you
# control is the sole thing that can reach the container, otherwise any
# client can forge X-Forwarded-For and poison the address column.
#
#
# The pids limit is 256 rather than 128 because the tarpit holds connections
# open on purpose and each held connection is a thread. TARPIT_MAX_HOLDING in
# receiver.py caps that at 64; this is the backstop if that ever fails.
#
# The arguments repeat the image's default CMD because anything passed after
# the image name replaces it rather than adding to it. EXTRA_ARGS is left
# unquoted on purpose, so that `EXTRA_ARGS="--no-tarpit --jsonl ''"` splits
# into separate words. 0.0.0.0 is the container's own namespace; the host
# side is published on $BIND, which defaults to loopback.
podman run \
    --detach \
    --name "$NAME" \
    --publish "$BIND:$PORT:8787" \
    --volume "$VOLUME:/data:Z" \
    --volume "$LOG_VOLUME:/var/log/tripwire:Z" \
    --env TRIPWIRE_JSONL=/var/log/tripwire/hits.jsonl \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --memory 256m \
    --pids-limit 256 \
    --restart unless-stopped \
    "$IMAGE" \
    --host 0.0.0.0 --port 8787 --db /data/tripwire.sqlite3 \
    ${EXTRA_ARGS:-}

echo "==> waiting for health"
healthy=no
for _ in $(seq 1 30); do
    status=$(podman inspect --format '{{.State.Health.Status}}' "$NAME" 2>/dev/null || true)
    if [ "$status" = healthy ]; then healthy=yes; break; fi
    # Fall back to probing the published port directly, so this still works
    # if the image was built without HEALTHCHECK support.
    if curl -fsS -o /dev/null "http://$BIND:$PORT/healthz" 2>/dev/null; then
        healthy=yes; break
    fi
    sleep 1
done

if [ "$healthy" != yes ]; then
    echo "!! receiver did not come up; last 40 log lines:" >&2
    podman logs --tail 40 "$NAME" >&2 || true
    exit 1
fi

podman ps --filter "name=$NAME" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

cat <<EOF

Read the log:
  podman exec $NAME python3 /app/analyze.py --db /data/tripwire.sqlite3

List every canary token the tarpit handed out, and to whom:
  podman exec $NAME python3 /app/analyze.py --db /data/tripwire.sqlite3 --canaries

Copy it out for offline analysis:
  podman cp $NAME:/data/tripwire.sqlite3 ./tripwire.sqlite3

Follow hits live:
  podman logs -f $NAME

The tarpit holds connections open on purpose, which is what you want against
a scanner and a nuisance while testing. To turn it off, re-run this script
with EXTRA_ARGS set:
  EXTRA_ARGS=--no-tarpit ./run.sh
EOF
