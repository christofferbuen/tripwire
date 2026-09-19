#!/usr/bin/env bash
# Read-only deployment inventory. Never print environment or captured traffic.
set -eu
role=${1:?expected sentinel or collector}
case "$role" in sentinel|collector) ;; *) exit 2 ;; esac

printf 'role=%s\n' "$role"
printf 'listening TCP ports (addresses omitted):\n'
ss -H -ltn | awk '{n=split($4,a,":"); print a[n]}' | sort -nu
if [ "$role" = sentinel ]; then
    printf 'candidate service accounts:\n'
    for account in sentinel fakevm; do
        if id "$account" >/dev/null 2>&1; then id "$account"; else printf '%s absent\n' "$account"; fi
    done
    printf 'fakevm log directory:\n'
    if [ -d /var/log/tripwire-fakevm ]; then
        stat -c '%a %U %G %n' /var/log/tripwire-fakevm
    else
        printf 'absent\n'
    fi
fi

stack_checks=$(cat <<'CHECKS'
set -eu
export XDG_RUNTIME_DIR=/run/user/$(id -u)
cd "$HOME/tripwire"
id
podman --version
printf 'container state:\n'
podman ps --format '{{.Names}} {{.Image}} {{.Status}}'
printf 'container networking:\n'
for container in $(podman ps -q); do
    podman inspect --format '{{.Name}} network={{.HostConfig.NetworkMode}}' "$container"
done
printf 'deployment file checksums:\n'
for file in compose.yaml compose.sentinel.yaml compose.fakevm.yaml sentinel.py vector-sentinel.toml vector-fakevm.toml bootstrap-opensearch.sh enrich.py droppers.py alerts.py dashboards.py; do
    if [ -f "$file" ]; then sha256sum "$file"; fi
done
printf 'rootless networking helpers:\n'
for helper in pasta slirp4netns podman-compose; do command -v "$helper" || true; done
printf 'disk capacity:\n'
df -h .
CHECKS
)
if [ "$role" = sentinel ]; then
    [ "$(id -u)" = 0 ] || { printf 'expected administrative account\n' >&2; exit 1; }
    printf '%s\n' "$stack_checks" | su - sentinel -c 'bash -s'
else
    [ "$(id -u)" != 0 ] || { printf 'collector must use unprivileged account\n' >&2; exit 1; }
    printf '%s\n' "$stack_checks" | bash -s
fi
