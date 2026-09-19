#!/usr/bin/env bash
# Run only from an approved, unpacked collector bundle as the stack owner.
set -euo pipefail
umask 077
bundle=$(cd "$(dirname "$0")" && pwd)
stack="$HOME/tripwire"
export XDG_RUNTIME_DIR=/run/user/$(id -u)
[ "$(id -u)" != 0 ] || { echo 'Use the unprivileged stack owner' >&2; exit 1; }
cd "$stack"
python3 - "$bundle" <<'PY'
import hashlib,json,pathlib,sys
bundle=pathlib.Path(sys.argv[1])
manifest=json.loads((bundle/'manifest.json').read_text())
expected={'bootstrap-opensearch.sh','enrich.py','droppers.py','alerts.py','dashboards.py'}
assert set(manifest)==expected
for name, hashes in manifest.items():
    assert hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()==hashes['before'], 'deployed file changed: '+name
    assert hashlib.sha256((bundle/name).read_bytes()).hexdigest()==hashes['after'], 'bundle checksum failed: '+name
print('PASS deployed baseline and bundle checksums')
PY
bash -n "$bundle/bootstrap-opensearch.sh"
podman exec tripwire-enricher python3 -c 'print("enricher available")'
backup=$(mktemp -d "$HOME/tripwire-backup-fakevm-XXXXXXXX")
files=(bootstrap-opensearch.sh enrich.py droppers.py alerts.py dashboards.py)
for file in "${files[@]}"; do cp -p "$file" "$backup/$file"; done
printf 'Code backup: %s\n' "${backup##*/}"
restore_on_error() {
    trap - ERR
    for file in "${files[@]}"; do cp -p "$backup/$file" "$stack/$file"; done
    podman restart tripwire-enricher >/dev/null || true
    echo 'FAILED: previous code restored. Additive cluster changes may remain; inspect before retry.' >&2
    echo 'Bootstrap output retained privately in the backup directory.' >&2
    exit 1
}
trap restore_on_error ERR
# Copy in place: the running enricher uses bind mounts of these files.
for file in "${files[@]}"; do cat "$bundle/$file" > "$stack/$file"; done
# This also updates dashboards/monitors and sends the existing ntfy test.
# Keep potentially sensitive endpoint/error output on the host.
bash ./bootstrap-opensearch.sh > "$backup/bootstrap.log" 2>&1
podman exec -i tripwire-enricher python3 - < "$bundle/verify-collector.py"
podman restart tripwire-enricher >/dev/null
sleep 3
[ "$(podman inspect --format '{{.State.Running}}' tripwire-enricher)" = true ]
trap - ERR
printf 'PASS collector code installed, schema verified, enricher running\n'
