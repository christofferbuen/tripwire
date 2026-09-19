#!/usr/bin/env bash
# Single entry point for the wave-1 Vector VRL tests (package C: vector.toml
# and vector-sentinel.toml). Runs the real config files through Vector's own
# `test` subcommand inside the same image the compose files deploy, so a
# pass here means the actual VRL was exercised, not a paraphrase of it.
#
# Usage:
#   ./test-vector.sh              # both topologies
#   ./test-vector.sh sentinel     # vector-sentinel.toml only
#   ./test-vector.sh collector    # vector.toml only
#
# Nothing is left running: podman run --rm --network=none, the repo mounted
# read-only, and a throwaway secrets file in a temp dir that is removed on
# exit. Exit code is Vector's own; exit 2 (with a message, no test output)
# means the environment could not run the tests at all.

set -u

IMAGE="docker.io/timberio/vector:0.58.0-alpine"

if ! command -v podman >/dev/null 2>&1; then
  echo "test-vector.sh: podman not found on PATH. Install podman (and, on Windows, run 'podman machine start') to run these tests." >&2
  exit 2
fi

if ! podman info >/dev/null 2>&1; then
  echo "test-vector.sh: podman is on PATH but not usable. On Windows this usually means the machine is stopped -- try 'podman machine start'." >&2
  exit 2
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Created under the repo checkout rather than the system temp dir: on
# Windows, Git Bash's /tmp lives outside any path the podman machine (WSL)
# can see, so a container mount of it fails, while the repo checkout is
# already known-mountable. Cleaned up on exit either way.
SECRETS_DIR="$(mktemp -d "${REPO_DIR}/.vector-test-secrets.XXXXXX")"
cleanup() {
  rm -rf "$SECRETS_DIR"
}
trap cleanup EXIT

# Dummy values only -- vector-sentinel.toml resolves an endpoint through the
# same secrets backend, vector.toml does not, but a spare key in the file is
# harmless either way. Never real credentials; this file lives only in a
# temp dir removed when the script exits.
cat > "$SECRETS_DIR/secrets.json" <<'JSON'
{
  "opensearch_password": "dummy-test-password",
  "opensearch_endpoint": "https://opensearch.invalid:9200"
}
JSON
chmod 600 "$SECRETS_DIR/secrets.json"

run_topology() {
  topology_name="$1"
  config_file="$2"
  tests_file="$3"
  echo "== ${topology_name} (${config_file}) =="
  # MSYS_NO_PATHCONV keeps Git Bash on Windows from mangling the
  # container-side /workspace and /etc/vector paths below into Windows
  # paths; it is a no-op on plain Linux. Host-side paths are passed through
  # as the POSIX-style paths Git Bash and Linux both already use.
  MSYS_NO_PATHCONV=1 podman run --rm --network=none \
    -v "${REPO_DIR}:/workspace:ro" \
    -v "${SECRETS_DIR}:/etc/vector:ro" \
    "$IMAGE" test "/workspace/${config_file}" "/workspace/${tests_file}"
}

target="${1:-both}"
status=0

case "$target" in
  sentinel)
    run_topology "sentinel" "vector-sentinel.toml" "vector-tests-sentinel.toml" || status=1
    ;;
  collector)
    run_topology "collector" "vector.toml" "vector-tests-collector.toml" || status=1
    ;;
  both)
    run_topology "sentinel" "vector-sentinel.toml" "vector-tests-sentinel.toml" || status=1
    run_topology "collector" "vector.toml" "vector-tests-collector.toml" || status=1
    ;;
  *)
    echo "test-vector.sh: unknown target '${target}' (expected 'sentinel', 'collector', or no argument for both)" >&2
    exit 2
    ;;
esac

exit "$status"
