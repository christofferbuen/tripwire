#!/usr/bin/env bash
# One-time preparation for the logging stack.
#
# Generates the OpenSearch admin password into .env, mirrors it into the
# secrets file Vector reads, and checks the two host settings OpenSearch
# needs. The password is never printed, never echoed and never passed on a
# command line where it would land in shell history or in another user's `ps`
# output. Read it out of .env when you need it.
set -euo pipefail

cd "$(dirname "$0")"

ENV_FILE=".env"
SECRETS_FILE="vector-secrets.json"

if [[ -f "$ENV_FILE" ]]; then
  echo "$ENV_FILE already exists. Leaving it alone."
  echo "Delete it and re-run only if you also delete the opensearch-data"
  echo "volume, because the admin password is baked in at cluster creation"
  echo "and changing the file afterwards will not change the cluster."
else
  # OpenSearch has rejected weak admin passwords since 2.12: it wants length
  # plus mixed case, a digit and a symbol. Forty random alphanumerics with a
  # fixed symbol suffix satisfies that with room to spare; the entropy is all
  # in the random part, so the predictable suffix costs nothing.
  #
  # Generated in python rather than with `tr -dc < /dev/urandom | head -c`.
  # That pipeline looks harmless and is not: head closes the pipe, tr dies of
  # SIGPIPE, and under `set -o pipefail` the whole script aborts after the
  # redirect has already created the file. The result is a half-written
  # password with no symbol in it, and a cluster that then refuses to
  # initialise for a reason that points nowhere near here.
  umask 077
  python3 - "$ENV_FILE" <<'PY'
import secrets, string, sys
alphabet = string.ascii_letters + string.digits
pw = "".join(secrets.choice(alphabet) for _ in range(40)) + "_Aa1!"
with open(sys.argv[1], "w") as fh:
    fh.write(f"OPENSEARCH_INITIAL_ADMIN_PASSWORD={pw}\n")
PY
  chmod 600 "$ENV_FILE"
  echo "Wrote $ENV_FILE with mode 600."
  echo "The password is in that file and was not printed here."
fi

# Vector cannot read .env, and since 0.57 it does not interpolate ${VAR} in
# its configuration either, so the password reaches it through a secrets
# file. Regenerated from .env on every run, which keeps the two in step if
# the password is ever rotated by hand.
#
# If a `podman compose up` ran before this script, the bind mount will have
# created a directory with this name. Say so rather than failing obscurely.
if [[ -d "$SECRETS_FILE" ]]; then
  echo "$SECRETS_FILE is a directory. Podman created it for a bind mount" >&2
  echo "before this script ran. Stop the stack, remove it, and re-run:" >&2
  echo "  podman compose down && rmdir $SECRETS_FILE && ./setup-logging.sh" >&2
  exit 1
fi

# .env is parsed rather than sourced, so a password containing shell
# metacharacters cannot be executed, and the value never becomes a shell word
# or a command-line argument where `ps` could see it.
umask 077
python3 - "$ENV_FILE" "$SECRETS_FILE" <<'PY'
import json, sys
env_path, out_path = sys.argv[1], sys.argv[2]
env = {}
for line in open(env_path, encoding="utf-8"):
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, _, value = line.partition("=")
    env[key.strip()] = value
password = env.get("OPENSEARCH_INITIAL_ADMIN_PASSWORD")
if not password:
    sys.exit(f"OPENSEARCH_INITIAL_ADMIN_PASSWORD is missing from {env_path}")
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump({"opensearch_password": password}, fh)
PY
chmod 600 "$SECRETS_FILE"
echo "Wrote $SECRETS_FILE with mode 600, matching $ENV_FILE."

echo
echo "Checking host settings OpenSearch needs."

MMAP=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
if [[ "$MMAP" -lt 262144 ]]; then
  cat <<'EOF'
  vm.max_map_count is too low. OpenSearch will refuse to start. A rootless
  container cannot raise it for itself, so run:

    sudo sysctl -w vm.max_map_count=262144
    echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-opensearch.conf
EOF
else
  echo "  vm.max_map_count = $MMAP, fine."
fi

FREE_KB=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
if [[ "$FREE_KB" -gt 0 && "$FREE_KB" -lt 3500000 ]]; then
  echo "  Only $((FREE_KB / 1024)) MB available. OpenSearch is configured for a"
  echo "  1 GB heap and Dashboards wants around 700 MB on top. Expect the"
  echo "  kernel to kill something on a host smaller than 4 GB."
else
  echo "  Memory looks sufficient."
fi

cat <<'EOF'

Next:

  podman compose up -d

First start takes a couple of minutes while the security plugin initialises.
Then reach the dashboard through an SSH tunnel, never by publishing 5601:

  ssh -L 5601:127.0.0.1:5601 <this-host>

and open http://127.0.0.1:5601 with user "admin" and the password from .env.

Create the index patterns "tripwire-hits-*" and "tripwire-sentinel-*", both
with @timestamp as the time field.
EOF
