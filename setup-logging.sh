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

# Dashboards logs in to OpenSearch with its own service account, and compose
# refuses to start it without this key. Appended rather than written with the
# block above, because an .env that predates harden-opensearch.sh will not
# have it and is otherwise left alone. Never regenerated: a running cluster
# already knows the password it was given, and only
# `./harden-opensearch.sh --apply-users` can tell it a new one.
python3 - "$ENV_FILE" <<'PY'
import secrets, string, sys
path, key = sys.argv[1], "DASHBOARDS_SERVICE_PASSWORD"
with open(path) as fh:
    text = fh.read()
if any(line.startswith(key + "=") for line in text.splitlines()):
    sys.exit(0)
alphabet = string.ascii_letters + string.digits
pw = "".join(secrets.choice(alphabet) for _ in range(40)) + "_Aa1!"
with open(path, "a") as fh:
    fh.write(("" if text.endswith("\n") or not text else "\n") + f"{key}={pw}\n")
print(f"Added {key} to {path}. It was not printed here.")
PY

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
# Every value stays a string, numbers and lists included. Vector's file
# backend reads the whole file as a map of strings and refuses all of it,
# password too, if one value is anything else. enrich.py converts on read.
secrets = {"opensearch_password": password}
# Optional. enrich.py asks GreyNoise and AbuseIPDB about each address when
# these are present in .env and skips them when they are not.
for env_key, out_key in (("GREYNOISE_API_KEY", "greynoise_api_key"),
                         ("ABUSEIPDB_API_KEY", "abuseipdb_api_key"),
                         ("OTX_API_KEY", "otx_api_key"),
                         ("SENTINEL_PUBLIC_IP", "sentinel_public_ip")):
    if env.get(env_key):
        secrets[out_key] = env[env_key]
# internetdb, dshield, otx: each is off unless named here. They send
# attacker addresses to third parties, so opting in is a line in .env.
if env.get("ENRICH_LOOKUPS"):
    secrets["lookups"] = env["ENRICH_LOOKUPS"]
# Sentinel's own coordinates, for the RTT-against-geography verdict. Without
# both, enrich.py skips that feature and says so once at start-up.
for env_key, out_key in (("SENTINEL_LAT", "sentinel_lat"), ("SENTINEL_LON", "sentinel_lon")):
    if env.get(env_key):
        try:
            float(env[env_key])
        except ValueError:
            sys.exit(f"{env_key} in {env_path} is not a number: {env[env_key]!r}")
        secrets[out_key] = env[env_key]
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(secrets, fh)
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
