#!/usr/bin/env bash
# Take the collector's OpenSearch off the demo security configuration.
#
# The image installs a demo security config unless told not to, and that
# config is public: six users whose passwords are their own names, and a
# static client certificate (CN=kirk) whose private key ships in every copy
# of the image and which opensearch.yml names as super-admin. Port 9200 is
# published on the WireGuard address so the sentinel can write to it, and
# the sentinel is the host this project expects to lose. Whoever owns it
# reads every index today; with kirk they also write, delete, and rewrite
# the monitors that would have told you.
#
# This script renders our own material -- one CA, one node certificate, one
# admin client certificate, our own internal_users.yml and opensearch.yml --
# into ./opensearch-config/, which compose.yaml bind-mounts read-only over
# the image's config. None of it is ever committed and none of it leaves the
# host that runs the cluster.
#
# Two paths in, because they are not the same problem:
#
#   fresh volume      no security index yet. OpenSearch builds one from the
#                     mounted internal_users.yml at first start, so --render
#                     and a recreate are the whole job.
#   existing volume   the security index is already in opensearch-data with
#                     the demo users in it, and the mounted file is ignored.
#                     --apply-users rewrites those entries over the security
#                     API, authenticating with the admin certificate: two of
#                     the demo users are `reserved` and nothing but an admin
#                     certificate may touch them.
#
# Existing clients are unaffected. Every one of them skips certificate
# verification already (curl -k, enrich.py INSECURE, Vector
# verify_certificate = false, Dashboards VERIFICATIONMODE none), so a new CA
# changes nothing for them. Teaching them to verify it is a separate job.
#
#   ./harden-opensearch.sh --render [--dir DIR] [--env FILE]
#   ./harden-opensearch.sh --apply-users [--container NAME] [--env FILE]
#   ./harden-opensearch.sh --check [--url URL] [--dash-url URL]
#                                  [--container NAME] [--env FILE]
#   ./harden-opensearch.sh --selftest
#
# On the collector, in this order:
#
#   ./harden-opensearch.sh --render
#   podman compose up -d --force-recreate opensearch dashboards
#   ./harden-opensearch.sh --apply-users      # existing volume only
#   ./harden-opensearch.sh --check
#
# The way back is the same three files: `podman compose down opensearch
# dashboards`, put the old compose.yaml back, start it again. The security
# index and the data are in the volume and are not touched by any of this.
set -euo pipefail

cd "$(dirname "$0")"

# --- knobs ---------------------------------------------------------------
CONFIG_DIR="./opensearch-config"
ENV_FILE=".env"
CONTAINER="tripwire-opensearch"
OS_URL=""
DASH_URL=""

# Dull, and naming nobody. These strings are also what opensearch.yml
# trusts, so they are the single source of truth for both.
#
# Note the order. openssl writes the parts of -subj into the certificate in
# the order given; Java reads a DN back as RFC 2253, which prints them in the
# REVERSE of that order, and that reversed string is what the security plugin
# compares against admin_dn and nodes_dn -- by equality, not by set. So
# `-subj /CN=x/O=tripwire` arrives as "O=tripwire,CN=x" and matches nothing,
# silently: the node starts, TLS works, and the admin certificate is simply
# not an admin (every security API call comes back 401). The demo
# configuration has the same shape for the same reason -- its kirk is
# `/C=de/L=test/O=client/OU=client/CN=kirk` and its admin_dn reads the other
# way round.
CA_SUBJ="/O=tripwire/CN=tripwire-ca"
NODE_SUBJ="/O=tripwire/CN=opensearch-node"
ADMIN_SUBJ="/O=tripwire/CN=opensearch-admin"
NODE_DN="CN=opensearch-node,O=tripwire"
ADMIN_DN="CN=opensearch-admin,O=tripwire"
# `opensearch` is the service name on the compose network, the other two are
# for a client on the host. No public name: this cluster has none.
NODE_SAN="DNS:opensearch,DNS:localhost,IP:127.0.0.1"
CERT_DAYS=3650

# The image that owns the password hashing tool, taken from compose.yaml so
# the two cannot drift, with the tag as a fallback for a copy of this script
# that has no compose.yaml next to it.
OS_IMAGE="$(sed -n 's#^[[:space:]]*image:[[:space:]]*\(docker\.io/opensearchproject/opensearch:[^[:space:]]*\)#\1#p' compose.yaml 2>/dev/null | head -1)"
OS_IMAGE="${OS_IMAGE:-docker.io/opensearchproject/opensearch:3.8.0}"
# No image on either host ships an openssl binary (checked: the OpenSearch
# image, alpine, the Vector image), and the collector has none either, so
# the fallback adds one to a throwaway alpine. It is the only step here that
# needs the network.
OPENSSL_IMAGE="docker.io/library/alpine:3.24"

# The six accounts the demo configuration creates, each with its own name as
# its password. `admin` is the seventh and keeps its .env password.
DEMO_USERS=(readall kibanaserver logstash kibanaro snapshotrestore anomalyadmin)
# The five that are not `reserved` and can simply go. kibanaserver stays:
# Dashboards logs in with it.
DEMO_DELETE=(readall logstash kibanaro snapshotrestore anomalyadmin)
# Demo role mappings that exist only to give those five their privileges.
# all_access (backend role "admin") and kibana_server (user kibanaserver)
# are deliberately not in this list.
DEMO_MAPPINGS=(readall logstash kibana_user manage_snapshots)

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

# --- helpers -------------------------------------------------------------
say()  { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'harden-opensearch: %s\n' "$*" >&2; exit 1; }

# .env is parsed, never sourced: a password is allowed to contain $, ", \ or
# a space, and none of those may ever become a shell word here. A trailing
# CR is stripped because files arrive on these hosts from Windows.
env_get() { # env_get KEY -- prints the value, rc 1 if the key is absent
  local key="$1" line
  [[ -r "$ENV_FILE" ]] || die "no readable $ENV_FILE (run ./setup-logging.sh first)"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == "$key="* ]] || continue
    line="${line#"$key"=}"
    printf '%s' "${line%$'\r'}"
    return 0
  done < "$ENV_FILE"
  return 1
}

env_need() { # env_need KEY -- prints the value or dies naming the key
  local value
  value="$(env_get "$1")" ||
    die "$1 is not in $ENV_FILE. ./setup-logging.sh adds it."
  [[ -n "$value" ]] || die "$1 is empty in $ENV_FILE"
  printf '%s' "$value"
}

# curl gets credentials as a config file on stdin, never as -u: argv is
# readable by every user on the host for as long as the process lives.
# printf is a builtin and has no argv of its own. Same escaping as
# bootstrap-opensearch.sh: backslash first, then double quote.
#
# `--config -` rather than bootstrap-opensearch.sh's `--config <(creds ...)`.
# Process substitution hands curl a path like /proc/self/fd/63, which only
# works when curl is the same kind of process as the shell. Under Git Bash
# the shell is MSYS and curl.exe is not, so it cannot open that path and
# every request dies before it is made. stdin costs nothing and works
# everywhere.
creds() { # creds USER PASSWORD
  local u=${1//\\/\\\\} p=${2//\\/\\\\}
  printf 'user = "%s:%s"\n' "${u//\"/\\\"}" "${p//\"/\\\"}"
}

# -k throughout: every client of this cluster already skips verification,
# and --check has to be able to say what certificate is being served rather
# than refuse to talk to it.
http_code() { # http_code USER PASSWORD URL
  creds "$1" "$2" | curl -sk -o /dev/null -w '%{http_code}' --max-time 20 \
    --config - "$3" 2>/dev/null || printf '000'
}

defaults_from_env() {
  local bind
  bind="$(env_get ADMIN_BIND || true)"
  bind="${bind:-127.0.0.1}"
  OS_URL="${OS_URL:-https://${bind}:9200}"
  DASH_URL="${DASH_URL:-http://${bind}:5601}"
}

# --- rendering -----------------------------------------------------------
# Run by whichever openssl we can reach: the host's if it has one, otherwise
# a throwaway container. POSIX sh only -- busybox ash is one of the two
# shells that runs it. Arguments rather than interpolation so that the DNs
# have exactly one definition, above.
CERT_SCRIPT='
set -e
cd "$1"
umask 077
ext="./ext.$$"
openssl req -x509 -newkey rsa:2048 -sha256 -days "$6" -nodes \
  -keyout root-ca-key.pem -out root-ca.pem -subj "$2" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
printf "%s\n" "basicConstraints=CA:FALSE" \
  "keyUsage=critical,digitalSignature,keyEncipherment" \
  "extendedKeyUsage=serverAuth,clientAuth" \
  "subjectAltName=$5" > "$ext"
openssl req -newkey rsa:2048 -nodes -keyout node-key.pem -out node.csr -subj "$3"
openssl x509 -req -in node.csr -CA root-ca.pem -CAkey root-ca-key.pem \
  -CAcreateserial -days "$6" -sha256 -extfile "$ext" -out node.pem
printf "%s\n" "basicConstraints=CA:FALSE" \
  "keyUsage=critical,digitalSignature" \
  "extendedKeyUsage=clientAuth" > "$ext"
openssl req -newkey rsa:2048 -nodes -keyout admin-key.pem -out admin.csr -subj "$4"
openssl x509 -req -in admin.csr -CA root-ca.pem -CAkey root-ca-key.pem \
  -CAcreateserial -days "$6" -sha256 -extfile "$ext" -out admin.pem
rm -f node.csr admin.csr root-ca.srl "$ext"
chmod 600 root-ca.pem root-ca-key.pem node.pem node-key.pem admin.pem admin-key.pem
'

CERT_FILES=(root-ca.pem root-ca-key.pem node.pem node-key.pem admin.pem admin-key.pem)

generate_certs() { # generate_certs DIR
  local dir="$1"
  # TW_FORCE_CONTAINER_OPENSSL exists for the test harness: the collector
  # has no openssl and takes the container path, the machine this is
  # developed on has one and would never take it, so without a way to ask
  # for it the path that matters is the path that is never run.
  if [[ -z "${TW_FORCE_CONTAINER_OPENSSL:-}" ]] && command -v openssl > /dev/null 2>&1; then
    say "  generating the CA, node and admin certificates with the host openssl"
    # MSYS_NO_PATHCONV: under Git Bash an argument that starts with a slash
    # is rewritten into a Windows path on its way to a native binary, and
    # every subject here starts with one. No effect on Linux.
    MSYS_NO_PATHCONV=1 sh -c "$CERT_SCRIPT" harden-openssl \
      "$dir" "$CA_SUBJ" "$NODE_SUBJ" "$ADMIN_SUBJ" "$NODE_SAN" "$CERT_DAYS" > /dev/null
    return 0
  fi
  command -v podman > /dev/null 2>&1 ||
    die "no openssl and no podman: nothing here can generate a certificate"
  say "  no host openssl; generating in a throwaway ${OPENSSL_IMAGE} container"
  # --user 0:0 so the writes land as the host user under rootless podman;
  # :Z for SELinux on Rocky. Keys are written straight into the bind mount
  # and never exist anywhere else.
  MSYS_NO_PATHCONV=1 podman run --rm --user 0:0 -v "$(cd "$dir" && pwd)":/out:Z \
    "$OPENSSL_IMAGE" sh -c '
      command -v openssl > /dev/null 2>&1 || apk add --no-cache openssl > /dev/null 2>&1 ||
        { echo "no openssl in this image and apk could not add one" >&2; exit 2; }
      '"$CERT_SCRIPT" harden-openssl \
    /out "$CA_SUBJ" "$NODE_SUBJ" "$ADMIN_SUBJ" "$NODE_SAN" "$CERT_DAYS" > /dev/null ||
    die "the certificate container failed; nothing was written"
}

hash_password() { # hash_password ENVVARNAME -- bcrypt hash on stdout
  command -v podman > /dev/null 2>&1 ||
    die "podman is needed to run the image's own password hashing tool"
  # The password is passed by NAME: hash.sh reads it from the environment,
  # so it is never an argument of any process. The container is --rm and
  # has no network.
  local out
  out="$(MSYS_NO_PATHCONV=1 podman run --rm --network=none --env "$1" \
    --entrypoint /bin/bash "$OS_IMAGE" \
    -c './plugins/opensearch-security/tools/hash.sh -env '"$1" 2>/dev/null)" ||
    die "could not run hash.sh in $OS_IMAGE"
  out="$(printf '%s\n' "$out" | grep -E '^\$2[aby]\$' | head -1)"
  [[ -n "$out" ]] || die "hash.sh produced no bcrypt hash"
  printf '%s' "$out"
}

write_opensearch_yml() { # write_opensearch_yml PATH
  local salt
  # Only used if field masking is ever switched on. Random rather than the
  # documented default, and rendered once so a re-render does not move it.
  # od rather than tr, which would be killed by SIGPIPE reading urandom and
  # take the whole script down through pipefail.
  salt="$(LC_ALL=C od -An -tx1 -N12 /dev/urandom | tr -d ' \n')"
  cat > "$1" <<YML
---
# Rendered by harden-opensearch.sh. Bind-mounted read-only over the image's
# own config/opensearch.yml, which is why the first two settings are
# repeated here: they come from the file this one replaces, not from the
# environment. cluster.name in particular must stay docker-cluster -- it is
# recorded in the existing opensearch-data volume and a node that disagrees
# with it refuses to start.
cluster.name: docker-cluster
network.host: 0.0.0.0

# Everything below is what the demo installer would have written, with our
# file names and our subjects: no demo certificate, no demo DN, nothing that
# exists in a published image. The settings compose.yaml passes by
# environment -- discovery, the disk watermark switch, memory lock, the heap
# -- are left to it.
plugins.security.ssl.transport.pemcert_filepath: node.pem
plugins.security.ssl.transport.pemkey_filepath: node-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: root-ca.pem
# One node, and the only transport peer it has is itself, reached on
# whatever address podman gave the container. No certificate can name that
# in advance, so verifying it would only ever fail.
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: node.pem
plugins.security.ssl.http.pemkey_filepath: node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: root-ca.pem
# OPTIONAL, as the demo leaves it, and now that means something different: a
# client certificate is accepted only if this CA signed it, and this CA was
# made on this host. It is how --apply-users reaches entries the security
# API calls reserved.
plugins.security.ssl.http.clientauth_mode: OPTIONAL
# Refuse to start if anything ever points this node back at the demo
# certificates.
plugins.security.allow_unsafe_democertificates: false
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn: ['${ADMIN_DN}']
plugins.security.nodes_dn: ['${NODE_DN}']
plugins.security.audit.type: internal_opensearch
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: [all_access, security_rest_api_access]
plugins.security.system_indices.enabled: true
plugins.security.compliance.salt: ${salt}
node.max_local_storage_nodes: 3
YML
  chmod 600 "$1"
}

write_internal_users() { # write_internal_users PATH
  local admin_hash dash_hash
  # Exported by name only. The value is never an argument, never echoed, and
  # the variables die with this shell.
  export TW_ADMIN_PW TW_DASH_PW
  TW_ADMIN_PW="$(env_need OPENSEARCH_INITIAL_ADMIN_PASSWORD)"
  TW_DASH_PW="$(env_need DASHBOARDS_SERVICE_PASSWORD)"
  say "  hashing two passwords with the image's own hash.sh"
  admin_hash="$(hash_password TW_ADMIN_PW)"
  dash_hash="$(hash_password TW_DASH_PW)"
  unset TW_ADMIN_PW TW_DASH_PW
  # An unquoted heredoc, but the hashes arrive through variables and a
  # variable's value is not expanded again, so the $2y$12$ in a bcrypt hash
  # survives intact.
  cat > "$1" <<YML
---
# Rendered by harden-opensearch.sh from .env. Read only when the security
# index does not exist yet, which means a fresh opensearch-data volume; an
# existing cluster keeps what is already in that index, and --apply-users is
# what rewrites it. Two accounts, no demo users, no reserved flags.
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "${admin_hash}"
  backend_roles:
  - "admin"
  description: "tripwire operator"

kibanaserver:
  hash: "${dash_hash}"
  description: "Dashboards service account"
YML
  chmod 600 "$1"
}

# Mode 600 protects these files from other users on the host; it also hides
# them from the container, which runs as uid 1000, and under rootless podman
# that is a subordinate uid on this host, not the operator. So the files are
# handed to that uid once, here. The directory itself stays owned by the
# operator (mode 700) -- chowning it too would lock the operator out of
# their own render.
fix_ownership() { # fix_ownership DIR
  local dir="$1"
  if [[ "$(id -u)" -eq 0 ]]; then
    chown 1000:1000 "$dir"/*.pem "$dir"/*.yml 2>/dev/null &&
      say "  ownership: uid 1000 (rootful podman: the same uid inside)"
    return 0
  fi
  if command -v podman > /dev/null 2>&1 &&
     podman unshare chown 1000:1000 "$dir"/*.pem "$dir"/*.yml 2>/dev/null; then
    say "  ownership: handed to the uid the container runs as (podman unshare chown 1000:1000)"
    return 0
  fi
  warn "could not run: podman unshare chown 1000:1000 ${dir}/*.pem ${dir}/*.yml
         These files are mode 600 and the container runs as uid 1000, which
         is a different uid on this host. If the node fails to start with a
         permission error on node-key.pem, run that command by hand, or add
         U to the mount options in compose.yaml and recreate."
}

cmd_render() {
  local dir="$CONFIG_DIR" missing=() present=() f
  mkdir -p "$dir"
  chmod 700 "$dir"
  dir="$(cd "$dir" && pwd)"
  say "Rendering into ${dir}"

  # If internal_users.yml still has to be written, .env has to hold both
  # passwords. Checked here, before anything is generated: a missing key
  # should stop this while there is still nothing on disk to explain.
  if [[ ! -e "$dir/internal_users.yml" ]]; then
    env_need OPENSEARCH_INITIAL_ADMIN_PASSWORD > /dev/null
    env_need DASHBOARDS_SERVICE_PASSWORD > /dev/null
  fi

  for f in "${CERT_FILES[@]}"; do
    if [[ -e "$dir/$f" ]]; then present+=("$f"); else missing+=("$f"); fi
  done
  if ((${#missing[@]} == 0)); then
    say "  certificates already there, left alone (${#present[@]} files)"
  elif ((${#present[@]} > 0)); then
    # Never a partial overwrite. Half a certificate set is a node that will
    # not start and a CA nobody has the key to any more.
    die "refusing to write into a half-rendered ${dir}:
    present: ${present[*]}
    missing: ${missing[*]}
  Move the directory aside and render again. There is no --rotate."
  else
    generate_certs "$dir"
    say "  root-ca.pem node.pem admin.pem and their keys, ${CERT_DAYS} days"
    say "  root-ca-key.pem stays here, unmounted: it is the only way to issue"
    say "  another certificate without redoing all of this."
  fi

  if [[ -e "$dir/opensearch.yml" ]]; then
    say "  opensearch.yml already there, left alone"
  else
    write_opensearch_yml "$dir/opensearch.yml"
    say "  opensearch.yml: admin_dn ${ADMIN_DN}, nodes_dn ${NODE_DN}"
  fi

  if [[ -e "$dir/internal_users.yml" ]]; then
    say "  internal_users.yml already there, left alone"
  else
    write_internal_users "$dir/internal_users.yml"
    say "  internal_users.yml: admin and kibanaserver, nothing else"
  fi

  fix_ownership "$dir"
  say "Done. Next: podman compose up -d --force-recreate opensearch dashboards"
}

# --- the existing cluster ------------------------------------------------
# Every call goes through the container's own curl, with the admin
# certificate that only exists on this host. Two of the demo entries are
# `reserved`, and the security API refuses those to everything except a
# request carrying an admin certificate -- which is the whole reason this
# package generated one.
api() { # api METHOD PATH [body] -- "body" means: read it from stdin
  local method="$1" path="$2" args=()
  [[ "${3:-}" == body ]] && args=(-H 'Content-Type: application/json' --data-binary @-)
  MSYS_NO_PATHCONV=1 podman exec -i "$CONTAINER" curl -sS -o /dev/null \
    -w '%{http_code}' -X "$method" \
    --cacert /usr/share/opensearch/config/root-ca.pem \
    --cert /usr/share/opensearch/config/admin.pem \
    --key /usr/share/opensearch/config/admin-key.pem \
    "${args[@]}" "https://localhost:9200${path}" 2>/dev/null || printf '000'
}

cmd_apply_users() {
  local rc=0 code name
  command -v podman > /dev/null 2>&1 || die "--apply-users needs podman"
  podman exec "$CONTAINER" true > /dev/null 2>&1 ||
    die "no running container named ${CONTAINER} (--container names another)"

  say "Rewriting the security index in ${CONTAINER}."

  export TW_DASH_PW
  TW_DASH_PW="$(env_need DASHBOARDS_SERVICE_PASSWORD)"
  # The body is built by python from the environment, so a password
  # containing a quote or a backslash is JSON-escaped rather than pasted
  # into a string, and it is piped in rather than passed as an argument.
  code="$(python3 -c 'import json, os
print(json.dumps({"password": os.environ["TW_DASH_PW"]}))' |
    api PUT /_plugins/_security/api/internalusers/kibanaserver body)"
  unset TW_DASH_PW
  case "$code" in
    200|201) say "  kibanaserver: password set from DASHBOARDS_SERVICE_PASSWORD" ;;
    *) say "  kibanaserver: FAILED, HTTP ${code}"; rc=1 ;;
  esac

  for name in "${DEMO_DELETE[@]}"; do
    code="$(api DELETE "/_plugins/_security/api/internalusers/${name}" < /dev/null)"
    case "$code" in
      200|404) say "  user ${name}: gone (HTTP ${code})" ;;
      *) say "  user ${name}: FAILED, HTTP ${code}"; rc=1 ;;
    esac
  done

  for name in "${DEMO_MAPPINGS[@]}"; do
    code="$(api DELETE "/_plugins/_security/api/rolesmapping/${name}" < /dev/null)"
    case "$code" in
      200|404) say "  role mapping ${name}: gone (HTTP ${code})" ;;
      *) say "  role mapping ${name}: FAILED, HTTP ${code}"; rc=1 ;;
    esac
  done

  if ((rc == 0)); then
    say "Done. Restart tripwire-dashboards so it logs in with the new password,"
    say "then run --check."
  fi
  return "$rc"
}

# --- check ---------------------------------------------------------------
cmd_check() {
  local rc=0 admin_pw code name issuer admin_dn
  defaults_from_env
  admin_pw="$(env_need OPENSEARCH_INITIAL_ADMIN_PASSWORD)"

  item() { # item ok|FAIL text
    printf '%-6s%s\n' "$1" "$2"
    [[ "$1" == ok ]] || rc=1
  }

  say "Checking ${OS_URL} and ${DASH_URL}"

  # 1. Nothing answers to a published default any more. Every one of these
  #    is a name from the demo configuration with its own name as password.
  for name in "${DEMO_USERS[@]}"; do
    code="$(http_code "$name" "$name" "${OS_URL}/_plugins/_security/authinfo")"
    if [[ "$code" == 401 ]]; then
      item ok "${name} with its demo password: 401"
    else
      item FAIL "${name} with its demo password: expected 401, got ${code}"
    fi
  done
  code="$(http_code admin admin "${OS_URL}/_plugins/_security/authinfo")"
  if [[ "$code" == 401 ]]; then
    item ok "admin:admin: 401"
  else
    item FAIL "admin:admin: expected 401, got ${code}"
  fi

  # 2. ... and the account that should work still does.
  code="$(http_code admin "$admin_pw" "${OS_URL}/_plugins/_security/authinfo")"
  if [[ "$code" == 200 ]]; then
    item ok "admin with the .env password: 200"
  else
    item FAIL "admin with the .env password: expected 200, got ${code}"
  fi

  # 3. The certificate on the wire is ours: verified against our own CA,
  #    from inside the container where that CA is mounted, with no -k. The
  #    demo certificate -- or anything else this CA did not sign -- fails the
  #    handshake and never reaches an HTTP status. The admin client
  #    certificate goes with it, so a 200 also says the DN in opensearch.yml
  #    is the DN in that certificate.
  #
  #    Done this way rather than by reading an issuer line out of `curl -v`:
  #    the collector has no openssl to ask with, and curl's verbose format
  #    depends on which TLS backend it was built against -- the Windows build
  #    used for the tests prints no issuer at all.
  if command -v podman > /dev/null 2>&1 && podman exec "$CONTAINER" true > /dev/null 2>&1; then
    # No -k, no credentials, no client certificate: only the CA. Any HTTP
    # status at all means the handshake completed, which is the whole claim --
    # a certificate this CA did not sign never gets that far (curl aborts and
    # we print 000). The status itself is not interesting: this node answers
    # 401 on /_plugins/_security/health, another build answers 200, and both
    # say the same thing about the certificate.
    code="$(MSYS_NO_PATHCONV=1 podman exec "$CONTAINER" curl -sS -o /dev/null \
      -w '%{http_code}' --cacert /usr/share/opensearch/config/root-ca.pem \
      https://localhost:9200/_plugins/_security/health 2>/dev/null || printf '000')"
    if [[ "$code" != 000 ]]; then
      item ok "the served certificate verifies against our CA (HTTP ${code})"
    else
      item FAIL "the served certificate did not verify against our CA"
    fi
    # And the other half: the admin certificate is what the security API
    # accepts as super-admin. This is the privilege --apply-users needs, and
    # a mismatch between the certificate's DN and admin_dn shows up only
    # here -- everything else keeps working.
    code="$(api GET /_plugins/_security/api/internalusers < /dev/null)"
    if [[ "$code" == 200 ]]; then
      item ok "the admin certificate is super-admin on the security API"
    else
      item FAIL "the admin certificate is not super-admin: HTTP ${code} (admin_dn mismatch?)"
    fi
  else
    # Nothing to verify with. Say so rather than scrape a format that is not
    # the same on every build of curl.
    issuer="$(curl -sk -v --max-time 20 -o /dev/null "${OS_URL}/" 2>&1 |
              sed -n 's/^\* *[Ii]ssuer: *//p' | head -1)"
    if [[ "$issuer" == *"Example Com Inc"* ]]; then
      item FAIL "server certificate issuer: still the demo CA (${issuer})"
    elif [[ -n "$issuer" ]]; then
      item ok "server certificate issuer: ${issuer} (no container to verify against)"
    else
      item FAIL "no ${CONTAINER} to verify against and curl reported no issuer: cannot tell"
    fi
  fi

  # 4. The file the node actually loaded, not the one on disk beside us.
  if command -v podman > /dev/null 2>&1 &&
     admin_dn="$(MSYS_NO_PATHCONV=1 podman exec "$CONTAINER" \
       grep -h 'admin_dn' /usr/share/opensearch/config/opensearch.yml 2>/dev/null)"; then
    if [[ "$admin_dn" == *kirk* ]]; then
      item FAIL "admin_dn in the running container: still kirk"
    elif [[ "$admin_dn" == *"$ADMIN_DN"* ]]; then
      item ok "admin_dn in the running container: ${ADMIN_DN}"
    else
      item FAIL "admin_dn in the running container: unexpected (${admin_dn})"
    fi
  else
    item FAIL "admin_dn in the running container: could not read it from ${CONTAINER}"
  fi

  # 5. Dashboards answering at all means its own service login worked: it
  #    signs in as kibanaserver before it will serve a status page.
  code="$(http_code admin "$admin_pw" "${DASH_URL}/api/status")"
  if [[ "$code" == 200 ]]; then
    item ok "Dashboards /api/status: 200 (so kibanaserver logs in)"
  else
    item FAIL "Dashboards /api/status: expected 200, got ${code}"
  fi

  return "$rc"
}

# --- selftest ------------------------------------------------------------
# What can be said with no cluster, no podman and no openssl: the argument
# parsing, what the rendered opensearch.yml says, and the refusal to write
# over key material. The cluster itself is tested by
# test-opensearch-hardening.sh, which needs podman.
cmd_selftest() {
  local tmp rc=0 dir yml
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  check() { # check NAME command...
    if "${@:2}" > /dev/null 2>&1; then
      printf 'ok    %s\n' "$1"
    else
      printf 'FAIL  %s\n' "$1"
      rc=1
    fi
  }

  printf 'OPENSEARCH_INITIAL_ADMIN_PASSWORD=pw with a $dollar "quote" and \\ backslash\n' \
    > "$tmp/env"
  printf 'DASHBOARDS_SERVICE_PASSWORD=another one\n' >> "$tmp/env"

  # Seeded with placeholders so that --render has nothing to generate: no
  # openssl, no podman, no network, and it exercises exactly the path a
  # second --render takes on a host that is already rendered.
  dir="$tmp/config"
  mkdir -p "$dir"
  for f in "${CERT_FILES[@]}"; do printf 'PLACEHOLDER %s\n' "$f" > "$dir/$f"; done
  printf 'PLACEHOLDER internal_users\n' > "$dir/internal_users.yml"

  "$SELF" --render --dir "$dir" --env "$tmp/env" > "$tmp/render.log" 2>&1 ||
    { cat "$tmp/render.log"; die "selftest: --render failed on a seeded directory"; }
  yml="$dir/opensearch.yml"

  check "1 opensearch.yml is written"        test -f "$yml"
  check "1 no kirk anywhere"                 bash -c "! grep -rqi kirk '$dir'"
  check "1 no esnode anywhere"               bash -c "! grep -rqi esnode '$dir'"
  check "1 admin_dn is ours"                 grep -qF "admin_dn: ['$ADMIN_DN']" "$yml"
  check "1 nodes_dn is ours"                 grep -qF "nodes_dn: ['$NODE_DN']" "$yml"
  check "1 our node certificate file names"  grep -q '^plugins.security.ssl.http.pemcert_filepath: node.pem$' "$yml"
  check "1 demo certificates refused"        grep -q '^plugins.security.allow_unsafe_democertificates: false$' "$yml"
  check "1 client certificates accepted"     grep -q '^plugins.security.ssl.http.clientauth_mode: OPTIONAL$' "$yml"
  check "1 the cluster name is unchanged"    grep -qx 'cluster.name: docker-cluster' "$yml"
  check "1 admin_dn and nodes_dn differ"     bash -c "[[ '$ADMIN_DN' != '$NODE_DN' ]]"

  # The trap this package walked into once: openssl writes the parts of
  # -subj in the order given and Java reads the DN back reversed, so a
  # subject and the DN it has to match are written in opposite orders. It
  # fails silently -- the cluster is healthy and only the security API says
  # 401 -- so it is asserted here rather than left to a running cluster.
  dn_of() { # dn_of /O=a/CN=b -- the RFC 2253 string the JVM will report
    local s="$1" out="" part
    while [[ "$s" == /* ]]; do
      part="${s#/}"; part="${part%%/*}"
      out="${part}${out:+,}${out}"
      s="${s#/"$part"}"
    done
    printf '%s' "$out"
  }
  check "1 the node subject reverses into nodes_dn" \
    bash -c "[[ '$(dn_of "$NODE_SUBJ")' == '$NODE_DN' ]]"
  check "1 the admin subject reverses into admin_dn" \
    bash -c "[[ '$(dn_of "$ADMIN_SUBJ")' == '$ADMIN_DN' ]]"

  # 2: key material is never touched by a re-render, and neither is
  # anything else that is already there.
  local before after
  before="$(cat "$dir/node-key.pem" "$dir/internal_users.yml" "$yml")"
  "$SELF" --render --dir "$dir" --env "$tmp/env" > /dev/null 2>&1
  after="$(cat "$dir/node-key.pem" "$dir/internal_users.yml" "$yml")"
  check "2 a second render changes nothing" bash -c "[[ \"\$1\" == \"\$2\" ]]" _ "$before" "$after"

  # 3: a half-rendered directory is refused loudly rather than completed.
  local half="$tmp/half" out
  mkdir -p "$half"
  printf 'PLACEHOLDER\n' > "$half/root-ca.pem"
  check "3 a partial certificate set is refused" \
    bash -c "! '$SELF' --render --dir '$half' --env '$tmp/env'"
  out="$("$SELF" --render --dir "$half" --env "$tmp/env" 2>&1 || true)"
  check "3 the refusal names the missing files" \
    bash -c "printf '%s' \"\$1\" | grep -q 'node-key.pem'" _ "$out"
  check "3 nothing was generated"  bash -c "! test -e '$half/node.pem'"

  # 4: arguments.
  check "4 an unknown flag is refused"  bash -c "! '$SELF' --nonsense"
  check "4 no arguments prints usage"   bash -c "'$SELF' 2>&1 | grep -q -- '--apply-users'"
  check "4 no arguments is not success" bash -c "! '$SELF' > /dev/null 2>&1"
  check "4 --help is success"           bash -c "'$SELF' --help > /dev/null"
  out="$("$SELF" --render --dir "$tmp/nokey" --env /dev/null 2>&1 || true)"
  check "4 a missing .env key names itself" \
    bash -c "printf '%s' \"\$1\" | grep -q OPENSEARCH_INITIAL_ADMIN_PASSWORD" _ "$out"

  ((rc == 0)) && say "selftest ok"
  return "$rc"
}

# --- entry ---------------------------------------------------------------
usage() {
  sed -n '2,/^set -euo/p' "$SELF" | sed 's/^# \{0,1\}//; $d'
}

main() {
  local mode=""
  while (($#)); do
    case "$1" in
      --render)      mode=render; shift ;;
      --apply-users) mode=apply;  shift ;;
      --check)       mode=check;  shift ;;
      --selftest)    mode=selftest; shift ;;
      --dir)         CONFIG_DIR="${2:-}"; [[ -n "$CONFIG_DIR" ]] || die "--dir needs a directory"; shift 2 ;;
      --env)         ENV_FILE="${2:-}";   [[ -n "$ENV_FILE" ]] || die "--env needs a file"; shift 2 ;;
      --container)   CONTAINER="${2:-}";  [[ -n "$CONTAINER" ]] || die "--container needs a name"; shift 2 ;;
      --url)         OS_URL="${2:-}";     [[ -n "$OS_URL" ]] || die "--url needs a URL"; shift 2 ;;
      --dash-url)    DASH_URL="${2:-}";   [[ -n "$DASH_URL" ]] || die "--dash-url needs a URL"; shift 2 ;;
      -h|--help)     usage; return 0 ;;
      *)             die "unknown argument: $(printf '%q' "$1")" ;;
    esac
  done
  case "$mode" in
    render)   cmd_render ;;
    apply)    cmd_apply_users ;;
    check)    cmd_check ;;
    selftest) cmd_selftest ;;
    *)        usage; return 1 ;;
  esac
}

main "$@"
