#!/usr/bin/env bash
# Acceptance tests for harden-opensearch.sh. One entrypoint, local podman,
# throwaway everything.
#
# Nothing here touches the real stack: every cluster gets its own compose
# project name, its own container names, its own volumes, its own loopback
# ports (192xx/156xx, never 9200/5601) and its own generated .env in a temp
# directory under this checkout. The real .env is never read. Everything is
# removed on exit, including after a failure and after Ctrl-C.
#
#   T1  fresh install: render, up, --check, bootstrap-opensearch.sh
#   T2  migration: demo cluster on a fresh volume, switch, --apply-users
#   T5  the image's own kirk certificate is rejected after hardening
#   T4  idempotence: --render twice byte-identical, --apply-users twice
#   T3  rollback: the old compose starts again on the same volume
#   T6  a password with a space, a quote and a backslash survives the whole
#       path (hash.sh, the security index, curl, compose, the REST body)
#
#   ./test-opensearch-hardening.sh            # all of it, ~12 minutes
#   ./test-opensearch-hardening.sh T1 T4      # named stages only
#
# Exit 0 only if every stage that ran passed. Exit 2 if podman is not
# usable, which is not a test failure.
set -euo pipefail

cd "$(dirname "$0")"
REPO="$(pwd)"

# Ports are per stage so a stray container from an earlier run cannot be
# mistaken for this one's.
T1_PROJ=ostest1; T1_OS=19200; T1_DASH=15601
T2_PROJ=ostest2; T2_OS=19210; T2_DASH=15611
T6_PROJ=ostest6; T6_OS=19220; T6_DASH=15621
PROJECTS=("$T1_PROJ" "$T2_PROJ" "$T6_PROJ")

# A throwaway box with a shell, curl and python3 in it, for running
# bootstrap-opensearch.sh from inside the compose network. Same image
# harden-opensearch.sh falls back to when the host has no openssl.
HELPER_IMAGE="${HELPER_IMAGE:-docker.io/library/alpine:3.24}"

# Generated once per run. Alphanumeric plus a fixed suffix, the same shape
# setup-logging.sh produces, because bootstrap-opensearch.sh sources .env
# and a value with a space in it would break it before it reached anything
# this package owns. T6 is where the awkward characters get their run.
PLAIN_PW="$(LC_ALL=C od -An -tx1 -N12 /dev/urandom | tr -d ' \n')_Aa1!"
# A space, a double quote, a backslash and a single quote. No dollar sign:
# compose interpolates .env values, so a $ never survives the file itself,
# which is a property of compose and not of anything here.
NASTY_PW='sp ace "q" \ b'"'"'s_Aa1!'

RESULTS=()
FAILURES=0
STAGE=""
STAGE_AT=0
STAGE_BAD=0
T2_READY=0
KIRK_OK=0

say()  { printf '%s\n' "$*"; }
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; STAGE_BAD=$((STAGE_BAD + 1)); }
die()  { printf 'test-opensearch-hardening: %s\n' "$*" >&2; exit 1; }

stage_begin() {
  STAGE="$1"; STAGE_AT=$SECONDS; STAGE_BAD=0
  printf '\n=== %s: %s ===\n' "$1" "$2"
}

stage_end() {
  local secs=$((SECONDS - STAGE_AT)) verdict=PASS
  ((STAGE_BAD == 0)) || { verdict=FAIL; FAILURES=$((FAILURES + 1)); }
  RESULTS+=("$(printf '%-4s %-4s %4ds  %s' "$STAGE" "$verdict" "$secs" \
    "$([[ $verdict == PASS ]] && echo '' || echo "${STAGE_BAD} assertion(s) failed")")")
  printf -- '--- %s %s (%ds) ---\n' "$STAGE" "$verdict" "$secs"
}

wants() { # wants NAME -- true if this stage was asked for
  ((${#WANTED[@]} == 0)) && return 0
  local w; for w in "${WANTED[@]}"; do [[ "$w" == "$1" ]] && return 0; done
  return 1
}

# --- talking to a cluster ------------------------------------------------
# A curl config on stdin, so no password in argv. Not `--config <(creds ...)`:
# Windows curl.exe cannot open the /proc/self/fd path an MSYS shell makes, so
# under Git Bash every such request fails before it is sent.
creds() { # creds USER PASSWORD
  local u=${1//\\/\\\\} p=${2//\\/\\\\}
  printf 'user = "%s:%s"\n' "${u//\"/\\\"}" "${p//\"/\\\"}"
}

code() { # code USER PASSWORD URL
  creds "$1" "$2" | curl -sk -o /dev/null -w '%{http_code}' --max-time 20 \
    --config - "$3" 2>/dev/null || printf '000'
}

body() { # body USER PASSWORD URL
  creds "$1" "$2" | curl -sk --max-time 20 --config - "$3" 2>/dev/null || true
}

expect_code() { # expect_code LABEL EXPECTED USER PASSWORD URL
  local got; got="$(code "$3" "$4" "$5")"
  if [[ "$got" == "$2" ]]; then ok "$1 (${got})"; else bad "$1: expected $2, got ${got}"; fi
}

wait_code() { # wait_code LABEL SECONDS EXPECTED USER PASSWORD URL
  local deadline=$((SECONDS + $2)) got=000 spun=0
  while ((SECONDS < deadline)); do
    got="$(code "$4" "$5" "$6")"
    if [[ "$got" == "$3" ]]; then
      ok "$1 after $((SECONDS - deadline + $2))s"
      return 0
    fi
    ((spun++ % 4 == 0)) && printf '  ...   %s (%s, %ds left)\n' "$1" "$got" "$((deadline - SECONDS))"
    sleep 5
  done
  bad "$1: never returned $3 within $2s (last ${got})"
  return 1
}

dump_logs() { # dump_logs CONTAINER -- only after something went wrong
  printf '  --- last 25 lines of %s ---\n' "$1"
  podman logs --tail 25 "$1" 2>&1 | sed 's/^/  | /' || true
}

# --- compose -------------------------------------------------------------
# Run from inside the project directory with a relative -f, so that whatever
# `podman compose` delegates to (docker-compose here, podman-compose on the
# collector) resolves ./opensearch-config and .env against that directory
# and never against the real checkout.
# `podman cp` resolves the host side itself and does not understand an MSYS
# path (/q/Projects/...), while MSYS_NO_PATHCONV=1 is still needed to stop it
# mangling the container side. cygpath exists only under Git Bash; on Linux
# the path is already what podman wants.
hostpath() { # hostpath PATH -- the same path, spelled for the podman binary
  if command -v cygpath > /dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

dc() { # dc DIR FILE PROJECT args...
  local dir="$1" file="$2" proj="$3"; shift 3
  (cd "$dir" && podman compose -p "$proj" -f "$file" "$@") && return 0
  # One retry, for `up` only. The local podman has been seen to lose a
  # container record between "Started" and the health wait ("no container
  # with ID ... found in database: no such container"), which is a hiccup in
  # the container engine, not a verdict on the configuration under test. A
  # second failure is reported as a failure.
  [[ "${1:-}" == up ]] || return 1
  printf '%s: compose up failed once, retried\n' "$proj" >> "$WORK/compose-retries.log"
  (cd "$dir" && podman compose -p "$proj" -f "$file" "$@")
}

make_compose() { # make_compose SRC DEST PREFIX OSPORT DASHPORT
  sed -e "s/container_name: tripwire-/container_name: ${3}-/" \
      -e "s/:9200:9200\"/:${4}:9200\"/" \
      -e "s/:5601:5601\"/:${5}:5601\"/" "$1" > "$2"
  grep -q "container_name: ${3}-opensearch" "$2" ||
    die "the container_name rewrite did not take in $2"
  grep -q ":${4}:9200\"" "$2" ||
    die "the port rewrite did not take in $2"
}

write_env() { # write_env PATH ADMINPW DASHPW
  umask 077
  { printf 'OPENSEARCH_INITIAL_ADMIN_PASSWORD=%s\n' "$2"
    printf 'DASHBOARDS_SERVICE_PASSWORD=%s\n' "$3"
    printf 'SENTINEL_WRITER_PASSWORD=%s\n' "$PLAIN_PW"
  } > "$1"
}

# bootstrap-opensearch.sh is not edited and not run from the checkout: it
# cd's to its own directory and hard-requires an .env beside it, so a byte
# copy goes into the project directory next to the throwaway .env. OS_URL and
# DASH_URL are variables it already reads, so it needs no argument it does
# not have.
#
# It runs inside a throwaway container joined to the compose network rather
# than on this host. Its own credential plumbing is `curl --config <(creds)`,
# and under Git Bash Windows curl.exe cannot open the /proc/self/fd path an
# MSYS shell makes, so every request fails before it is sent. Editing the
# script is out of scope for this package, so the test moves instead: same
# script, same variables, one hop further in. On the collector the same call
# would work directly on the host; the container path is what makes the stage
# runnable on both.
run_bootstrap() { # run_bootstrap DIR PROJECT LOGFILE
  local d="$1" proj="$2" log="$3" ctr="${2}-bootstrap"
  cp "$REPO/bootstrap-opensearch.sh" "$REPO/dashboards.py" "$d/"
  podman rm -f "$ctr" > /dev/null 2>&1 || true
  # The names go into /etc/hosts rather than being left to the network's DNS.
  # aardvark-dns answers NXDOMAIN for a moment while it reloads its config,
  # and one run died on exactly that, half way through bootstrap ("Could not
  # resolve host: opensearch"). The names still have to be the certificate's
  # names -- "opensearch" is in the node SAN for this -- only the resolution
  # is made static.
  local hosts=() name ip
  for name in opensearch dashboards; do
    ip="$(podman inspect -f \
      "{{(index .NetworkSettings.Networks \"${proj}_tripwire\").IPAddress}}" \
      "${proj}-${name}" 2>/dev/null || true)"
    if [[ -n "$ip" ]]; then hosts+=(--add-host "${name}:${ip}"); fi
  done
  MSYS_NO_PATHCONV=1 podman run -d --name "$ctr" --network "${proj}_tripwire" \
    "${hosts[@]}" "$HELPER_IMAGE" sleep 1800 > "$log" 2>&1 || return 1
  MSYS_NO_PATHCONV=1 podman exec "$ctr" mkdir -p /w >> "$log" 2>&1 || return 1
  MSYS_NO_PATHCONV=1 podman cp "$(hostpath "$d")/." "${ctr}:/w" >> "$log" 2>&1 || return 1
  # Service names, not 127.0.0.1: inside the container loopback is its own.
  # "opensearch" is in the node certificate's SAN list for exactly this.
  MSYS_NO_PATHCONV=1 podman exec \
    -e OS_URL="https://opensearch:9200" -e DASH_URL="http://dashboards:5601" \
    "$ctr" sh -c 'apk add --no-cache bash curl python3 > /dev/null 2>&1 &&
                  cd /w && exec bash ./bootstrap-opensearch.sh' >> "$log" 2>&1
}

# The demo super-admin certificate, tried against a cluster's security API.
# Prints the HTTP status and exits with curl's exit code, so a refusal in the
# handshake (no status at all) can be told apart from one in HTTP.
#
# Run from inside the container, on its own loopback, because the client
# certificate is the whole point of the test: the curl that ships with Git
# Bash will not load a PEM client certificate at all and fails 58 before the
# server is ever asked, which would make the test pass without proving
# anything. The files are written through `exec -i` rather than `podman cp`
# so they belong to the user curl runs as.
kirk_probe() { # kirk_probe CONTAINER DIR
  MSYS_NO_PATHCONV=1 podman exec -i "$1" sh -c 'cat > /tmp/kirk.pem' < "$2/kirk.pem" || return 90
  MSYS_NO_PATHCONV=1 podman exec -i "$1" \
    sh -c 'cat > /tmp/kirk-key.pem && chmod 600 /tmp/kirk-key.pem' < "$2/kirk-key.pem" || return 90
  MSYS_NO_PATHCONV=1 podman exec "$1" curl -s -o /dev/null -w '%{http_code}' \
    --max-time 20 -k --cert /tmp/kirk.pem --key /tmp/kirk-key.pem \
    "https://localhost:9200/_plugins/_security/api/internalusers"
}

# Every line ends in `|| true`. Removing a container is not instant, so the
# volume that was attached to it can still be "in use" a moment later and
# podman exits non-zero; under `set -e` that would end the whole run in the
# middle of a teardown, with no message because the output is discarded. A
# teardown that cannot fail is worth more here than one that reports.
teardown_project() { # teardown_project NAME -- by label, so nothing is missed
  local ids
  ids="$(podman ps -aq --filter "label=com.docker.compose.project=$1" 2>/dev/null || true)"
  [[ -n "$ids" ]] && podman rm -f $ids > /dev/null 2>&1 || true
  ids="$(podman volume ls -q --filter "label=com.docker.compose.project=$1" 2>/dev/null || true)"
  [[ -n "$ids" ]] && podman volume rm $ids > /dev/null 2>&1 || true
  ids="$(podman network ls -q --filter "label=com.docker.compose.project=$1" 2>/dev/null || true)"
  [[ -n "$ids" ]] && podman network rm $ids > /dev/null 2>&1 || true
  # Belt and braces: the names are ours, so remove them even if the labels
  # were not what this podman writes.
  podman rm -f "${1}-opensearch" "${1}-dashboards" "${1}-bootstrap" \
    > /dev/null 2>&1 || true
  podman volume rm "${1}_opensearch-data" > /dev/null 2>&1 || true
  return 0
}

cleanup() {
  local p
  printf '\nTearing down.\n'
  for p in "${PROJECTS[@]}"; do teardown_project "$p"; done
  [[ -n "${WORK:-}" && -d "$WORK" ]] && rm -rf "$WORK"
  return 0
}

# --- preflight -----------------------------------------------------------
WANTED=("$@")
command -v podman > /dev/null 2>&1 || { echo "podman is not installed." >&2; exit 2; }
podman info > /dev/null 2>&1 || {
  echo "podman is installed but not usable (is the machine started?)." >&2; exit 2; }
podman compose version > /dev/null 2>&1 || {
  echo "podman compose has no provider on this host." >&2; exit 2; }

# /tmp is not visible to a podman machine on Windows, and these directories
# are bind mount sources. The name matches the *.local.* rule in .gitignore.
WORK="$(mktemp -d "${REPO}/.os-test.local.XXXXXX")"
trap cleanup EXIT INT TERM

say "Work directory: ${WORK}"
say "Image: $(grep -m1 'opensearchproject/opensearch:' "${REPO}/compose.yaml" | tr -d ' ')"
for p in "${PROJECTS[@]}"; do teardown_project "$p"; done

# ==========================================================================
# T1  fresh install
# ==========================================================================
if wants T1; then
  stage_begin T1 "fresh install: render, up, --check, bootstrap"
  D="$WORK/t1"; mkdir -p "$D"
  write_env "$D/.env" "$PLAIN_PW" "$PLAIN_PW"
  make_compose "$REPO/compose.yaml" "$D/compose.yaml" "$T1_PROJ" "$T1_OS" "$T1_DASH"

  if "$REPO/harden-opensearch.sh" --render --dir "$D/opensearch-config" \
       --env "$D/.env" > "$D/render.log" 2>&1; then
    ok "--render on an empty directory"
  else
    bad "--render failed"; sed 's/^/  | /' "$D/render.log"
  fi

  if dc "$D" compose.yaml "$T1_PROJ" up -d opensearch dashboards > "$D/up.log" 2>&1; then
    ok "compose up"
  else
    bad "compose up failed"; sed 's/^/  | /' "$D/up.log"
  fi

  wait_code "opensearch answers as admin" 240 200 admin "$PLAIN_PW" \
    "https://127.0.0.1:${T1_OS}/_cluster/health" || dump_logs "${T1_PROJ}-opensearch"
  wait_code "dashboards answers" 240 200 admin "$PLAIN_PW" \
    "http://127.0.0.1:${T1_DASH}/api/status" || dump_logs "${T1_PROJ}-dashboards"

  if "$REPO/harden-opensearch.sh" --check --env "$D/.env" \
       --url "https://127.0.0.1:${T1_OS}" --dash-url "http://127.0.0.1:${T1_DASH}" \
       --container "${T1_PROJ}-opensearch" > "$D/check.log" 2>&1; then
    ok "--check passes"
  else
    bad "--check failed"; sed 's/^/  | /' "$D/check.log"
  fi

  if run_bootstrap "$D" "$T1_PROJ" "$D/bootstrap.log"; then
    ok "bootstrap-opensearch.sh ran to the end"
  else
    bad "bootstrap-opensearch.sh failed (tail below)"
    tail -25 "$D/bootstrap.log" | sed 's/^/  | /'
  fi
  expect_code "sentinel-writer authenticates" 200 sentinel-writer "$PLAIN_PW" \
    "https://127.0.0.1:${T1_OS}/_plugins/_security/authinfo"

  teardown_project "$T1_PROJ"
  stage_end
fi

# ==========================================================================
# T2  migration from the demo configuration, on a volume with data in it
# ==========================================================================
if wants T2 || wants T3 || wants T5 || wants T4; then
  stage_begin T2 "migration: demo cluster, switch, --apply-users"
  D="$WORK/t2"; mkdir -p "$D"
  write_env "$D/.env" "$PLAIN_PW" "$PLAIN_PW"
  git show HEAD:compose.yaml > "$D/compose.head.yaml" ||
    die "could not read compose.yaml from HEAD"
  grep -q 'DISABLE_INSTALL_DEMO_CONFIG: "false"' "$D/compose.head.yaml" ||
    die "HEAD's compose.yaml is not the demo-config version; T2 would prove nothing"
  # The old compose has no DASHBOARDS_SERVICE_PASSWORD in it, which is the
  # point: this is the file the collector is running today.
  make_compose "$D/compose.head.yaml" "$D/compose.old.yaml" "$T2_PROJ" "$T2_OS" "$T2_DASH"
  make_compose "$REPO/compose.yaml" "$D/compose.yaml" "$T2_PROJ" "$T2_OS" "$T2_DASH"

  dc "$D" compose.old.yaml "$T2_PROJ" up -d opensearch dashboards > "$D/up-old.log" 2>&1 ||
    { bad "the old compose failed to start"; sed 's/^/  | /' "$D/up-old.log"; }
  wait_code "demo cluster up" 240 200 admin "$PLAIN_PW" \
    "https://127.0.0.1:${T2_OS}/_cluster/health" || dump_logs "${T2_PROJ}-opensearch"
  expect_code "demo user readall works before" 200 readall readall \
    "https://127.0.0.1:${T2_OS}/_plugins/_security/authinfo"

  # A user created over REST and a document, both of which have to survive.
  creds admin "$PLAIN_PW" | curl -sk -o /dev/null --max-time 20 --config - \
    -X PUT -H 'Content-Type: application/json' \
    -d "{\"password\":\"${PLAIN_PW}\",\"backend_roles\":[]}" \
    "https://127.0.0.1:${T2_OS}/_plugins/_security/api/internalusers/sentinel-writer" || true
  expect_code "sentinel-writer created" 200 sentinel-writer "$PLAIN_PW" \
    "https://127.0.0.1:${T2_OS}/_plugins/_security/authinfo"
  creds admin "$PLAIN_PW" | curl -sk -o /dev/null --max-time 20 --config - \
    -X PUT -H 'Content-Type: application/json' -d '{"marker":"t2-survives"}' \
    "https://127.0.0.1:${T2_OS}/t2-marker/_doc/1?refresh=true" || true
  [[ "$(body admin "$PLAIN_PW" "https://127.0.0.1:${T2_OS}/t2-marker/_doc/1")" == *t2-survives* ]] &&
    ok "document indexed" || bad "could not index the document"

  # T5 needs the demo certificate, and the only place it exists is inside
  # this container: the image does not ship it, the demo installer makes it
  # at first start.
  if MSYS_NO_PATHCONV=1 podman cp "${T2_PROJ}-opensearch:/usr/share/opensearch/config/kirk.pem" "$(hostpath "$D/kirk.pem")" 2>/dev/null &&
     MSYS_NO_PATHCONV=1 podman cp "${T2_PROJ}-opensearch:/usr/share/opensearch/config/kirk-key.pem" "$(hostpath "$D/kirk-key.pem")" 2>/dev/null; then
    ok "kept a copy of the demo kirk certificate for T5"
    # The positive control for T5. On this demo cluster kirk IS the
    # super-admin, so the same probe must come back 200 here. Without this,
    # a probe that cannot load the certificate at all would refuse in T5 for
    # its own reasons and be scored as the hole being closed.
    got="$(kirk_probe "${T2_PROJ}-opensearch" "$D")" || rc=$?
    if [[ "${got:-}" == 200 ]]; then
      KIRK_OK=1
      ok "kirk is super-admin on the demo cluster (200), so the T5 probe works"
    else
      say "  note  the kirk probe does not work even on the demo cluster (HTTP '${got:-}', curl exit ${rc:-0}); T5 will skip"
    fi
    unset rc
  else
    say "  note  could not copy kirk.pem out of the container; T5 will skip"
  fi

  dc "$D" compose.old.yaml "$T2_PROJ" stop opensearch dashboards > /dev/null 2>&1 || true

  if "$REPO/harden-opensearch.sh" --render --dir "$D/opensearch-config" \
       --env "$D/.env" > "$D/render.log" 2>&1; then
    ok "--render"
  else
    bad "--render failed"; sed 's/^/  | /' "$D/render.log"
  fi

  if dc "$D" compose.yaml "$T2_PROJ" up -d --force-recreate opensearch dashboards \
       > "$D/up-new.log" 2>&1; then
    ok "compose up on the new configuration, same volume"
  else
    bad "the new compose failed to start"; sed 's/^/  | /' "$D/up-new.log"
  fi

  if wait_code "admin still logs in" 240 200 admin "$PLAIN_PW" \
       "https://127.0.0.1:${T2_OS}/_cluster/health"; then
    T2_READY=1
  else
    dump_logs "${T2_PROJ}-opensearch"
  fi
  [[ "$(body admin "$PLAIN_PW" "https://127.0.0.1:${T2_OS}/t2-marker/_doc/1")" == *t2-survives* ]] &&
    ok "the document is still there" || bad "the document did not survive the switch"
  expect_code "sentinel-writer still authenticates" 200 sentinel-writer "$PLAIN_PW" \
    "https://127.0.0.1:${T2_OS}/_plugins/_security/authinfo"
  # Expected to still work: the security index came from the old cluster and
  # a mounted internal_users.yml does not touch an index that already exists.
  # This is the whole reason --apply-users has to exist.
  expect_code "demo users still work before --apply-users" 200 readall readall \
    "https://127.0.0.1:${T2_OS}/_plugins/_security/authinfo"

  if "$REPO/harden-opensearch.sh" --apply-users --env "$D/.env" \
       --container "${T2_PROJ}-opensearch" > "$D/apply.log" 2>&1; then
    ok "--apply-users"
  else
    bad "--apply-users failed"; sed 's/^/  | /' "$D/apply.log"
  fi

  # Dashboards is holding a session on the old kibanaserver password.
  dc "$D" compose.yaml "$T2_PROJ" restart dashboards > /dev/null 2>&1 || true
  wait_code "dashboards back after the password change" 180 200 admin "$PLAIN_PW" \
    "http://127.0.0.1:${T2_DASH}/api/status" || dump_logs "${T2_PROJ}-dashboards"

  if "$REPO/harden-opensearch.sh" --check --env "$D/.env" \
       --url "https://127.0.0.1:${T2_OS}" --dash-url "http://127.0.0.1:${T2_DASH}" \
       --container "${T2_PROJ}-opensearch" > "$D/check.log" 2>&1; then
    ok "--check passes"
  else
    bad "--check failed"; sed 's/^/  | /' "$D/check.log"
  fi
  expect_code "sentinel-writer survived --apply-users" 200 sentinel-writer "$PLAIN_PW" \
    "https://127.0.0.1:${T2_OS}/_plugins/_security/authinfo"
  stage_end
fi

# ==========================================================================
# T5  the demo super-admin certificate is no longer trusted
# ==========================================================================
if wants T5; then
  stage_begin T5 "the image's kirk certificate is rejected"
  D="$WORK/t2"
  if ((T2_READY == 0)); then
    say "  skip  T2 did not leave a cluster running"
  elif ((KIRK_OK == 0)); then
    say "  skip  the demo certificate was not usable in T2, so a refusal here would prove nothing"
  else
    # No password: anything that is not a refusal means the demo super-admin
    # certificate still works, which is the hole this package closes. The
    # security API, not authinfo -- super-admin is exactly the privilege that
    # certificate used to carry.
    #
    # Exactly the probe that answered 200 on this cluster before it was
    # hardened (T2 checks that), so a refusal here is the cluster's doing.
    #
    # Two shapes of refusal count, and curl's exit code is what tells them
    # apart from "nothing was listening". The node may reject the certificate
    # during the handshake, because our CA did not sign it (curl 35/56/58,
    # no HTTP status at all), or accept the connection and refuse the
    # request (401/403). The first is the stronger of the two.
    got="$(kirk_probe "${T2_PROJ}-opensearch" "$D" 2>/dev/null)" || rc=$?
    rc="${rc:-0}"
    case "${got}:${rc}" in
      401:*|403:*) ok "kirk rejected by the cluster (HTTP ${got})" ;;
      *:35|*:56|*:58|*:60|*:77)
        ok "kirk rejected in the TLS handshake (curl exit ${rc}), no HTTP request reached the node" ;;
      200:*) bad "kirk was ACCEPTED on the security API: the demo super-admin still works" ;;
      *)     bad "kirk: HTTP '${got}', curl exit ${rc} -- neither a refusal nor a success, cannot tell" ;;
    esac
    unset rc
  fi
  stage_end
fi

# ==========================================================================
# T4  idempotence
# ==========================================================================
if wants T4; then
  stage_begin T4 "idempotence"
  D="$WORK/t4"; mkdir -p "$D"
  write_env "$D/.env" "$PLAIN_PW" "$PLAIN_PW"

  "$REPO/harden-opensearch.sh" --render --dir "$D/cfg" --env "$D/.env" \
    > "$D/render1.log" 2>&1 || bad "the first --render failed"
  # sha256sum cannot read the files once --render has handed them to the
  # container's uid, which is what happens on a Linux host; the same
  # namespace that changed them can read them back.
  hashes() {
    sha256sum "$1"/* 2> /dev/null ||
      podman unshare sha256sum "$1"/* 2> /dev/null ||
      die "could not hash the rendered files"
  }
  before="$(hashes "$D/cfg" | sort)"
  "$REPO/harden-opensearch.sh" --render --dir "$D/cfg" --env "$D/.env" \
    > "$D/render2.log" 2>&1 || bad "the second --render failed"
  after="$(hashes "$D/cfg" | sort)"
  if [[ "$before" == "$after" ]]; then
    ok "--render twice: every file byte-identical ($(wc -l <<< "$before") files)"
  else
    bad "--render twice changed something:"
    diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") | sed 's/^/  | /' || true
  fi

  if ((T2_READY == 1)); then
    if "$REPO/harden-opensearch.sh" --apply-users --env "$WORK/t2/.env" \
         --container "${T2_PROJ}-opensearch" > "$D/apply2.log" 2>&1; then
      ok "--apply-users a second time exits 0"
    else
      bad "--apply-users is not idempotent"; sed 's/^/  | /' "$D/apply2.log"
    fi
    expect_code "admin still logs in afterwards" 200 admin "$PLAIN_PW" \
      "https://127.0.0.1:${T2_OS}/_cluster/health"
  else
    say "  skip  no T2 cluster for the --apply-users half"
  fi
  stage_end
fi

# ==========================================================================
# T3  rollback
# ==========================================================================
if wants T3; then
  stage_begin T3 "rollback: the old compose on the same volume"
  D="$WORK/t2"
  if [[ ! -f "$D/compose.old.yaml" ]]; then
    say "  skip  T2 did not run"
  else
    dc "$D" compose.yaml "$T2_PROJ" stop opensearch dashboards > /dev/null 2>&1 || true
    if dc "$D" compose.old.yaml "$T2_PROJ" up -d --force-recreate opensearch \
         > "$D/up-rollback.log" 2>&1; then
      ok "the old compose starts again"
    else
      bad "the old compose would not start"; sed 's/^/  | /' "$D/up-rollback.log"
    fi
    wait_code "admin logs in after rollback" 240 200 admin "$PLAIN_PW" \
      "https://127.0.0.1:${T2_OS}/_cluster/health" || dump_logs "${T2_PROJ}-opensearch"
    [[ "$(body admin "$PLAIN_PW" "https://127.0.0.1:${T2_OS}/t2-marker/_doc/1")" == *t2-survives* ]] &&
      ok "the document is still there" || bad "the document did not survive the rollback"
  fi
  teardown_project "$T2_PROJ"
  stage_end
fi

# ==========================================================================
# T6  a password with a space, a quote and a backslash
# ==========================================================================
if wants T6; then
  stage_begin T6 "awkward password end to end"
  D="$WORK/t6"; mkdir -p "$D"
  # Only the Dashboards password. The admin one is also pasted into the
  # compose healthcheck's `curl -u "admin:$PW"` shell string, where a space
  # or a quote breaks the quoting and the node never reports healthy -- a
  # property of a healthcheck this package is told not to change.
  write_env "$D/.env" "$PLAIN_PW" "$NASTY_PW"
  make_compose "$REPO/compose.yaml" "$D/compose.yaml" "$T6_PROJ" "$T6_OS" "$T6_DASH"

  if "$REPO/harden-opensearch.sh" --render --dir "$D/opensearch-config" \
       --env "$D/.env" > "$D/render.log" 2>&1; then
    ok "--render with an awkward password"
  else
    bad "--render failed"; sed 's/^/  | /' "$D/render.log"
  fi
  dc "$D" compose.yaml "$T6_PROJ" up -d opensearch dashboards > "$D/up.log" 2>&1 ||
    { bad "compose up failed"; sed 's/^/  | /' "$D/up.log"; }

  wait_code "cluster up" 240 200 admin "$PLAIN_PW" \
    "https://127.0.0.1:${T6_OS}/_cluster/health" || dump_logs "${T6_PROJ}-opensearch"
  # The assertion that matters: this cluster's security index was built from
  # the hash hash.sh made, and Dashboards will not answer until it has
  # logged in as kibanaserver. A 200 means the awkward password survived
  # .env, the environment, the hashing container, the rendered YAML and
  # compose's own interpolation without losing a character.
  wait_code "dashboards logs in as kibanaserver with it" 240 200 admin "$PLAIN_PW" \
    "http://127.0.0.1:${T6_DASH}/api/status" || dump_logs "${T6_PROJ}-dashboards"
  expect_code "and the awkward password is what it is" 200 kibanaserver "$NASTY_PW" \
    "https://127.0.0.1:${T6_OS}/_plugins/_security/authinfo"

  # And again through the JSON body --apply-users sends.
  if "$REPO/harden-opensearch.sh" --apply-users --env "$D/.env" \
       --container "${T6_PROJ}-opensearch" > "$D/apply.log" 2>&1; then
    ok "--apply-users with an awkward password"
  else
    bad "--apply-users failed"; sed 's/^/  | /' "$D/apply.log"
  fi
  dc "$D" compose.yaml "$T6_PROJ" restart dashboards > /dev/null 2>&1 || true
  wait_code "dashboards still logs in after the REST password set" 180 200 admin "$PLAIN_PW" \
    "http://127.0.0.1:${T6_DASH}/api/status" || dump_logs "${T6_PROJ}-dashboards"

  teardown_project "$T6_PROJ"
  stage_end
fi

# ==========================================================================
printf '\n===== results =====\n'
printf '%s\n' "${RESULTS[@]}"
if [[ -s "$WORK/compose-retries.log" ]]; then
  printf '\nengine hiccups (a retry succeeded, not a test result):\n'
  sed 's/^/  /' "$WORK/compose-retries.log"
fi
if ((FAILURES == 0)); then
  printf '\nall stages passed\n'
else
  printf '\n%d stage(s) failed\n' "$FAILURES"
fi
exit $((FAILURES > 0))
