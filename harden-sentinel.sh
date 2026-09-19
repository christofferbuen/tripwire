#!/usr/bin/env bash
# Harden the sentinel VM and decide what an owner of it can do next.
#
# The sentinel is the one host in this project that is meant to be reached,
# and the one that should be assumed compromised eventually. The valuable
# question is therefore not "how do we keep them out" but "what can they do
# from in here": scan the neighbours, brute-force somebody's sshd, send mail,
# pull a second stage. The answer this script installs is: nothing outbound,
# and loudly. Every refusal is logged with the destination and the owning
# uid, and `egress-watch.py` turns those log lines into events the existing
# Vector already ships.
#
# THIS SCRIPT CAN LOCK YOU OUT OF A REMOTE MACHINE. The sequence in --apply
# is the point of the file, not decoration:
#
#   1. render everything to a temp directory and gate it: `nft -c -f` and
#      `sshd -t`. A syntax error stops here, with nothing touched.
#   2. snapshot the live ruleset and every file about to be replaced.
#   3. arm a rollback timer -- BEFORE the new ruleset is loaded, because the
#      ruleset is the thing that can cut the session that would disarm it.
#   4. only then install, load, and reload.
#   5. tell the operator, in one sentence, to open a second session and what
#      happens if they do nothing.
#
# Nothing survives a reboot until --confirm. Until then the cloud console and
# a power cycle are a second way back in. --rollback is always available, by
# hand or from the timer.
#
# Nothing here changes how the VM answers a probe on its persona ports. No
# sysctl touches TCP timestamps, window scaling, TTL or ICMP echo; the ICMP
# rules accept what the stack answers today. An OS-detection scan must read
# the same before and after, or the deception is worse off than it started.
#
# Two consequences only the VM itself can show you, both deliberate:
#
#   - aardvark-dns and pasta run as the podman user, so a container
#     resolving a NAME is a container uid sending to port 53, and is dropped
#     and logged like any other attempt. vector-sentinel.toml reaches the
#     collector by address, which is why this stays quiet; put a hostname in
#     it and every lookup becomes an egress event.
#   - an administrator whose uid is >= 1000 and who is not the podman user
#     falls into the catch-all: their own curl, git or apt is dropped and
#     logged as tripwire-egress-other. That is the intent -- this is a
#     sensor, not a workstation -- but it is worth knowing before the first
#     "why is my curl hanging".
#
# Site values live in /etc/tripwire/harden.env (root, 0600), never here:
#
#   ADMIN_PORT           port the real sshd already listens on; never changed
#   ADMIN_SOURCES        CIDRs allowed to reach it, comma separated. Also:
#                        `any` for no source restriction (warned about), and
#                        empty for no public admin rule at all -- then the
#                        only way in on that port is the break-glass rule
#                        over the tunnel, plus the cloud console
#   ADMIN_USERS          value for sshd AllowUsers
#   SSHD_HARDEN          yes (default) or no. `no` installs no sshd drop-in
#                        at all, so the firewall half can be applied on its
#                        own. Everything else is unaffected
#   PUBLIC_PORTS         persona ports, default 22,25,80
#   COLLECTOR_ENDPOINT   public address of the WireGuard peer
#   COLLECTOR_WG         the collector's address inside the tunnel
#   WG_IFACE             default wg0
#   WG_LISTEN_PORT       empty when the VM always initiates; then no inbound
#                        WireGuard rule exists at all
#   PODMAN_UID           uid of the rootless podman user
#   SUBUID_RANGE         that user's subordinate range, as first-last
#   REBOOT_TIME          unattended-upgrades reboot time, default 04:40
#   ROLLBACK_SECONDS     default 180
#   FAKEVM_UID, FAKEVM_SUBUID_RANGE, FAKEVM_PORT, LLM_HOST
#                        all empty until the fake VM exists. Support is here
#                        now so that work never has to edit this script
#
#   ./harden-sentinel.sh --render DIR [--env FILE]   no root, touches nothing
#   ./harden-sentinel.sh --selftest                  the render tests
#   sudo ./harden-sentinel.sh --apply
#   sudo /usr/local/sbin/harden-sentinel.sh --confirm
#   sudo /usr/local/sbin/harden-sentinel.sh --rollback
#   sudo /usr/local/sbin/harden-sentinel.sh --check
#   sudo /usr/local/sbin/harden-sentinel.sh --build-window 10
#   sudo /usr/local/sbin/harden-sentinel.sh --refresh-llm-set
set -euo pipefail

# --- knobs ---------------------------------------------------------------
ENV_FILE=/etc/tripwire/harden.env
STATE_DIR=/var/lib/tripwire-harden
SBIN_DIR=/usr/local/sbin
NFT_FILE=/etc/nftables.d/tripwire.nft
NFT_MAIN=/etc/nftables.conf
SSHD_CONF=/etc/ssh/sshd_config.d/10-tripwire.conf
SYSCTL_CONF=/etc/sysctl.d/60-tripwire.conf
APT_CONF=/etc/apt/apt.conf.d/52-tripwire-reboot
EGRESS_UNIT=/etc/systemd/system/tripwire-egress-watch.service
LLM_SERVICE=/etc/systemd/system/tripwire-llm-set.service
LLM_TIMER=/etc/systemd/system/tripwire-llm-set.timer
EGRESS_DIR=/var/log/tripwire-egress
WG_DIR=/etc/wireguard
ROLLBACK_UNIT=tripwire-harden-rollback
WINDOW_UNIT=tripwire-build-window
LOG_RATE="30/minute"        # kernel log lines per prefix, per minute
LLM_TIMEOUT="1h"            # how long an address stays in the llm4 set
LLM_REFRESH="10min"         # how often the set is refreshed
SHIP_PORT=9200              # OpenSearch, inside the tunnel
MASK_UNITS=(multipathd.service multipathd.socket atd.service)

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
SRC_DIR="$(dirname "$SELF")"

# --- helpers -------------------------------------------------------------
say()  { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'harden-sentinel: %s\n' "$*" >&2; exit 1; }

need_root() { [[ "$(id -u)" -eq 0 ]] || die "$1 needs root"; }

join() {
  local sep="$1" out=""
  shift
  local item
  for item in "$@"; do out+="${out:+$sep}$item"; done
  printf '%s' "$out"
}

# --- the env file --------------------------------------------------------
# Keys that must be set to something, keys that must exist but may be empty,
# and keys with a default. A typo in the first group is a missing rule; a
# typo in the second is a rule that silently matches nothing, which is why
# the file has to declare them either way.
REQUIRED=(ADMIN_PORT ADMIN_USERS COLLECTOR_ENDPOINT COLLECTOR_WG
          PODMAN_UID SUBUID_RANGE)
DECLARED=(ADMIN_SOURCES WG_LISTEN_PORT FAKEVM_UID FAKEVM_SUBUID_RANGE
          FAKEVM_PORT LLM_HOST)

load_env() {
  [[ -r "$ENV_FILE" ]] || die "no readable env file at $ENV_FILE (see the header)"
  # shellcheck disable=SC1090
  set -a; source "$ENV_FILE"; set +a

  local key missing=()
  for key in "${REQUIRED[@]}"; do
    [[ -n "${!key:-}" ]] || missing+=("$key")
  done
  for key in "${DECLARED[@]}"; do
    [[ -v "$key" ]] || missing+=("$key")
  done
  ((${#missing[@]} == 0)) || die "$ENV_FILE is missing: $(join ', ' "${missing[@]}")"

  PUBLIC_PORTS="${PUBLIC_PORTS:-22,25,80}"
  WG_IFACE="${WG_IFACE:-wg0}"
  REBOOT_TIME="${REBOOT_TIME:-04:40}"
  ROLLBACK_SECONDS="${ROLLBACK_SECONDS:-180}"
  SSHD_HARDEN="${SSHD_HARDEN:-yes}"
  validate
  derive
}

want() { # want VALUE REGEX NAME
  [[ "$1" =~ $2 ]] || die "$3 is not usable as given: $(printf '%q' "$1")"
}

validate() {
  want "$ADMIN_PORT"    '^[0-9]{1,5}$'            ADMIN_PORT
  want "$PUBLIC_PORTS"  '^[0-9]+(,[0-9]+)*$'      PUBLIC_PORTS
  want "$ADMIN_USERS"   '^[A-Za-z0-9_@.-]+( [A-Za-z0-9_@.-]+)*$' ADMIN_USERS
  want "$SSHD_HARDEN"   '^(yes|no)$'              SSHD_HARDEN
  want "$COLLECTOR_ENDPOINT" '^[0-9a-fA-F:.]+$'   COLLECTOR_ENDPOINT
  want "$COLLECTOR_WG"  '^[0-9a-fA-F:.]+$'        COLLECTOR_WG
  want "$WG_IFACE"      '^[A-Za-z0-9_.-]+$'       WG_IFACE
  want "$PODMAN_UID"    '^[0-9]+$'                PODMAN_UID
  want "$SUBUID_RANGE"  '^[0-9]+-[0-9]+$'         SUBUID_RANGE
  want "$REBOOT_TIME"   '^[0-9]{2}:[0-9]{2}$'     REBOOT_TIME
  want "$ROLLBACK_SECONDS" '^[0-9]+$'             ROLLBACK_SECONDS
  want "$WG_LISTEN_PORT" '^([0-9]{1,5})?$'        WG_LISTEN_PORT
  want "$FAKEVM_UID"    '^([0-9]+)?$'             FAKEVM_UID
  want "$FAKEVM_SUBUID_RANGE" '^([0-9]+-[0-9]+)?$' FAKEVM_SUBUID_RANGE
  want "$FAKEVM_PORT"   '^([0-9]{1,5})?$'         FAKEVM_PORT
  want "$LLM_HOST"      '^([A-Za-z0-9._-]+)?$'    LLM_HOST
  ((ROLLBACK_SECONDS >= 30)) || die "ROLLBACK_SECONDS below 30 is not enough time to test a session"
  if [[ -n "$FAKEVM_UID" ]]; then
    [[ -n "$FAKEVM_SUBUID_RANGE" && -n "$FAKEVM_PORT" && -n "$LLM_HOST" ]] ||
      die "FAKEVM_UID is set, so FAKEVM_SUBUID_RANGE, FAKEVM_PORT and LLM_HOST must be too"
  fi
}

derive() {
  ADMIN4=(); ADMIN6=()
  ADMIN_MODE=sources
  if [[ -z "$ADMIN_SOURCES" ]]; then
    ADMIN_MODE=none
  elif [[ "$ADMIN_SOURCES" == "any" ]]; then
    ADMIN_MODE=any
  else
    local items=() item
    IFS=',' read -r -a items <<< "$ADMIN_SOURCES"
    for item in "${items[@]}"; do
      item="${item//[[:space:]]/}"
      [[ -n "$item" ]] || continue
      [[ "$item" =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]] ||
        die "ADMIN_SOURCES entry is not an address or CIDR: $(printf '%q' "$item")"
      if [[ "$item" == *:* ]]; then ADMIN6+=("$item"); else ADMIN4+=("$item"); fi
    done
    ((${#ADMIN4[@]} + ${#ADMIN6[@]} > 0)) || ADMIN_MODE=none
  fi

  # The tunnel is v4 in this deployment, but the table is `inet` and there is
  # no reason to assume it: pick the keyword from the value.
  if [[ "$COLLECTOR_WG" == *:* ]]; then WG_FAM=ip6; WG_BITS=128; else WG_FAM=ip; WG_BITS=32; fi
  if [[ "$COLLECTOR_ENDPOINT" == *:* ]]; then EP_FAM=ip6; else EP_FAM=ip; fi

  # The env names OUR listen port, which is the source port of everything
  # wg sends. The peer's port, which would be the destination, has no key,
  # so the outbound rule is narrowed on the half that is actually known.
  if [[ -n "$WG_LISTEN_PORT" ]]; then
    WG_SPORT=" udp sport ${WG_LISTEN_PORT}"
  else
    WG_SPORT=" meta l4proto udp"
  fi

  SKUIDS="$PODMAN_UID, $SUBUID_RANGE"
  FAKE_SKUIDS=""
  if [[ -n "$FAKEVM_UID" ]]; then
    SKUIDS="$SKUIDS, $FAKEVM_UID, $FAKEVM_SUBUID_RANGE"
    FAKE_SKUIDS="$FAKEVM_UID, $FAKEVM_SUBUID_RANGE"
  fi

  case "$ADMIN_MODE" in
    none) warn "ADMIN_SOURCES is empty: no public rule for the admin port is rendered.
         The only route to it is ${WG_IFACE} from ${COLLECTOR_WG}, plus the cloud
         console. Prove that path works before --confirm." ;;
    any)  warn "ADMIN_SOURCES=any: the admin port is open to the whole internet.
         sshd will be found and hammered. This is the weaker of the two answers." ;;
  esac
  [[ "$SSHD_HARDEN" == yes ]] ||
    say "sshd hardening is off (SSHD_HARDEN=no): no drop-in is rendered, installed or checked."
}

# Everything this script owns. NFT_FILE is rendered and loaded at --apply but
# only written to this path by --confirm, which is what "nothing survives a
# reboot until you confirm" means in practice.
managed_paths() {
  printf '%s\n' "$NFT_FILE" "$SYSCTL_CONF" "$APT_CONF" "$EGRESS_UNIT"
  [[ "$SSHD_HARDEN" == yes ]] && printf '%s\n' "$SSHD_CONF"
  if [[ -n "$FAKEVM_UID" ]]; then printf '%s\n' "$LLM_SERVICE" "$LLM_TIMER"; fi
  return 0
}

# Also snapshotted, because --confirm and --apply edit them in place.
snapshot_paths() {
  managed_paths
  printf '%s\n' "$NFT_MAIN" "${WG_DIR}/${WG_IFACE}.conf"
}

# --- rendering -----------------------------------------------------------
render_nft() {
  local out="$1"
  mkdir -p "$(dirname "$out")"
  cat > "$out" <<'NFT'
#!/usr/sbin/nft -f
# tripwire: the sentinel VM's own table. Rendered by harden-sentinel.sh from
# /etc/tripwire/harden.env. Edit the env file and re-run; never this file.
#
# Replaced as one transaction. `add` then `delete` makes the delete safe on a
# host that has never seen this table, and `flush ruleset` is never used: the
# distribution's own tables are not ours to take out.

add table inet tripwire
delete table inet tripwire

table inet tripwire {
NFT

  if ((${#ADMIN4[@]})); then
    {
      printf '  set admin4 {\n'
      printf '    type ipv4_addr\n    flags interval\n'
      printf '    elements = { %s }\n  }\n\n' "$(join ', ' "${ADMIN4[@]}")"
    } >> "$out"
  fi
  if ((${#ADMIN6[@]})); then
    {
      printf '  set admin6 {\n'
      printf '    type ipv6_addr\n    flags interval\n'
      printf '    elements = { %s }\n  }\n\n' "$(join ', ' "${ADMIN6[@]}")"
    } >> "$out"
  fi
  if [[ -n "$FAKEVM_UID" ]]; then
    cat >> "$out" <<NFT
  # Filled by --refresh-llm-set every ${LLM_REFRESH}; elements expire after
  # ${LLM_TIMEOUT}. If resolution stops working the set drains and the fake VM's
  # model goes quiet, which is the failure mode to want.
  set llm4 {
    type ipv4_addr
    flags timeout
    timeout ${LLM_TIMEOUT}
  }

  # The resolver from /etc/resolv.conf, filled at --apply. A named set
  # rather than a rendered literal so that rendering stays a pure function
  # of the env file and can be diffed between two machines.
  set resolver4 {
    type ipv4_addr
  }

NFT
  fi

  cat >> "$out" <<NFT
  chain input {
    type filter hook input priority filter; policy drop;

    ct state established,related accept
    ct state invalid drop
    iif lo accept

    # Exactly what the stack answers today, echo included and with no new
    # rate limit: an OS fingerprint of this host has to read the same after
    # hardening as before it, or the persona is worse off.
    meta l4proto icmp accept
    icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, echo-reply, mld-listener-query, mld-listener-report, mld-listener-done, mld2-listener-report, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept

    # The persona. The only ports the internet is meant to find.
    tcp dport { ${PUBLIC_PORTS//,/, } } accept
NFT

  [[ -n "$FAKEVM_PORT" ]] &&
    printf '    tcp dport %s accept\n' "$FAKEVM_PORT" >> "$out"

  case "$ADMIN_MODE" in
    sources)
      printf '\n    # Administrative sshd. Source-restricted: what works against a\n' >> "$out"
      printf '    # mandatory version banner is the packet not arriving.\n' >> "$out"
      ((${#ADMIN4[@]})) && printf '    ip saddr @admin4 tcp dport %s accept\n' "$ADMIN_PORT" >> "$out"
      ((${#ADMIN6[@]})) && printf '    ip6 saddr @admin6 tcp dport %s accept\n' "$ADMIN_PORT" >> "$out"
      ;;
    any)
      printf '\n    # ADMIN_SOURCES=any: no source restriction on the admin port.\n' >> "$out"
      printf '    tcp dport %s accept\n' "$ADMIN_PORT" >> "$out"
      ;;
    none)
      printf '\n    # ADMIN_SOURCES is empty: no public rule for the admin port.\n' >> "$out"
      ;;
  esac

  cat >> "$out" <<NFT

    # Break-glass, for the day the operator's own address changes. The
    # tunnel is already paid for; this costs one rule.
    iifname "${WG_IFACE}" ${WG_FAM} saddr ${COLLECTOR_WG} tcp dport ${ADMIN_PORT} accept
NFT

  [[ -n "$WG_LISTEN_PORT" ]] && cat >> "$out" <<NFT

    # Inbound WireGuard, only because WG_LISTEN_PORT is set. When the VM
    # always initiates there is no listener to reach and no rule here.
    ${EP_FAM} saddr ${COLLECTOR_ENDPOINT} udp dport ${WG_LISTEN_PORT} accept
NFT

  cat >> "$out" <<NFT
  }

  # Opened for a few minutes by --build-window so the podman user can pull an
  # image, flushed by a timer afterwards. Empty the rest of the time.
  chain egress_window {
  }

  chain output {
    type filter hook output priority filter; policy drop;

    # Replies on the persona ports are established traffic: the sentinel
    # itself is untouched by any of this.
    ct state established,related accept
    oif lo accept

    # Vector shipping to the collector, inside the tunnel. Rootless podman
    # moves container traffic through the user's own network helper, so it
    # arrives here carrying the podman user's uid.
    meta skuid ${PODMAN_UID} oifname "${WG_IFACE}" ${WG_FAM} daddr ${COLLECTOR_WG} tcp dport ${SHIP_PORT} accept

    jump egress_window
NFT

  if [[ -n "$FAKEVM_UID" ]]; then
    cat >> "$out" <<NFT

    # The fake VM reaches one model provider and nothing else. Both the uid
    # and its subordinate range, because which of the two owns the socket
    # depends on the container's network mode.
    #
    # Be honest about what this buys: the provider sits behind a CDN, so the
    # rule narrows "the internet" to "that CDN's edge on 443". It stops
    # scanning, SSH, mail and arbitrary hosts. It does not stop a request to
    # another site on the same CDN.
    meta skuid { ${FAKE_SKUIDS} } ip daddr @llm4 tcp dport 443 accept
    meta skuid { ${FAKE_SKUIDS} } ip daddr @resolver4 udp dport 53 accept
    meta skuid { ${FAKE_SKUIDS} } ip daddr @resolver4 tcp dport 53 accept
NFT
  fi

  cat >> "$out" <<NFT

    # Anything else from a container uid is something on this machine trying
    # to get out. Log a bounded number of them and drop every one: the drop
    # is a rule of its own, never behind the rate limit.
    meta skuid { ${SKUIDS} } ct state new limit rate ${LOG_RATE} log prefix "tripwire-egress " flags skuid
    meta skuid { ${SKUIDS} } counter drop

    # The tunnel, deliberately BELOW the container rules. WireGuard
    # encapsulation is built in the kernel and carries no socket owner, so
    # it never matched them and arrives here regardless; a container uid,
    # on the other hand, was already dropped above and so cannot use the
    # collector's public address as a way out on an arbitrary UDP port.
    ${EP_FAM} daddr ${COLLECTOR_ENDPOINT}${WG_SPORT} accept

    # System services: resolver, time, apt, certificate renewal later.
    meta skuid 0-999 udp dport { 53, 123 } accept
    meta skuid 0-999 tcp dport { 53, 80, 443 } accept

    meta l4proto icmp accept
    meta l4proto icmpv6 accept

    # ct state new, like the container rule above: an expired conntrack
    # entry turns a late FIN or RST for a persona connection into an
    # invalid packet with no socket owner, and logging those would report
    # the scanner's own address as something this VM tried to reach.
    ct state new limit rate ${LOG_RATE} log prefix "tripwire-egress-other " flags skuid
    counter drop
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
  }
}
NFT
}

render_sshd() {
  local out="$1"
  mkdir -p "$(dirname "$out")"
  cat > "$out" <<CONF
# tripwire: administrative sshd. Rendered by harden-sentinel.sh.
#
# sshd takes the FIRST value it sees for a keyword, so this file sorts ahead
# of cloud-init's drop-in and wins. Port and listen addresses are deliberately
# absent: moving the admin port is the operator's decision and this script
# never makes it for them.
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 3
LoginGraceTime 30
AllowUsers ${ADMIN_USERS}
CONF
}

render_sysctl() {
  local out="$1"
  mkdir -p "$(dirname "$out")"
  cat > "$out" <<'CONF'
# tripwire: kernel settings for the sentinel VM. Rendered by
# harden-sentinel.sh.
#
# Every key here is invisible from outside. Nothing that changes how the
# stack answers a probe -- no timestamps, no window scaling, no TTL, no ICMP
# echo or rate-limit keys -- because an OS-detection scan of the persona
# ports has to read the same before and after.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
CONF
}

render_apt() {
  local out="$1"
  mkdir -p "$(dirname "$out")"
  cat > "$out" <<CONF
// tripwire: let unattended-upgrades finish the job. Rendered by
// harden-sentinel.sh. A kernel or openssl update that needs a reboot and
// never gets one leaves the VM patched on disk and vulnerable in memory.
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "${REBOOT_TIME}";
CONF
}

render_egress_unit() {
  local out="$1"
  mkdir -p "$(dirname "$out")"
  cat > "$out" <<CONF
[Unit]
Description=tripwire: report outbound connections the firewall refused
Documentation=file://${SBIN_DIR}/egress-watch.py
After=nftables.service systemd-journald.service

[Service]
# Root, and not DynamicUser: it has to read the kernel journal, and the
# directory it writes has to stay world-readable for the rootless Vector
# that tails it from a container.
Type=simple
ExecStart=${SBIN_DIR}/egress-watch.py --out ${EGRESS_DIR}/egress.jsonl
Restart=always
RestartSec=5
LogsDirectory=$(basename "$EGRESS_DIR")
LogsDirectoryMode=0755
ReadWritePaths=${EGRESS_DIR}
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateNetwork=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectKernelTunables=yes
ProtectControlGroups=yes
MemoryMax=128M

[Install]
WantedBy=multi-user.target
CONF
}

render_llm_service() {
  local out="$1"
  mkdir -p "$(dirname "$out")"
  cat > "$out" <<CONF
[Unit]
Description=tripwire: refresh the addresses the fake VM's model may be reached at
After=network-online.target nftables.service

[Service]
Type=oneshot
ExecStart=${SBIN_DIR}/harden-sentinel.sh --refresh-llm-set
CONF
}

render_llm_timer() {
  local out="$1"
  mkdir -p "$(dirname "$out")"
  cat > "$out" <<CONF
[Unit]
Description=tripwire: refresh the model address set every ${LLM_REFRESH}

[Timer]
OnBootSec=2min
OnUnitActiveSec=${LLM_REFRESH}
AccuracySec=30s

[Install]
WantedBy=timers.target
CONF
}

render_all() {
  local root="$1"
  render_nft         "${root}${NFT_FILE}"
  render_sysctl      "${root}${SYSCTL_CONF}"
  render_apt         "${root}${APT_CONF}"
  render_egress_unit "${root}${EGRESS_UNIT}"
  [[ "$SSHD_HARDEN" == yes ]] && render_sshd "${root}${SSHD_CONF}"
  if [[ -n "$FAKEVM_UID" ]]; then
    render_llm_service "${root}${LLM_SERVICE}"
    render_llm_timer   "${root}${LLM_TIMER}"
  fi
  return 0
}

# --- gates ---------------------------------------------------------------
nft_gate() {
  local staged="$1"
  command -v nft > /dev/null || die "nft is not installed; nothing changed"
  nft -c -f "$staged" || die "the ruleset did not pass nft -c; nothing changed"
}

sshd_gate() {
  local staged="$1" bin tmp
  bin="$(command -v sshd || true)"
  [[ -n "$bin" ]] || bin=/usr/sbin/sshd
  if [[ ! -x "$bin" ]]; then
    warn "no sshd binary to test against; skipping the sshd gate"
    return 0
  fi
  if [[ -z "$staged" ]]; then
    "$bin" -t || die "sshd -t rejects the configuration already on this host; fix that first"
    return 0
  fi
  tmp="$(mktemp)"
  # sshd takes the first value it sees, so the staged drop-in ahead of the
  # running configuration tests exactly the state installing it would make.
  cat "$staged" /etc/ssh/sshd_config > "$tmp" 2>/dev/null || cp "$staged" "$tmp"
  chmod 600 "$tmp"
  if ! "$bin" -t -f "$tmp"; then
    rm -f "$tmp"
    die "sshd -t rejected the drop-in; nothing changed"
  fi
  rm -f "$tmp"
}

# --- snapshot and rollback -----------------------------------------------
snapshot() {
  if [[ -f "$STATE_DIR/manifest" && ! -f "$STATE_DIR/confirmed" ]]; then
    warn "an apply is already pending and unconfirmed; keeping the original snapshot"
    return 0
  fi
  rm -rf "$STATE_DIR/files" "$STATE_DIR/manifest" "$STATE_DIR/confirmed"
  mkdir -p "$STATE_DIR/files"
  chmod 700 "$STATE_DIR"
  nft list ruleset > "$STATE_DIR/ruleset.nft" 2>/dev/null || : > "$STATE_DIR/ruleset.nft"
  local path mode
  while read -r path; do
    if [[ -e "$path" ]]; then
      mode="$(stat -c %a "$path")"
      install -D -m 0600 "$path" "${STATE_DIR}/files${path}"
      printf 'PRESENT\t%s\t%s\n' "$mode" "$path" >> "$STATE_DIR/manifest"
    else
      printf 'ABSENT\t0644\t%s\n' "$path" >> "$STATE_DIR/manifest"
    fi
  done < <(snapshot_paths)
  # So --rollback needs nothing but this directory: it has to work on the
  # day the env file is what somebody broke.
  printf 'WG_IFACE=%s\n' "$WG_IFACE" > "$STATE_DIR/context"
}

arm_rollback() {
  systemctl stop "${ROLLBACK_UNIT}.timer" "${ROLLBACK_UNIT}.service" 2>/dev/null || true
  systemctl reset-failed "${ROLLBACK_UNIT}.service" 2>/dev/null || true
  systemd-run --unit="$ROLLBACK_UNIT" --on-active="$ROLLBACK_SECONDS" \
    "${SBIN_DIR}/harden-sentinel.sh" --rollback > /dev/null ||
    die "could not arm the rollback timer; nothing has been loaded"
}

# --- modes ---------------------------------------------------------------
cmd_render() {
  local dir="$1"
  [[ -n "$dir" ]] || die "--render needs a directory"
  load_env
  mkdir -p "$dir"
  render_all "$dir"
  say "Rendered under ${dir}. Nothing outside it was touched."
}

cmd_apply() {
  need_root --apply
  load_env
  local stage
  stage="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$stage'" EXIT
  render_all "$stage"

  nft_gate "${stage}${NFT_FILE}"
  if [[ "$SSHD_HARDEN" == yes ]]; then sshd_gate "${stage}${SSHD_CONF}"; else sshd_gate ""; fi
  say "Gates passed: nft -c and sshd -t both accept what is about to be installed."

  snapshot
  install_scripts          # before the timer: it needs a stable path to call
  arm_rollback
  say "Rollback armed: ${ROLLBACK_SECONDS}s from now, unless --confirm stops it."

  local path
  while read -r path; do
    [[ "$path" == "$NFT_FILE" ]] && continue   # --confirm installs this one
    install -D -m 0644 "${stage}${path}" "$path"
  done < <(managed_paths)
  rm -rf "$STATE_DIR/pending"
  install -D -m 0600 "${stage}${NFT_FILE}" "${STATE_DIR}/pending${NFT_FILE}"

  nft -f "${stage}${NFT_FILE}" || die "nft refused the ruleset after the check passed"
  sysctl --system > /dev/null || warn "sysctl --system reported a problem"
  reload_sshd
  fix_wireguard
  mask_units
  enable_linger
  systemctl daemon-reload
  systemctl enable --now tripwire-egress-watch.service > /dev/null 2>&1 ||
    warn "could not start tripwire-egress-watch.service"
  if [[ -n "$FAKEVM_UID" ]]; then
    systemctl enable --now tripwire-llm-set.timer > /dev/null 2>&1 ||
      warn "could not enable the model address set timer"
    populate_sets
  fi

  cat <<MSG

Applied. Nothing here survives a reboot yet.

  Open a NEW ssh session now. If it works, run
      sudo ${SBIN_DIR}/harden-sentinel.sh --confirm
  If it does not, do nothing: everything reverts in ${ROLLBACK_SECONDS} seconds.
MSG
}

cmd_confirm() {
  need_root --confirm
  systemctl stop "${ROLLBACK_UNIT}.timer" "${ROLLBACK_UNIT}.service" 2>/dev/null || true
  systemctl reset-failed "${ROLLBACK_UNIT}.service" 2>/dev/null || true
  [[ -f "${STATE_DIR}/pending${NFT_FILE}" ]] || die "nothing pending to confirm; run --apply first"
  install -D -m 0644 "${STATE_DIR}/pending${NFT_FILE}" "$NFT_FILE"
  ensure_include
  systemctl enable nftables.service > /dev/null 2>&1 ||
    warn "could not enable nftables.service; the ruleset will not load at boot"
  touch "$STATE_DIR/confirmed"
  say "Confirmed. The rollback timer is cancelled and the ruleset loads at boot."
  say "In doubt later, run: sudo ${SBIN_DIR}/harden-sentinel.sh --check"
}

cmd_rollback() {
  need_root --rollback
  local rc=0
  # Deliberately independent of the env file: the day this is needed may be
  # the day somebody broke it.
  # shellcheck disable=SC1091
  [[ -f "$STATE_DIR/context" ]] && source "$STATE_DIR/context"
  WG_IFACE="${WG_IFACE:-wg0}"

  # The firewall first. It is the thing that cuts sessions.
  if nft list table inet tripwire > /dev/null 2>&1; then
    nft delete table inet tripwire || warn "could not delete table inet tripwire"
    say "Removed table inet tripwire."
  fi
  systemctl disable --now tripwire-llm-set.timer > /dev/null 2>&1 || true
  systemctl disable --now tripwire-egress-watch.service > /dev/null 2>&1 || true

  if [[ -f "$STATE_DIR/manifest" ]]; then
    local state mode path
    while IFS=$'\t' read -r state mode path; do
      [[ -n "${path:-}" ]] || continue
      case "$state" in
        PRESENT) install -D -m "$mode" "${STATE_DIR}/files${path}" "$path" ||
                   warn "could not restore $path" ;;
        ABSENT)  rm -f "$path" || warn "could not remove $path" ;;
      esac
    done < "$STATE_DIR/manifest"
    say "Restored every file in the snapshot."
  else
    warn "no manifest in $STATE_DIR; only the firewall was removed"
  fi

  sysctl --system > /dev/null 2>&1 || true
  systemctl daemon-reload || true
  reload_sshd
  wg syncconf "$WG_IFACE" <(wg-quick strip "$WG_IFACE") > /dev/null 2>&1 || true
  rm -rf "$STATE_DIR/pending"

  # A second --apply on a host that was already confirmed snapshots the
  # ruleset that was in force. Deleting the table and stopping there would
  # leave that host with no egress block until the next reboot, which is the
  # opposite of what a rollback is for. So: if the file was there before
  # this apply, it has just been restored, and it goes back into the kernel.
  if [[ -f "$STATE_DIR/manifest" ]] &&
     awk -F'\t' -v p="$NFT_FILE" '$1 == "PRESENT" && $3 == p { found = 1 }
                                  END { exit !found }' "$STATE_DIR/manifest"; then
    if nft -f "$NFT_FILE"; then
      touch "$STATE_DIR/confirmed"
      say "Reloaded the ruleset that was confirmed before this apply."
    else
      warn "could not load $NFT_FILE: THIS HOST HAS NO FIREWALL. Load it by hand."
      rm -f "$STATE_DIR/confirmed"
      rc=1
    fi
  else
    rm -f "$STATE_DIR/confirmed"
  fi

  say "Rolled back. The snapshot of the previous ruleset is ${STATE_DIR}/ruleset.nft."
  return "$rc"
}

cmd_check() {
  need_root --check
  load_env
  local stage rc=0
  stage="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$stage'" EXIT
  render_all "$stage"

  item() { # item ok|DRIFT text
    printf '%-6s%s\n' "$1" "$2"
    [[ "$1" == ok ]] || rc=1
  }
  verdict() { if "${@:2}"; then item ok "$1"; else item DRIFT "$1"; fi; }

  local path
  while read -r path; do
    if [[ "$path" == "$NFT_FILE" && ! -f "$STATE_DIR/confirmed" ]]; then
      item ok "$path (not persisted yet: --confirm has not been run)"
      continue
    fi
    verdict "$path" cmp -s "${stage}${path}" "$path"
  done < <(managed_paths)

  verdict "table inet tripwire loaded" \
    bash -c "nft list table inet tripwire 2>/dev/null | grep -c 'policy drop' | grep -qx 3"
  verdict "input chain is not empty" \
    bash -c "nft list chain inet tripwire input 2>/dev/null | grep -q 'ct state established'"

  local key want_value
  while read -r key want_value; do
    [[ -n "$key" ]] || continue
    verdict "sysctl $key = $want_value" \
      bash -c "[[ \"\$(sysctl -n '$key' 2>/dev/null)\" == '$want_value' ]]"
  done < <(sed -n 's/^\([a-z0-9._]*\) = \(.*\)$/\1 \2/p' "${stage}${SYSCTL_CONF}")

  if [[ "$SSHD_HARDEN" == yes ]]; then
    local setting
    for setting in "passwordauthentication no" "permitrootlogin prohibit-password" \
                   "maxauthtries 3" "allowtcpforwarding no" "logingracetime 30"; do
      verdict "sshd -T: $setting" \
        bash -c "sshd -T 2>/dev/null | grep -qix '$setting'"
    done
  else
    item ok "sshd hardening off by SSHD_HARDEN=no"
  fi

  local unit
  for unit in "${MASK_UNITS[@]}"; do
    verdict "$unit masked" \
      bash -c "[[ \"\$(systemctl is-enabled '$unit' 2>/dev/null)\" == masked ]]"
  done

  local user
  user="$(getent passwd "$PODMAN_UID" | cut -d: -f1)"
  if [[ -n "$user" ]]; then
    verdict "linger for $user" \
      bash -c "loginctl show-user '$user' --property=Linger 2>/dev/null | grep -qx 'Linger=yes'"
    verdict "podman-restart.service enabled for $user" \
      bash -c "systemctl --user --machine='${user}@.host' is-enabled podman-restart.service 2>/dev/null | grep -qx enabled"
  else
    item DRIFT "no user with uid $PODMAN_UID"
  fi

  verdict "tripwire-egress-watch.service running" \
    bash -c "systemctl is-active tripwire-egress-watch.service 2>/dev/null | grep -qx active"

  if [[ -f "$STATE_DIR/confirmed" ]]; then
    verdict "nftables.service enabled" \
      bash -c "systemctl is-enabled nftables.service 2>/dev/null | grep -qx enabled"
    verdict "$NFT_MAIN includes $NFT_FILE" grep -q "nftables.d" "$NFT_MAIN"
  else
    item ok "not confirmed yet: reverts on reboot, by design"
  fi

  local wgconf="${WG_DIR}/${WG_IFACE}.conf"
  if [[ -f "$wgconf" ]]; then
    verdict "AllowedIPs is ${COLLECTOR_WG}/${WG_BITS}" \
      bash -c "grep -qE '^[[:space:]]*AllowedIPs[[:space:]]*=[[:space:]]*${COLLECTOR_WG}/${WG_BITS}[[:space:]]*\$' '$wgconf'"
  else
    item ok "no $wgconf on this host"
  fi

  if [[ -n "$FAKEVM_UID" ]]; then
    verdict "llm4 set has elements" \
      bash -c "nft list set inet tripwire llm4 2>/dev/null | grep -q 'elements'"
  fi

  exit "$rc"
}

cmd_build_window() {
  local minutes="$1"
  need_root --build-window
  [[ "$minutes" =~ ^[0-9]+$ ]] || die "--build-window takes a number of minutes"
  load_env
  nft list table inet tripwire > /dev/null 2>&1 ||
    die "table inet tripwire is not loaded; run --apply first"
  systemctl stop "${WINDOW_UNIT}.timer" "${WINDOW_UNIT}.service" 2>/dev/null || true
  systemctl reset-failed "${WINDOW_UNIT}.service" 2>/dev/null || true
  nft flush chain inet tripwire egress_window
  # The user, never the subordinate range: the pull runs as the podman user,
  # the containers stay where they are.
  nft add rule inet tripwire egress_window meta skuid "$PODMAN_UID" tcp dport 443 accept
  nft add rule inet tripwire egress_window meta skuid "$PODMAN_UID" udp dport 53 accept
  nft add rule inet tripwire egress_window meta skuid "$PODMAN_UID" tcp dport 53 accept
  systemd-run --unit="$WINDOW_UNIT" --on-active="${minutes}m" \
    "$(command -v nft)" flush chain inet tripwire egress_window > /dev/null ||
    die "could not arm the timer that closes the window; run --build-window again or flush the chain by hand"
  say "Build window open for ${minutes} minutes, for uid ${PODMAN_UID} only."
}

cmd_refresh_llm_set() {
  need_root --refresh-llm-set
  load_env
  [[ -n "$FAKEVM_UID" ]] || die "FAKEVM_UID is empty; there is no set to refresh"
  nft list set inet tripwire llm4 > /dev/null 2>&1 ||
    die "set llm4 does not exist; run --apply first"
  populate_sets
  systemctl is-enabled tripwire-llm-set.timer > /dev/null 2>&1 ||
    systemctl enable --now tripwire-llm-set.timer > /dev/null 2>&1 ||
    warn "could not enable tripwire-llm-set.timer"
}

# --- system actions ------------------------------------------------------
install_scripts() {
  local src dest name
  for name in harden-sentinel.sh egress-watch.py; do
    src="${SRC_DIR}/${name}"
    dest="${SBIN_DIR}/${name}"
    [[ -f "$src" ]] || die "$name is not next to this script; copy both files and retry"
    if [[ "$src" -ef "$dest" ]]; then continue; fi
    # Written beside the target and renamed, never in place: this script may
    # be the one bash is reading from right now.
    install -D -m 0755 "$src" "${dest}.new"
    mv -f "${dest}.new" "$dest"
  done
}

reload_sshd() {
  local unit
  for unit in ssh sshd; do
    if systemctl cat "$unit" > /dev/null 2>&1; then
      systemctl reload "$unit" > /dev/null 2>&1 || warn "could not reload $unit"
      return 0
    fi
  done
  warn "no ssh unit found to reload"
}

fix_wireguard() {
  local conf="${WG_DIR}/${WG_IFACE}.conf"
  [[ -f "$conf" ]] || { warn "no $conf; leaving WireGuard alone"; return 0; }
  if (($(grep -c '^\[Peer\]' "$conf") > 1)); then
    warn "$conf has more than one peer; not touching AllowedIPs"
    return 0
  fi
  sed -i -E "s#^[[:space:]]*AllowedIPs[[:space:]]*=.*#AllowedIPs = ${COLLECTOR_WG}/${WG_BITS}#" "$conf"
  wg syncconf "$WG_IFACE" <(wg-quick strip "$WG_IFACE") > /dev/null 2>&1 ||
    warn "wg syncconf failed; is ${WG_IFACE} up?"
}

mask_units() {
  systemctl mask --now "${MASK_UNITS[@]}" > /dev/null 2>&1 ||
    warn "could not mask one of: ${MASK_UNITS[*]}"
}

enable_linger() {
  local user
  user="$(getent passwd "$PODMAN_UID" | cut -d: -f1)"
  [[ -n "$user" ]] || { warn "no user with uid $PODMAN_UID"; return 0; }
  loginctl enable-linger "$user" > /dev/null 2>&1 || warn "could not enable linger for $user"
  systemctl --user --machine="${user}@.host" enable podman-restart.service > /dev/null 2>&1 ||
    warn "could not enable podman-restart.service for $user; containers will not return after a reboot"
}

# The two sets that hold addresses rather than policy. Both fail closed: an
# empty set matches nothing, so a resolution failure means no traffic rather
# than all traffic.
populate_sets() {
  local addr count=0
  while read -r addr; do
    [[ -n "$addr" ]] || continue
    nft add element inet tripwire llm4 "{ $addr timeout $LLM_TIMEOUT }" 2>/dev/null &&
      count=$((count + 1))
  done < <(getent ahostsv4 "$LLM_HOST" 2>/dev/null | awk '{print $1}' | sort -u)
  ((count > 0)) || warn "could not resolve $LLM_HOST; llm4 will drain and the fake VM will go quiet"

  nft flush set inet tripwire resolver4 2>/dev/null || true
  while read -r addr; do
    [[ -n "$addr" ]] || continue
    nft add element inet tripwire resolver4 "{ $addr }" 2>/dev/null || true
  done < <(sed -n 's/^nameserver[[:space:]]\+\([0-9.]\+\)[[:space:]]*$/\1/p' /etc/resolv.conf)
}

ensure_include() {
  if [[ ! -f "$NFT_MAIN" ]]; then
    printf '#!/usr/sbin/nft -f\ninclude "/etc/nftables.d/*.nft"\n' > "$NFT_MAIN"
    chmod 755 "$NFT_MAIN"
    return 0
  fi
  grep -q 'nftables\.d' "$NFT_MAIN" && return 0
  printf '\n# tripwire\ninclude "/etc/nftables.d/*.nft"\n' >> "$NFT_MAIN"
}

# --- the render tests ----------------------------------------------------
# The acceptance tests from docs/plans/2026-09-19-sentinel-vm-hardening.md,
# runnable anywhere: no root, no systemd, no nft. Documentation addresses
# and invented uids only -- no value here is a site value.
sample_env() { # sample_env FILE plain|fakevm|any|nosshd
  cat > "$1" <<'ENV'
ADMIN_PORT=61022
ADMIN_SOURCES=192.0.2.0/24,198.51.100.10,2001:db8:1::/48
ADMIN_USERS=exampleadmin
PUBLIC_PORTS=22,25,80
COLLECTOR_ENDPOINT=192.0.2.200
COLLECTOR_WG=198.51.100.2
WG_IFACE=wgtest0
WG_LISTEN_PORT=
PODMAN_UID=1000
SUBUID_RANGE=100000-165535
REBOOT_TIME=04:40
ROLLBACK_SECONDS=180
FAKEVM_UID=
FAKEVM_SUBUID_RANGE=
FAKEVM_PORT=
LLM_HOST=
ENV
  case "$2" in
    fakevm) cat >> "$1" <<'ENV'
WG_LISTEN_PORT=51820
FAKEVM_UID=1500
FAKEVM_SUBUID_RANGE=200000-265535
FAKEVM_PORT=2222
LLM_HOST=models.example.invalid
ENV
      ;;
    any)    printf 'ADMIN_SOURCES=any\n' >> "$1" ;;
    nosshd) printf 'SSHD_HARDEN=no\n' >> "$1" ;;
  esac
}

cmd_selftest() {
  local tmp rc=0
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
  # Every line naming the admin port also names a set or the tunnel.
  admin_fenced() {
    ! grep -n '\b61022\b' "$1" | grep -qv -e '@admin4' -e '@admin6' -e 'iifname "wgtest0"'
  }
  same_output_chain() {
    diff <(sed -n '/^  chain output {/,/^  }$/p' "$1") \
         <(sed -n '/^  chain output {/,/^  }$/p' "$2") > /dev/null
  }
  first_line() { grep -n -- "$2" "$1" | head -1 | cut -d: -f1; }
  # The tunnel accept has to sit below the container drop -- otherwise a
  # container uid can use the collector's public address as a way out on any
  # UDP port -- and above the rules for system uids.
  chain_order_ok() {
    local drop tunnel system
    drop="$(first_line "$1" 'skuid { 1000, 100000-165535 } counter drop')"
    tunnel="$(first_line "$1" 'daddr 192.0.2.200')"
    system="$(first_line "$1" 'skuid 0-999')"
    [[ -n "$drop" && -n "$tunnel" && -n "$system" ]] || return 1
    ((drop < tunnel)) && ((tunnel < system))
  }
  # ... and the last rule of the output chain is an unconditional drop.
  ends_in_drop() {
    sed -n '/^  chain output {/,/^  }$/p' "$1" | tail -2 | head -1 |
      grep -qx '    counter drop'
  }

  # 1 is `bash -n`, run from the command line; 7 is egress-watch.py.
  # 2: a plain render.
  sample_env "$tmp/plain.env" plain
  "$SELF" --render "$tmp/plain" --env "$tmp/plain.env" > /dev/null
  local nft="$tmp/plain${NFT_FILE}"
  check "2 three chains with policy drop"  bash -c "grep -c 'policy drop' '$nft' | grep -qx 3"
  check "2 the persona ports"              grep -q 'tcp dport { 22, 25, 80 } accept' "$nft"
  check "2 admin port only behind a set or the tunnel" admin_fenced "$nft"
  check "2 the subordinate range in skuid" grep -q 'skuid { 1000, 100000-165535 }' "$nft"
  check "2 the egress log prefix"          grep -q 'tripwire-egress ' "$nft"
  check "2 no FAKEVM anywhere"             bash -c "! grep -rq FAKEVM '$tmp/plain'"
  check "2 no llm4 anywhere"               bash -c "! grep -rq llm4 '$tmp/plain'"
  check "2 no empty set literal"           bash -c "! grep -rqF '{ }' '$tmp/plain'"
  check "2 the tunnel accept is below the container drop" chain_order_ok "$nft"
  check "2 the catch-all log is ct state new" \
    grep -q 'ct state new limit rate 30/minute log prefix "tripwire-egress-other "' "$nft"
  check "2 the output chain ends in an unconditional drop" ends_in_drop "$nft"

  # 3: the fake-VM keys filled.
  sample_env "$tmp/fakevm.env" fakevm
  "$SELF" --render "$tmp/fakevm" --env "$tmp/fakevm.env" > /dev/null
  local fnft="$tmp/fakevm${NFT_FILE}"
  check "3 the llm4 set"        grep -q 'set llm4' "$fnft"
  check "3 the fake-VM uid"     grep -q 'skuid { 1500, 200000-265535 }' "$fnft"
  check "3 the fake-VM port"    grep -q 'tcp dport 2222 accept' "$fnft"
  check "3 the refresh timer"   test -f "$tmp/fakevm${LLM_TIMER}"
  check "3 no empty set literal" bash -c "! grep -rqF '{ }' '$tmp/fakevm'"

  # 4: a missing key names itself, and nothing is rendered.
  grep -v '^COLLECTOR_WG=' "$tmp/plain.env" > "$tmp/broken.env"
  local out
  out="$("$SELF" --render "$tmp/broken" --env "$tmp/broken.env" 2>&1 || true)"
  check "4 a missing key is refused"    bash -c "! '$SELF' --render '$tmp/broken' --env '$tmp/broken.env'"
  check "4 the message names the key"   bash -c "printf '%s' \"\$1\" | grep -q COLLECTOR_WG" _ "$out"
  check "4 nothing was rendered"        bash -c "! test -d '$tmp/broken'"

  # 5: rendering is a pure function of the env file.
  "$SELF" --render "$tmp/twice" --env "$tmp/plain.env" > /dev/null
  check "5 two renders are identical"   diff -r "$tmp/plain" "$tmp/twice"

  # 6: nothing that changes how the host answers a probe.
  check "6 no tcp_timestamps"   bash -c "! grep -rq tcp_timestamps '$tmp/plain' '$tmp/fakevm'"
  check "6 no icmp_echo_ignore" bash -c "! grep -rq icmp_echo_ignore '$tmp/plain' '$tmp/fakevm'"
  check "6 no ip_default_ttl"   bash -c "! grep -rq ip_default_ttl '$tmp/plain' '$tmp/fakevm'"

  # 8: ADMIN_SOURCES=any opens the admin port without a source match, and
  # changes nothing about what may leave.
  sample_env "$tmp/any.env" any
  "$SELF" --render "$tmp/any" --env "$tmp/any.env" > /dev/null 2>&1
  local anft="$tmp/any${NFT_FILE}"
  check "8 an unconditional admin accept" grep -qx '    tcp dport 61022 accept' "$anft"
  check "8 no admin set"                  bash -c "! grep -q '@admin4' '$anft'"
  check "8 three chains with policy drop" bash -c "grep -c 'policy drop' '$anft' | grep -qx 3"
  check "8 the output chain is unchanged" same_output_chain "$anft" "$nft"

  # 9: SSHD_HARDEN=no renders no drop-in at all.
  sample_env "$tmp/nosshd.env" nosshd
  "$SELF" --render "$tmp/nosshd" --env "$tmp/nosshd.env" > /dev/null
  check "9 no sshd drop-in when off" bash -c "! test -e '$tmp/nosshd${SSHD_CONF}'"
  check "9 a drop-in when on"        test -f "$tmp/plain${SSHD_CONF}"
  check "9 the firewall is unaffected" diff "$tmp/nosshd${NFT_FILE}" "$nft"

  # 10: the rollback state machine, driven against a fake root with stubs on
  # PATH standing in for nft, systemd and wg. The case that matters is the
  # second --apply on a host that was already confirmed: deleting the table
  # and stopping there would leave it with no firewall until a reboot.
  local bin="$tmp/bin" name
  mkdir -p "$bin"
  cat > "$bin/stub" <<'STUB'
#!/usr/bin/env bash
printf '%s %s\n' "${0##*/}" "$*" >> "$STUB_LOG"
[[ "${0##*/}" == id ]] && echo 0
exit 0
STUB
  chmod +x "$bin/stub"
  for name in nft systemctl sysctl wg wg-quick id; do cp "$bin/stub" "$bin/$name"; done

  rollback_cycle() { # rollback_cycle ROOT LOG first|reapply
    local root="$1"
    mkdir -p "$root/etc"
    (
      set +e
      export STUB_LOG="$2"
      PATH="$bin:$PATH"
      STATE_DIR="$root/state"
      NFT_FILE="$root/etc/tripwire.nft"      NFT_MAIN="$root/etc/nftables.conf"
      SSHD_CONF="$root/etc/10-tripwire.conf" SYSCTL_CONF="$root/etc/60-tripwire.conf"
      APT_CONF="$root/etc/52-tripwire"       EGRESS_UNIT="$root/etc/egress.service"
      WG_DIR="$root/etc/wireguard"
      WG_IFACE=wgtest0 SSHD_HARDEN=yes FAKEVM_UID=""
      snapshot
      if [[ "$3" == reapply ]]; then
        mkdir -p "$(dirname "${STATE_DIR}/pending${NFT_FILE}")"
        printf 'RULESET ONE\n' > "${STATE_DIR}/pending${NFT_FILE}"
        cmd_confirm
        snapshot                             # the second --apply
      fi
      cmd_rollback
    ) > /dev/null 2>&1
  }

  rollback_cycle "$tmp/rb1" "$tmp/rb1.log" reapply
  check "10 the confirmed ruleset is loaded again" \
    grep -qx "nft -f $tmp/rb1/etc/tripwire.nft" "$tmp/rb1.log"
  check "10 the ruleset file is restored" grep -q 'RULESET ONE' "$tmp/rb1/etc/tripwire.nft"
  check "10 the confirmed flag is back"   test -f "$tmp/rb1/state/confirmed"

  rollback_cycle "$tmp/rb2" "$tmp/rb2.log" first
  check "10 a first apply loads nothing back" bash -c "! grep -q 'nft -f' '$tmp/rb2.log'"
  check "10 the table is still deleted"  grep -q 'nft delete table inet tripwire' "$tmp/rb2.log"
  check "10 no confirmed flag"           bash -c "! test -e '$tmp/rb2/state/confirmed'"
  check "10 no ruleset file"             bash -c "! test -e '$tmp/rb2/etc/tripwire.nft'"

  ((rc == 0)) && say "selftest ok"
  return "$rc"
}

# --- entry ---------------------------------------------------------------
usage() {
  sed -n '2,/^set -euo/p' "$SELF" | sed 's/^# \{0,1\}//; $d'
}

main() {
  local mode="" dir="" minutes=""
  while (($#)); do
    case "$1" in
      --render)         mode=render;  dir="${2:-}";     [[ -n "$dir" ]] || die "--render needs a directory"; shift 2 ;;
      --env)            ENV_FILE="${2:-}"; [[ -n "$ENV_FILE" ]] || die "--env needs a file"; shift 2 ;;
      --build-window)   mode=window;  minutes="${2:-}"; [[ -n "$minutes" ]] || die "--build-window needs minutes"; shift 2 ;;
      --check)          mode=check;   shift ;;
      --apply)          mode=apply;   shift ;;
      --confirm)        mode=confirm; shift ;;
      --rollback)       mode=rollback; shift ;;
      --refresh-llm-set) mode=llmset; shift ;;
      --selftest)       mode=selftest; shift ;;
      -h|--help)        usage; return 0 ;;
      *)                die "unknown argument: $(printf '%q' "$1")" ;;
    esac
  done
  case "$mode" in
    render)   cmd_render "$dir" ;;
    check)    cmd_check ;;
    apply)    cmd_apply ;;
    confirm)  cmd_confirm ;;
    rollback) cmd_rollback ;;
    window)   cmd_build_window "$minutes" ;;
    llmset)   cmd_refresh_llm_set ;;
    selftest) cmd_selftest ;;
    *)        usage; return 1 ;;
  esac
}

main "$@"
