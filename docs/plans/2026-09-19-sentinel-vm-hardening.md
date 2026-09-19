# D: sentinel VM, hardening and the egress block

Read `2026-09-19-wave1-overview.md` first.

**Owner files:** `harden-sentinel.sh` (new), `egress-watch.py` (new), and in
`compose.sentinel.yaml` one added mount line on the `vector` service.
**Builder model:** opus. A mistake here locks the operator out or, worse,
looks fine and blocks nothing.

The VM is meant to be owned one day. This package decides what an owner can
do from it: nothing outbound, and loudly. It is also the precondition for
package E. The builder has no access to the VM; everything that needs root
there is run by the orchestrator from the "On the VM" section.

This plan describes the required end state only. It holds no site values.

## Site values

`/etc/tripwire/harden.env` on the VM, root, mode 600, written by the
operator. The script refuses to run without it and names every missing key.

| key | meaning |
|---|---|
| `ADMIN_PORT` | the port the real sshd already listens on. The script never changes it |
| `ADMIN_SOURCES` | comma-separated v4 and v6 CIDRs allowed to reach `ADMIN_PORT`. The word `any` leaves the port open to every source, with a warning; empty means no public admin rule at all (tunnel break-glass only), with a louder one |
| `SSHD_HARDEN` | `yes` (default) or `no`. With `no` the sshd drop-in is not rendered, installed, checked or rolled back |
| `ADMIN_USERS` | value for sshd `AllowUsers` |
| `PUBLIC_PORTS` | persona ports, default `22,25,80` |
| `COLLECTOR_ENDPOINT` | public address of the WireGuard peer |
| `COLLECTOR_WG` | the collector's address inside the tunnel |
| `WG_IFACE` | default `wg0` |
| `WG_LISTEN_PORT` | empty when the VM always initiates (the normal case): then no inbound WireGuard rule exists |
| `PODMAN_UID` | uid of the rootless podman user |
| `SUBUID_RANGE` | that user's subordinate range, as `first-last` |
| `REBOOT_TIME` | unattended-upgrades reboot time, default `04:40` |
| `ROLLBACK_SECONDS` | default `180` |
| `FAKEVM_UID`, `FAKEVM_SUBUID_RANGE`, `FAKEVM_PORT`, `LLM_HOST` | all empty until package E. Support for them is built now so E never edits this script |

## `harden-sentinel.sh`

Bash, `set -euo pipefail`, idempotent, root only. Installs itself to
`/usr/local/sbin/` on first apply so the rollback timer has a stable path.

| mode | does |
|---|---|
| `--render DIR [--env FILE]` | writes every file it would install under `DIR`, touches nothing else, needs no root. This is what the builder tests |
| `--check` | compares the system with the rendered state, prints one line per item as `ok` or `DRIFT`, exits 1 on any drift |
| `--apply` | see "Apply without locking yourself out" |
| `--confirm` | cancels the rollback and makes the state survive a reboot |
| `--rollback` | restores the snapshot. Called by the timer, or by hand |
| `--build-window MINUTES` | lets the podman user pull images for that long |
| `--refresh-llm-set` | package E's address set, below |

### Firewall: `table inet tripwire`

Own table only, replaced atomically (`add table`, `delete table`, then the
definition, in one `nft -f` file). Never `flush ruleset`.

Input, policy drop:

1. `ct state established,related accept`; `ct state invalid drop`; `iif lo accept`.
2. ICMP and ICMPv6: accept exactly what the stack answers today (echo
   included, no new rate limit), plus the ICMPv6 neighbour discovery types.
3. `tcp dport { PUBLIC_PORTS } accept`, plus `FAKEVM_PORT` when set.
4. `tcp dport ADMIN_PORT` from the `admin4` / `admin6` sets.
5. `iifname WG_IFACE ip saddr COLLECTOR_WG tcp dport ADMIN_PORT accept`: the
   break-glass path for the day the operator's own address changes.
6. `udp dport WG_LISTEN_PORT ip saddr COLLECTOR_ENDPOINT accept`, only when set.

Output, policy drop:

1. `ct state established,related accept`; `oif lo accept`. Replies on the
   persona ports are established traffic: the sentinel is unaffected.
2. (Moved to 6b after review, 2026-09-19. Here it let any container uid out
   to the collector's public address on any UDP port.)
3. `meta skuid PODMAN_UID oifname WG_IFACE ip daddr COLLECTOR_WG tcp dport 9200 accept`
   (Vector shipping; rootless bridged traffic leaves through the user's own
   network helper, so it carries the podman user's uid).
4. `jump egress_window` (an empty chain, see `--build-window`).
5. When `FAKEVM_UID` is set: `meta skuid { FAKEVM_UID, FAKEVM_SUBUID_RANGE }
   ip daddr @llm4 tcp dport 443 accept`, and DNS for the same uids only
   toward the resolver in `/etc/resolv.conf`. Both the uid and its range,
   because which one owns the socket depends on the container's network mode.
6. `meta skuid { PODMAN_UID, SUBUID_RANGE, FAKEVM_UID, FAKEVM_SUBUID_RANGE }
   ct state new` → `limit rate 30/minute log prefix "tripwire-egress " flags
   skuid`, then an unconditional `counter drop`. The drop is never behind the
   rate limit.
6b. `ip daddr COLLECTOR_ENDPOINT udp sport WG_LISTEN_PORT accept` (plain
   `meta l4proto udp` when the port key is empty). The tunnel itself: kernel
   packets carry no socket uid, so they never matched rule 6 and arrive here,
   while a container uid was already dropped above. `sport`, not `dport`:
   the env names this host's listen port, the peer's port has no key.
7. `meta skuid 0-999`: `udp dport { 53, 123 }`, `tcp dport { 53, 80, 443 }`
   accept (resolver, time, apt, later certificate renewal).
8. ICMP and ICMPv6 out: accept.
9. Everything else: `ct state new` + `log prefix "tripwire-egress-other "`
   rate-limited, then an unconditional drop. `ct state new` because a late
   FIN or RST after conntrack expiry is an ownerless invalid packet and would
   be logged as the VM reaching out to the scanner.

Forward: policy drop.

Closed ports stop answering with a reset and go silent. That is how a
firewalled Ubuntu host looks and the cloud firewall hides the difference
anyway, so there is no knob for it.

`--build-window N` adds to `egress_window`: `meta skuid PODMAN_UID tcp dport
443 accept` and the same uid's DNS, then `systemd-run --on-active=Nm` flushes
the chain. The subordinate range is never in the window: the pull runs as
the user, the containers do not get out.

`--refresh-llm-set`: set `llm4` has `flags timeout` and elements live one
hour. The mode resolves `LLM_HOST` with `getent ahostsv4`, adds each address
again, and installs a 10-minute timer for itself when `FAKEVM_UID` is set.
If resolution fails for an hour the set drains and the fake VM's model goes
quiet: it fails closed. Be honest in the script header about what this set
is worth: the provider sits behind a CDN, so the rule narrows "the internet"
to "that CDN's edge on 443". It stops scanning, SSH, SMTP and arbitrary
hosts; it does not stop a request to another site on the same CDN.

### sshd: `/etc/ssh/sshd_config.d/10-tripwire.conf`

sshd takes the first value it sees, so the file sorts before cloud-init's.

```
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
AllowUsers <ADMIN_USERS>
```

`sshd -t` before any reload. Port and listen addresses are not touched.

### Kernel: `/etc/sysctl.d/60-tripwire.conf`

`accept_redirects = 0` and `send_redirects = 0` for `all` and `default`, v4
and v6 where the key exists; `kernel.kptr_restrict = 2`;
`kernel.dmesg_restrict = 1`; `kernel.unprivileged_bpf_disabled = 1`.

Nothing that changes how the stack answers a probe: no TCP timestamps,
window scaling, TTL, ICMP echo or rate-limit keys. An OS-detection scan of
the persona ports must read the same before and after.

### The rest

- WireGuard: `AllowedIPs` for the collector peer is `COLLECTOR_WG/32`.
  Rewrite the line with a backup, apply with `wg syncconf`.
- `systemctl mask --now multipathd.service multipathd.socket atd.service`.
- `/etc/apt/apt.conf.d/52-tripwire-reboot`: `Unattended-Upgrade::Automatic-Reboot
  "true";` and `Automatic-Reboot-Time "<REBOOT_TIME>";`.
- `loginctl enable-linger` for the podman user, and that user's
  `podman-restart.service` enabled, so containers return after a reboot with
  nobody logged in. `--check` verifies both.
- Installs `egress-watch.py` to `/usr/local/sbin/` and its unit (below).

Skipped on purpose: fail2ban (the admin port is source-restricted and 22 is
not a real sshd), auditd (add when there is something to audit), disabling
IPv6 (the firewall covers it and apt wants it).

### Apply without locking yourself out

1. Render to a temp directory. `nft -c -f` the ruleset and `sshd -t` with the
   drop-in in place of the live one. Any failure stops here, nothing changed.
2. Snapshot to `/var/lib/tripwire-harden/`: `nft list ruleset`, and a copy of
   every file about to be replaced (or a marker that it did not exist).
3. `systemd-run --unit=tripwire-harden-rollback --on-active=ROLLBACK_SECONDS
   /usr/local/sbin/harden-sentinel.sh --rollback`.
4. Install, `nft -f`, `sysctl --system`, reload sshd, `wg syncconf`.
5. Print, and mean it: `Open a NEW ssh session now. If it works, run
   harden-sentinel.sh --confirm. If it does not, do nothing: everything
   reverts in N seconds.`

Only `--confirm` writes the ruleset where it is loaded at boot and enables
`nftables.service`. Until then a reboot from the cloud console is a second
way back in.

## `egress-watch.py`

Standard library. Follows the kernel log and turns blocked attempts into
events the existing Vector ships.

```python
LINE = re.compile(r"tripwire-egress(?P<other>-other)? .*?SRC=(?P<src>\S+) DST=(?P<dst>\S+) .*?PROTO=(?P<proto>\w+)(?: SPT=\d+ DPT=(?P<dport>\d+))?(?:.*? UID=(?P<uid>\d+))?")

def parse_line(text: str) -> dict | None
def main(argv=None) -> int      # --selftest, --out FILE, --window SECONDS
```

- Input: `subprocess.Popen(["journalctl", "-k", "-f", "-n", "0", "-o", "cat"])`.
- `parse_line` validates `dst` with `ipaddress.ip_address` and returns
  `{"kind": "egress", "egress_dst_ip", "egress_dst_port", "egress_proto",
  "egress_uid", "egress_scope": "container" | "other"}` or `None`.
- One event per distinct `(dst, port, uid)` per `--window` (default 60 s),
  with `egress_count`. A compromised container that floods cannot fill the
  disk: the kernel rate limit bounds the input, this bounds the output.
- Output: JSONL appended to `/var/log/tripwire-egress/egress.jsonl`, `ts` in
  the same format the sentinel uses. `# ponytail:` one file, truncated at
  start when over 10 MB; rotate properly if it ever matters.
- Unit `tripwire-egress-watch.service`: root (it must read the journal and
  the directory must be world-readable for the rootless Vector, which rules
  out `DynamicUser`), with `CapabilityBoundingSet=`, `NoNewPrivileges=yes`,
  `PrivateNetwork=yes`, `ProtectSystem=strict`,
  `ReadWritePaths=/var/log/tripwire-egress`, `Restart=always`.

`compose.sentinel.yaml`, `vector` service, one line:
`- /var/log/tripwire-egress:/var/log/tripwire-egress:ro`. Package C adds the
source; package M adds the mapping and the `egress` monitor (high channel).

## Acceptance tests

Builder, anywhere:

1. `bash -n harden-sentinel.sh`; `shellcheck` clean when it is installed.
2. `--render` with a sample env (documentation addresses `192.0.2.0/24`,
   `2001:db8::/32`, uid 1000, range `100000-165535`, fake-VM keys empty)
   into a temp dir. Assert the ruleset contains: `policy drop` three times;
   the persona ports; the admin port only beside `@admin4` / `@admin6` or the
   tunnel interface; `skuid` with `100000-165535`; the string
   `tripwire-egress `; no occurrence of `FAKEVM`, `llm4` or an empty set
   literal `{ }`.
3. Same with the fake-VM keys filled: `llm4`, the fake-VM uid and port appear.
4. Missing env key: exit non-zero, the message names the key, nothing rendered.
5. Render twice: byte-identical output.
6. The rendered output contains none of `tcp_timestamps`, `icmp_echo_ignore`,
   `ip_default_ttl`.
7. `python egress-watch.py --selftest`: a container line parses to the dict
   above with the right uid; an `-other` line gives `egress_scope ==
   "other"`; an ICMP line (no ports) parses with no port key; garbage and a
   line with `DST=not-an-ip` give `None`; 500 identical lines inside one
   window give one event with `egress_count == 500`.
8. `ADMIN_SOURCES=any`: the admin port is accepted with no source condition,
   all three chains still have `policy drop`, and the output chain is
   byte-identical to the one rendered with restricted sources.
9. `SSHD_HARDEN=no` renders no `10-tripwire.conf`; `yes` does.

## On the VM (orchestrator, with the operator present)

Keep the current session open throughout. Cloud console access checked first.

1. Before anything: from outside, save `nmap -sV -p<PUBLIC_PORTS>` and
   `nmap -O` output.
2. `--apply`, new session, `--confirm`. Then `--check` exits 0.
3. **The egress proof, host network.** As the podman user: run the sentinel
   image with `--network=host` and a Python one-liner that tries
   `socket.create_connection(("<any public address>", 443), 5)`. It must
   fail. Within 90 s a matching line is in `egress.jsonl`.
4. **The egress proof, bridged.** Same from a bridged container. Same result.
5. The event is in OpenSearch within two minutes; after M, the alert arrives.
6. From a host outside `ADMIN_SOURCES`: the admin port is filtered, the
   persona ports are open, and the `-sV` output equals step 1.
7. Shipping still works: the sentinel event count for the last five minutes
   is above zero and rising.
8. `--build-window 10`, rebuild the sentinel image, confirm the pull works
   and that a container in that window still cannot connect out.
9. Reboot once. Without logging in as the podman user: both containers are
   back, the firewall is loaded, `--check` exits 0.
10. `sshd -T` shows the drop-in's values.

Package E does not start until 3, 4 and 9 have passed and the operator has
seen the alert from 5.

## The cloud firewall (operator, by hand, walkthrough)

The outer layer, and the one an owner of the VM cannot edit. Cloud console →
Firewalls → create → apply to the VM.

Inbound: TCP `PUBLIC_PORTS` from anywhere; TCP `ADMIN_PORT` from
`ADMIN_SOURCES`; ICMP from anywhere; UDP `WG_LISTEN_PORT` from the collector
only if it is set.

Outbound (adding the first outbound rule turns the default from allow into
deny): UDP to `COLLECTOR_ENDPOINT` on the tunnel port; TCP 80 and 443 to
anywhere; UDP and TCP 53; UDP 123; ICMP. No outbound 22, 25 or anything
else. The host firewall narrows 80/443 by uid; this layer guarantees that
even root on the VM cannot scan, brute-force SSH or send mail.

Do this after step 2 above, then repeat steps 6 and 7.

## Edge-case matrix

| axis | applies | note |
|---|---|---|
| operator's address changes | yes | break-glass through the tunnel, then the cloud console |
| rollback timer fires mid-confirm | yes | `--confirm` stops the timer first, then persists |
| script run twice | yes | test 5 and `--check` |
| reboot before `--confirm` | yes | comes up unhardened by design |
| image rebuild | yes | `--build-window`, otherwise the pull fails with a clear firewall log line |
| IPv6 | yes | same policy in the `inet` table; persona does not listen on v6 |
| existing connections at apply time | yes | picked up as established; the open session survives |
| log flood from an owned container | yes | kernel limit, then the window in `egress-watch.py` |
| fake-VM keys empty | yes | no rule, no set, no timer |
| kernel-generated packets (no uid) | yes | matched by address rules, never by `skuid` |

## Knobs

`ROLLBACK_SECONDS`, `REBOOT_TIME`, the log rate (`30/minute`), the
`egress-watch.py` window, the set element timeout. All in the env file or as
constants at the top of the file that uses them.

## Where's the door handle

The operator copies two files, writes the env file from their notes, runs
`--apply`, and is told in one sentence what to do next and what happens if
they do nothing. `--check` is the thing to run whenever in doubt; it prints
every item and says `DRIFT` beside the ones that are off. When a container
tries to get out, the phone buzzes with the destination and the uid. When a
pull fails because the window is shut, the last line of `journalctl -k`
says `tripwire-egress` and the README section M writes says why.

## Validation and report

Tests 1-7. `git add harden-sentinel.sh egress-watch.py compose.sentinel.yaml`
only. Report deviations with reasons, and list separately every assumption
about the VM that could not be checked from the builder's seat (nft syntax
accepted by the installed version, how the rootless network helper's uid
shows up in `skuid`, the resolver path for containers). The orchestrator
verifies those in steps 3, 4 and 8.
