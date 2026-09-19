# Wave 1: overview, field contract, order

Sequencing amendment approved 2026-09-19: see `2026-09-19-beelzebub-first.md`.
Beelzebub local preparation and HTTP bait now precede full D and SMTP A2.
Public deployment still needs verified containment. Original ordering below
is retained for context; the amendment governs current work.

Eight work packages. This file is the index and the shared contract; each
package has its own plan beside it. Builders read this file and their own
plan, nothing else is required.

No hostname, address or SSH alias appears in any plan: the repo is public.
Site values are written as `<PLACEHOLDER>` and live in the operator's notes.

## Packages

| id | plan file | owner files | model | depends on |
|---|---|---|---|---|
| A1 | `2026-09-19-sentinel-passive.md` | `sentinel.py` | opus | none |
| B1 | `2026-09-19-enrich-intel.md` | `enrich.py`, `setup-logging.sh` | sonnet | none |
| B2 | `2026-09-19-dropper-ledger.md` | `droppers.py` (new) | sonnet | none |
| C | `2026-09-19-vector-tags.md` | `vector-sentinel.toml`, `vector.toml`, `vector-tests-sentinel.toml` (new), `vector-tests-collector.toml` (new), `test-vector.sh` (new) | sonnet | field contract below |
| D | `2026-09-19-sentinel-vm-hardening.md` | `harden-sentinel.sh` (new), `egress-watch.py` (new), one mount line in `compose.sentinel.yaml` | opus | none |
| M | `2026-09-19-mappings-dashboards.md` | `bootstrap-opensearch.sh`, `dashboards.py`, `alerts.py`, `compose.yaml`, `README.md`, `CLAUDE.md` | orchestrator | A1, B1, B2, C, D landed |
| A2 | `2026-09-19-sentinel-bait.md` | `sentinel.py`, `compose.sentinel.yaml`, `make-snakeoil.sh` (new), `.gitignore` | opus | A1 landed and deployed |
| E | `2026-09-19-fake-vm.md` | builder: `beelzebub/` (new directory), `compose.fakevm.yaml` (new), `vector-fakevm.toml` (new). Orchestrator: the shared files listed at the end of E's plan | opus | D deployed and verified, A2 landed |

Wave 1a runs A1, B1, B2, C, D in parallel: the fences are disjoint.
`compose.sentinel.yaml` is D's in wave 1a (one line) and A2's in wave 1b, so
the two never hold it at once. M follows as soon as 1a lands. Wave 1b is A2
then E, in that order, and E does not start until the egress block from D
has been proven on the VM with the test in D's plan. That ordering is the
safety argument, not a convenience.

The fake VM runs under its own Unix user on the sentinel VM, not under the
sentinel's. That is what lets the firewall tell its traffic apart and keeps
the log shipper's write credential out of its reach.

## Field contract

The sentinel writes flat names into its JSONL. Vector moves them into
objects. Nobody invents a name that is not in this table.

| flat name (sentinel.py) | index field | type | producer | meaning |
|---|---|---|---|---|
| `tcp_rtt_ms` | `network.rtt_ms` | float | A1 | kernel smoothed RTT at close, milliseconds |
| `tcp_rttvar_ms` | `network.rttvar_ms` | float | A1 | RTT variance |
| `tcp_mss` | `network.mss` | integer | A1 | send MSS toward the peer |
| `proto_mismatch` | `proto_mismatch` | keyword | A1 | what the client actually spoke when it was not the port's protocol: `http`, `tls`, `rdp`, `ssh`, `mglndd`, `binary` |
| `tls_ja4`, `tls_version`, `tls_sni`, `tls_alpn` | unchanged | unchanged | A1 | now also set for a ClientHello on 22 or 25 |
| `smtp_helo` | `smtp.helo` | keyword 256 | A1 | EHLO or HELO argument |
| `smtp_mail_from` | `smtp.mail_from` | keyword 320 | A1 | address in MAIL FROM |
| `smtp_rcpt` | `smtp.rcpt` | keyword 320, array | A1 | addresses in RCPT TO, up to 8 |
| `smtp_auth_user` | `smtp.auth_user` | keyword 128 | A1 | decoded login name when the client volunteered one |
| `http_host_foreign` | `http.host_foreign` | boolean | A1 | Host header names neither this machine's address nor its hostname |
| `smtp_starttls` | `smtp.starttls` | boolean | A2 | the client completed STARTTLS |
| `smtp_auth_pass` | `smtp.auth_pass` | keyword 128 | A2 | decoded password from an AUTH exchange inside TLS. Nobody is ever authenticated |
| `bait_served` | `bait.served` | keyword | A2 | which bait file this connection was given |
| `bait_credential_used` | `bait.credential_used` | boolean | A2, E | a bait credential came back |
| none | `threat.exploit` | keyword, array | C | named exploit or CVE recognised in the request |
| none | `threat.proxy_probe` | boolean | C | CONNECT or absolute-URI request |
| none | `threat.tor` | boolean | B1 | address is a Tor exit |
| none | `threat.fake_crawler` | keyword | B1 | crawler it claims to be and is not |
| none | `source.hosting` | keyword | B1 | `vpn` or `datacenter` |
| none | `network.geo_km`, `network.rtt_floor_ms` | float | B1 | distance to the GeoIP location, and the RTT light allows for it |
| none | `network.rtt_verdict` | keyword | B1 | `impossible`, `plausible`, `detour` |
| none | `reputation.internetdb.*`, `reputation.dshield.*`, `reputation.otx.*` | see B1 | B1 | opt-in lookups |
| none | `dropper.urls`, `dropper.hosts`, `dropper.scanned` | keyword arrays, boolean | B2 | second-stage locations named in a payload. Never fetched |
| `egress_dst_ip` | `egress.dst_ip` | ip | D | where something on the VM tried to connect and was refused |
| `egress_dst_port`, `egress_uid`, `egress_count` | `egress.dst_port`, `egress.uid`, `egress.count` | integer | D | port, owning uid, attempts inside the dedupe window |
| `egress_proto`, `egress_scope` | `egress.proto`, `egress.scope` | keyword | D | `tcp`/`udp`/`icmp`; `container` or `other` |

Egress lines carry `kind: "egress"` and no `ip`; Vector classifies them
`egress-blocked`.

Outside the event indices: `dropper-book` (B2; one document per location,
`url` and `url_defanged`, alerts use only the defanged form) and the
`address-book` document `self` (B1; `scope: "self"`, `honeypot_tagged`).

Fake-VM events (package E) go to their own index family, `tripwire-fakevm-*`,
with a closed mapping (`dynamic: false`): the text is attacker input and
model output, and neither gets to create fields. Their fields are
`fakevm.session`, `fakevm.status`, `fakevm.user`, `fakevm.password`,
`fakevm.client`, `fakevm.command`, `fakevm.output`, plus
`bait.credential_used` on a session start.

## Rules every package inherits

- Standard library only. Package E runs one upstream container image
  unmodified; that is the single exception and it is fenced by D.
- Nothing attacker-supplied is executed, fetched, resolved or rendered.
  Attacker strings in test output and logs go through `ascii()`.
- A1 changes no byte the sentinel sends. A2 changes exactly the bytes its
  plan lists and no others.
- Secrets only in `.env` and `*-secrets.json` on the hosts.
- Each builder commits only its owner files by name, runs the validation in
  its plan, and ends its report with deviations and reasons. The
  orchestrator reads each diff against the plan before anything is built on
  top of it.

## Operator decisions (2026-09-19)

1. **How admin SSH reaches the VM** (package D): **deferred**, and with it
   every step of D on the VM. D is built and tested locally now; nothing is
   applied. Options when it is picked up: source-restrict the admin port at
   both the cloud firewall and nftables (recommended), or admin only over
   WireGuard with the collector as a jump host and the cloud console as the
   fallback.

   E's gate is the egress block, not the SSH restriction: the containment
   argument rests on default-drop egress, the separate Unix user and the
   absence of a real shell. So D carries two knobs, `ADMIN_SOURCES=any` and
   `SSHD_HARDEN=no`, that allow an egress-only apply. Once that is applied
   and D's VM steps 3, 4 and 9 plus the alert have been seen, E may deploy,
   whether or not the SSH question has been answered.
2. **Fake VM engine** (package E): **Beelzebub with an OpenRouter key.** The
   earlier Cowrie choice is withdrawn. Reasons are in E's plan.
3. **Opt-in lookups** (package B1): **build all three** (InternetDB, DShield,
   OTX), each one individually optional through `ENRICH_LOOKUPS`. The code
   default stays off; they send attacker addresses to third parties, and
   turning them on is a line in `.env` on the collector.

Noted the same day: the receiver's lure is not placed on the public page yet,
which is why `tripwire-hits-*` holds only the heartbeat and test hits. Placing
it is an operator step outside wave 1.
