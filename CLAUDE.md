# Working on tripwire

Read `README.md` first; it explains the design. This file is the operating
notes: what is deployed, where the data is, how to change things without
breaking the deception. Hostnames, addresses and SSH aliases are deliberately
not in this repo (it is public); they live in the operator's private notes.

## Shape of the deployment

Two hosts, joined by WireGuard.

- **Collector** (bare metal, kept safe). Rootless podman, `~/tripwire`,
  `compose.yaml`: receiver (port 8787, published to the world only through a
  Cloudflare tunnel), Vector, OpenSearch 3.8, Dashboards, enricher.
  OpenSearch and Dashboards bind to the WireGuard address (`ADMIN_BIND` in
  `.env`); Dashboards is reachable through the lab's nginx + Authentik gateway.
  Never `--network=host`, never a `0.0.0.0` publish on this host.
- **Sentinel** (disposable VM, meant to be scanned and eventually owned).
  Rootless podman as user `sentinel`, `compose.sentinel.yaml`: the sentinel
  container (`network_mode: host`, ports 22/25/80, persona `ubuntu-web`) and a
  Vector that ships over WireGuard to the collector as a write-only user. Its
  image is built on the VM from `Containerfile.sentinel`, so any change to
  `sentinel.py` needs a rebuild there. `harden-sentinel.sh` (default-drop
  egress, rollback timer) and `egress-watch.py` belong to this host; they
  are built and tested but NOT applied yet, and the script can lock you out:
  `--render` and `--selftest` anywhere, `--check` on the VM, `--apply` only
  with the cloud console open, `--build-window 10` before an image build.

Alerts go to a self-hosted ntfy (topic `tripwire`, two channels: high for
incidents, low for the 07:00 digest). A cron on the collector fetches the
public site every 10 min as `tripwire-heartbeat`; the receiver dead-man
monitor watches for it.

## Where the data is

Indices: `tripwire-hits-*` (receiver, 90 d), `tripwire-sentinel-*` (sentinel,
daily rollover, 30 d), `address-book` (one doc per address, enrichment cache
plus first-seen per producer), `fingerprint-book` (one doc per distinct
HASSH / JA4 / header-order hash, created once, `@timestamp` = first sighting),
`dropper-book` (one doc per second-stage location named in a payload, same
convention, written by `droppers.py` inside the enricher).

What the sentinel captures, per protocol (all attacker-controlled strings,
keep them out of terminals unescaped):

| field | content |
|---|---|
| `ssh_client` | client ident banner |
| `fingerprint.hassh`, `ssh.kex` | HASSH of the client KEXINIT, kex list |
| `http_requests` | request lines (up to 16 per connection) |
| `http_body` | first 4 KiB of the first POST/PUT body |
| `http.header_order`, `fingerprint.http` | header names in wire order, hash |
| `http.user_agent`, `http.host` | as sent |
| `smtp_commands` | up to 24 commands, AUTH data included |
| `mysql_user` | login name from the handshake response |
| `payload_text` / `payload_hex` | bytes on ports without a protocol handler, or non-TLS on 443 |
| `fingerprint.ja4`, `tls.*` | ClientHello fingerprint on 443, dormant until the VM has a certificate; also a TLS hello on 22/25 when it arrived whole |
| `proto_mismatch` | `tls`, `http`, `rdp`...: what was spoken on a port that expects something else |
| `smtp.helo`, `smtp.mail_from`, `smtp.rcpt`, `smtp.auth_user` | lifted from `smtp_commands` |
| `http.host_foreign`, `threat.proxy_probe` | Host header that is not ours; open-proxy check |
| `threat.exploit` | named by Vector from the needle table in `vector-sentinel.toml` |
| `network.rtt_ms`, `network.mss` | kernel TCP_INFO at close; `network.rtt_verdict` added by the enricher |
| `dropper.urls`, `dropper.hosts` | second-stage locations found in the payload, never fetched |
| `egress.*` | not a visitor: the VM's own blocked outbound attempts, `classification: egress-blocked` |

SSH passwords are never seen: completing the key exchange needs a host key
signature and there is no crypto in the standard library. This is a design
choice, not a gap to fix.

Receiver events carry `tier_name`, `path`, `method`, `body_excerpt`,
`canary`, and after enrichment `prior.sentinel_hours` (hours since the same
address first touched the sentinel, only when positive).

**To read payloads:** Dashboards → Discover → saved search "Sentinel
payloads" or "Receiver: posted bodies and odd paths"; or panels "Sentinel:
request lines" and "SSH stacks (HASSH)" on the overview dashboard. From a
shell on the collector, `campaigns.py --days 7` clusters addresses by
fingerprint + ports. Saved searches "Droppers", "Dropper ledger: first
seen", "Unlabelled payloads", "SMTP identities" and "Egress attempts" cover
the rest. Never fetch a URL or run a command found in a payload.

## Changing things

- **Sentinel** (`sentinel.py`, `vector-sentinel.toml`): `python sentinel.py
  --selftest` locally, then copy both files to the VM, rebuild
  (`podman compose -f compose.sentinel.yaml build`, podman-compose has no
  `-q`) and `up -d --force-recreate`. Nothing may change a byte the sentinel
  sends on 22/25/80/3306; read the module header before touching handlers.
  New event fields need a mapping line in `bootstrap-opensearch.sh` (both the
  template and the live-index `_mapping` block) or dynamic mapping makes
  them `keyword` capped at 1024.
- **Vector on the sentinel** (`vector-sentinel.toml`): `./test-vector.sh`
  runs the real config against fixed events in a container.
- **Collector** (`enrich.py`, `droppers.py`, `alerts.py`, `dashboards.py`,
  `bootstrap-opensearch.sh`): selftests are `python enrich.py --selftest`,
  `python droppers.py --selftest`, `python dashboards.py --selftest` (panels
  against the mappings), `python alerts.py --selftest` (monitor structure)
  and `python alerts.py --dump` (both with a dummy env). Copy to
  `~/tripwire` on the
  collector, rerun `./bootstrap-opensearch.sh` (idempotent: mappings,
  policies, dashboards import, monitors), `podman restart
  tripwire-enricher` (bind-mounted, no rebuild). Vector containers need
  stop/start, not restart, under rootless podman.
- Files copied from Windows carry CRLF: `sed -i 's/\r$//'` after every scp.
- Secrets only in `.env` / `*-secrets.json` on the hosts, never in the repo
  or on a command line.
- Everything is standard-library Python. Plans for multi-part work go in
  `docs/plans/`; the fingerprint work is the worked example.

## Monitors (alerts.py)

canary, agent, both, returned, novel-fingerprint (hassh and ja4 only; new
header orders are a digest line), novel-dropper, honeypot-tagged, egress,
bait-used (fake VM), bait-used-sentinel (dormant until the bait is on) (high
channel); sentinel-silent 60 min and
receiver-silent 30 min dead-man switches; digest 07:00 `DIGEST_TZ` (low
channel). `novel-fingerprint` and `novel-dropper` are noisy for the first
days after a fresh book; that is expected, not a bug. `egress` means the VM
tried to connect out: snapshot from the cloud console, destroy, do not log
in first. Egress events do not count as sentinel life for the dead-man
switch. Novelty monitors window on `recorded` (when the book learned it),
not on `@timestamp` (first sighting), so enricher lag cannot hide one;
`both` and `returned` key on the index a document is in, never on
`event.module`, which the sender fills in. `honeypot-tagged` only exists with `ENRICH_LOOKUPS` naming
`internetdb` and `SENTINEL_PUBLIC_IP` set.

## Roadmap

- **Sentinel PTR record.** Hetzner Cloud console → the VM → Networking →
  Primary IPs → edit reverse DNS. Pick a dull name that matches the persona
  (a `mail.` or `www.` under a domain that is not the operator's), and make
  the forward A record agree, so a scanner's lookup does not stand out.
- **Certificate for 443 on the sentinel.** Wakes JA4: `do_https` already
  does a real handshake once `--tls-cert`/`--tls-key` are passed (and 443 added to the persona ports). Needs a hostname
  pointing at the VM (see PTR), then a Let's Encrypt cert obtained on the VM
  and bind-mounted into the container. Self-signed is fine for the
  fingerprint itself, but a real cert makes the persona hold up.
- Optional: GreyNoise / AbuseIPDB keys in the collector `.env` for
  reputation enrichment; `ENRICH_LOOKUPS` for InternetDB / DShield / OTX
  (each sends visitor addresses to a third party, so off by default).
- **Apply `harden-sentinel.sh` on the VM.** Deferred until the admin SSH
  path is decided. The fake VM (`docs/plans/2026-09-19-fake-vm.md`) is gated
  on the egress block being proven there.
