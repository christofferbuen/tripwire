# Tripwire

Detects clients that read a page you own as text and act on what they read.
Replaces a single canarytokens email address with your own receiver, so you
get the full request fingerprint and attribution rather than one anonymous
ping.

Three things live here:

- **The receiver** catches agents that acted on injected text, and holds the
  ones that go looking for loot in a labyrinth.
- **The sentinel** catches port scanners, on a separate host, while trying
  hard not to look like a honeypot.
- **The logging stack** collects both into OpenSearch so the pattern across
  weeks is visible rather than just the last hit.

The two detectors are standard library Python only. Nothing to install,
nothing to pin. The logging stack is three containers.

## Shape

Your page lives on someone else's server. The tripwire lives on a host you
control, fronted by a Cloudflare Tunnel, and presents itself as an
unremarkable personal blog. The profile page references it, and every
reference that gets fetched becomes a log line.

```
  the profile page                      your host, behind a tunnel
  ┌─────────────────────┐              ┌──────────────────────────┐
  │ visible bio text    │              │  receiver.py             │
  │ <img> logo      ────┼─────────────►│  /static/img/logo.png t0 │
  │ <link> stylesheet ──┼─────────────►│  /static/css/site.css t0 │
  │ hidden bare URL ····┼·············►│  /notes/...?t=1       t1 │
  │ hidden instruction ·┼·············►│  /notes/...?t=2&as=   t2 │
  └─────────────────────┘              │  POST /contact?p=     t3 │
                                       │  /  cover blog        t0 │
     ───► browsers do this             │  anything unknown     t4 │
     ···► only readers do this         │  /archive/...         t5 │
                                       │         │                │
  nobody links to this                 │  tripwire.sqlite3        │
  ┌─────────────────────┐              │  hits.jsonl              │
  │ robots.txt          │              └─────────┬────────────────┘
  │ Disallow: /archive/ ┼············►           │
  └─────────────────────┘                        │
```

Nothing in that URL structure reads as instrumentation. A stylesheet, a logo
and a notes page are what a blog has. Anyone who pastes the hostname into a
browser lands on a dull site rather than on something that announces itself.

## Tiers

| Tier | Endpoint | A hit proves |
|---|---|---|
| 0 | `/static/css/site.css`, `/static/img/logo.png` | the client rendered the page like a browser |
| 0 | `/` | somebody looked the hostname up by hand |
| 1 | `/notes/profile-mirror?t=1` | something read the text and fetched a URL it found |
| 2 | `/notes/profile-mirror?t=2&as=` | something followed an instruction embedded in content |
| 3 | `POST /contact?p=` | something posted data on the page's say-so |
| 4 | anything unrecognised | something is guessing at paths |
| 5 | `/archive/…` and the bait paths | something is hunting for loot |

The useful reading is the combination. A visit that trips tier 1 or 2 while
fetching zero tier 0 beacons is a client that read the page as text and never
rendered it. The analyzer flags that as `NO-RENDER`.

Tier 2 asks the reader to name itself in the `as` parameter. Compliant agents
often fill it in truthfully, which is free model attribution.

The `p=` tag on tier 3 is load-bearing. The cover site has a working contact
form, so a POST alone proves nothing. That tag, plus the absence of any
rendering, separates a baited agent from a person sending a message. Without
it every genuine contact-form submission would be logged as an exfiltrator.

`analyze.py` reduces a session to one label and a set of flags:

```
EXFILTRATOR  INSTRUCTION-FOLLOWER  URL-EXTRACTOR  CONTACT-FORM
LABYRINTH-WALKER  BAIT-TAKER  GRINDER  BROWSER

NO-RENDER  ROBOTS-DEFIER  CLAIMED-CRAWLER  MAX-DEPTH=n  TOOK-CANARIES=n  HELD=Ns
```

## The labyrinth

A conventional tarpit answers slowly and that is all it does. This one is
built so that the *shape* of what a client did is itself the evidence.

**The only advertised entrance is a prohibition.** `robots.txt` disallows
`/archive/`. Nothing on the site links there. A client inside the labyrinth
either read robots.txt and went where it was told not to, or guessed. The
analyzer separates those two as `ROBOTS-DEFIER`.

**Depth is a compliance meter.** Every directory under `/archive/` contains
more directories, generated from a hash of the path so a refetch returns the
identical listing. Nothing real is down there, so depth measures only how far
something will follow links it was warned off. `MAX-DEPTH` is the number that
distinguishes a scanner with a wordlist from something that decided to
explore.

**Every artifact is a tracer.** The fabricated `.env` files, SQL dumps, CSVs
and private keys each carry a unique `tw-` token, recorded against the path,
address and user agent that received it. If one of those strings ever
resurfaces, you know exactly which session leaked it.
`analyze.py --canaries` prints the ledger.

**The delay is earned, not fixed.** Latency scales with depth and with
request rate, so a browser that wanders in once is barely slowed while a
grinder ramps toward the ceiling. Responses are dribbled out in slices rather
than after one long sleep, because a uniform pause is a fingerprint.

Real search engine crawlers are logged and released immediately. Anything
claiming to be one while behaving otherwise gets `CLAIMED-CRAWLER`.

The limits are constants at the top of `receiver.py`: 24 levels of depth, 12
seconds of delay per response, 900 seconds of total hold, 64 connections held
at once. Nothing here damages a client. There are no decompression bombs and
no malformed responses, only slow ones.

## The port-scan sentinel

The tunnel means the receiver's host has no reachable address, so it cannot
see a port scan by construction. The sentinel is a second, deliberately
exposed host that can.

Its whole design problem is that honeypots are easy to spot, and a host
flagged as one is worthless. `sentinel.py` opens with a long comment
enumerating the tells and what is done about each. In short:

- **It picks one persona and stays inside it.** A Debian box gets Debian
  build strings, Debian's Apache default page and Debian's MySQL package
  version. Mismatched banners across distributions are the cheapest possible
  giveaway.
- **It speaks the protocols for real.** SSH completes binary packet framing
  and sends a genuine `SSH_MSG_KEXINIT` with OpenSSH's actual algorithm
  lists and a fresh cookie. MySQL sends a well-formed protocol 10 handshake
  with a fresh salt, then a real error packet. A banner with nothing behind
  it is detected instantly.
- **No two responses are byte-identical.** Fresh entropy per connection, and
  a few milliseconds of jitter before every response.
- **Timeouts match the real software.** OpenSSH's login grace period,
  nginx's header timeout, Postfix's smtpd timeout.
- **It refuses to relay mail.** An open relay is itself a honeypot
  signature.
- **It does not tarpit the obvious way.** A fixed-interval drip is the
  published signature of well-known SSH tarpits. Holds are quadratic in the
  number of distinct ports touched, randomised, never applied to a first
  contact, and never applied to the web ports.
- **Its identity persists.** Hostname, boot time and install date survive
  restarts, because a host whose uptime resets every time you scan it is not
  a host.

Four tells it cannot fix from inside a container, and you have to handle:
the PTR record, the address's reputation and allocation, the TLS certificate,
and the host's history.

It also fingerprints the client's protocol stack, which is much harder to
change than an address. `fingerprint.hassh` is the
[HASSH](https://github.com/salesforce/hassh) of the client's `KEXINIT`
algorithm lists, `fingerprint.ja4` is the
[JA4](https://github.com/FoxIO-LLC/ja4) of the TLS ClientHello on 443 (the
sentinel terminates TLS itself so it can read the hello before the
handshake), and `fingerprint.http` hashes the order of the request headers,
kept verbatim in `http.header_order`. Two scanners with different addresses
and the same HASSH are the same program. `python3 sentinel.py --selftest`
checks the parsers against known bytes.

What it records of the conversation itself: the SSH banner, request lines
and the first 4 KiB of a POST body on the web ports (the router exploits
and the credential sprays live there), up to 24 SMTP commands including
AUTH, the MySQL login name, and the raw bytes on anything that was not the
expected protocol. SSH passwords are never seen: the key exchange is never
completed, on purpose. `CLAUDE.md` has the field table and the saved
searches that show all of it in Dashboards.

Each connection is filed as one of:

| Classification | Means |
|---|---|
| `port-confirm` | completed the handshake, said nothing, moved on |
| `service-interaction` | actually spoke the protocol |
| `sweep-interaction` | spoke the protocol while already sweeping |
| `sweep-detected` | crossed the threshold of distinct ports; one summary per address |
| `shed-load` | the sensor was at capacity and dropped the connection |
| `egress-blocked` | not a connection at all: the VM itself tried to connect out, see below |

### What it learns without asking

None of this changes a byte the sentinel sends, or when it closes.

- **Round trip against geography.** The kernel already measured the
  handshake (`network.rtt_ms`, `network.mss`). With `SENTINEL_LAT` and
  `SENTINEL_LON` in the collector `.env`, the enricher compares it with the
  distance to where GeoIP puts the address: light in fibre sets a floor, and
  `network.rtt_verdict` is `impossible` below it, `detour` far above it,
  `plausible` otherwise. It tests the GeoIP claim. It says nothing about who
  is behind a proxy: a relay answers the handshake itself, so the round trip
  is to the relay.
- **The wrong protocol.** A TLS hello, an HTTP request or an RDP cookie on
  22 or 25 lands in `proto_mismatch`. On 22 a hello is fingerprinted only
  when it arrived whole in the reads the handler always made; capture loses
  to timing there, on purpose.
- **SMTP identities.** `smtp.helo`, `smtp.mail_from`, `smtp.rcpt`,
  `smtp.auth_user`, lifted out of the command list so they can be counted.
- **Names for what was asked.** Vector tags request lines and bodies with
  `threat.exploit` from a needle table in `vector-sentinel.toml`, and open
  proxy checks with `threat.proxy_probe` (`http.host_foreign` is the raw
  signal). `./test-vector.sh` runs that config against fixed events. The
  saved search "Unlabelled payloads" is where the next needle comes from.
- **Second stages.** `droppers.py` runs inside the enricher, reads stored
  payloads and records every location they tell a victim to fetch from, in
  `dropper.urls` on the event and once in the `dropper-book` ledger. It
  parses text and nothing else: it has no socket, never resolves a name and
  never fetches. Alerts and the ledger view show the defanged form
  (`hxxp://`, `[.]`). Do not open them either.
- **Free context.** Tor exit and hosting-range lists are fetched in bulk, so
  nothing about a visitor leaves the collector. Three per-address lookups
  exist (Shodan InternetDB, DShield, AlienVault OTX) and are off: each one
  sends the attacker's address to a third party, which tells that party what
  your sensor saw. Opt in by name, `ENRICH_LOOKUPS=internetdb,dshield` in
  `.env`. With `internetdb` on and `SENTINEL_PUBLIC_IP` set, the enricher
  also asks once a day what InternetDB says about the sentinel itself, and
  `tripwire-honeypot-tagged` fires if the answer includes `honeypot`.

Addresses that stay for days ("residents") have no panel yet: that needs a
per-address day count, which is `campaigns.py` work and comes with it.

### When the sentinel itself calls out

`harden-sentinel.sh` puts a default-drop nftables output chain on the VM:
the tunnel to the collector is allowed, a short build window can be opened
by hand for image builds, everything else is dropped and logged.
`egress-watch.py` sums those log lines per minute into events with
`classification: egress-blocked`, and the `tripwire-egress` monitor pushes
them at the highest priority. `egress.scope` is `container` for the podman
user and `other` for anything else on the host.

Nothing on that machine has a reason to connect out, so treat the alert as
"the VM is owned". Snapshot it from the cloud console, then destroy it and
build a new one. Do not log in to look first: that hands your key agent and
your source address to whoever is on it. The one benign cause is an
administrator running `curl`, `apt` or `git` there outside a build window.

The script can lock you out of a remote machine. Read its header, run
`--render` and `--selftest` anywhere, and keep the cloud console open for
the first `--apply`; nothing survives a reboot until `--confirm`.

## Logging

`compose.yaml` brings up the receiver, Vector, OpenSearch and Dashboards.
The receiver writes the same events twice: to SQLite for `analyze.py`, and as
JSON lines for Vector. Vector never touches the database, so the shipper can
never stall the writer.

Everything is bound to `127.0.0.1`. Reach the dashboard through an SSH
tunnel, never by publishing 5601.

Two things in the pipeline are not defaults and matter:

- **Request headers ship as an encoded string.** Header names are attacker
  controlled. Mapping them dynamically would let anyone who can reach the
  honeypot create unlimited fields and break the cluster. The handful worth
  querying are lifted into fixed fields; the rest travel as opaque text.
  `bootstrap-opensearch.sh` also caps total fields and mapping depth.
- **The dashboard import overwrites.** Saved objects have fixed ids and
  `bootstrap-opensearch.sh` imports them with `overwrite=true` on every run,
  so a panel edited in the browser is reset by the next bootstrap. Copy it
  under a new name first, or change `dashboards.py`.
- **Secrets come from a file, not the environment.** Vector 0.57 disabled
  `${VAR}` interpolation in config files. A config still using it does not
  fail loudly: Vector sends the literal string `${OPENSEARCH_PASSWORD}` as
  the password and every write returns 401. Both shipper configs use the
  secrets backend instead.

## Run it

Order matters on the collector host.

```sh
sudo sysctl -w vm.max_map_count=262144   # OpenSearch will not start without it
./setup-logging.sh                       # writes .env and vector-secrets.json, mode 600
podman compose up -d
./bootstrap-opensearch.sh                # index template, retention, dashboards; after healthy
```

`setup-logging.sh` generates the admin password and never prints it. Read it
out of `.env` when the dashboard asks.

Every hit gets country, city and network owner at ingest, from the
geospatial plugin's `ip2geo` processor and the GeoLite2 mirror the
OpenSearch project runs (`geoip.maps.opensearch.org`). The database is
downloaded to the cluster and refreshed every three days; lookups are local,
so no address is ever sent anywhere. Fields land under `source.geo.*` and
`source.as.*`.

Three more things are added after the fact by the `enricher` container
(`enrich.py`, stdlib only), which polls for addresses without an
`enrichment.at` mark once a minute, looks each one up once, and copies the
answer onto every event from that address:

- **Reverse DNS** in `source.domain`. A PTR that ends in a known scanner
  domain (`censys-scanner.com`, `shadowserver.org`, `stretchoid.com`, ...)
  also names it in `threat.scanner`.
- **Published lists** in `threat.lists`, and `threat.scanner` when one of
  them is a scanning organisation. Sources: the per-organisation CIDR files
  from OpenFilters/internet-scanners (Censys, Shodan, Stretchoid, BinaryEdge,
  Shadowserver, Driftnet, Xpanse, and sixty-odd more), the FireHOL sets
  `maltrail_scanners`, `level1`, `blocklist_de`, `greensnow` and `dshield`,
  and IPsum, whose count of agreeing blocklists lands in
  `threat.ipsum_score` when it is three or more. Refreshed daily; a failed
  refresh keeps the previous copy.
- **Reputation** in `reputation.greynoise.*` and `reputation.abuseipdb.*`,
  only when `GREYNOISE_API_KEY` or `ABUSEIPDB_API_KEY` is in `.env` before
  `setup-logging.sh` runs. Both free tiers are quota-limited; a 429 pauses
  that API for an hour. Note these two do send the attacker's address to a
  third party, which is why they are opt-in.

The per-address answers are cached in the `address-book` index (one document
per address, re-checked weekly), which the bootstrap also exposes as a
Dashboards index pattern. The book also records when each address was first
seen by the sentinel and by the receiver, refreshed on every pass, and the
enricher stamps `prior.*` onto events from it: a receiver hit gets
`prior.sentinel_hours`, the time since that address first touched the
sentinel, which is how "scanned first, visited later" becomes a query. A
second index, `fingerprint-book`, holds the first sighting of every HASSH,
JA4 and header-order hash (created once, never updated), so a fingerprint
nobody has shown before is a new document with a fresh `@timestamp`. Vector adds `threat.tool` at ingest from what the
client volunteered: SSH banners (`SSH-2.0-Go`, the fake `PUTTY`), user
agents (ZGrab, CensysInspect, Nuclei, masscan, ...) and tell-tale paths
(`/boaform/`, `/.env`). Cloudflare's own `Cf-Ipcountry` and `Cf-Ray` are
kept as `http.cf_ipcountry` and `http.cf_ray` on receiver hits.

`bootstrap-opensearch.sh` also creates the `tripwire` index pattern and
imports the "Tripwire overview" dashboard, which `dashboards.py` generates.
Both go into the Global tenant, so every login sees them. Edit
`dashboards.py` and re-run the bootstrap to change the panels; the fixed ids
mean re-importing updates in place.

**Alerts** go to a self-hosted [ntfy](https://ntfy.sh) server when `NTFY_URL`
and `NTFY_TOKEN` are in `.env` (the token is a write-only ntfy access token
for the topic; `NTFY_TOPIC` defaults to `tripwire`). The bootstrap then runs
`alerts.py`, which creates two webhook channels and eight monitors in the
Alerting plugin, all idempotent: a canary token presented back to the
receiver, something following an embedded instruction or posting to the
collection endpoint (tiers 2 and 3), one address touching both the
sentinel and the receiver within an hour, a receiver hit from an address
that scanned the sentinel an hour or more earlier (`prior.sentinel_hours`),
a fingerprint never seen before (a new `fingerprint-book` document), two
dead-man switches (no sentinel events for an hour, no receiver heartbeat for
30 minutes), and a low-priority digest at 07:00 (`DIGEST_TZ`, default
Europe/Oslo). `python3 alerts.py --dump` prints the monitors without
touching the cluster. Messages are plain text,
so the attacker strings they quote can do nothing on the phone. Without the
token the monitors are skipped and nothing else changes.

The receiver heartbeat is a cron job on the collector host that fetches the
public site every ten minutes, so the whole path (tunnel, receiver, Vector,
OpenSearch) is exercised and the digest can exclude it by user agent:

```
*/10 * * * * curl -sS -A tripwire-heartbeat -o /dev/null --max-time 20 https://<public host>/ >/dev/null 2>&1
```

`campaigns.py` groups the sentinel's addresses by what they share: the same
HASSH, JA4 or header hash (falling back to `threat.tool`) plus the same set
of ports. One cluster of forty addresses across six ASNs is one campaign,
not forty scanners. Run it against the cluster with `OS_URL` and `OS_PASS`
set:

```sh
python3 campaigns.py --days 7            # text table, biggest cluster first
python3 campaigns.py --days 30 --json    # same, as JSON
```

The receiver alone, without the logging stack:

```sh
./run.sh                       # build, run, wait for health
PORT=9000 ./run.sh             # different host port
EXTRA_ARGS=--no-tarpit ./run.sh
podman exec tripwire python3 /app/analyze.py --db /data/tripwire.sqlite3
podman exec tripwire python3 /app/analyze.py --db /data/tripwire.sqlite3 --canaries
podman logs -f tripwire        # hits as they land
```

Three deployment paths for the receiver, pick one: `run.sh` for a quick
start, `compose.yaml` for the full stack, `tripwire.container` as a systemd
quadlet for anything long-lived.

The sentinel runs on a **different host**, with `compose.sentinel.yaml`. Read
the header of that file before you start it. The short version: that host is
meant to be reached, so put nothing else on it; the sentinel takes port 22,
so move your real sshd first or you will lock yourself out; logs come home
over WireGuard or Tailscale, not over a published 9200.

Containers run as an unprivileged UID with a read-only root filesystem, all
capabilities dropped, `no-new-privileges`, and memory and PID caps. CPython
3.14.7 on Alpine 3.24, no third-party packages, so the only things to patch
are CPython and the base.

## Cloudflare Tunnel

See `cloudflared-config.yml`. Use a **named** tunnel: a quick tunnel's
`trycloudflare.com` hostname changes on every restart, which silently breaks
the URL baked into the profile page.

```sh
cloudflared tunnel login
cloudflared tunnel create tripwire
cloudflared tunnel route dns tripwire notes.YOURDOMAIN.TLD
cloudflared tunnel run tripwire
```

**Attribution needs `--trust-proxy`.** Behind a tunnel every client arrives
from the container bridge address, so the log fills with one useless source
IP. Cloudflare puts the true client in `CF-Connecting-IP`, which the receiver
reads only when started with that flag. It detects the broken case and warns
once on stderr:

```
WARNING: hit came from private address 10.88.0.19 and carries a
forwarded-address header that is being ignored...
```

Enable it only when the tunnel is the sole route to the port. Anything that
can reach the container directly can otherwise forge its own source address.

What the tunnel costs you: Cloudflare terminates TLS and sees every canary
hit, so a third party holds a copy of your detection data. That was a
deliberate trade for not opening an inbound port.

## Install the payload

**Do not paste `payload.html` directly.** It is the annotated source, written
for you rather than for the page. Its comments say "Tier 0, render beacons"
and "Tiers 1 and 2, the lure", and HTML comments are served to every client.
Publishing it hands the design to the first person who views the source,
which is exactly the population you are watching for.

`render-payload.py` fills in the hostname, strips every comment, and refuses
to emit anything that still looks wrong:

```sh
./render-payload.py notes.example.com
./render-payload.py notes.example.com --placement profile-no
./render-payload.py notes.example.com --with-collection   # tier 3, off by default
```

It fails rather than emits when the placeholder survives, when a comment
survives, when an `http://` URL is present, when the number of hostname
references has drifted from what the file is supposed to contain, when the
output still names the mechanism anywhere, or when the hostname itself gives
the game away. Output is on stdout, checks on stderr. It touches nothing
outside the directory; publishing stays a manual act.

Paste the result into the profile body, then confirm what the CMS actually
kept:

```sh
curl -s "$PROFILE_URL" | grep -o 'notes\.example\.com[^"]*'
```

Keep `PROFILE_URL` and the real hostname in an untracked `*.local.*` file, not
here. The target is the one detail that turns this repository from a generic
tool into a description of a specific deployment.

The CMS may strip inline styles, `aria-hidden`, or a `<link>` inside the body.
Whatever does not appear in that output did not survive, and any tier
depending on it is dead.

## Putting it on a VPS

One VPS is not quite enough, and the reason is worth understanding before you
buy anything.

The collector is meant to be unreachable: it sits behind the tunnel with no
inbound ports and holds the whole hit history. The sentinel is meant to be
reached, advertises itself, and should be assumed compromised eventually.
Those are opposite postures, and putting them on one box means an attacker
who gets in through the sentinel lands next to the OpenSearch cluster.

So:

- **Collector on the VPS you own.** No inbound ports at all, `cloudflared`
  making an outbound connection, everything else on loopback. Budget 4 GB of
  RAM: OpenSearch takes a 1 GB heap and Dashboards wants around 700 MB on
  top, and the kernel will start killing things on a 2 GB box.
- **Sentinel on a second, disposable one.** Cheapest tier is fine, since it
  runs one small async process. Different provider or at least a different
  network is better, because the point is to observe scanning and you want
  the address to have no relationship to anything else of yours.

Check before you commit:

- **`vm.max_map_count` must be raisable.** OpenSearch will not start
  otherwise. Container-based VPS products (OpenVZ, some LXC offerings) do not
  let you set sysctls at all. KVM does.
- **You need control of the PTR record** on the sentinel's address. A
  reverse name that reads as a hosting provider's default is fine and
  ordinary; one that reads as a security tool is not.
- **Check the address's history.** A recycled IP already in scanning
  blocklists skews everything the sentinel records.
- **Rootless podman needs lingering** so containers survive logout:
  `loginctl enable-linger "$USER"`.

The two hosts are joined by WireGuard or Tailscale, and the sentinel's Vector
ships over that link. Do not publish 9200 to connect them.

### The admin port problem

The sentinel wants 22, which is where you are already logged in. Move
administrative sshd first and confirm a login on the new port from a second
session before closing the first.

Moving it does not hide it. RFC 4253 §4.2 makes the identification string
mandatory, so sshd announces `SSH-2.0-<software>` before key exchange and any
port it listens on is one `nmap -sV` away from being labelled correctly.
`DebianBanner no` strips the distro suffix and the patch level with it, which
is worth doing. Recompiling for a fake version is not: fingerprinters key on
the `SSH_MSG_KEXINIT` algorithm list and its ordering, and a host that lies
about its version is more distinctive than one that does not.

What works is the packet not arriving, so restrict the port by source.
`build-ssh-allowlist.py` builds that list from the ASNs you actually connect
from and can confirm you are inside it before you apply it. Country-wide
filtering usually will not fit — a mid-sized country runs to thousands of
prefixes against a cloud firewall ceiling of a few hundred entries — and is
the weaker control anyway.

The end state is sshd bound to the tunnel address only. WireGuard has the
property sshd cannot: it never answers a packet that lacks a valid
authenticated handshake, so a UDP scan cannot distinguish it from a closed
port. The tunnel is already needed to ship logs, so the key is being paid for
regardless.

### Keep deployment facts out of the repository

Which page is instrumented, which hosts run this and which networks you
administer from are facts about one operation, not about the tool. They live
in untracked `*.local.*` files — `hosts.local.md`, `allowlist.local.json` —
and `allowlist.example.json` shows the shape. Git history is an awkward place
to discover you would rather not have committed something.

## Things that will bite you

- **TLS is not optional.** The profile page is https. An http subresource is
  blocked as mixed content, so tier 0 never fires and you will read the
  silence as "no browsers visited".
- **Caching.** The receiver sends `no-store`. If Cloudflare adds caching in
  front, repeat visits vanish and your counts go quiet for the wrong reason.
- **The sentinel takes port 22.** Move your administrative sshd to another
  port and verify you can log in on it from a second session *before* you
  start that stack.
- **Vector fails quietly on secrets.** `${VAR}` in a Vector config is not
  substituted and not rejected. It is sent as a literal. If OpenSearch starts
  returning 401, this is why.
- **Podman discards `HEALTHCHECK`** unless you build with `--format docker`,
  which `run.sh` does. The other two paths declare the probe at run time.
- **Arguments after the image name replace the default command**, they do not
  add to it. `run.sh` and the quadlet unit both restate the full argument
  list for that reason.
- **`--network=host` breaks the isolation.** The `0.0.0.0` in the Containerfile
  is the container's own namespace, and every path here publishes to
  `127.0.0.1`. That flag collapses the namespace into a real public listener.
- **The labyrinth holds threads, not coroutines.** Each held connection is a
  thread. `TARPIT_MAX_HOLDING` caps it at 64 and the PID limit is the
  backstop, but do not raise one without the other.
- **A summarising fetch layer can eat the payload.** This is how the previous
  version failed: an agent asked its fetch tool a narrow question, a small
  model answered only that question, and the injected paragraph was dropped as
  off-topic before the main model ever saw it. Keeping real bio text in the
  block, and phrasing the lure as an indexing note, is what makes it survive.
- **You cannot see a passive reader.** An agent that fetches the page and
  follows nothing leaves no trace on your host, by construction. The complete
  answer is the origin access log: a client that pulls the HTML document and
  zero subresources is an agent whether or not it takes the bait. If you can
  get those logs for your own profile page, that channel beats everything here.
- **Reporting burns the token.** Any agent working for a human will quote the
  payload back to its operator, so a careful attacker learns the page is
  instrumented on first contact. Vary wording per placement, rotate, and do not
  reuse one hostname across your whole estate.
- **Hidden text has side effects.** Screen readers read it unless `aria-hidden`
  survives, and hidden text on an institutional domain can read as search
  engine cloaking. Tell whoever runs the site that it is deliberate.

## Data handling

Most of what these indices hold belongs to somebody else. Tier 3 captures
request bodies, which may contain a third party's prompt or session text; it
ships disabled in `payload.html`. The sentinel captures credentials sprayed
at it, which are often real credentials stolen from real people. Keeping
either indefinitely is not defensible.

`bootstrap-opensearch.sh` installs a retention policy that deletes the
indices after 90 days. Set `RETENTION_DAYS` lower and re-run. Keep the
database and the volumes off shared storage.

The cover site carries no invented person's name on purpose, and neither does
the sentinel. A fabricated identity can collide with a real one, and a
honeypot that impersonates somebody is a different kind of problem.

The sentinel host should be assumed compromised eventually. Give it a
dedicated OpenSearch user with write access to `tripwire-sentinel-*` only,
rather than the admin account, and plan to rebuild it from scratch.
