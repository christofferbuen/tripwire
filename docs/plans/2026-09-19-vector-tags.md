# C: Vector, field moves, exploit and proxy tags

Read `2026-09-19-wave1-overview.md` first. The field contract there is the
specification for the moves.

**Owner files:** `vector-sentinel.toml`, `vector.toml`,
`vector-tests-sentinel.toml` (new), `vector-tests-collector.toml` (new),
`test-vector.sh` (new).
**Builder model:** sonnet.

Both transforms run with `drop_on_error = true`. One unguarded expression
loses the whole event, silently as far as the dashboards are concerned.
Every line added here is either guarded by `exists()` or ends in `??`.

## 1. Field moves, `vector-sentinel.toml`

After the existing fingerprint moves, in the same style (`del()` returns the
value, so each line is a move):

```
if exists(.tcp_rtt_ms) { .network.rtt_ms = del(.tcp_rtt_ms) }
if exists(.tcp_rttvar_ms) { .network.rttvar_ms = del(.tcp_rttvar_ms) }
if exists(.tcp_mss) { .network.mss = del(.tcp_mss) }
if exists(.smtp_helo) { .smtp.helo = del(.smtp_helo) }
if exists(.smtp_mail_from) { .smtp.mail_from = del(.smtp_mail_from) }
if exists(.smtp_rcpt) { .smtp.rcpt = del(.smtp_rcpt) }
if exists(.smtp_auth_user) { .smtp.auth_user = del(.smtp_auth_user) }
if exists(.smtp_auth_pass) { .smtp.auth_pass = del(.smtp_auth_pass) }
if exists(.smtp_starttls) { .smtp.starttls = del(.smtp_starttls) }
if exists(.http_host_foreign) { .http.host_foreign = del(.http_host_foreign) }
if exists(.bait_served) { .bait.served = del(.bait_served) }
if exists(.bait_credential_used) { .bait.credential_used = del(.bait_credential_used) }
if exists(.egress_dst_ip) { .egress.dst_ip = del(.egress_dst_ip) }
if exists(.egress_dst_port) { .egress.dst_port = del(.egress_dst_port) }
if exists(.egress_proto) { .egress.proto = del(.egress_proto) }
if exists(.egress_uid) { .egress.uid = del(.egress_uid) }
if exists(.egress_scope) { .egress.scope = del(.egress_scope) }
if exists(.egress_count) { .egress.count = del(.egress_count) }
```

`proto_mismatch` stays flat. The A2 and egress names are moved now so this
file is not reopened later; an absent field costs nothing.

## 2. Egress events, `vector-sentinel.toml`

Package D writes `/var/log/tripwire-egress/egress.jsonl`. Add that path to
the existing source's `include` list. Those lines carry `kind: "egress"` and
no `ip`. In the classification chain, before the `sweep` test: `kind ==
"egress"` gives `"egress-blocked"`. `.source = { "ip": .ip }` with a null
`ip` must not drop the event; test E1 proves it. A missing file must not
stop Vector from starting (it does not, for a file source; leave a comment
saying so).

## 3. `threat.exploit`, both files

An array of names, because one request line can carry two. Computed from a
haystack: in the sentinel file, the lowercased join of `http_requests` plus
`http_body`; in the collector file, lowercased `path` plus `body_excerpt`.
Placed **after** the line that assigns `.threat`, since that line replaces
the object. Written as `.threat.exploit = names` only when the array is not
empty.

Needles are matched lowercased, with `contains()`:

| needle | name |
|---|---|
| `/sdk/weblanguage` | `hikvision-cve-2021-36260` |
| `/boaform/admin/formlogin` | `boa-formlogin` |
| `/cgi-bin/luci/;stok=/locale` | `tplink-cve-2023-1389` |
| `/gponform/diag_form` | `gpon-cve-2018-10561` |
| `/hnap1` | `dlink-hnap` |
| `setup.cgi?next_file=netgear.cfg` | `netgear-dgn-setup-cgi` |
| `eval-stdin.php` | `phpunit-cve-2017-9841` |
| `/actuator/gateway/routes` | `spring-gateway-cve-2022-22947` |
| `/cgi-bin/.%2e/` | `apache-cve-2021-41773` |
| `/_ignition/execute-solution` | `laravel-ignition-cve-2021-3129` |
| `${jndi:` | `log4shell-cve-2021-44228` |
| `/autodiscover/autodiscover.json` | `exchange-proxyshell` |
| `/mgmt/tm/util/bash` | `f5-cve-2022-1388` |
| `/ws/v1/cluster/apps/new-application` | `hadoop-yarn-rce` |
| `/device.rsp?opt=sys&cmd=` | `tbk-dvr-cve-2024-3721` |
| `/shell?cd+/tmp` | `jaws-webserver-rce` |

The table is duplicated in the two files, like the user-agent table already
is, with the same "keep them in step" comment. VRL has no includes; a
generator script would be more machinery than sixteen lines deserve.

Form: build the array with `push` inside guarded `if contains(hay, "...")`
blocks, one per row, so adding a row is adding a line.

## 4. `threat.proxy_probe`, `vector-sentinel.toml` only

`true` when any request line starts with `CONNECT ` or matches
`^[A-Z]+ https?://` (an absolute-URI target). Case-sensitive on the method,
as HTTP is. Absent otherwise. The receiver sits behind a CDN that never
forwards such requests, so the collector file does not get this.

## Tests

Vector's own unit tests (`[[tests]]`), one file per topology because the two
configs cannot be loaded together. `test-vector.sh` is the single entry
point:

```
./test-vector.sh            # both
./test-vector.sh sentinel   # one
```

It writes a dummy secrets JSON to a temp dir, then runs the pinned image
(`timberio/vector:0.58.0-alpine`, same tag the compose files use) with
`podman run --rm --network=none`, mounting the repo read-only and the dummy
secrets at the path each config expects, and executes `vector test <config>
<tests file>`. Exit code is Vector's. No network, no daemon, nothing left
running. If `podman` is missing it says so and exits 2.

`vector-tests-sentinel.toml`, each inserting at `sentinel_events` with a
`message` holding one JSON line:

- S1 baseline: a plain SSH connect line from today's format still yields
  `classification == "service-interaction"` and `threat.tool == "go-ssh"`.
- S2 moves: a line with every flat field from section 1 yields the nested
  fields with the same values and none of the flat names; `smtp.rcpt` is
  still an array of two.
- S3 absent: a line with none of them yields no `network`, `smtp`, `bait` or
  `egress` key.
- S4 `http_requests: ["POST /SDK/webLanguage HTTP/1.1"]` yields
  `threat.exploit == ["hikvision-cve-2021-36260"]` and keeps `threat.tool`.
- S5 two needles in one event (`/HNAP1` request, `${jndi:ldap://x}` in
  `http_body`) yield both names.
- S6 `http_requests: ["GET / HTTP/1.1"]` yields no `threat.exploit`.
- S7 `CONNECT example.com:443 HTTP/1.1` and `GET http://example.com/ HTTP/1.1`
  each yield `threat.proxy_probe == true`; `GET /http://x HTTP/1.1` and
  `connect x` do not.
- S8 types under attack: `http_requests` as a string, as `null`, as an array
  holding a number; `http_body` as an object. The event is not dropped.
- E1 an egress line (`kind: "egress"`, no `ip`, the six `egress_*` fields)
  yields `classification == "egress-blocked"`, `egress.dst_port` as sent, and
  is not dropped.
- E2 a `kind: "sweep"` line still yields `sweep-detected`.

`vector-tests-collector.toml`, inserting at `hits`:

- H1 baseline: a current-format hit still yields its `tier_name` and
  `threat.tool`.
- H2 `path: "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"` yields the
  phpunit name.
- H3 `body_excerpt` containing `${jndi:` yields the log4shell name with
  `path: "/"`.
- H4 `path` missing and `body_excerpt` a number: not dropped.

Take the baseline lines from the selftests of `sentinel.py` and
`receiver.py` output formats, not from production data.

## Edge-case matrix

| axis | applies | note |
|---|---|---|
| old sentinel still deployed (no new fields) | yes | S3; this package can ship before A1 |
| new sentinel, old Vector | yes | flat fields get dynamically mapped until C deploys; deploy C first or together |
| sweep and shed-load lines | yes | E2; they carry no `http_requests` |
| egress file absent | yes | source tolerates it |
| hostile types in payload fields | yes | S8, H4 |
| needle in upper or mixed case | yes | haystack is lowercased, needles are written lowercase |
| Vector on the VM reads config at start only | yes | stop/start, not restart, under rootless podman |

## Where's the door handle

Operator: `threat.exploit` and `threat.proxy_probe` become filters and a
panel (package M). Adding a signature is one table row in two files and one
test line; the comment above each table says exactly that. A developer who
breaks a transform finds out from `./test-vector.sh` instead of from an
empty dashboard a day later.

## Validation

`./test-vector.sh`. `git add` the five owner files by name. Report
deviations with reasons, including any VRL function that behaves differently
in 0.58 than this plan assumes.
