# A2: sentinel, STARTTLS and the bait file

Read `2026-09-19-wave1-overview.md` first. Starts only after A1 has landed
and been deployed: it builds on `_note_client_hello`, `smtp_identity` and
`WIRE_GOLDEN`.

**Owner files:** `sentinel.py`, `compose.sentinel.yaml`, `make-snakeoil.sh`
(new), `.gitignore`.
**Builder model:** opus.

## The constraint, and its three exceptions

A1's rule was "no byte changes". This package changes bytes, on purpose,
with the operator's approval, in exactly three places. Each is off unless a
flag turns it on, and with the flags absent `WIRE_GOLDEN` passes unedited.

| # | where | today | with the flag |
|---|---|---|---|
| X1 | port 25, `STARTTLS` | `454 4.7.0 TLS not available due to temporary reason` | `220 2.0.0 Ready to start TLS`, then a TLS handshake |
| X2 | port 25, inside TLS only | not reachable | EHLO list without `250-STARTTLS` and with `250-AUTH PLAIN LOGIN` in its place; an AUTH dialogue that always fails; a second `STARTTLS` answered `554 5.5.1 Error: TLS already active` |
| X3 | port 80, `GET` or `HEAD` of `/.env` | the 404 page | `200` with the bait file |

Outside TLS, `AUTH` keeps answering `503 5.5.1 Error: authentication not
enabled`. That is what Postfix says when `smtpd_tls_auth_only = yes`, so the
existing line and the new behaviour tell one consistent story.

Anything else that changes on the wire is a defect.

## Feature 1: STARTTLS on 25

Flags `--smtp-cert`, `--smtp-key`. `main()` builds a second server-side
`ssl.SSLContext` from them; both or neither, else exit with a clear message.

Refactor first, in its own commit, with no behaviour change: lift the
handshake loop out of `do_https` into

```python
async def _tls_accept(self, reader, writer, note, context, first_bytes: bytes = b"") -> TlsStream | None
```

which reads the ClientHello with `read_until(reader, _hello_complete, 16384,
…)`, calls `_note_client_hello(note, buf)`, runs the `MemoryBIO` handshake
and returns the stream, or `None` on any failure (silently, as today).
`do_https` becomes a caller. Likewise lift the SMTP command loop into a
method that takes `(reader, writer, note, commands, secure: bool)` so it can
run a second time over the `TlsStream`.

On `STARTTLS` with a context: write the `220`, drain, `_tls_accept`. On
`None`, return: Postfix drops a failed handshake without a word. On success
set `note["smtp_starttls"] = True` and continue the dialogue on the stream
with `secure=True`. The 24-command cap and the timeouts span both halves.
Plaintext that was pipelined behind `STARTTLS` ends up parsed as a hello,
fails, and the connection closes; that is the fixed-Postfix behaviour too.

This is what wakes JA4 on the mail port: about 75 addresses were already
sending `STARTTLS` to a server that could not answer it.

### The certificate: `make-snakeoil.sh`

The standard library cannot make a certificate, so this one step uses the
`openssl` binary, once, at deploy time, outside the sentinel. Ubuntu's
Postfix ships pointing at the `ssl-cert` package's snakeoil pair: RSA 2048,
self-signed, subject and SAN equal to the host's name, ten years from the
day the package was installed.

```
make-snakeoil.sh IDENTITY_JSON OUT_DIR
```

Reads `hostname` and `installed` from the identity file (with `python3 -c`,
no `jq`), runs `openssl req -x509 -newkey rsa:2048 -nodes` with
`-subj "/CN=<hostname>"`, `-addext "subjectAltName=DNS:<hostname>"`,
`-not_before <installed>` and `-not_after <installed + 3650 d>`. Refuses to
overwrite an existing pair: a certificate that changes is a tell. If the
local `openssl` is too old for `-not_before`, say so and stop; do not fall
back to today's date silently.

## Feature 2: AUTH inside TLS

Only when `secure` is true.

- `AUTH LOGIN` → `334 VXNlcm5hbWU6`, read a line, → `334 UGFzc3dvcmQ6`, read
  a line, → `535 5.7.8 Error: authentication failed: UGFzc3dvcmQ6`.
- `AUTH LOGIN <initial>` skips the first prompt.
- `AUTH PLAIN <initial>` → `535 5.7.8 Error: authentication failed:`.
  `AUTH PLAIN` alone → `334 `, read a line, same `535`.
- `*` as a response → `501 5.7.0 Authentication aborted`.
- Any other mechanism → `535 5.7.8 Error: authentication failed: Invalid
  authentication mechanism`.

The response lines are appended to `commands` like any other line.
Extend `smtp_identity` to read them: `smtp_auth_user` as in A1, plus
`smtp_auth_pass` (decoded, max 128) when a complete LOGIN or PLAIN exchange
is present. Nobody is ever authenticated. There is no code path that
returns a 235.

## Feature 3: the bait file

Flag `--bait-env FILE`. Read once at start, at most 8 KiB, else exit with a
message.

- Served for `GET` and `HEAD` of exactly `/.env` (query string ignored), on
  nginx personas only. An Apache persona logs a start-up note and keeps the
  404: Apache's headers for an extensionless file differ and nobody needs
  that yet.
- Response: `200`, `Content-Type: application/octet-stream` (nginx's
  `default_type`; add a `content_type` keyword to `http_response`, defaulting
  to today's value), `Last-Modified` from the bait file's mtime, `ETag` in
  the same form `identity.etag` produces but from that mtime and length,
  `Accept-Ranges: bytes`.
- `note["bait_served"] = "env"`.

Tokens: every `KEY=value` line whose value, quotes stripped, is 8 characters
or longer contributes that value to `self.bait_tokens`.

```python
def bait_hit(self, *texts: str) -> bool     # any token in any text
```

Checked against: decoded SMTP AUTH user and password, `http_body`, the
request lines, a decoded `Authorization: Basic` header. A hit sets
`note["bait_credential_used"] = True`. The token is not echoed into the
event: the raw fields already hold it.

### What goes in the file

The file is **not in this repo and neither is a template for it**. The repo
is public; a published bait is a signature. The operator writes it on the
VM. Requirements: it reads like a small PHP application's production
`.env`; database settings point at `127.0.0.1`; mail settings point at this
host's port 25 with a username and password (these come back through
Feature 2); a deploy block names this host, the fake VM's port, user
`deploy` and the bait password from package E's env file; no cloud-provider
keys, because nothing here could see them being tried; every secret in it
is random and used nowhere else. Set the mtime to a believable date with
`touch -d`.

## `compose.sentinel.yaml`, `.gitignore`

Read-only mounts for the certificate pair and the bait file from a `bait/`
directory beside the compose file, and the three flags on the command.
`.gitignore` gains `bait/` and `*.pem`. The container user must be able to
read the key: the deploy notes say how (`podman unshare chown`), the repo
holds no key.

## Acceptance tests (implement exactly these in `selftest()`)

The TLS tests need a certificate. The selftest makes a throwaway pair with
`openssl` when `shutil.which("openssl")` finds one, in its temp directory,
and otherwise prints `SKIPPED: no openssl, STARTTLS not tested` and
continues. The builder's own run must not be a skipped one (Git Bash has
`openssl`); paste the line that proves it into the report.

1. `WIRE_GOLDEN` W1-W7 pass unedited with no new flags.
2. With the cert flags, plaintext EHLO is byte-identical to W6's EHLO reply.
3. `STARTTLS` → `220 2.0.0 Ready to start TLS\r\n`; a stdlib `ssl` client
   (verification off) completes the handshake; the event has `smtp_starttls
   is True` and a `tls_ja4` that starts with `t`.
4. Inside TLS: the EHLO reply has no `STARTTLS` line and has `250-AUTH PLAIN
   LOGIN` as its sixth line; a second `STARTTLS` gets the `554`.
5. Inside TLS: `AUTH LOGIN`, `dXNlcg==`, `cGFzcw==` gets the two `334` lines
   and the LOGIN `535`; the event has `smtp_auth_user == "user"` and
   `smtp_auth_pass == "pass"`. `AUTH PLAIN AHVzZXIAcGFzcw==` gets the PLAIN
   `535` and the same two fields. No input produces a line starting `235`.
6. Outside TLS, with the cert flags: `AUTH LOGIN` still gets the `503`.
7. `STARTTLS` followed by garbage instead of a hello: the connection closes,
   the event exists, no exception reaches the log.
8. With `--bait-env` holding `MAIL_PASSWORD=Zx81-bait-token\nAPP_ENV=prod\n`:
   `GET /.env` gives `200`, `Content-Type: application/octet-stream`, the
   exact body, and `bait_served == "env"`; `HEAD` gives the same headers and
   no body; `GET /.env.bak` and `GET /.ENV` give the 404 page byte for byte;
   `POST /.env` gives the 405 as today.
9. Without `--bait-env`, `GET /.env` is the golden 404.
10. Bait tokens: `prod` (4 characters) is not a token. A POST body containing
    `Zx81-bait-token` sets `bait_credential_used`; test 5 repeated with that
    password sets it; a body with `Zx81-bait` does not.
11. New goldens W8 (test 3's plaintext half), W9 (test 8's response with
    `Date` and `ETag` masked) are added. W1-W7 literals are untouched in the
    diff.
12. `bash -n make-snakeoil.sh`; run against a sample identity it yields a
    certificate whose subject, SAN, `notBefore` and key size are asserted
    with `openssl x509 -noout -text`; a second run refuses.

## Edge-case matrix

| axis | applies | note |
|---|---|---|
| no flags | yes | today's sentinel, byte for byte |
| cert flags, client never sends STARTTLS | yes | test 2 |
| TLS client with no shared cipher, or SSLv3 | yes | handshake fails, silent close |
| slow-loris inside TLS | yes | same timeouts and command cap as plaintext |
| https role also enabled | yes | separate context; `_tls_accept` shared |
| Apache persona with `--bait-env` | yes | start-up note, 404 |
| bait file unreadable or over 8 KiB | yes | exit at start with a message, not a traceback |
| keep-alive: `/.env` as second request | yes | served; `bait_served` still set |
| attacker strings in test output | yes | `ascii()` |
| Windows dev machine | yes | tests run from Git Bash; skip is loud |

## Knobs

None with a feel. The bait token minimum length (8) and the file size cap
are module constants.

## Where's the door handle

The attacker's: the `.env` they were already asking for, 1 500 addresses
strong, now exists. It gives them a mailbox login that fails politely over
TLS and a deploy login that works (package E).

The operator's: `bait.served` and `bait.credential_used` as filters, the
high-channel alert from E when the deploy login is used, SMTP passwords as a
column in "SMTP identities". At start-up the sentinel prints one line for
each feature: on, or off and why.

## Validation

```
python -m py_compile sentinel.py
python sentinel.py --selftest        # from Git Bash, STARTTLS not skipped
bash -n make-snakeoil.sh
```

Commits: the refactor alone first (goldens prove it changed nothing), then
the features. `git add` the four owner files by name. Report deviations
with reasons.

## Deploy (orchestrator, with the operator)

`--build-window`, make the certificate on the VM from the live identity
file, write the bait file, fix ownership for the container user, rebuild,
recreate. From outside: `nmap -sV -p22,25,80` equals the pre-deploy capture
except that `smtp-commands`-style scripts now complete STARTTLS; `openssl
s_client -starttls smtp` shows the snakeoil certificate with the expected
dates. The bait file's deploy block goes live only when package E is up:
until then, serve a version without it.
