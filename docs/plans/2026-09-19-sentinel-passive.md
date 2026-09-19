# A1: sentinel, passive additions

Read `2026-09-19-wave1-overview.md` first. Field names come from its contract
table.

**Owner files:** `sentinel.py`. Nothing else.
**Builder model:** opus. The work is small; the constraint is not.

## The constraint

Nothing here may change any byte the sentinel sends, or when it sends it.
Every feature below reads bytes that were arriving anyway or asks the kernel
a question about the socket. Read the module header and the fingerprints
section comment before touching a handler.

Step 0 exists to make that constraint checkable.

## Step 0: characterisation test, before any other edit

Add `_selftest_wire()` and call it from `selftest()` after `_selftest_live()`.
It starts the server the same way `_selftest_live()` does (own port offset
`41000`, own temp directory) and records what the server sends for each probe
below. Random fields are masked before comparison: the 16-byte KEXINIT cookie,
KEXINIT padding bytes, the SMTP queue id, `Date:` header values.

| probe | port role | client sends |
|---|---|---|
| W1 | ssh | `GET / HTTP/1.1\r\nHost: x\r\n\r\n` |
| W2 | ssh | `_hello_bytes()` |
| W3 | ssh | `\x03\x00\x00\x2f\x2a\xe0\x00\x00\x00\x00\x00Cookie: mstshash=hello\r\n` |
| W4 | smtp | `_hello_bytes()` |
| W5 | smtp | `GET / HTTP/1.1\r\nHost: x\r\n\r\n` |
| W6 | smtp | `EHLO WIN-TEST\r\nMAIL FROM:<a@b.example>\r\nRCPT TO:<c@d.example>\r\nAUTH LOGIN dXNlcg==\r\nQUIT\r\n` |
| W7 | http | `GET http://judge.example/azenv.php HTTP/1.1\r\nHost: judge.example\r\n\r\n` |

Run it against the untouched file, paste the masked transcripts into the
test as literals (`WIRE_GOLDEN`), commit that alone as the first commit. Every
later commit in this package must leave `WIRE_GOLDEN` untouched and passing.
A builder who needs to edit a golden literal has broken the constraint: stop
and report.

## Feature 1: RTT and MSS from the kernel

```python
def parse_tcp_info(raw: bytes) -> dict[str, float | int]:
```

Pure. Linux `struct tcp_info`: eight one-byte fields, then `u32` fields.
`tcpi_snd_mss` is at byte offset 16, `tcpi_rtt` at 68, `tcpi_rttvar` at 72,
both in microseconds, native byte order. Returns
`{"tcp_rtt_ms": rtt/1000, "tcp_rttvar_ms": rttvar/1000, "tcp_mss": snd_mss}`,
rounded to 3 places, and `{}` when `raw` is shorter than 76 bytes or the RTT
is 0.

```python
def sample_tcp_info(writer) -> dict:
```

`sock = writer.get_extra_info("socket")`; `TCP_INFO = getattr(socket,
"TCP_INFO", None)`; returns `{}` when either is missing or `getsockopt(
socket.IPPROTO_TCP, TCP_INFO, 104)` raises `OSError`. No capability is
needed for this call.

In `handle()`: sample once right after the peer address is known and once in
the path that builds the event, before the writer is closed. The event gets
the later sample when it is non-empty, otherwise the earlier one. For the
https role the writer in `handle()` is still the raw one, so nothing special
is needed.

## Feature 2: wrong-protocol detector, JA4 on any port

```python
def sniff_protocol(data: bytes) -> str | None:
```

Pure, looks at the first bytes a client sent:

| test, in order | result |
|---|---|
| starts with `SSH-` | `ssh` |
| `data[0] == 0x16 and data[1] == 0x03` and `len(data) >= 5` | `tls` |
| `data[:2] == b"\x03\x00"` or `b"mstshash=" in data[:64]` | `rdp` |
| matches `rb"^[A-Z]{3,8} \S+ HTTP/1\.[01]\r?\n"` | `http` |
| starts with `MGLNDD_` | `mglndd` |
| more than a quarter of the first 32 bytes are outside `0x09-0x0d, 0x20-0x7e` | `binary` |
| otherwise | `None` |

`EHLO`, `HELO` and other SMTP verbs return `None`: the detector names
foreign protocols, it does not validate the native one.

Wiring. `note["proto_mismatch"] = sniffed` only when `sniffed` is not `None`
and differs from the port's own protocol (`ssh` on an ssh role is not a
mismatch; `tls` on the https role is not a mismatch).

- `do_ssh`: today the client's first line goes into `note["ssh_client"]`. Keep
  that exactly as it is, and additionally run `sniff_protocol` on the same
  bytes. When the result is `tls`, the hello has no newline and `readline()`
  will have returned whatever arrived before its limit or the timeout: keep
  those bytes, continue with `read_until(reader, _hello_complete, 16384,
  <the existing ssh timeout budget>)` seeded with them, and on a complete
  hello set `tls_ja4`, `tls_version`, `tls_sni`, `tls_alpn` exactly as
  `do_https` does. Factor the four assignments in `do_https` into
  `_note_client_hello(note, data)` and call it from all three places rather
  than copying them.
- `do_smtp`: same, on the first data the client sends. A TLS hello will not
  end in `\r\n`; whatever read call the handler uses today must keep
  returning to the client what it returns today (W4 proves it).
- What the server replies and when it closes stays as it is. If getting the
  hello bytes would require holding the connection longer than the handler
  does today, do not hold it: record what arrived and move on.

## Feature 3: SMTP identity keys

```python
def smtp_identity(commands: list[str]) -> dict:
```

Pure, fed the same list that becomes `note["smtp_commands"]`.

- `smtp_helo`: argument of the first `EHLO` or `HELO`, stripped, max 255.
- `smtp_mail_from`: text between `<` and `>` of the first `MAIL FROM:`, max 320.
- `smtp_rcpt`: same for every `RCPT TO:`, in order, distinct, max 8.
- `smtp_auth_user`: for `AUTH LOGIN <b64>` the decoded initial response; for
  `AUTH PLAIN <b64>` the second NUL-separated part. `base64.b64decode(...,
  validate=True)`, then `decode("utf-8", "replace")`, max 128. Any decoding
  error yields no key. The password half is not extracted: the raw command
  is already in `smtp_commands` and that is enough.
- Verbs match case-insensitively. Keys with no value are omitted.

`do_smtp` merges the result into `note` once, where it stores
`smtp_commands`.

## Feature 4: foreign Host header

In `do_http`, for the first request: `http_host_foreign = True` when a Host
header is present and its host part (port stripped, brackets stripped,
lowercased) equals neither `writer.get_extra_info("sockname")[0]` nor the
identity hostname. Omit the key otherwise. Under `TlsStream` the sockname
comes from the underlying writer; pass it in rather than reaching through.

## Acceptance tests (the builder implements exactly these in `selftest()`)

1. `parse_tcp_info(b"\x00" * 16 + struct.pack("=I", 1448) + b"\x00" * 48 +
   struct.pack("=II", 23500, 4200) + b"\x00" * 28)` equals
   `{"tcp_rtt_ms": 23.5, "tcp_rttvar_ms": 4.2, "tcp_mss": 1448}`.
2. `parse_tcp_info(b"")` and `parse_tcp_info(b"\x00" * 104)` are `{}`.
3. `sample_tcp_info` on an object whose `get_extra_info` returns `None` is `{}`.
4. On Linux only (`hasattr(socket, "TCP_INFO")`): the live event for a
   loopback connection has `0 < tcp_rtt_ms < 50` and `tcp_mss > 0`. On other
   platforms the assertion is skipped with a printed note, never silently.
5. `sniff_protocol` returns, in order, `ssh`, `tls`, `rdp`, `http`, `mglndd`,
   `binary`, `None`, `None` for: `b"SSH-2.0-Go\r\n"`, `_hello_bytes()`, W3's
   bytes, `b"GET / HTTP/1.1\r\n"`, `b"MGLNDD_192.0.2.1_22\n"`,
   `bytes(range(32))`, `b"EHLO x\r\n"`, `b""`.
6. Live, port role ssh: W1 produces an event with `proto_mismatch == "http"`
   and `ssh_client` still set as today; W2 produces `proto_mismatch == "tls"`
   and `tls_ja4 == ja4(parse_client_hello(_hello_bytes()))`; a normal
   `SSH-2.0-Test` client produces no `proto_mismatch` key.
7. Live, port role smtp: W4 produces `proto_mismatch == "tls"` and the same
   JA4; W6 produces no `proto_mismatch`, `smtp_helo == "WIN-TEST"`,
   `smtp_mail_from == "a@b.example"`, `smtp_rcpt == ["c@d.example"]`,
   `smtp_auth_user == "user"`.
8. `smtp_identity(["AUTH PLAIN AHVzZXIAcGFzcw=="])["smtp_auth_user"] ==
   "user"`; `smtp_identity(["AUTH LOGIN !!!"])` has no `smtp_auth_user`;
   `smtp_identity(["rcpt to:<A@B>"] * 20)["smtp_rcpt"] == ["A@B"]`.
9. Live, http: W7 produces `http_host_foreign is True`; `Host: 127.0.0.1`
   produces no such key.
10. `WIRE_GOLDEN` from step 0 passes unchanged.

## Edge-case matrix

| axis | applies | note |
|---|---|---|
| Windows dev machine, no `TCP_INFO` | yes | tests 1-3 run everywhere, 4 only on Linux |
| IPv6 peer | yes | `sockname` is a 4-tuple, index 0 still the address |
| client resets before close | yes | second sample raises `OSError`, first sample is used |
| shed-load and sweep summary events | yes | they have no socket at build time: no `tcp_*` keys, no error |
| https role with certificate | yes | `tls` there is not a mismatch |
| hello split across segments on 22/25 | yes | record what arrived within the existing time budget, never wait longer |
| attacker text in assertions output | yes | print with `ascii()` |

## Knobs

None of these features has a feel component. The one number is the
`binary` threshold (a quarter of 32 bytes): make it a module constant
`SNIFF_BINARY_RATIO = 0.25`.

## Where's the door handle

The operator meets these in Dashboards (package M adds the panels): a
"spoke the wrong protocol" breakdown, JA4 values appearing weeks before the
VM has a certificate, EHLO names as a column in the SMTP saved search, and
RTT as a number beside every address. If `TCP_INFO` is unavailable the
sentinel prints one line at start-up, `NOTE: no TCP_INFO on this platform,
RTT not recorded`, to stderr. Silence would look like a bug.

## Validation

```
python -m py_compile sentinel.py
python sentinel.py --selftest
```

`git add sentinel.py` only. Two commits minimum: step 0 alone, then the
features. Commit messages in plain prose, why before what. Report deviations
with reasons, in particular anywhere the existing read calls made it
impossible to get the hello bytes without changing timing.

## Deploy (orchestrator)

Copy to the VM, strip CRLF, rebuild, `up -d --force-recreate`. Then from
outside: `nmap -sV -p22,25,80` output must be identical to a capture taken
before the deploy.
