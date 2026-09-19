# Wave 1a, sitting 2: the sentinel VM

Runbook for one sitting with the operator present, same rules as sitting 1
(`2026-09-19-wave1a-collector-deploy.md`): every step that touches the host
is proposed, approved, then run. `<sentinel>` is the SSH alias from the
private notes, `<sentinel-address>` the VM's public address, `<collector>`
the other alias. No hostname, address or secret belongs in this file, and
neither do the capture files of step 3: they hold the persona's hostname.

Code: `main` at or after "Keep every value in the secrets file a string",
full suite green. The collector already runs it, so every field the new
sentinel sends has a mapping waiting.

## What goes to the VM

| file | change |
|---|---|
| `sentinel.py` | passive capture only: RTT / MSS from the kernel, wrong-protocol sniff, SMTP identity fields, foreign `Host`. No byte it sends may differ; step 8 is the gate for that. |
| `vector-sentinel.toml` | field moves, `threat.exploit` table, `threat.proxy_probe`, egress classification, second path in the file source |
| `compose.sentinel.yaml` | one line: a read-only mount of `/var/log/tripwire-egress` into the Vector container |

`Containerfile.sentinel` has not changed.

## What this sitting does not do

- **Package D stays unapplied.** `harden-sentinel.sh` and `egress-watch.py`
  are not copied, no firewall rule, no sshd or sysctl change. Its one side
  effect here is step 4: the compose file now mounts a directory that only
  D's systemd unit would have created.
- No certificate, no 443, no STARTTLS (that is 1b).
- No `down`, and never `down -v`: the named volume `sentinel-logs` holds
  the identity file (the persona's stable values; losing it changes what a
  returning scanner sees) and `vector-data` holds the shipping checkpoint.

## The wire probe

`nmap -sV` classifies; this compares bytes. It sends the same seven probes
the selftest pins in `WIRE_GOLDEN`, plus a plain `GET /`, masks what is
random by design (KEXINIT cookie and padding, `Date:`), and prints one line
per probe: name, hash, length, `ascii()` of the bytes. Run from the repo
at the workstation, output to a directory outside the repo:

```bash
PYTHONPATH=. python3 - <sentinel-address> > <outside-repo>/before.txt <<'PY'
import hashlib, socket, sys
import sentinel
host = sys.argv[1]
offset = int(sys.argv[2]) if len(sys.argv) > 2 else 0   # local rehearsal only

def probe(port, data):
    with socket.create_connection((host, port + offset), timeout=30) as c:
        c.sendall(data)
        c.shutdown(socket.SHUT_WR)
        chunks = []
        try:
            while chunk := c.recv(65536):
                chunks.append(chunk)
        except TimeoutError:
            chunks.append(b"<timeout>")
    return sentinel._mask_wire(b"".join(chunks))

http = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
for name, port, data in (
    ("W1", 22, http), ("W2", 22, sentinel._hello_bytes()), ("W3", 22, sentinel._RDP_PROBE),
    ("W4", 25, sentinel._hello_bytes()), ("W5", 25, http),
    ("W6", 25, b"EHLO WIN-TEST\r\nMAIL FROM:<a@b.example>\r\nRCPT TO:<c@d.example>\r\n"
               b"AUTH LOGIN dXNlcg==\r\nQUIT\r\n"),
    ("W7", 80, b"GET http://judge.example/azenv.php HTTP/1.1\r\nHost: judge.example\r\n\r\n"),
    ("W8", 80, http),
):
    got = probe(port, data)
    print(name, hashlib.sha256(got).hexdigest()[:16], len(got), ascii(got))
PY
```

Rehearsed against a local sentinel with holds on: two runs, identical
output. Three ports from one address inside ten minutes makes the
workstation a sweeper, so ports 22 and 25 answer a few seconds late from
the second contact on (at most about ten; the timeout is 30). That is the
sentinel working. It also means the workstation's address lands in the
data: a `sweep-detected` event, and probably one `novel-fingerprint` push
for the bare-`Host` header order. Expected, once.

If `nmap` is installed, `nmap -sV -Pn -p22,25,80 <sentinel-address>` before
and after is a second opinion; compare the three port lines only, the rest
is timing. It is not needed for the gate.

## Steps

### 1. Look before touching (read-only)

```bash
# <sentinel>, as the account that owns the stack
cd ~/tripwire
podman ps --format '{{.Names}} {{.Status}} {{.Image}}'
podman compose version 2>&1 | head -n 3
podman volume ls --format '{{.Name}}'
podman images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.Created}}' localhost/sentinel
df -h ~ | tail -n 1
ls -ld /var/log/tripwire-egress
python3 -c "import json; print({k: type(v).__name__ for k, v in json.load(open('sentinel-secrets.json')).items()})"
ss -ltn | awk 'NR==1 || /:(22|25|80) /'
```

Expect `sentinel` and `sentinel-vector` up, both volumes present, the
egress directory absent (`No such file or directory`), two secrets keys
both `str` (key names and types only, never values; Vector refuses the
whole file if one value is not a string, see sitting 1). Note which compose
provider answers: `podman-compose` has no `-q` and recreates dependants
along with a service; an external `docker-compose` behaves as on the
collector.

### 2. Make sure the host copy is the one we think it is

Workstation, in the repo:

```bash
for f in sentinel.py vector-sentinel.toml compose.sentinel.yaml Containerfile.sentinel; do
  printf '%s  %s\n' "$(git show da9c980:$f | tr -d '\r' | sha256sum | cut -c1-64)" "$f"
done
```

VM: `cd ~/tripwire && sha256sum sentinel.py vector-sentinel.toml compose.sentinel.yaml Containerfile.sentinel`.

Any mismatch is an edit made on the host (or a deploy older than
`da9c980`: try the hash of the commit before). Stop, `diff`, carry the edit
into the repo or decide to drop it. `compose.sentinel.yaml` is the likely
one. A changed `sentinel.py` also makes the "before" capture of step 3 a
capture of something the repo does not know.

### 3. Capture "before"

The wire probe above, from the workstation, into `before.txt`. Pass: eight
lines, no `<timeout>`, W1 to W3 share one hash, W4 and W5 share one.

### 4. The directory the new mount needs (root, one command)

The only root step of the sitting, and the only trace of D:

```bash
sudo install -d -m 0755 -o root -g root /var/log/tripwire-egress
```

Without it `podman` refuses to create the Vector container (a bind mount
source must exist), and the sentinel would run with nothing shipping. D's
unit declares the same path as its `LogsDirectory`, root-owned, so this is
the state D will expect. An empty directory is inert: Vector's file source
treats a missing `egress.jsonl` as nothing to read.

If the operator would rather not touch root today: hold
`compose.sentinel.yaml` back, ship the other two files, and accept that
step 2 of the next sitting will report the compose file as behind.

### 5. Backup, tag the running image, copy, strip CRLF, verify

```bash
# VM
cd ~/tripwire && mkdir -p ../tripwire-backup-wave1a && cp -a sentinel.py vector-sentinel.toml compose.sentinel.yaml ../tripwire-backup-wave1a/
podman tag localhost/sentinel:latest localhost/sentinel:pre-wave1a
```

```bash
# workstation
scp sentinel.py vector-sentinel.toml compose.sentinel.yaml <sentinel>:tripwire/
```

```bash
# VM
cd ~/tripwire && sed -i 's/\r$//' sentinel.py vector-sentinel.toml compose.sentinel.yaml
sha256sum sentinel.py vector-sentinel.toml compose.sentinel.yaml
```

Compare with `git show main:$f | tr -d '\r' | sha256sum` at the
workstation. Every line must agree: that is what lets the VM trust the
workstation's `./test-vector.sh sentinel` and `sentinel.py --selftest`.

Nothing running has changed: `sentinel.py` is baked into the image, and
`sed -i` gave `vector-sentinel.toml` a new inode the running mount does not
see.

### 6. Build, and test the image before it serves anyone

```bash
podman compose -f compose.sentinel.yaml build
podman run --rm --network=none localhost/sentinel:latest --selftest
```

The build retags `latest`; the running container keeps the image it
started from, so there is still no downtime. The selftest is the first run
of the new code on this kernel, with a real `TCP_INFO`. Pass: `selftest
ok`, and no "no TCP_INFO on this platform" note (that note is for Windows).
A failure here stops the sitting with the old sentinel still serving:
`podman tag localhost/sentinel:pre-wave1a localhost/sentinel:latest` and
restore the files.

### 7. Recreate

```bash
podman compose -f compose.sentinel.yaml up -d --force-recreate
podman ps --format '{{.Names}} {{.Status}}'
podman logs --since 2m sentinel 2>&1 | tail -n 5
podman logs --since 2m sentinel-vector 2>&1 | grep -ci error
ss -ltn | awk 'NR==1 || /:(22|25|80) /'
```

Ports 22, 25 and 80 are closed for a few seconds. Pass: both containers
up and not restarting, the same three listeners as step 1, zero Vector
error lines. With `--quiet` the sentinel says little; silence is fine, a
traceback is not. Vector resumes from its checkpoint in `vector-data`, so
the connections logged during the recreate are shipped, not lost.

### 8. Capture "after": the gate

The wire probe again, into `after.txt` (wait ten minutes after step 3, or
accept that holds are a little longer: the answer bytes are the same either
way).

```bash
diff <outside-repo>/before.txt <outside-repo>/after.txt && echo IDENTICAL
```

Pass: `IDENTICAL`. **Any difference is a byte a scanner can see: go back
(table below) first, investigate at the workstation afterwards.** Do not
reason about whether the difference matters while it is live.

### 9. Do the new fields arrive?

The probe of step 8 is also the functional test: W2 is a TLS hello on 22,
W6 an SMTP session naming itself, W7 a proxy-judge request. On the
collector, with the `osq` helper of sitting 1 (GET only):

```bash
osq '/tripwire-sentinel-*/_count?q=_exists_:network.rtt_ms%20AND%20@timestamp:>now-15m'
osq '/tripwire-sentinel-*/_count?q=proto_mismatch:tls%20AND%20@timestamp:>now-15m'
osq '/tripwire-sentinel-*/_count?q=smtp.helo:WIN-TEST%20AND%20@timestamp:>now-15m'
osq '/tripwire-sentinel-*/_count?q=threat.proxy_probe:true%20AND%20http.host_foreign:true%20AND%20@timestamp:>now-15m'
osq '/tripwire-sentinel-*/_mapping/field/network.rtt_ms,proto_mismatch,smtp.helo,http.host_foreign'
```

Pipe these inside a script to `ssh <collector> bash -s`; a URL with `&`
passed as an ssh argument is split by the remote shell. Pass: every count
over zero, types `float`, `keyword`, `keyword`, `boolean` (none guessed).
In Dashboards the panels "Spoke the wrong protocol", "SMTP: EHLO names",
"RTT against GeoIP" and "Proxy probes" stop being empty; the RTT verdict
needs an address with a GeoIP position, so give it an hour.

### 10. Close

- VM: two containers up. Collector: `tripwire-sentinel-silent` stayed quiet.
- Tomorrow 07:00: digest lines "exploits:" and "wrong protocol:" are no
  longer stuck at zero.
- After a quiet day: remove `../tripwire-backup-wave1a` on both hosts and
  `podman rmi localhost/sentinel:pre-wave1a` on the VM; delete
  `before.txt` / `after.txt`; delete the six merged branches.
- `tripwire-egress` still cannot fire. That waits for D, which waits for
  the admin-path decision.

## Going back

| after step | undo |
|---|---|
| 4 | Leave the directory. It is empty and D wants it. |
| 5, 6 | `cp -a ../tripwire-backup-wave1a/* .` and `podman tag localhost/sentinel:pre-wave1a localhost/sentinel:latest`. Nothing was running the new files. |
| 7, 8 | The same two commands, then `podman compose -f compose.sentinel.yaml up -d --force-recreate` **without** `build`. Run the wire probe once more: it must equal `before.txt`. Events already indexed with the new fields stay; they are mapped and inert. |

Nothing in this sitting deletes data or a volume.

## Edge cases

| case | applies | handling |
|---|---|---|
| host file differs from the repo | possible | step 2 stops the sitting |
| egress directory missing | always, D is deferred | step 4, or hold the compose file back |
| secrets file holds a non-string | not expected (hand-written, two strings) | step 1 type check; Vector would refuse to start in step 7 |
| Windows line endings | always | step 5 `sed` |
| image rebuilt but container not recreated | would be silent | step 7 uses `--force-recreate`; step 9 proves the new code is the one answering |
| identity file lost | only through `down -v` | never run it; step 8 would show the changed hostname |
| probe address trips monitors | yes, once | expected `sweep-detected` and `novel-fingerprint` for the workstation |
| kernel without the `TCP_INFO` fields | unlikely | step 6 selftest; sentinel logs without RTT rather than failing |
| sentinel down longer than planned | possible | dead-man switch is 60 min; going back takes two commands |
| TLS on 443, JA4 | no | dormant until a certificate exists |
