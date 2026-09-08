#!/usr/bin/env python3
"""Sentinel: a low-interaction listener that records who is scanning you.

Standard library only. Runs on its own host, deliberately exposed, and ships
into the same OpenSearch index as the tripwire receiver.

Why a separate host. The receiver sits behind a Cloudflare Tunnel, which
means it has no reachable address at the IP layer: the tunnel dials out and
nothing can dial in. That is the right shape for the receiver and it makes
port-scan detection on that box impossible. This is the other half.

================================================================================
NOT LOOKING LIKE A HONEYPOT
================================================================================

Anything that answers on a port gets fingerprinted. Shodan, Censys and the
various honeypot scorers all run the same handful of checks, and the naive
version of this program fails every one of them. What follows is what those
checks actually look for and what this program does about it.

1. An implausible spread of ports. The single loudest tell. One host with
   FTP, telnet, SMB, RDP, MySQL, Postgres, Redis, VNC and Mongo all open is
   not a server anybody runs, it is a honeypot advertising itself. Fixed by
   personas: a small, coherent set of ports that tells one consistent story
   about one machine. The default is three ports.

2. Banners that disagree with each other. A Debian FTP daemon next to an
   Ubuntu SSH daemon next to a Windows-build MySQL is a machine that cannot
   exist. Every version string in a persona is drawn from one real
   distribution release and they agree.

3. A protocol banner with no protocol behind it. Printing "SSH-2.0-OpenSSH"
   and then falling silent is detected by the first `nmap -sV`, because the
   service probe expects a key exchange. This program speaks enough of SSH
   to send a real KEXINIT with OpenSSH's actual algorithm lists, and enough
   of MySQL to send a well-formed protocol 10 handshake and a proper access
   denied error. A scanner gets a clean, correct fingerprint.

4. Byte-identical responses. Real servers vary: a fresh SSH cookie, a fresh
   MySQL salt and thread id, a moving Date header, a new SMTP queue id. A
   service that returns the same bytes to every connection forever is a
   recording. Everything variable here varies.

5. Suspiciously constant timing. Every response carries a small jittered
   delay, because a service that answers in exactly the same number of
   microseconds every time is not doing any work.

6. The tarpit itself. Dripping junk into a connection at a fixed interval is
   the published signature of the well-known SSH tarpits, and sending banner
   noise before the ident string is that signature exactly. This one holds
   connections by going quiet after a legitimate protocol exchange, which is
   what a loaded server looks like. Holds are jittered, never applied to a
   first contact, and never applied to the web port at all, because a person
   might genuinely be reading it.

7. An identity that changes. Shodan comes back. If the version strings move
   between scans the host is synthetic. The persona and every stable value
   derived from it are written to an identity file on first run and reused.

What this program cannot fix, and you have to handle yourself:

  - The PTR record. No reverse DNS, or a cloud provider's default, is a
    strong negative signal. Set something dull and plausible.
  - The address itself. Ranges belonging to hosting providers known for
    research scanning are pre-tagged by the scorers regardless of what you
    serve. A residential or small-business allocation scores far better.
  - The TLS certificate, if you enable the HTTPS port. A self-signed
    certificate with a one-day-old notBefore is a tell. Use a real one.
  - History. A host that appeared last week with these ports open and no
    prior record is thin. There is no shortcut for this; it just takes time.

None of the above makes the host attack anything. Nothing a client sends is
executed, interpreted, or stored anywhere it can run. There is no shell, no
filesystem access and no real service. The entire program is a set of
sockets that write to a log.

Data note. Ports 25 and 3306 collect login attempts, and those contain
credentials belonging to whoever was sprayed before you. Treat the log as
sensitive, keep retention short, and do not republish it.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import pathlib
import random
import signal
import socket
import struct
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Personas
#
# Each one is a single real machine: one distribution release, and the
# package versions that release actually shipped. Ports are the ones that
# machine would plausibly have open and no others. Adding a port to a persona
# because it might catch something is how you end up with the implausible
# spread that gets the host flagged.
# ---------------------------------------------------------------------------

PERSONAS: dict[str, dict[str, object]] = {
    # The commonest thing on the internet: a small Ubuntu box with a web
    # server nobody finished configuring and a mail daemon that came with it.
    "ubuntu-web": {
        "release": "Ubuntu 20.04.6 LTS",
        "roles": {22: "ssh", 25: "smtp", 80: "http", 443: "https"},
        "ssh_ident": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.13",
        "http_server": "nginx/1.18.0 (Ubuntu)",
        "smtp_software": "Postfix (Ubuntu)",
        "mysql_version": "8.0.36-0ubuntu0.20.04.1",
    },
    # A Debian LAMP host with the database port left open to the world, which
    # is careless and extremely common.
    "debian-lamp": {
        "release": "Debian GNU/Linux 11 (bullseye)",
        "roles": {22: "ssh", 80: "http", 443: "https", 3306: "mysql"},
        "ssh_ident": "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
        "http_server": "Apache/2.4.62 (Debian)",
        "smtp_software": "Postfix (Debian/GNU)",
        # Oracle's MySQL APT repo build for bullseye. An Ubuntu build string
        # on a Debian box is precisely the inconsistency that gets a host
        # flagged, so this is not interchangeable with the entries above.
        "mysql_version": "8.0.36-1debian11",
    },
    # A developer's box. Fewer ports, more interesting ones.
    "dev-box": {
        "release": "Ubuntu 22.04.5 LTS",
        "roles": {22: "ssh", 80: "http", 8080: "http", 3306: "mysql"},
        "ssh_ident": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        "http_server": "nginx/1.18.0 (Ubuntu)",
        "smtp_software": "Postfix (Ubuntu)",
        "mysql_version": "8.0.39-0ubuntu0.22.04.1",
    },
}

# The actual Ubuntu nginx default page. Serving this invents nothing and puts
# the host in the company of the hundreds of thousands of real machines whose
# owner installed a web server and stopped there. A page naming a made-up
# company would be both a lie and a thing that could collide with a real one.
NGINX_DEFAULT = b"""<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
"""

APACHE_DEFAULT = b"""<!DOCTYPE html>
<html><head><title>Apache2 Debian Default Page: It works</title></head>
<body><div class="page_header"><h1>Apache2 Debian Default Page</h1></div>
<p>This is the default welcome page used to test the correct operation of the
Apache2 server after installation on Debian systems.</p>
<p>If you are a normal user of this web site and don't know what this page is
about, this probably means that the site is currently unavailable due to
maintenance.</p>
</body></html>
"""

# OpenSSH 8.2's real server algorithm lists. A scanner running ssh-audit gets
# a consistent answer, and one that matches the version string in the ident.
SSH_KEX = (
    "curve25519-sha256,curve25519-sha256@libssh.org,"
    "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
    "diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,"
    "diffie-hellman-group18-sha512,diffie-hellman-group14-sha256"
)
SSH_HOSTKEY = (
    "rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519"
)
SSH_CIPHER = (
    "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,"
    "aes128-gcm@openssh.com,aes256-gcm@openssh.com"
)
SSH_MAC = (
    "umac-64-etm@openssh.com,umac-128-etm@openssh.com,"
    "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
    "hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,"
    "hmac-sha2-256,hmac-sha2-512,hmac-sha1"
)
SSH_COMPRESSION = "none,zlib@openssh.com"

READ_LIMIT = 8192

# How long each role waits for a client that has connected and said nothing.
# These are the real daemons' defaults, not round numbers: OpenSSH's
# LoginGraceTime, nginx's client_header_timeout and keepalive_timeout,
# Postfix's smtpd_timeout, MySQL's connect_timeout. A client that measures
# how long a socket stays open before being dropped is measuring a
# configuration value, and it should get the one the banner implies.
TIMEOUTS = {
    "ssh": 120.0,
    "http_header": 60.0,
    "http_keepalive": 65.0,
    "smtp": 300.0,
    "mysql": 10.0,
    "other": 30.0,
}

SWEEP_PORTS = 3            # distinct ports before an address counts as sweeping
SWEEP_WINDOW = 600.0       # seconds of history behind that count
MAX_HOLD = 240.0           # seconds any single connection is held
MAX_CONCURRENT = 512
FORGET = 3600.0

# Never held, whatever the client has been doing. Somebody might be reading
# the page, and a web server that stalls is the thing a human notices and
# reports. The evidence is in the log either way.
NEVER_HOLD = {"http", "https"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def http_date(when: float | None = None) -> str:
    stamp = datetime.fromtimestamp(when or time.time(), timezone.utc)
    return stamp.strftime("%a, %d %b %Y %H:%M:%S GMT")


class JsonlSink:
    """Append one JSON object per event, for a log shipper to tail."""

    def __init__(self, path: str, max_bytes: int = 32 * 1024 * 1024) -> None:
        self._path = pathlib.Path(path)
        self._max = max_bytes
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self._path.open("a", encoding="utf-8")

    def write(self, event: dict[str, object]) -> None:
        line = json.dumps(event, ensure_ascii=False, default=str)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
            if self._fh.tell() >= self._max:
                self._fh.close()
                self._path.replace(self._path.with_suffix(self._path.suffix + ".1"))
                self._fh = self._path.open("a", encoding="utf-8")

    def close(self) -> None:
        with self._lock:
            self._fh.close()


class Identity:
    """Values that must stay the same across restarts.

    Scanners revisit. A host whose ETag, boot time or MySQL server id moves
    every time the process restarts is a process, not a machine. These are
    generated once and written next to the log.
    """

    def __init__(self, path: pathlib.Path, persona: str, hostname: str) -> None:
        self.path = path
        data: dict[str, object] = {}
        if path.exists():
            with contextlib.suppress(Exception):
                data = json.loads(path.read_text())

        self.persona = str(data.get("persona") or persona)
        self.hostname = str(data.get("hostname") or hostname)
        self.boot = float(data.get("boot") or time.time())
        # nginx derives its ETag from the file's mtime and size. A plausible
        # install date makes the whole thing hang together.
        self.installed = float(
            data.get("installed") or (self.boot - random.uniform(90, 700) * 86400)
        )
        self.mysql_base_id = int(data.get("mysql_base_id") or random.randint(80, 4000))

        if not path.exists() or data.get("persona") != self.persona:
            with contextlib.suppress(Exception):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({
                    "persona": self.persona,
                    "hostname": self.hostname,
                    "boot": self.boot,
                    "installed": self.installed,
                    "mysql_base_id": self.mysql_base_id,
                }, indent=2))

    def etag(self, body: bytes) -> str:
        return f'"{int(self.installed):x}-{len(body):x}"'


class Tracker:
    """What each address has touched, and how patient we should be with it."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: dict[str, dict[str, object]] = {}

    def note(self, ip: str, port: int) -> tuple[int, bool, bool]:
        """Record a connection.

        Returns (distinct ports in window, first contact on this port,
        newly crossed the sweep threshold).
        """
        now = time.monotonic()
        with self._lock:
            if len(self._seen) > 8192:
                for stale in [
                    k for k, v in self._seen.items()
                    if now - float(v["last"]) > FORGET
                ]:
                    del self._seen[stale]

            state = self._seen.get(ip)
            if state is None:
                state = {"events": deque(), "announced": False, "last": now}
                self._seen[ip] = state
            state["last"] = now

            events: deque[tuple[float, int]] = state["events"]  # type: ignore
            before = {p for _, p in events}
            events.append((now, port))
            while events and now - events[0][0] > SWEEP_WINDOW:
                events.popleft()

            distinct = len({p for _, p in events})
            newly = False
            if distinct >= SWEEP_PORTS and not state["announced"]:
                state["announced"] = True
                newly = True
            return distinct, port not in before, newly

    def ports_of(self, ip: str) -> list[int]:
        with self._lock:
            state = self._seen.get(ip)
            if not state:
                return []
            events: deque[tuple[float, int]] = state["events"]  # type: ignore
            return sorted({p for _, p in events})


def hold_seconds(distinct: int, first_contact: bool, role: str) -> float:
    """How long to keep a connection open.

    Zero for a first contact, zero below the sweep threshold, and zero for
    anything a person might legitimately be using. Past that it climbs with
    the number of distinct ports the address has touched, jittered by a third
    so the durations do not form a recognisable ladder.
    """
    if role in NEVER_HOLD or first_contact or distinct < SWEEP_PORTS:
        return 0.0
    base = 8.0 * (distinct - SWEEP_PORTS + 1) ** 2
    return min(MAX_HOLD, base * random.uniform(0.7, 1.3))


# ---------------------------------------------------------------------------
# Protocol construction
# ---------------------------------------------------------------------------

def ssh_packet(payload: bytes) -> bytes:
    """Wrap a payload in the SSH binary packet framing from RFC 4253."""
    block = 8
    length = len(payload) + 1
    padding = block - ((length + 4) % block)
    if padding < 4:
        padding += block
    return (
        struct.pack(">IB", length + padding, padding)
        + payload
        + os.urandom(padding)
    )


def ssh_kexinit() -> bytes:
    """A real SSH_MSG_KEXINIT, with a fresh cookie every connection."""
    def namelist(value: str) -> bytes:
        raw = value.encode("ascii")
        return struct.pack(">I", len(raw)) + raw

    payload = (
        bytes([20])                     # SSH_MSG_KEXINIT
        + os.urandom(16)                # cookie, different every time
        + namelist(SSH_KEX)
        + namelist(SSH_HOSTKEY)
        + namelist(SSH_CIPHER)          # client to server
        + namelist(SSH_CIPHER)          # server to client
        + namelist(SSH_MAC)
        + namelist(SSH_MAC)
        + namelist(SSH_COMPRESSION)
        + namelist(SSH_COMPRESSION)
        + namelist("")                  # languages
        + namelist("")
        + bytes([0])                    # first_kex_packet_follows
        + struct.pack(">I", 0)          # reserved
    )
    return ssh_packet(payload)


def mysql_handshake(version: str, connection_id: int) -> bytes:
    """A well-formed protocol 10 initial handshake.

    The salt is fresh per connection, which is what a real server does and
    what a replayed capture cannot do.
    """
    salt = bytes(random.randint(1, 255) for _ in range(20))
    capabilities = 0xA20F7FFF          # what MySQL 8 actually advertises
    payload = (
        bytes([10])
        + version.encode("ascii") + b"\x00"
        + struct.pack("<I", connection_id)
        + salt[:8]
        + b"\x00"
        + struct.pack("<H", capabilities & 0xFFFF)
        + bytes([0x2D])                # utf8mb4_general_ci
        + struct.pack("<H", 0x0002)    # SERVER_STATUS_AUTOCOMMIT
        + struct.pack("<H", (capabilities >> 16) & 0xFFFF)
        + bytes([21])                  # auth plugin data length
        + b"\x00" * 10
        + salt[8:] + b"\x00"
        + b"caching_sha2_password\x00"
    )
    return struct.pack("<I", len(payload))[:3] + bytes([0]) + payload


def mysql_error(seq: int, code: int, sqlstate: str, message: str) -> bytes:
    payload = (
        b"\xff"
        + struct.pack("<H", code)
        + b"#" + sqlstate.encode("ascii")
        + message.encode("utf-8")
    )
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload


def mysql_username(packet: bytes) -> str | None:
    """Pull the username out of a client handshake response, if it is there."""
    if len(packet) < 40:
        return None
    body = packet[4:]              # skip the 4-byte packet header
    if len(body) < 32:
        return None
    name = body[32:]               # 4 caps, 4 max packet, 1 charset, 23 filler
    end = name.find(b"\x00")
    if end <= 0:
        return None
    return name[:end].decode("utf-8", "replace")[:64]


# ---------------------------------------------------------------------------
# Sentinel
# ---------------------------------------------------------------------------

class Sentinel:
    def __init__(self, sink: JsonlSink, persona: dict[str, object],
                 identity: Identity, quiet: bool, hold: bool) -> None:
        self.sink = sink
        self.persona = persona
        self.identity = identity
        self.quiet = quiet
        self.hold_enabled = hold
        self.tracker = Tracker()
        self.open_conns = 0
        self.body = (
            APACHE_DEFAULT if "Apache" in str(persona["http_server"])
            else NGINX_DEFAULT
        )

    def emit(self, event: dict[str, object]) -> None:
        event.setdefault("persona", self.identity.persona)
        self.sink.write(event)
        if not self.quiet:
            print(json.dumps(event, default=str), flush=True)

    @staticmethod
    async def jitter() -> None:
        """A few milliseconds of variable delay before answering.

        A real service is doing work: reading a config, taking a lock,
        touching a socket buffer. One that answers in a constant number of
        microseconds is a lookup table.
        """
        await asyncio.sleep(random.uniform(0.003, 0.028))

    # -- protocol handlers ---------------------------------------------

    async def do_ssh(self, reader, writer, note: dict[str, object]) -> None:
        await self.jitter()
        writer.write(str(self.persona["ssh_ident"]).encode() + b"\r\n")
        await writer.drain()

        client_ident = b""
        with contextlib.suppress(Exception):
            client_ident = await asyncio.wait_for(
                reader.readline(), timeout=TIMEOUTS["ssh"])
        if client_ident:
            note["ssh_client"] = client_ident.decode("utf-8", "replace").strip()[:120]

        # A real KEXINIT. This is what makes `nmap -sV` and ssh-audit report
        # a normal OpenSSH server rather than an unidentified socket.
        await self.jitter()
        writer.write(ssh_kexinit())
        await writer.drain()

        with contextlib.suppress(Exception):
            data = await asyncio.wait_for(reader.read(READ_LIMIT),
                                          timeout=TIMEOUTS["ssh"])
            note["bytes_received"] = note.get("bytes_received", 0) + len(data)
            if data and data[5:6] == bytes([20]):
                note["ssh_kexinit_received"] = True

        # Stop here. Completing the key exchange needs a host key signature,
        # and there is no signing primitive in the standard library. Going
        # quiet after KEXINIT is what a loaded or misconfigured server looks
        # like. It is a far weaker tell than dripping junk, which is the
        # published signature of the well-known SSH tarpits.

    async def do_http(self, reader, writer, note: dict[str, object],
                      port: int) -> None:
        """Enough HTTP to be an unremarkable web server, including keep-alive."""
        server = str(self.persona["http_server"])
        requests: list[str] = []

        first = True
        for _ in range(16):
            try:
                line = await asyncio.wait_for(
                    reader.readline(),
                    timeout=TIMEOUTS["http_header" if first else "http_keepalive"],
                )
            except (asyncio.TimeoutError, Exception):
                break
            if not line:
                break
            request = line.decode("utf-8", "replace").strip()[:256]
            requests.append(request)

            headers: dict[str, str] = {}
            for _ in range(64):
                with contextlib.suppress(Exception):
                    hline = await asyncio.wait_for(
                        reader.readline(), timeout=TIMEOUTS["http_header"])
                    if not hline or hline in (b"\r\n", b"\n"):
                        break
                    key, _, value = hline.decode("utf-8", "replace").partition(":")
                    headers[key.strip().lower()] = value.strip()[:256]
                    continue
                break

            if "user-agent" in headers:
                note.setdefault("http_user_agent", headers["user-agent"])
            if "host" in headers:
                note.setdefault("http_host", headers["host"])

            parts = request.split()
            method = parts[0] if parts else ""
            target = parts[1] if len(parts) > 1 else "/"
            keep = headers.get("connection", "").lower() != "close"

            await self.jitter()
            if method not in ("GET", "HEAD"):
                writer.write(self.http_response(
                    405, b"", server, extra={"Allow": "GET, HEAD"}, keep=keep))
            elif target in ("/", "/index.html", "/index.nginx-debian.html"):
                writer.write(self.http_response(
                    200, self.body, server, head=(method == "HEAD"),
                    etag=self.identity.etag(self.body),
                    last_modified=http_date(self.identity.installed), keep=keep))
            else:
                page = self.http_404(server)
                writer.write(self.http_response(
                    404, page, server, head=(method == "HEAD"), keep=keep))
            with contextlib.suppress(Exception):
                await writer.drain()
            first = False
            if not keep:
                break

        if requests:
            note["http_requests"] = requests[:16]

    def http_404(self, server: str) -> bytes:
        if "Apache" in server:
            return (
                b"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                b"<html><head><title>404 Not Found</title></head><body>\n"
                b"<h1>Not Found</h1><p>The requested URL was not found on "
                b"this server.</p><hr>\n<address>" + server.encode()
                + b" Server</address>\n</body></html>\n"
            )
        return (
            b"<html>\r\n<head><title>404 Not Found</title></head>\r\n"
            b"<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
            b"<hr><center>" + server.encode() + b"</center>\r\n"
            b"</body>\r\n</html>\r\n"
        )

    @staticmethod
    def http_response(status: int, body: bytes, server: str, *,
                      head: bool = False, keep: bool = True,
                      etag: str | None = None,
                      last_modified: str | None = None,
                      extra: dict[str, str] | None = None) -> bytes:
        reasons = {200: "OK", 404: "Not Found", 405: "Method Not Allowed"}
        lines = [
            f"HTTP/1.1 {status} {reasons.get(status, 'OK')}",
            f"Server: {server}",
            f"Date: {http_date()}",
            "Content-Type: text/html",
            f"Content-Length: {len(body)}",
            f"Connection: {'keep-alive' if keep else 'close'}",
        ]
        if etag:
            lines.append(f"ETag: {etag}")
        if last_modified:
            lines.append(f"Last-Modified: {last_modified}")
        if status == 200:
            lines.append("Accept-Ranges: bytes")
        for key, value in (extra or {}).items():
            lines.append(f"{key}: {value}")
        head_bytes = ("\r\n".join(lines) + "\r\n\r\n").encode()
        return head_bytes if head else head_bytes + body

    async def do_smtp(self, reader, writer, note: dict[str, object]) -> None:
        host = self.identity.hostname
        software = str(self.persona["smtp_software"])
        await self.jitter()
        writer.write(f"220 {host} ESMTP {software}\r\n".encode())
        await writer.drain()

        commands: list[str] = []
        for _ in range(24):
            try:
                line = await asyncio.wait_for(reader.readline(),
                                              timeout=TIMEOUTS["smtp"])
            except (asyncio.TimeoutError, Exception):
                break
            if not line:
                break
            text = line.decode("utf-8", "replace").strip()[:512]
            commands.append(text)
            verb = text.split(" ")[0].upper() if text else ""
            await self.jitter()

            if verb in ("EHLO", "HELO"):
                if verb == "HELO":
                    reply = f"250 {host}\r\n"
                else:
                    reply = (
                        f"250-{host}\r\n"
                        "250-PIPELINING\r\n"
                        "250-SIZE 10240000\r\n"
                        "250-VRFY\r\n"
                        "250-ETRN\r\n"
                        "250-STARTTLS\r\n"
                        "250-ENHANCEDSTATUSCODES\r\n"
                        "250-8BITMIME\r\n"
                        "250-DSN\r\n"
                        "250 CHUNKING\r\n"
                    )
                writer.write(reply.encode())
            elif verb == "STARTTLS":
                # Postfix says exactly this when its certificate is missing
                # or unreadable, which is an ordinary misconfiguration.
                writer.write(b"454 4.7.0 TLS not available due to temporary "
                             b"reason\r\n")
            elif verb == "MAIL":
                writer.write(b"250 2.1.0 Ok\r\n")
            elif verb == "RCPT":
                # Refusing to relay is what a correctly configured Postfix
                # does, and an open relay is itself a honeypot signature.
                writer.write(b"554 5.7.1 <unknown>: Relay access denied\r\n")
            elif verb == "DATA":
                writer.write(b"554 5.5.1 Error: no valid recipients\r\n")
            elif verb == "AUTH":
                writer.write(b"503 5.5.1 Error: authentication not enabled\r\n")
            elif verb == "QUIT":
                writer.write(b"221 2.0.0 Bye\r\n")
                with contextlib.suppress(Exception):
                    await writer.drain()
                break
            elif verb in ("RSET", "NOOP"):
                writer.write(b"250 2.0.0 Ok\r\n")
            else:
                writer.write(b"502 5.5.2 Error: command not recognized\r\n")
            with contextlib.suppress(Exception):
                await writer.drain()

        if commands:
            note["smtp_commands"] = commands[:24]

    async def do_mysql(self, reader, writer, note: dict[str, object]) -> None:
        # Connection ids climb from a base fixed at install time, the way a
        # long-running server's would. Starting from 1 on every restart is a
        # tell to anybody who connects twice.
        conn_id = self.identity.mysql_base_id + int(time.time() - self.identity.boot)
        await self.jitter()
        writer.write(mysql_handshake(str(self.persona["mysql_version"]), conn_id))
        await writer.drain()

        packet = b""
        with contextlib.suppress(Exception):
            packet = await asyncio.wait_for(reader.read(READ_LIMIT),
                                            timeout=TIMEOUTS["mysql"])
        note["bytes_received"] = note.get("bytes_received", 0) + len(packet)
        user = mysql_username(packet) if packet else None
        if user:
            note["mysql_user"] = user

        if packet:
            peer = str(note.get("ip", "unknown"))
            await self.jitter()
            writer.write(mysql_error(
                2, 1045, "28000",
                f"Access denied for user '{user or 'root'}'@'{peer}' "
                "(using password: YES)",
            ))
            with contextlib.suppress(Exception):
                await writer.drain()

    async def do_silent(self, reader, writer, note: dict[str, object]) -> None:
        """A port that waits for the client, then says nothing useful."""
        with contextlib.suppress(Exception):
            data = await asyncio.wait_for(reader.read(READ_LIMIT),
                                          timeout=TIMEOUTS["other"])
            note["bytes_received"] = note.get("bytes_received", 0) + len(data)
            if data:
                note["payload_hex"] = data[:512].hex()

    # -- dispatch ------------------------------------------------------

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter, port: int, role: str) -> None:
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "?"
        started = time.monotonic()

        self.open_conns += 1
        try:
            if self.open_conns > MAX_CONCURRENT:
                # Out of capacity. A sensor that falls over during a scan
                # records nothing about the scan, so shed load rather than
                # die. A real server under load resets connections too.
                self.emit({"ts": now_iso(), "kind": "connect", "port": port,
                           "ip": ip, "role": role, "outcome": "shed-load"})
                return

            distinct, first_contact, newly_sweeping = self.tracker.note(ip, port)
            if newly_sweeping:
                self.emit({
                    "ts": now_iso(), "kind": "sweep", "ip": ip,
                    "distinct_ports": distinct,
                    "ports": self.tracker.ports_of(ip),
                    "note": f"touched {distinct} of the {len(self.persona['roles'])} "
                            f"open ports within {int(SWEEP_WINDOW)}s",
                })

            note: dict[str, object] = {"ip": ip, "bytes_received": 0}
            handler = {
                "ssh": self.do_ssh,
                "smtp": self.do_smtp,
                "mysql": self.do_mysql,
            }.get(role)
            with contextlib.suppress(Exception):
                if role in ("http", "https"):
                    await self.do_http(reader, writer, note, port)
                elif handler is not None:
                    await handler(reader, writer, note)
                else:
                    await self.do_silent(reader, writer, note)

            hold = hold_seconds(distinct, first_contact, role) if self.hold_enabled else 0.0
            if hold:
                # Silence, not noise. The socket stays open and the server
                # says nothing further, which is indistinguishable from a
                # machine that is swapping. Anything written on a schedule
                # would be a pattern to match on.
                with contextlib.suppress(Exception):
                    await asyncio.sleep(hold)

            held = time.monotonic() - started
            event: dict[str, object] = {
                "ts": now_iso(),
                "kind": "connect",
                "port": port,
                "role": role,
                "ip": ip,
                "distinct_ports": distinct,
                "first_contact": first_contact,
                "sweeping": distinct >= SWEEP_PORTS,
                # held_ms is the whole connection, most of which is usually
                # the client thinking or the protocol timeout running out.
                # hold_ms is only the part we added on purpose. Keeping them
                # apart matters: without it, a scanner that opens a socket
                # and says nothing looks the same as one we deliberately sat
                # on for four minutes.
                "held_ms": int(held * 1000),
                "hold_ms": int(hold * 1000),
                # A connect that completes the handshake and sends nothing is
                # a scanner confirming the port is open. One that speaks the
                # protocol is trying to use the service.
                "spoke": bool(note.get("bytes_received")
                              or note.get("http_requests")
                              or note.get("smtp_commands")),
            }
            event.update(note)
            self.emit(event)
        finally:
            self.open_conns -= 1
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def serve(self, host: str, ports: dict[int, str],
                    ssl_context: object | None) -> None:
        servers, opened, refused = [], [], []
        for port, role in sorted(ports.items()):
            kwargs = {}
            if role == "https":
                if ssl_context is None:
                    refused.append((port, "no certificate supplied"))
                    continue
                kwargs["ssl"] = ssl_context
            try:
                server = await asyncio.start_server(
                    lambda r, w, p=port, x=role: self.handle(r, w, p, x),
                    host, port, **kwargs,
                )
            except OSError as exc:
                refused.append((port, exc.strerror or str(exc)))
                continue
            servers.append(server)
            opened.append(f"{port}/{role}")

        if refused:
            print("could not bind: "
                  + ", ".join(f"{p} ({why})" for p, why in refused),
                  file=sys.stderr, flush=True)
            if any(p < 1024 for p, _ in refused):
                print("Ports below 1024 need a capability. In a container add "
                      "--cap-add NET_BIND_SERVICE, or on the host set "
                      "net.ipv4.ip_unprivileged_port_start=0.",
                      file=sys.stderr, flush=True)
            print("A persona with a port missing is a persona that does not "
                  "hang together. Fix the binding rather than running "
                  "partially.", file=sys.stderr, flush=True)
        if not servers:
            print("no ports bound, nothing to do", file=sys.stderr, flush=True)
            return

        print(f"sentinel [{self.identity.persona}] as {self.identity.hostname} "
              f"on {host}: " + ", ".join(opened), flush=True)

        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, stop.set)
        await stop.wait()
        print("stopping", flush=True)
        for server in servers:
            server.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address. The default is loopback. This sensor "
                         "is only useful when exposed, so setting this to "
                         "0.0.0.0 is a deliberate act on a host you have "
                         "decided to expose, and nothing else should run there")
    ap.add_argument("--persona", default="ubuntu-web", choices=sorted(PERSONAS),
                    help="which machine this pretends to be. Changing it "
                         "after the host has been scanned is itself a tell")
    ap.add_argument("--hostname", default=None,
                    help="name used in the SMTP banner. Defaults to the real "
                         "fully qualified name, which should match your PTR "
                         "record")
    ap.add_argument("--log", default=os.environ.get(
        "SENTINEL_JSONL", "/var/log/sentinel/connections.jsonl"))
    ap.add_argument("--identity", default=None,
                    help="file holding values that must survive a restart "
                         "(default: identity.json beside the log)")
    ap.add_argument("--tls-cert", default=None,
                    help="certificate for the https port. Without it that "
                         "port is not opened, because a self-signed "
                         "certificate minted yesterday is worse than a "
                         "closed port")
    ap.add_argument("--tls-key", default=None)
    ap.add_argument("--port-offset", type=int, default=0,
                    help="add this to every port. For testing on a machine "
                         "where you cannot bind low ports. Never use it in "
                         "production: SSH on 10022 is not a persona, it is a "
                         "honeypot with the label still attached")
    ap.add_argument("--no-hold", action="store_true",
                    help="observe only, never keep a connection open")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    persona = PERSONAS[args.persona]
    roles: dict[int, str] = dict(persona["roles"])  # type: ignore[arg-type]

    log_path = pathlib.Path(args.log)
    identity = Identity(
        pathlib.Path(args.identity) if args.identity
        else log_path.parent / "identity.json",
        args.persona,
        args.hostname or socket.getfqdn(),
    )
    if identity.persona != args.persona:
        print(f"NOTE: identity file already says persona={identity.persona}; "
              f"keeping it. Delete {identity.path} to change identity, and "
              "understand that anything which scanned this host before will "
              "see the change.", file=sys.stderr, flush=True)
        persona = PERSONAS[identity.persona]
        roles = dict(persona["roles"])  # type: ignore[arg-type]

    ssl_context = None
    if args.tls_cert and args.tls_key:
        import ssl
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(args.tls_cert, args.tls_key)

    if args.host not in ("127.0.0.1", "::1", "localhost"):
        print("NOTE: bound off loopback. Inside a container namespace that is "
              "expected. On a host, this box is now presenting itself to the "
              "internet as an ordinary server, which is the intent, but it "
              "must be a host that holds nothing else.",
              file=sys.stderr, flush=True)

    if args.port_offset:
        roles = {port + args.port_offset: role for port, role in roles.items()}
        print(f"NOTE: ports shifted by {args.port_offset}. This is a test "
              "configuration and it does not look like a real machine.",
              file=sys.stderr, flush=True)

    sink = JsonlSink(str(log_path))
    sentinel = Sentinel(sink, persona, identity, args.quiet, not args.no_hold)
    try:
        asyncio.run(sentinel.serve(args.host, roles, ssl_context))
    except KeyboardInterrupt:
        pass
    finally:
        sink.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
