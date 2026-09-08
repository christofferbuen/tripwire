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

What it keeps. Besides who connected and what they said, the sentinel hashes
the shape of the client's own protocol stack: its SSH algorithm lists
(HASSH), the order of its HTTP headers, and its TLS ClientHello (JA4). None
of it is sent back to the client, and none of it changes what the client
sees; it is read from bytes that were arriving anyway. An address is cheap
identity and these are not, which is what makes the same tool recognisable
from a new address next week.

Data note. Ports 25 and 3306 collect login attempts, and those contain
credentials belonging to whoever was sprayed before you. Treat the log as
sensitive, keep retention short, and do not republish it.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import os
import pathlib
import random
import re
import signal
import socket
import ssl
import struct
import sys
import tempfile
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


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from(">H", data, offset)[0]


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
# Fingerprints
#
# An address is cheap identity: it is rented, rotated and shared. A protocol
# stack is expensive identity. The exact algorithm lists in a client's
# KEXINIT, the exact order of its HTTP headers and the exact shape of its
# ClientHello are properties of the tool, not of where it is running from,
# and they are already arriving on the wire. These functions are pure so the
# selftest can drive them without a socket; nothing here changes a byte that
# goes back out.
# ---------------------------------------------------------------------------

# GREASE, RFC 8701: reserved values a client sprinkles into its lists to keep
# middleboxes honest. They are picked at random per connection, so anything
# that hashes them produces a different fingerprint every time.
GREASE = frozenset(range(0x0A0A, 0x10000, 0x1010))

TLS_VERSIONS = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
                0x0300: "s3"}

SSH_NAMELISTS = ("kex", "hostkey", "enc_c2s", "enc_s2c", "mac_c2s", "mac_s2c",
                 "comp_c2s", "comp_s2c", "lang_c2s", "lang_s2c")


def parse_kexinit(data: bytes) -> dict[str, str] | None:
    """The ten algorithm name-lists out of an SSH_MSG_KEXINIT packet.

    None when the bytes are not a KEXINIT or are not all there yet. The
    framing is RFC 4253: uint32 packet length, byte padding length, byte
    message type, 16-byte cookie, then the lists.
    """
    if len(data) < 6:
        return None
    length = struct.unpack(">I", data[:4])[0]
    padding = data[4]
    if not 2 <= length <= 65536 or len(data) < 4 + length or padding >= length:
        return None
    if data[5] != 20:                       # SSH_MSG_KEXINIT
        return None
    rest = data[6:4 + length - padding]
    if len(rest) < 16:
        return None
    rest = rest[16:]                        # cookie
    names = []
    for _ in range(len(SSH_NAMELISTS)):
        if len(rest) < 4:
            return None
        size = struct.unpack(">I", rest[:4])[0]
        if len(rest) < 4 + size:
            return None
        names.append(rest[4:4 + size].decode("ascii", "replace"))
        rest = rest[4 + size:]
    return dict(zip(SSH_NAMELISTS, names))


def hassh(lists: dict[str, str]) -> str:
    """HASSH: md5 of kex;cipher;mac;compression, client to server."""
    raw = ";".join((lists["kex"], lists["enc_c2s"],
                    lists["mac_c2s"], lists["comp_c2s"]))
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()


def header_fingerprint(lines: list[str], version: str) -> tuple[str, str]:
    """Header names in wire order, and a hash of that order plus the version.

    Duplicates are kept: sending Accept twice is itself characteristic. The
    values are deliberately not hashed, only the shape of the request.
    """
    names = [line.partition(":")[0].strip().lower() for line in lines]
    order = ",".join(names)
    digest = hashlib.sha256(f"{version}|{order}".encode()).hexdigest()[:12]
    return order[:1024], digest


def _parse_sni(body: bytes) -> str | None:
    end = 2 + _u16(body, 0)
    pos = 2
    while pos + 3 <= end:
        kind = body[pos]
        size = _u16(body, pos + 1)
        pos += 3
        if kind == 0:
            # Punycode on the wire, so ASCII; anything else is a client
            # doing something odd and is recorded as it arrived.
            return body[pos:pos + size].decode("ascii", "replace")[:253]
        pos += size
    return None


def _parse_alpn(body: bytes) -> list[bytes]:
    end = 2 + _u16(body, 0)
    pos, protocols = 2, []
    while pos < end and pos < len(body):
        size = body[pos]
        protocols.append(body[pos + 1:pos + 1 + size])
        pos += 1 + size
    return protocols


def _uint16_list(body: bytes, offset: int, size: int) -> list[int]:
    return [v for v in (_u16(body, offset + k) for k in range(0, size - 1, 2))
            if v not in GREASE]


def parse_client_hello(data: bytes) -> dict | None:
    """A TLS ClientHello out of a stream of TLS records.

    None when this is not a TLS handshake at all, or when the hello has not
    all arrived: a handshake message may be split across records, and records
    across segments.
    """
    handshake, pos = b"", 0
    while len(data) - pos >= 5:
        if data[pos] != 22:                 # not handshake: SSLv2, HTTP, junk
            return None
        size = _u16(data, pos + 3)
        if len(data) - pos - 5 < size:
            break
        handshake += data[pos + 5:pos + 5 + size]
        pos += 5 + size
    if len(handshake) < 4 or handshake[0] != 1:     # 1 = ClientHello
        return None
    size = int.from_bytes(handshake[1:4], "big")
    if len(handshake) < 4 + size:
        return None
    try:
        return _client_hello_fields(handshake[4:4 + size])
    except (struct.error, IndexError, ValueError):
        return None


def _client_hello_fields(body: bytes) -> dict:
    legacy = _u16(body, 0)
    pos = 34                                        # version, 32-byte random
    pos += 1 + body[pos]                            # legacy session id
    size = _u16(body, pos)
    ciphers = _uint16_list(body, pos + 2, size)
    pos += 2 + size
    pos += 1 + body[pos]                            # compression methods

    extensions: list[int] = []
    sni: str | None = None
    sni_present = False
    alpn: list[bytes] = []
    versions: list[int] = []
    sigalgs: list[int] = []
    if pos + 2 <= len(body):
        end = min(pos + 2 + _u16(body, pos), len(body))
        pos += 2
        while pos + 4 <= end:
            kind = _u16(body, pos)
            size = _u16(body, pos + 2)
            pos += 4
            if pos + size > end:
                raise ValueError("extension runs past the hello")
            ext = body[pos:pos + size]
            pos += size
            if kind in GREASE:
                continue
            extensions.append(kind)
            if kind == 0x0000:
                # An empty server_name still counts as present: the JA4 flag
                # is about whether the client asked by name at all.
                sni_present = True
                if ext:
                    sni = _parse_sni(ext)
            elif kind == 0x0010 and ext:
                alpn = _parse_alpn(ext)
            elif kind == 0x002B and ext:
                versions = _uint16_list(ext, 1, ext[0])
            elif kind == 0x000D and ext:
                sigalgs = _uint16_list(ext, 2, _u16(ext, 0))

    # supported_versions wins when it holds anything real; a hello carrying
    # only GREASE there falls back to the legacy field, as does TLS 1.2.
    chosen = max(versions) if versions else legacy
    return {
        "version": TLS_VERSIONS.get(chosen, "00"),
        "sni": sni,
        "sni_present": sni_present,
        "alpn": alpn,
        "ciphers": ciphers,
        "extensions": extensions,
        "sigalgs": sigalgs,
    }


def _alpn_code(protocols: list[bytes]) -> str:
    """The two-character ALPN part of a JA4: first and last character."""
    if not protocols or not protocols[0]:
        return "00"
    raw = protocols[0]
    if 0x21 <= raw[0] <= 0x7E and 0x21 <= raw[-1] <= 0x7E:
        return chr(raw[0]) + chr(raw[-1])
    return f"{raw[0]:02x}"[0] + f"{raw[-1]:02x}"[1]


def _truncate_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def ja4(hello: dict) -> str:
    """JA4 for a TCP ClientHello: t<version><sni><ciphers><exts><alpn>_b_c."""
    ciphers, extensions = hello["ciphers"], hello["extensions"]
    a = ("t" + hello["version"]
         + ("d" if hello["sni_present"] else "i")
         + f"{min(len(ciphers), 99):02d}{min(len(extensions), 99):02d}"
         + _alpn_code(hello["alpn"]))
    zero = "0" * 12
    b = (_truncate_hash(",".join(sorted(f"{c:04x}" for c in ciphers)))
         if ciphers else zero)
    if extensions:
        # SNI and ALPN are counted above but left out of the hash: both are
        # about who is being called, not about what is calling.
        text = ",".join(sorted(f"{e:04x}" for e in extensions
                               if e not in (0x0000, 0x0010)))
        if 0x000D in extensions:
            text += "_" + ",".join(f"{s:04x}" for s in hello["sigalgs"])
        c = _truncate_hash(text)
    else:
        c = zero
    return f"{a}_{b}_{c}"


async def read_until(reader, complete, cap: int, timeout: float) -> bytes:
    """Accumulate bytes until complete(buf), or the cap or the clock stops us.

    A fingerprint is a hash of a whole structure, so one read() of whatever
    the first segment carried is not enough: the client's KEXINIT and its
    ClientHello both routinely arrive in pieces.
    """
    buf = b""
    deadline = time.monotonic() + timeout
    while len(buf) < cap and not complete(buf):
        left = deadline - time.monotonic()
        if left <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(READ_LIMIT), timeout=left)
        except Exception:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _ssh_packet_complete(buf: bytes) -> bool:
    return len(buf) >= 4 and len(buf) >= 4 + struct.unpack(">I", buf[:4])[0]


def _hello_complete(buf: bytes) -> bool:
    # Stop early on anything that is not a TLS handshake record: an SSLv2
    # hello, plain HTTP sent to 443, or a scanner's own probe string.
    return buf[:1] not in (b"", b"\x16") or parse_client_hello(buf) is not None


class TlsStream:
    """StreamReader and StreamWriter, near enough, over an ssl.SSLObject.

    The https port has to listen in the clear so the ClientHello can be read
    before the standard library eats it. That leaves the handshake and the
    record layer to us, and this is the adapter that lets the existing
    do_http() run on top of it unchanged.
    """

    def __init__(self, reader, writer, tls: ssl.SSLObject,
                 incoming: ssl.MemoryBIO, outgoing: ssl.MemoryBIO) -> None:
        self._reader = reader
        self._writer = writer
        self._tls = tls
        self._incoming = incoming
        self._outgoing = outgoing
        self._buf = b""

    async def _fill(self) -> bool:
        """Decrypt more application data. False once nothing more is coming."""
        while True:
            try:
                data = self._tls.read(READ_LIMIT)
            except ssl.SSLWantReadError:
                data = None
            except ssl.SSLError:
                return False
            if data:
                self._buf += data
                return True
            if data == b"":
                return False
            chunk = await self._reader.read(READ_LIMIT)
            if not chunk:
                with contextlib.suppress(ssl.SSLError):
                    self._incoming.write_eof()
                return False
            self._incoming.write(chunk)
            await self.drain()          # session tickets, renegotiation

    async def readline(self) -> bytes:
        while b"\n" not in self._buf:
            if not await self._fill():
                break
        line, sep, rest = self._buf.partition(b"\n")
        self._buf = rest
        return line + sep

    async def read(self, size: int) -> bytes:
        if not self._buf and not await self._fill():
            return b""
        data, self._buf = self._buf[:size], self._buf[size:]
        return data

    def write(self, data: bytes) -> None:
        with contextlib.suppress(ssl.SSLError):
            self._tls.write(data)

    async def drain(self) -> None:
        data = self._outgoing.read()
        if data:
            self._writer.write(data)
            await self._writer.drain()

    def close(self) -> None:
        self._writer.close()

    async def wait_closed(self) -> None:
        await self._writer.wait_closed()


# ---------------------------------------------------------------------------
# Sentinel
# ---------------------------------------------------------------------------

class Sentinel:
    def __init__(self, sink: JsonlSink, persona: dict[str, object],
                 identity: Identity, quiet: bool, hold: bool,
                 ssl_context: ssl.SSLContext | None = None) -> None:
        self.sink = sink
        self.persona = persona
        self.identity = identity
        self.quiet = quiet
        self.hold_enabled = hold
        self.ssl_context = ssl_context
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

        # Read the client's own KEXINIT whole rather than whatever the first
        # segment happened to carry: HASSH is a hash of all four lists, so a
        # packet split across segments is a packet with no fingerprint.
        data = await read_until(reader, _ssh_packet_complete,
                                65536, TIMEOUTS["ssh"])
        note["bytes_received"] = note.get("bytes_received", 0) + len(data)
        if data[5:6] == bytes([20]):
            note["ssh_kexinit_received"] = True
        lists = parse_kexinit(data)
        if lists:
            note["ssh_hassh"] = hassh(lists)
            note["ssh_kex_client"] = lists["kex"][:512]

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
            header_lines: list[str] = []
            for _ in range(64):
                with contextlib.suppress(Exception):
                    hline = await asyncio.wait_for(
                        reader.readline(), timeout=TIMEOUTS["http_header"])
                    if not hline or hline in (b"\r\n", b"\n"):
                        break
                    text = hline.decode("utf-8", "replace")
                    header_lines.append(text)
                    key, _, value = text.partition(":")
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

            # Which headers, in which order, hashed with the protocol
            # version. Every library and every scanner has its own habits
            # here, and they survive a change of address or user-agent.
            if first and header_lines:
                order, digest = header_fingerprint(
                    header_lines,
                    parts[2] if len(parts) > 2 else "HTTP/0.9")
                note["http_header_order"] = order
                note["http_header_hash"] = digest

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

    async def do_https(self, reader, writer, note: dict[str, object],
                       port: int) -> None:
        """Read the ClientHello ourselves, then hand the rest to do_http.

        asyncio's own TLS support would complete the handshake before any of
        this ran, and the ClientHello is the interesting part: JA4 identifies
        the client's TLS library and its build far more sharply than a
        user-agent string, which is only ever what the client chose to say.
        """
        buf = await read_until(reader, _hello_complete, 16384,
                               TIMEOUTS["http_header"])
        note["bytes_received"] = note.get("bytes_received", 0) + len(buf)
        hello = parse_client_hello(buf)
        if hello is None:
            if buf:
                note["payload_hex"] = buf[:512].hex()
            return

        note["tls_ja4"] = ja4(hello)
        note["tls_version"] = hello["version"]
        if hello["sni"]:
            note["tls_sni"] = hello["sni"]
        if hello["alpn"]:
            note["tls_alpn"] = hello["alpn"][0].decode("utf-8", "replace")[:32]

        if self.ssl_context is None:
            return
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = self.ssl_context.wrap_bio(incoming, outgoing, server_side=True)
        incoming.write(buf)
        stream = TlsStream(reader, writer, tls, incoming, outgoing)
        while True:
            try:
                tls.do_handshake()
                done = True
            except ssl.SSLWantReadError:
                done = False
            except ssl.SSLError:
                # A client that will not negotiate has already told us
                # everything it was going to. Drop it the way a server with
                # no shared cipher does, without a word.
                return
            await stream.drain()
            if done:
                break
            chunk = await asyncio.wait_for(reader.read(READ_LIMIT),
                                           timeout=TIMEOUTS["http_header"])
            if not chunk:
                return
            incoming.write(chunk)

        await self.do_http(stream, stream, note, port)

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
                if role == "https":
                    await self.do_https(reader, writer, note, port)
                elif role == "http":
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

    async def serve(self, host: str, ports: dict[int, str]) -> None:
        servers, opened, refused = [], [], []
        for port, role in sorted(ports.items()):
            # https listens in the clear and does its own handshake, so that
            # do_https() sees the ClientHello. The certificate is still
            # required: a port that cannot complete a handshake is worse
            # than a closed one.
            if role == "https" and self.ssl_context is None:
                refused.append((port, "no certificate supplied"))
                continue
            try:
                server = await asyncio.start_server(
                    lambda r, w, p=port, x=role: self.handle(r, w, p, x),
                    host, port,
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
            # Not on Windows, and not off the main thread, which is where the
            # selftest runs it. Neither is a reason to refuse to serve.
            with contextlib.suppress(NotImplementedError, ValueError,
                                     RuntimeError):
                loop.add_signal_handler(sig, stop.set)
        await stop.wait()
        print("stopping", flush=True)
        for server in servers:
            server.close()


# ---------------------------------------------------------------------------
# Selftest
# ---------------------------------------------------------------------------

def _hello_bytes(*, sni: bool = True, alpn=(b"h2", b"http/1.1"),
                 versions=(0x0A0A, 0x0304), records: int = 1) -> bytes:
    """A ClientHello built by hand, so the parser is checked against bytes
    nobody generated with the same code that reads them."""
    def ext(kind: int, body: bytes) -> bytes:
        return struct.pack(">HH", kind, len(body)) + body

    extensions = b""
    if sni:
        entry = b"\x00" + struct.pack(">H", 11) + b"example.com"
        extensions += ext(0x0000, struct.pack(">H", len(entry)) + entry)
    offered = b"".join(struct.pack(">H", v) for v in versions)
    extensions += ext(0x002B, bytes([len(offered)]) + offered)
    if alpn:
        protocols = b"".join(bytes([len(p)]) + p for p in alpn)
        extensions += ext(0x0010, struct.pack(">H", len(protocols)) + protocols)
    sigalgs = struct.pack(">HH", 0x0403, 0x0804)
    extensions += ext(0x000D, struct.pack(">H", len(sigalgs)) + sigalgs)
    extensions += ext(0x0017, b"")                  # zero length, on purpose
    ciphers = struct.pack(">HHH", 0x1A1A, 0x1301, 0x1302)
    body = (struct.pack(">H", 0x0303) + bytes(32) + b"\x00"
            + struct.pack(">H", len(ciphers)) + ciphers
            + b"\x01\x00"                           # one compression method
            + struct.pack(">H", len(extensions)) + extensions)
    message = bytes([1]) + len(body).to_bytes(3, "big") + body
    if records == 1:
        return b"\x16\x03\x01" + struct.pack(">H", len(message)) + message
    cut = len(message) // 2
    return (b"\x16\x03\x01" + struct.pack(">H", cut) + message[:cut]
            + b"\x16\x03\x01" + struct.pack(">H", len(message) - cut)
            + message[cut:])


def _selftest_live() -> None:
    """One real connection to each of two ports, through the real server."""
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="sentinel-selftest-"))
    log = tmp / "connections.jsonl"
    threading.Thread(target=main, daemon=True, args=([
        "--host", "127.0.0.1", "--port-offset", "40000", "--no-hold",
        "--quiet", "--log", str(log), "--identity", str(tmp / "identity.json"),
    ],)).start()

    def connect(port: int) -> socket.socket:
        for _ in range(100):
            with contextlib.suppress(OSError):
                return socket.create_connection(("127.0.0.1", port), timeout=5)
            time.sleep(0.05)
        raise AssertionError(f"nothing came up on {port}")

    client = connect(40022)
    client.recv(512)                                # the server's ident
    client.sendall(b"SSH-2.0-Test\r\n" + ssh_kexinit())
    client.close()

    client = connect(40080)
    client.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: y\r\n\r\n")
    assert client.recv(4096).startswith(b"HTTP/1.1 200 ")
    client.close()

    want = hashlib.md5(
        f"{SSH_KEX};{SSH_CIPHER};{SSH_MAC};{SSH_COMPRESSION}".encode(),
        usedforsecurity=False).hexdigest()
    events: list[dict] = []
    for _ in range(100):
        time.sleep(0.05)
        if not log.exists():
            continue
        events = [json.loads(line) for line
                  in log.read_text(encoding="utf-8").splitlines() if line]
        if (any(e.get("ssh_hassh") for e in events)
                and any(e.get("http_header_order") for e in events)):
            break
    assert any(e.get("ssh_hassh") == want for e in events), events
    assert any(e.get("ssh_kex_client") == SSH_KEX for e in events), events
    assert any(e.get("http_header_order") == "host,user-agent"
               for e in events), events


def selftest() -> int:
    lists = parse_kexinit(ssh_kexinit())
    assert lists is not None
    assert lists["kex"] == SSH_KEX, lists["kex"]
    assert lists["enc_c2s"] == SSH_CIPHER, lists["enc_c2s"]
    assert lists["mac_c2s"] == SSH_MAC, lists["mac_c2s"]
    assert lists["comp_c2s"] == SSH_COMPRESSION, lists["comp_c2s"]
    assert lists["lang_c2s"] == "", lists["lang_c2s"]
    assert hassh(lists) == hashlib.md5(
        f"{SSH_KEX};{SSH_CIPHER};{SSH_MAC};{SSH_COMPRESSION}".encode(),
        usedforsecurity=False).hexdigest(), hassh(lists)
    assert parse_kexinit(ssh_kexinit()[:20]) is None
    assert parse_kexinit(ssh_packet(bytes([21]) + os.urandom(16))) is None
    assert parse_kexinit(b"") is None

    hello = parse_client_hello(_hello_bytes())
    assert hello is not None
    assert hello["version"] == "13", hello["version"]
    assert hello["sni"] == "example.com", hello["sni"]
    assert hello["ciphers"] == [0x1301, 0x1302], hello["ciphers"]
    assert hello["alpn"][0] == b"h2", hello["alpn"]
    assert hello["sigalgs"] == [0x0403, 0x0804], hello["sigalgs"]
    assert len(hello["extensions"]) == 5, hello["extensions"]

    print_ = ja4(hello)
    assert re.fullmatch(r"t13d02\d\dh2_[0-9a-f]{12}_[0-9a-f]{12}", print_), print_
    assert print_[6:8] == "05", print_
    assert print_.split("_")[1] == hashlib.sha256(
        b"1301,1302").hexdigest()[:12], print_
    assert ja4(parse_client_hello(_hello_bytes(records=2))) == print_
    assert ja4(parse_client_hello(_hello_bytes(alpn=()))) .startswith(
        "t13d020400_"), "alpn absent"
    assert ja4(parse_client_hello(_hello_bytes(sni=False))).startswith(
        "t13i0204h2_"), "sni absent"
    assert parse_client_hello(
        _hello_bytes(versions=(0x0A0A,)))["version"] == "12"
    assert parse_client_hello(b"\x80\x2e\x01\x03\x01") is None      # SSLv2
    assert parse_client_hello(b"GET / HTTP/1.1\r\n\r\n") is None
    assert parse_client_hello(_hello_bytes()[:20]) is None          # fragment

    order, digest = header_fingerprint(["Host: x", "User-Agent: y"], "HTTP/1.1")
    assert order == "host,user-agent", order
    assert re.fullmatch(r"[0-9a-f]{12}", digest), digest
    assert header_fingerprint(["Host: x", "User-Agent: y"],
                              "HTTP/1.0")[1] != digest
    assert header_fingerprint(["User-Agent: y", "Host: x"],
                              "HTTP/1.1")[1] != digest
    assert header_fingerprint(["Accept: a", "Accept: b"],
                              "HTTP/1.1")[0] == "accept,accept"

    _selftest_live()
    print("selftest ok")
    return 0


def main(argv: list[str] | None = None) -> int:
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
    ap.add_argument("--selftest", action="store_true",
                    help="check the fingerprint parsers and one loopback "
                         "connection, then exit. Touches no network the "
                         "machine can see")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

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
    sentinel = Sentinel(sink, persona, identity, args.quiet, not args.no_hold,
                        ssl_context)
    try:
        asyncio.run(sentinel.serve(args.host, roles))
    except KeyboardInterrupt:
        pass
    finally:
        sink.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
