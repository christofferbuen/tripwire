#!/usr/bin/env python3
"""Tripwire receiver: logs canary hits from instrumented pages.

Standard library only, so there is nothing to pin and nothing to patch.

Binds to 127.0.0.1 by default. Exposing this is a deliberate act. Behind a
proxy or tunnel the real client address arrives as CF-Connecting-IP or
X-Forwarded-For, and is only believed when --trust-proxy is set.

The cover site in site/ is served as an ordinary personal blog, so every
path here is a stylesheet, a logo, a post or a contact form. Nothing in the
URL structure reads as instrumentation, and anyone who pastes the hostname
into a browser lands on a dull site.

  tier 0  /static/...            the client rendered the page like a browser
  tier 0  /, /about, /notes/...  cover pages, somebody looked the host up
  tier 1  /notes/profile-mirror  something read page text and fetched a URL
  tier 2  ...?t=2&as=NAME        something followed an embedded instruction
  tier 3  POST /contact          something posted data on a page's say-so
  tier 4  anything else          a probe for a path that does not exist
  tier 5  /archive/..., bait     the tarpit, see below

Tier 3 can capture text belonging to a third party. Treat the database as
sensitive, keep retention short, and do not replicate it.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pathlib
import random
import secrets
import sqlite3
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from hashlib import blake2b
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

MAX_BODY = 64 * 1024
BODY_EXCERPT = 2000

LURE_PATH = "/notes/profile-mirror"
COLLECT_PATH = "/contact"

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".gif": "image/gif",
    ".jpg": "image/jpeg",
    ".txt": "text/plain; charset=utf-8",
    ".xml": "application/xml; charset=utf-8",
}

# ---------------------------------------------------------------------------
# Tarpit
#
# Not a uniform slow-loris sink. Three things happen at once, and the point
# of combining them is that each one measures something the others cannot.
#
#   1. Hall of mirrors. /archive/ is an infinite seeded directory tree. Every
#      listing is generated from a hash of its own path, so it is stable
#      across refetches, and every link goes one level deeper. Depth is not
#      encoded in a parameter that a client could reset, it is simply how
#      many path segments below the root the client has walked. That makes
#      depth a compliance meter: it is a count of how many times something
#      chose to follow a link it had no reason to trust.
#
#   2. Seeded artifacts. Scattered through the tree are files a scraper
#      wants: .env, config.php, backup.sql, id_rsa. Each one is fabricated
#      and each one carries a canary token minted for that single request and
#      written to the canaries table alongside the address and user-agent
#      that took it. If that token ever turns up in a credential-stuffing
#      attempt, a paste, or a log somewhere else, it names the exact fetch.
#
#   3. Adaptive latency. A standard tarpit is slow to everybody, which makes
#      it trivial to fingerprint and punishes the curious as hard as the
#      hostile. This one is proportionate: the delay is a function of how
#      deep the client has gone and how fast it is asking. A person clicking
#      around gets a near-normal site. Something issuing twenty requests a
#      second at depth eight gets held for the maximum. The client's own
#      behaviour sets its own sentence.
#
# Deliberately absent: decompression bombs, oversized payloads, anything
# that damages the client. Everything here is passive. The worst outcome for
# a visitor is that a connection they opened stays open.
# ---------------------------------------------------------------------------

TARPIT_ROOT = "/archive"

# Paths that appear in scanner wordlists and nowhere else. Nothing on the
# cover site links to any of them, no browser requests them, and no person
# types them. A request for one is unambiguous, so it opens the labyrinth
# rather than returning the ordinary 404.
TARPIT_BAIT = {
    "/.env", "/.env.local", "/.git/config", "/.aws/credentials",
    "/backup.sql", "/db_backup.zip", "/dump.sql", "/config.php.bak",
    "/wp-admin", "/wp-admin/", "/wp-login.php", "/admin", "/admin/",
    "/phpmyadmin", "/phpmyadmin/", "/server-status", "/.svn/entries",
    "/credentials.csv", "/id_rsa", "/.ssh/id_rsa",
}

# Vocabulary for the fake tree. Dull, plausible, and deliberately the kind of
# thing a scanner's own path list already contains, so following the links
# feels like progress and keeps it inside the labyrinth.
TARPIT_DIRS = (
    "archive", "backup", "old", "tmp", "data", "export", "inc", "lib",
    "assets", "uploads", "config", "admin", "panel", "cgi", "vendor",
    "reports", "invoices", "2019", "2020", "2021", "staging", "dev",
    "private", "internal", "db", "sql", "logs", "cache", "session",
)
TARPIT_FILES = (
    ".env", "config.php", "config.php.bak", "settings.ini", "backup.sql",
    "dump.sql", "users.csv", "credentials.csv", "id_rsa", "database.yml",
    "notes.txt", "readme.txt", "changelog.txt", "index.php.old",
)

# Crawlers exempted from the tarpit. Holding these achieves nothing and can
# only cause collateral. They are also told to stay out by robots.txt, so a
# client presenting one of these strings from inside the labyrinth is either
# lying about who it is or ignoring the file it just read. Either way it gets
# logged and released rather than held.
TARPIT_EXEMPT = (
    "googlebot", "bingbot", "duckduckbot", "applebot", "yandexbot",
    "baiduspider", "slurp", "archive.org_bot", "ia_archiver",
)

TARPIT_MAX_DEPTH = 24        # below this the tree stops offering subdirectories
TARPIT_MAX_SLEEP = 12.0      # seconds held on any single response
TARPIT_MAX_HELD = 900.0      # seconds we will spend on one client, then release
TARPIT_MAX_HOLDING = 64      # concurrent held connections, our own thread budget
TARPIT_RATE_WINDOW = 60.0    # seconds of history behind the rate measurement
TARPIT_RATE_FREE = 10        # requests per window that attract no rate penalty
TARPIT_FORGET = 3600.0       # seconds of silence after which a client is forgotten

SCHEMA = """
CREATE TABLE IF NOT EXISTS hits (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT    NOT NULL,
    tier         INTEGER NOT NULL,
    placement    TEXT,
    agent_self   TEXT,
    method       TEXT    NOT NULL,
    path         TEXT    NOT NULL,
    query        TEXT,
    ip           TEXT,
    user_agent   TEXT,
    headers      TEXT,
    body_len     INTEGER,
    body_excerpt TEXT
);
CREATE INDEX IF NOT EXISTS hits_ts   ON hits (ts);
CREATE INDEX IF NOT EXISTS hits_tier ON hits (tier);

CREATE TABLE IF NOT EXISTS canaries (
    token      TEXT PRIMARY KEY,
    ts         TEXT NOT NULL,
    hit_id     INTEGER,
    kind       TEXT,
    path       TEXT,
    ip         TEXT,
    user_agent TEXT
);
"""

# Columns added after the first release. CREATE TABLE IF NOT EXISTS will not
# add a column to a table that already exists, so an existing database has to
# be migrated explicitly or every tarpit insert fails.
MIGRATIONS = (
    ("hits", "depth", "INTEGER"),
    ("hits", "delay_ms", "INTEGER"),
    ("hits", "held_ms", "INTEGER"),
    ("hits", "canary", "TEXT"),
)


def load_site(root: pathlib.Path) -> dict[str, tuple[str, bytes]]:
    """Read the whole cover site into memory once, at startup.

    Serving from a dict rather than off disk means no request ever touches
    the filesystem, so directory traversal is not mitigated here, it is
    impossible. The site is a handful of small files; holding it in memory
    costs nothing.
    """
    pages: dict[str, tuple[str, bytes]] = {}
    if not root.is_dir():
        return pages

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        url = "/" + path.relative_to(root).as_posix()
        ctype = CONTENT_TYPES.get(path.suffix.lower(), "application/octet-stream")
        entry = (ctype, path.read_bytes())
        pages[url] = entry
        if path.suffix.lower() == ".html":
            # Serve /about as well as /about.html, and / for the index.
            pages[url[: -len(".html")]] = entry
            if path.name == "index.html":
                pages[url[: -len("index.html")]] = entry
    return pages


class Store:
    """Serialised SQLite writer. One connection, one lock."""

    def __init__(self, path: str) -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        self._migrate()
        self._db.commit()

    def _migrate(self) -> None:
        for table, column, decl in MIGRATIONS:
            existing = {
                row[1] for row in self._db.execute(f"PRAGMA table_info({table})")
            }
            if column not in existing:
                self._db.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {decl}"
                )

    def record(self, **row: object) -> int:
        cols = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        with self._lock:
            cur = self._db.execute(
                f"INSERT INTO hits ({cols}) VALUES ({marks})", tuple(row.values())
            )
            self._db.commit()
            return int(cur.lastrowid or 0)

    def record_canary(self, **row: object) -> None:
        cols = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        with self._lock:
            self._db.execute(
                f"INSERT OR REPLACE INTO canaries ({cols}) VALUES ({marks})",
                tuple(row.values()),
            )
            self._db.commit()

    def set_held(self, hit_id: int, held_ms: int) -> None:
        """Fill in how long a response was held, once it has finished."""
        with self._lock:
            self._db.execute(
                "UPDATE hits SET held_ms = ? WHERE id = ?", (held_ms, hit_id)
            )
            self._db.commit()


class JsonlSink:
    """Append one JSON object per hit, for a log shipper to tail.

    Rotation is size-based and keeps a single previous generation. Vector
    follows the inode, so a rename mid-read finishes the old file before
    picking up the new one and nothing is lost across a rotation.
    """

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
                self._rotate()

    def _rotate(self) -> None:
        self._fh.close()
        self._path.replace(self._path.with_suffix(self._path.suffix + ".1"))
        self._fh = self._path.open("a", encoding="utf-8")

    def close(self) -> None:
        with self._lock:
            self._fh.close()


class Tarpit:
    """Per-client behaviour tracking and the delay derived from it."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._clients: dict[str, dict[str, object]] = {}
        self._holding = 0

    def _state(self, ip: str, now: float) -> dict[str, object]:
        state = self._clients.get(ip)
        if state is None:
            state = {"events": deque(), "held": 0.0, "depth": 0, "seen": now}
            self._clients[ip] = state
        state["seen"] = now
        return state

    def _prune(self, now: float) -> None:
        if len(self._clients) < 4096:
            return
        stale = [
            ip for ip, st in self._clients.items()
            if now - float(st["seen"]) > TARPIT_FORGET
        ]
        for ip in stale:
            del self._clients[ip]

    def delay_for(self, ip: str, depth: int | None) -> tuple[float, int, float]:
        """Return (seconds to hold, rate in the window, cumulative held).

        depth is None for an ordinary 404, where only the request rate
        matters. A single mistyped URL costs nothing; a wordlist grind at
        twenty requests a second gets slower with every request.
        """
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            state = self._state(ip, now)
            events: deque[float] = state["events"]  # type: ignore[assignment]
            events.append(now)
            while events and now - events[0] > TARPIT_RATE_WINDOW:
                events.popleft()
            rate = len(events)
            held = float(state["held"])
            if depth is not None:
                state["depth"] = max(int(state["depth"]), depth)

            # Budget exhausted, or too many connections already parked. Serve
            # immediately: continuing to hold costs us threads and buys no
            # further evidence.
            if held >= TARPIT_MAX_HELD or self._holding >= TARPIT_MAX_HOLDING:
                return 0.0, rate, held

        if depth is None:
            # Rate-only. Stays at zero until the client is clearly grinding.
            over = max(0, rate - TARPIT_RATE_FREE * 2)
            delay = min(TARPIT_MAX_SLEEP, 0.05 * over)
        else:
            # Exponential in depth: 0.2s at the entrance, about 5s at depth
            # seven, capped from depth nine. Then scaled by how hard the
            # client is pushing.
            delay = 0.2 * (1.6 ** min(depth, 12))
            surplus = max(0, rate - TARPIT_RATE_FREE)
            delay *= 1.0 + surplus / 10.0
            delay = min(TARPIT_MAX_SLEEP, delay)

        remaining = max(0.0, TARPIT_MAX_HELD - held)
        return min(delay, remaining), rate, held

    def enter(self) -> bool:
        with self._lock:
            if self._holding >= TARPIT_MAX_HOLDING:
                return False
            self._holding += 1
            return True

    def leave(self, ip: str, seconds: float) -> None:
        with self._lock:
            self._holding -= 1
            state = self._clients.get(ip)
            if state is not None:
                state["held"] = float(state["held"]) + seconds

    def depth_of(self, ip: str) -> int:
        with self._lock:
            state = self._clients.get(ip)
            return int(state["depth"]) if state else 0


def tarpit_rng(path: str) -> random.Random:
    """Deterministic generator keyed to a path.

    The same URL must always produce the same listing. A tree that shuffles
    itself between requests is the single most obvious way to give the game
    away, and it also stops a crawler from ever finishing, which turns a
    measurement into a grudge.
    """
    digest = blake2b(path.encode("utf-8", "replace"), digest_size=8).digest()
    return random.Random(int.from_bytes(digest, "big"))


def tarpit_listing(path: str, depth: int, token: str) -> bytes:
    """A plausible open directory index for a path that does not exist."""
    rng = tarpit_rng(path)
    base = path if path.endswith("/") else path + "/"

    entries: list[tuple[str, str, str]] = []  # (href, name, size)
    if depth < TARPIT_MAX_DEPTH:
        for name in rng.sample(TARPIT_DIRS, rng.randint(3, 7)):
            entries.append((name + "/", name + "/", "-"))
    for name in rng.sample(TARPIT_FILES, rng.randint(2, 5)):
        entries.append((name, name, f"{rng.randint(1, 9000)}K"))

    year = rng.randint(2018, 2024)
    rows = "\n".join(
        f'<tr><td><a href="{href}">{name}</a></td>'
        f'<td>{year}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d} '
        f'{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}</td>'
        f"<td>{size}</td></tr>"
        for href, name, size in entries
    )
    html = (
        "<!doctype html><html><head><meta charset=utf-8>"
        f"<title>Index of {base}</title>"
        "<meta name=robots content=\"noindex,nofollow\"></head><body>"
        f"<h1>Index of {base}</h1><hr><table>"
        "<tr><th>Name</th><th>Last modified</th><th>Size</th></tr>"
        '<tr><td><a href="../">../</a></td><td>-</td><td>-</td></tr>'
        f"{rows}</table><hr>"
        f"<address>Apache/2.4.41 (Ubuntu) Server at {base}</address>"
        f"<!-- build {token} -->"
        "</body></html>\n"
    )
    return html.encode("utf-8")


def tarpit_artifact(name: str, token: str) -> tuple[str, bytes]:
    """A fabricated file of the kind a scraper is hunting for.

    Everything in here is invented. The value is the token: it is minted for
    one request and written to the canaries table with the address and
    user-agent that took it, so if it is ever presented anywhere it names
    that exact fetch. Nothing here is a working credential for anything.
    """
    lower = name.lower()
    host = f"db-{token[:6].lower()}.internal.example"

    if lower.endswith(".env") or lower == ".env.local":
        kind = "env"
        body = (
            "APP_ENV=production\n"
            "APP_DEBUG=false\n"
            f"APP_KEY=base64:{token}\n"
            f"DB_HOST={host}\n"
            "DB_PORT=3306\n"
            "DB_DATABASE=appdb\n"
            "DB_USERNAME=appuser\n"
            f"DB_PASSWORD=tw-{token}\n"
            f"MAIL_PASSWORD=tw-{token}\n"
            f"API_TOKEN=tw-{token}\n"
        )
    elif lower.endswith(".php") or lower.endswith(".php.bak"):
        kind = "php"
        body = (
            "<?php\n"
            "// database connection\n"
            f"$db_host = '{host}';\n"
            "$db_user = 'appuser';\n"
            f"$db_pass = 'tw-{token}';\n"
            "$db_name = 'appdb';\n"
            f"define('API_TOKEN', 'tw-{token}');\n"
        )
    elif lower.endswith(".sql"):
        kind = "sql"
        body = (
            "-- MySQL dump 10.13\n"
            f"-- Host: {host}    Database: appdb\n\n"
            "CREATE TABLE `users` (\n"
            "  `id` int(11) NOT NULL AUTO_INCREMENT,\n"
            "  `email` varchar(255) NOT NULL,\n"
            "  `password` varchar(255) NOT NULL,\n"
            "  PRIMARY KEY (`id`)\n"
            ") ENGINE=InnoDB;\n\n"
            "INSERT INTO `users` VALUES "
            f"(1,'svc-{token[:6].lower()}@example.invalid','tw-{token}');\n"
        )
    elif lower.endswith(".csv"):
        kind = "csv"
        body = (
            "id,email,password,role\n"
            f"1,svc-{token[:6].lower()}@example.invalid,tw-{token},admin\n"
            f"2,backup@example.invalid,tw-{token},service\n"
        )
    elif lower.endswith(".yml") or lower.endswith(".yaml"):
        kind = "yaml"
        body = (
            "production:\n"
            "  adapter: mysql2\n"
            f"  host: {host}\n"
            "  username: appuser\n"
            f"  password: tw-{token}\n"
        )
    elif "id_rsa" in lower:
        kind = "key"
        # Not a key. Filler shaped like one, so a harvester stores it and the
        # token travels with it.
        filler = "\n".join(
            secrets.token_urlsafe(48)[:64] for _ in range(12)
        )
        body = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{filler}\n"
            f"{token}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
    elif lower.endswith("config") or ".git" in lower:
        kind = "git"
        body = (
            "[core]\n"
            "\trepositoryformatversion = 0\n"
            "[remote \"origin\"]\n"
            f"\turl = https://svc:tw-{token}@git.internal.example/app.git\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        )
    elif lower.endswith(".ini"):
        kind = "ini"
        body = (
            "[database]\n"
            f"host = {host}\n"
            "user = appuser\n"
            f"password = tw-{token}\n"
        )
    else:
        kind = "text"
        body = (
            "Migration notes.\n\n"
            "Old host is being retired. Service account details are in the\n"
            f"backup bundle. Temporary token: tw-{token}\n"
        )

    return kind, body.encode("utf-8")


def is_private(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False


def make_handler(store: Store, pages: dict[str, tuple[str, bytes]],
                 trust_proxy: bool, quiet: bool, tarpit: Tarpit | None,
                 sink: JsonlSink | None):
    # Fires once, the first time a hit arrives from a private address while a
    # forwarded-address header is being ignored. Behind a tunnel every client
    # shows up as the bridge address, so without this the address column looks
    # populated while carrying no attribution at all.
    warned = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        server_version = "nginx"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        # -- helpers ---------------------------------------------------

        def forwarded_ip(self) -> str | None:
            """Client address as reported by the proxy, if any.

            CF-Connecting-IP first: a Cloudflare Tunnel sets it to the true
            client and, unlike X-Forwarded-For, it is a single value that
            Cloudflare overwrites rather than appends to.
            """
            cf = self.headers.get("CF-Connecting-IP")
            if cf:
                return cf.strip()
            fwd = self.headers.get("X-Forwarded-For")
            if fwd:
                return fwd.split(",")[0].strip()
            real = self.headers.get("X-Real-IP")
            return real.strip() if real else None

        def client_ip(self) -> str:
            if trust_proxy:
                forwarded = self.forwarded_ip()
                if forwarded:
                    return forwarded
            return self.client_address[0]

        def log_message(self, fmt: str, *args: object) -> None:
            if not quiet:
                sys.stderr.write("%s %s\n" % (self.client_address[0], fmt % args))

        def send_payload(self, ctype: str, body: bytes, status: int = 200) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            # Defeat caching so every visit produces a hit.
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def dribble(self, ctype: str, body: bytes, delay: float,
                    status: int = 200) -> float:
            """Send a response slowly. Returns seconds actually spent.

            Part of the delay lands before the headers, so a client waiting
            on a first byte waits. The rest is spread across the body, so a
            client that got its headers and thinks it is receiving still has
            to sit through the transfer. Both halves are ordinary blocking
            writes of a small, bounded body. Nothing is amplified.
            """
            if delay <= 0:
                self.send_payload(ctype, body, status)
                return 0.0

            started = time.monotonic()
            head = min(delay * 0.3, 5.0)
            tail = delay - head
            try:
                time.sleep(head)
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store, max-age=0")
                self.end_headers()
                if self.command == "HEAD" or not body:
                    self.wfile.flush()
                    return time.monotonic() - started

                slices = 8
                step = max(1, (len(body) + slices - 1) // slices)
                pause = tail / slices
                for offset in range(0, len(body), step):
                    self.wfile.write(body[offset:offset + step])
                    self.wfile.flush()
                    time.sleep(pause)
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                # It hung up. That is a result too: the held time up to this
                # point is what its patience was worth.
                self.close_connection = True
            return time.monotonic() - started

        def check_attribution(self, ip: str) -> None:
            if trust_proxy or warned.is_set() or not is_private(ip):
                return
            if not self.forwarded_ip():
                return
            warned.set()
            print(
                f"WARNING: hit came from private address {ip} and carries a "
                "forwarded-address header that is being ignored. Every client "
                "will log as this address and attribution is lost. Restart "
                "with --trust-proxy, but only once the proxy or tunnel is the "
                "sole route to this port.",
                file=sys.stderr, flush=True,
            )

        def capture(self, tier: int, query: dict[str, list[str]], body: bytes,
                    depth: int | None = None, canary: str | None = None,
                    delay_ms: int | None = None) -> int:
            excerpt = body[:BODY_EXCERPT].decode("utf-8", "replace") if body else None
            ip = self.client_ip()
            self.check_attribution(ip)
            row = dict(
                ts=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                tier=tier,
                placement=(query.get("p") or [None])[0],
                agent_self=(query.get("as") or [None])[0],
                method=self.command,
                path=urlsplit(self.path).path,
                query=urlsplit(self.path).query or None,
                ip=ip,
                user_agent=self.headers.get("User-Agent"),
                headers=json.dumps(dict(self.headers.items()), ensure_ascii=False),
                body_len=len(body),
                body_excerpt=excerpt,
                depth=depth,
                # The delay we intend to apply, known before the response
                # starts. held_ms is filled in afterwards with what actually
                # elapsed, which is shorter when the client hangs up early.
                # The shipped event carries the intent; the local database
                # carries both.
                delay_ms=delay_ms,
                canary=canary,
            )
            hit_id = store.record(**row)
            if sink is not None:
                event = dict(row)
                event["id"] = hit_id
                event["headers"] = dict(self.headers.items())
                sink.write(event)
            if not quiet:
                print(
                    f"[hit {hit_id}] tier={tier} "
                    f"placement={(query.get('p') or ['-'])[0]} "
                    f"as={(query.get('as') or ['-'])[0]} ip={ip}"
                    + (f" depth={depth}" if depth is not None else ""),
                    flush=True,
                )
            return hit_id

        def read_body(self) -> bytes:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return b""
            return self.rfile.read(min(length, MAX_BODY)) if length > 0 else b""

        def not_found(self) -> None:
            self.send_payload(
                "text/html; charset=utf-8",
                b"<!doctype html><meta charset=utf-8><title>Not found</title>"
                b"<h1>Not found</h1><p><a href=\"/\">Back</a></p>\n",
                404,
            )

        def exempt_crawler(self) -> bool:
            ua = (self.headers.get("User-Agent") or "").lower()
            return any(name in ua for name in TARPIT_EXEMPT)

        # -- tarpit ----------------------------------------------------

        def serve_tarpit(self, path: str, query: dict[str, list[str]]) -> None:
            """Hold a client inside the labyrinth and record how far it went."""
            assert tarpit is not None
            ip = self.client_ip()

            # Depth is structural: how many segments below the root the
            # client has walked. It cannot be reset without leaving.
            rel = path[len(TARPIT_ROOT):].strip("/")
            depth = len([seg for seg in rel.split("/") if seg]) if rel else 0

            # Something claiming to be a search engine, inside a directory
            # robots.txt tells it to stay out of. Log it, do not hold it.
            if self.exempt_crawler():
                self.capture(5, query, b"", depth=depth)
                self.not_found()
                return

            token = secrets.token_urlsafe(12)
            last = rel.rsplit("/", 1)[-1] if rel else ""
            looks_like_file = "." in last and not path.endswith("/")

            if looks_like_file:
                kind, body = tarpit_artifact(last, token)
                ctype = CONTENT_TYPES.get(
                    "." + last.rsplit(".", 1)[-1].lower(), "text/plain; charset=utf-8"
                )
                if kind in ("php", "git", "key", "env", "ini"):
                    ctype = "text/plain; charset=utf-8"
            else:
                kind, body = "listing", tarpit_listing(path, depth, token)
                ctype = "text/html; charset=utf-8"

            delay, rate, _held = tarpit.delay_for(ip, depth)
            hit_id = self.capture(5, query, b"", depth=depth, canary=token,
                                  delay_ms=int(delay * 1000))
            store.record_canary(
                token=token,
                ts=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                hit_id=hit_id,
                kind=kind,
                path=path,
                ip=ip,
                user_agent=self.headers.get("User-Agent"),
            )

            admitted = tarpit.enter() if delay > 0 else False
            spent = 0.0
            try:
                spent = self.dribble(ctype, body, delay if admitted else 0.0)
            finally:
                if admitted:
                    tarpit.leave(ip, spent)
            if spent:
                store.set_held(hit_id, int(spent * 1000))
            if not quiet:
                print(
                    f"[tarpit {hit_id}] depth={depth} rate={rate}/min "
                    f"held={spent:.1f}s kind={kind}",
                    flush=True,
                )

        # -- routes ----------------------------------------------------

        def do_HEAD(self) -> None:  # noqa: N802
            self.do_GET()

        def do_GET(self) -> None:  # noqa: N802
            split = urlsplit(self.path)
            path, query = split.path, parse_qs(split.query)

            if path == "/healthz":
                self.send_payload("text/plain; charset=utf-8", b"ok")
                return

            # The lure is checked before the site, so a real page can never
            # shadow it.
            if path == LURE_PATH:
                try:
                    tier = int((query.get("t") or ["1"])[0])
                except ValueError:
                    tier = 1
                tier = tier if tier in (1, 2) else 1
                self.capture(tier, query, b"")
                self.send_payload(
                    "text/plain; charset=utf-8",
                    b"Mirror current as of publication. No further action "
                    b"required.\n",
                )
                return

            if path in pages:
                self.capture(0, query, b"")
                ctype, body = pages[path]
                self.send_payload(ctype, body)
                return

            if tarpit is not None and (
                path == TARPIT_ROOT
                or path.startswith(TARPIT_ROOT + "/")
                or path in TARPIT_BAIT
            ):
                self.serve_tarpit(path, query)
                return

            # Tier 4 is off the ladder: it proves nothing on its own. A
            # request for a path that does not exist is background scanner
            # noise, and a public host gets a great deal of it. Logging these
            # as tier 1 would mean every probe for a random admin panel
            # looked like something that had read the profile page.
            #
            # The rate-only delay still applies. One mistyped URL costs
            # nothing. A wordlist grind gets slower with every request, which
            # is what catches the scanner that never takes the bait.
            body = (
                b"<!doctype html><meta charset=utf-8><title>Not found</title>"
                b"<h1>Not found</h1><p><a href=\"/\">Back</a></p>\n"
            )
            if tarpit is None or self.exempt_crawler():
                self.capture(4, query, b"")
                self.send_payload("text/html; charset=utf-8", body, 404)
                return
            # Measure the rate before recording, so the shipped event carries
            # the delay this request earned rather than the previous one's.
            delay, _rate, _held = tarpit.delay_for(self.client_ip(), None)
            hit_id = self.capture(4, query, b"", delay_ms=int(delay * 1000))
            admitted = tarpit.enter() if delay > 0 else False
            spent = 0.0
            try:
                spent = self.dribble(
                    "text/html; charset=utf-8", body,
                    delay if admitted else 0.0, 404,
                )
            finally:
                if admitted:
                    tarpit.leave(self.client_ip(), spent)
            if spent:
                store.set_held(hit_id, int(spent * 1000))

        def do_POST(self) -> None:  # noqa: N802
            split = urlsplit(self.path)
            path, query = split.path, parse_qs(split.query)
            body = self.read_body()

            # Same reasoning: only a POST to the real form is on the ladder.
            self.capture(3 if path == COLLECT_PATH else 4, query, body)
            if path == COLLECT_PATH:
                self.send_payload(
                    "text/html; charset=utf-8",
                    b"<!doctype html><meta charset=utf-8><title>Thanks</title>"
                    b"<h1>Thanks</h1><p>Message received.</p>"
                    b"<p><a href=\"/\">Back</a></p>\n",
                )
                return
            self.not_found()

    return Handler


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default: 127.0.0.1, loopback only)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--db", default="tripwire.sqlite3")
    ap.add_argument("--site", default=str(pathlib.Path(__file__).resolve().parent / "site"),
                    help="directory holding the cover site")
    ap.add_argument("--jsonl", default=os.environ.get("TRIPWIRE_JSONL"),
                    help="also append every hit as JSON to this file, for a "
                         "log shipper to tail")
    ap.add_argument("--trust-proxy", action="store_true",
                    help="read the client address from CF-Connecting-IP or "
                         "X-Forwarded-For; only set this when a tunnel or "
                         "proxy you control is the sole route to this port")
    ap.add_argument("--no-tarpit", action="store_true",
                    help="disable the labyrinth and all response delays")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    pages = load_site(pathlib.Path(args.site))
    if not pages:
        print(f"WARNING: no cover site loaded from {args.site}. The hostname "
              "will answer 404 at the root, which is itself a tell.",
              file=sys.stderr, flush=True)

    store = Store(args.db)
    sink = JsonlSink(args.jsonl) if args.jsonl else None
    tarpit = None if args.no_tarpit else Tarpit()
    handler = make_handler(store, pages, args.trust_proxy, args.quiet, tarpit, sink)

    # One thread per connection, and the tarpit deliberately keeps some of
    # them parked. daemon_threads means a shutdown does not wait them out.
    ThreadingHTTPServer.daemon_threads = True
    httpd = ThreadingHTTPServer((args.host, args.port), handler)

    print(f"tripwire receiver on http://{args.host}:{args.port}  "
          f"db={args.db}  cover pages={len(pages)}  "
          f"tarpit={'off' if tarpit is None else 'on'}"
          + (f"  jsonl={args.jsonl}" if sink else ""), flush=True)
    if args.host not in ("127.0.0.1", "::1", "localhost"):
        print("NOTE: bound to a non-loopback address. Inside a container "
              "namespace that is expected, and host exposure is governed by "
              "the published port. Anywhere else, this is reachable off-box.",
              file=sys.stderr, flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping", flush=True)
    finally:
        httpd.server_close()
        if sink is not None:
            sink.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
