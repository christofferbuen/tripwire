#!/usr/bin/env python3
"""Turn payload.html into the block you actually paste into the CMS.

payload.html is the annotated source. It is written for you, not for the
page, and it cannot be pasted anywhere as it stands. Two reasons.

The hostname is a placeholder. That one is obvious and would fail loudly.

The comments are not. They say "Tier 0, render beacons", "Tiers 1 and 2, the
lure", and the placeholder itself is the word TRIPWIRE. HTML comments are
served to every client and are one keystroke away in any browser. Publishing
them hands the whole design to the first person who views the source, which
is precisely the population being watched for. Stripping them by hand is the
kind of step that gets skipped once.

So this does both, and then refuses to emit anything that still looks wrong.

    ./render-payload.py notes.example.com
    ./render-payload.py notes.example.com --with-collection

Output goes to stdout, checks go to stderr. Nothing here touches the network
or the profile page; publishing stays a manual, deliberate act.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PLACEHOLDER = "TRIPWIRE_HOST"
COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)

# Occurrences expected to survive comment stripping. Getting this wrong in
# either direction means the file changed underneath this script: too few and
# a beacon was dropped, too many and something is being emitted that was
# meant to stay commented out.
EXPECTED_HOSTS = 4
EXPECTED_HOSTS_WITH_COLLECTION = 5

# Words that give the game away to anyone reading the page source. The point
# of the cover story is that the block looks like an ordinary indexing note.
#
# Matched on word boundaries, not as substrings. "lure" inside "failure" is
# the obvious one, and a check that cries wolf on ordinary prose is a check
# that gets commented out.
TELLS = (
    "tripwire", "canary", "canaries", "honeypot", "honeytoken", "beacon",
    "beacons", "tarpit", "lure", "bait", "trap", "tier", "tiers", "payload",
    "instrumented", "exfil", "labyrinth", "sentinel",
)
TELL_RE = re.compile(r"\b(" + "|".join(TELLS) + r")\b")

# A hostname that describes the trap is self-defeating, however clean the
# markup is.
HOSTNAME_TELLS = ("tripwire", "canary", "honeypot", "honey", "trap", "bait")


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def check_hostname(host: str) -> None:
    if "://" in host or "/" in host:
        fail(f"give a bare hostname, not a URL: {host!r}")
    if any(c.isspace() for c in host) or not host:
        fail(f"not a hostname: {host!r}")
    if host.startswith(".") or host.endswith(".") or ".." in host:
        fail(f"not a hostname: {host!r}")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        fail(f"not a hostname: {host!r}")
    if "." not in host:
        fail(f"{host!r} has no dot in it. A bare label will not resolve for "
             "anyone reading the profile page.")
    for tell in HOSTNAME_TELLS:
        if tell in host.lower():
            fail(f"the hostname contains {tell!r}. The whole cover story is "
                 "that this is an unremarkable personal blog; a hostname that "
                 "describes the trap gives it away before anything is fetched.")


def extract_collection_block(source: str) -> str:
    """Pull the tier 3 paragraph out of the comment that disables it."""
    for comment in COMMENT.findall(source):
        if "/contact?p=" not in comment:
            continue
        match = re.search(r"<p\b.*?</p>", comment, re.DOTALL)
        if match:
            return match.group(0)
    fail("--with-collection was given but the commented-out collection "
         "paragraph is not in payload.html any more.")
    raise AssertionError("unreachable")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render payload.html into a pasteable block.")
    parser.add_argument("hostname",
                        help="the receiver's hostname, bare, e.g. notes.example.com")
    parser.add_argument("--source", default=None,
                        help="path to payload.html (default: next to this script)")
    parser.add_argument(
        "--with-collection", action="store_true",
        help="also emit the tier 3 collection paragraph. This captures other "
             "people's request bodies, which you then have to justify holding "
             "and delete on a schedule. Off by default on purpose.")
    parser.add_argument("--placement", default=None,
                        help="override the p= tag, so one hostname can serve "
                             "several placements and you can tell them apart")
    args = parser.parse_args()

    check_hostname(args.hostname)

    source_path = Path(args.source) if args.source else Path(__file__).with_name("payload.html")
    if not source_path.is_file():
        fail(f"no such file: {source_path}")
    source = source_path.read_text(encoding="utf-8")

    collection = extract_collection_block(source) if args.with_collection else ""

    body = COMMENT.sub("", source)
    if collection:
        body = body.rstrip() + "\n\n" + collection + "\n"

    # Collapse the blank runs the stripped comments left behind.
    body = re.sub(r"\n{3,}", "\n\n", body).strip() + "\n"
    body = body.replace(PLACEHOLDER, args.hostname)

    if args.placement:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", args.placement):
            fail(f"placement tag must be plain: {args.placement!r}")
        body = re.sub(r"(?<=[?&]p=)[A-Za-z0-9._-]+", args.placement, body)

    # ---- refuse to emit anything that still looks wrong -------------------

    if PLACEHOLDER in body:
        fail("the placeholder survived substitution")
    if "<!--" in body or "-->" in body:
        fail("a comment survived stripping")
    if "http://" in body:
        fail("an http:// URL is in the output. The profile page is https, so "
             "browsers block it as mixed content and tier 0 dies silently.")

    hosts = body.count(args.hostname)
    expected = EXPECTED_HOSTS_WITH_COLLECTION if args.with_collection else EXPECTED_HOSTS
    if hosts != expected:
        fail(f"expected {expected} references to the hostname, found {hosts}. "
             "payload.html has changed; check what was added or lost before "
             "publishing this.")

    found = sorted(set(TELL_RE.findall(body.lower())))
    if found:
        fail("the output still names the mechanism: "
             + ", ".join(repr(f) for f in found)
             + ". Reword payload.html; anyone can read this in the page source.")

    print(body, end="")

    placements = sorted(set(re.findall(r"[?&]p=([A-Za-z0-9._-]+)", body)))
    print(f"ok: {hosts} references to {args.hostname}, comments stripped, "
          f"placement tag {', '.join(placements) or 'none'}",
          file=sys.stderr)
    if args.with_collection:
        print("note: collection is ON. This records request bodies belonging "
              "to third parties. Keep retention short and delete on a "
              "schedule.", file=sys.stderr)
    print("nothing was published. Paste it yourself, then check what the CMS "
          "kept.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
