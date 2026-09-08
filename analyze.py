#!/usr/bin/env python3
"""Classify tripwire hits into visits and say what each client proved.

Standard library only.

A visit is all hits sharing a client address and user-agent within a time
window. Classification is driven by which tiers the visit touched:

  EXFILTRATOR          posted to the collection endpoint on a page's say-so
  INSTRUCTION-FOLLOWER hit the instructed lure, self-named or not
  URL-EXTRACTOR        hit the bare lure but never the instructed one
  CONTACT-FORM         posted, but rendered the site and carried no
                       placement tag: almost certainly a person using the
                       cover site's form rather than a baited agent
  LABYRINTH-WALKER     went three or more levels into the fake archive. It
                       kept following links no real page ever offered
  BAIT-TAKER           asked for a scanner-wordlist path, or scratched at
                       the archive without going deep
  GRINDER              a sustained run of requests for paths that do not
                       exist. A wordlist, not a person
  BROWSER              fetched every render beacon and no lure
  PARTIAL-RENDERER     fetched some render beacons and no lure
  COVER-VISITOR        loaded the cover pages only, without rendering them.
                       Somebody looked the hostname up by hand
  PROBE                a handful of requests for paths that do not exist.
                       Background scanner noise, which a public host gets
  UNCLASSIFIED         anything else

The NO-RENDER flag marks a visit that tripped a lure without fetching a
single render beacon. That is the strongest available signal for a client
that read the page as text rather than rendering it.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta

# Subresources the cover site's pages reference. A browser fetches these
# automatically; something reading the HTML as text does not.
BEACONS = {
    "/static/css/site.css",
    "/static/img/logo.svg",
    "/static/js/site.js",
}

ROBOTS = "/robots.txt"

# Kept in step with TARPIT_EXEMPT in receiver.py. A visit presenting one of
# these strings from inside the labyrinth is either lying about who it is or
# ignoring the robots file it just read.
CRAWLER_UAS = (
    "googlebot", "bingbot", "duckduckbot", "applebot", "yandexbot",
    "baiduspider", "slurp", "archive.org_bot", "ia_archiver",
)

GRINDER_THRESHOLD = 15  # tier-4 requests in one visit before it stops being noise


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def get(row: sqlite3.Row, key: str, default=None):
    """Column access that tolerates a database written before a migration."""
    try:
        value = row[key]
    except (IndexError, KeyError):
        return default
    return default if value is None else value


def load(db_path: str, since_hours: float | None) -> list[sqlite3.Row]:
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    sql = "SELECT * FROM hits ORDER BY ts ASC, id ASC"
    rows = list(db.execute(sql))
    db.close()
    if since_hours is None:
        return rows
    if not rows:
        return rows
    newest = parse_ts(rows[-1]["ts"])
    cutoff = newest - timedelta(hours=since_hours)
    return [r for r in rows if parse_ts(r["ts"]) >= cutoff]


def load_canaries(db_path: str) -> list[sqlite3.Row]:
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    try:
        rows = list(db.execute("SELECT * FROM canaries ORDER BY ts ASC"))
    except sqlite3.OperationalError:
        rows = []
    db.close()
    return rows


def group(rows: list[sqlite3.Row], window_min: float) -> list[list[sqlite3.Row]]:
    """Bucket hits by (ip, user-agent), splitting on gaps over the window."""
    buckets: dict[tuple[str, str], list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        buckets[(row["ip"] or "?", row["user_agent"] or "?")].append(row)

    visits: list[list[sqlite3.Row]] = []
    gap = timedelta(minutes=window_min)
    for hits in buckets.values():
        current = [hits[0]]
        for prev, nxt in zip(hits, hits[1:]):
            if parse_ts(nxt["ts"]) - parse_ts(prev["ts"]) > gap:
                visits.append(current)
                current = [nxt]
            else:
                current.append(nxt)
        visits.append(current)
    visits.sort(key=lambda v: parse_ts(v[0]["ts"]))
    return visits


def classify(visit: list[sqlite3.Row]) -> tuple[str, list[str]]:
    tiers = {row["tier"] for row in visit}
    tier0 = {row["path"] for row in visit if row["tier"] == 0}
    beacons = tier0 & BEACONS
    cover = tier0 - BEACONS - {ROBOTS}
    probes = [row for row in visit if row["tier"] == 4]
    trapped = [row for row in visit if row["tier"] == 5]
    max_depth = max((int(get(r, "depth", 0)) for r in trapped), default=0)
    flags: list[str] = []

    # The cover site has a working contact form, so a POST on its own does
    # not prove anything. A baited POST carries the placement tag from the
    # payload, and a baited client does not fetch the stylesheet first.
    posts = [row for row in visit if row["tier"] == 3]
    baited_post = any(row["placement"] for row in posts)

    if posts and (baited_post or not beacons):
        label = "EXFILTRATOR"
    elif posts:
        label = "CONTACT-FORM"
    elif 2 in tiers:
        label = "INSTRUCTION-FOLLOWER"
    elif 1 in tiers:
        label = "URL-EXTRACTOR"
    elif trapped and max_depth >= 3:
        label = "LABYRINTH-WALKER"
    elif trapped:
        label = "BAIT-TAKER"
    elif len(probes) >= GRINDER_THRESHOLD:
        label = "GRINDER"
    elif beacons == BEACONS:
        label = "BROWSER"
    elif beacons:
        label = "PARTIAL-RENDERER"
    elif cover:
        label = "COVER-VISITOR"
    elif probes:
        label = "PROBE"
    else:
        label = "UNCLASSIFIED"

    if tiers & {1, 2, 3} and not beacons:
        flags.append("NO-RENDER")

    named = [r["agent_self"] for r in visit if r["agent_self"]]
    if named:
        flags.append("SELF-NAMED=" + named[0])

    for row in visit:
        try:
            headers = json.loads(row["headers"] or "{}")
        except json.JSONDecodeError:
            continue
        lowered = {k.lower() for k in headers}
        if "sec-fetch-mode" not in lowered and row["path"] in BEACONS:
            flags.append("NO-FETCH-METADATA")
            break

    if any(r["body_len"] for r in visit):
        flags.append("CARRIED-BODY")

    # The contact form carries an off-screen "website" field that a person
    # never sees and never fills in. Anything that arrives with it populated
    # was filled by a machine walking the form.
    for row in posts:
        excerpt = row["body_excerpt"] or ""
        for pair in excerpt.split("&"):
            key, _, value = pair.partition("=")
            if key.strip() == "website" and value.strip():
                flags.append("FILLED-SPAM-TRAP")
                break

    if trapped:
        flags.append(f"MAX-DEPTH={max_depth}")
        tokens = [get(r, "canary") for r in trapped if get(r, "canary")]
        if tokens:
            flags.append(f"TOOK-CANARIES={len(tokens)}")

        # It read the file that told it to stay out, then went in anyway.
        robots_at = [
            parse_ts(r["ts"]) for r in visit
            if r["tier"] == 0 and r["path"] == ROBOTS
        ]
        if robots_at and min(robots_at) <= min(parse_ts(r["ts"]) for r in trapped):
            flags.append("ROBOTS-DEFIER")

        ua = (visit[0]["user_agent"] or "").lower()
        if any(name in ua for name in CRAWLER_UAS):
            flags.append("CLAIMED-CRAWLER")

    held = sum(int(get(r, "held_ms", 0)) for r in visit)
    if held >= 1000:
        flags.append(f"HELD={held // 1000}s")

    return label, sorted(set(flags))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", default="tripwire.sqlite3")
    ap.add_argument("--window", type=float, default=30.0,
                    help="minutes of inactivity that end a visit (default: 30)")
    ap.add_argument("--since", type=float, default=None,
                    help="only consider the last N hours of hits")
    ap.add_argument("--show-bodies", action="store_true",
                    help="print captured request bodies; these may contain "
                         "third-party data, so treat the output as sensitive")
    ap.add_argument("--canaries", action="store_true",
                    help="list every canary token handed out and who took it")
    args = ap.parse_args()

    if args.canaries:
        rows = load_canaries(args.db)
        if not rows:
            print("no canary tokens issued")
            return 0
        print(f"{len(rows)} canary tokens issued\n")
        for row in rows:
            print(f"  tw-{row['token']}")
            print(f"    taken   {row['ts']} by {row['ip']}")
            print(f"    as      {row['kind']} at {row['path']}")
            print(f"    agent   {row['user_agent']}")
        print("\nIf one of these is ever presented anywhere, look it up here "
              "to name the exact fetch that leaked it.")
        return 0

    rows = load(args.db, args.since)
    if not rows:
        print("no hits recorded")
        return 0

    visits = group(rows, args.window)
    counts: dict[str, int] = defaultdict(int)

    for visit in visits:
        label, flags = classify(visit)
        counts[label] += 1
        first, last = visit[0], visit[-1]
        span = parse_ts(last["ts"]) - parse_ts(first["ts"])
        placements = sorted({r["placement"] for r in visit if r["placement"]})

        print(f"\n{'=' * 72}")
        print(f"{label}{'  [' + ', '.join(flags) + ']' if flags else ''}")
        print(f"  when       {first['ts']}  (+{int(span.total_seconds())}s)")
        print(f"  address    {first['ip']}")
        print(f"  user-agent {first['user_agent']}")
        if placements:
            print(f"  placement  {', '.join(placements)}")
        print(f"  requests   {len(visit)}")
        for row in visit:
            q = f"?{row['query']}" if row["query"] else ""
            depth = get(row, "depth")
            extra = f"  d{depth}" if depth is not None else ""
            ms = int(get(row, "held_ms", 0))
            extra += f"  held {ms / 1000:.1f}s" if ms else ""
            print(f"    t{row['tier']}  {row['method']:4} {row['path']}{q}{extra}")
        if args.show_bodies:
            for row in visit:
                if row["body_excerpt"]:
                    print(f"  body ({row['body_len']} bytes):")
                    for line in row["body_excerpt"].splitlines():
                        print(f"    | {line}")

    print(f"\n{'=' * 72}")
    print(f"{len(visits)} visits from {len(rows)} hits")
    for label, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {n:5}  {label}")

    total_held = sum(int(get(r, "held_ms", 0)) for r in rows)
    if total_held:
        print(f"\n  {total_held / 1000:.0f}s of client time held in the tarpit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
