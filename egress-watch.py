#!/usr/bin/env python3
"""Turn refused outbound connections on the sentinel VM into events.

The VM is meant to be owned one day. `harden-sentinel.sh` decides what an
owner can do from it -- nothing outbound -- and the interesting half of that
is not the drop, it is the attempt. The first thing a payload does after it
lands is call home, and the call names the address it was built to reach.

nftables logs those attempts to the kernel ring buffer with a fixed prefix.
This follows the journal, turns each line into one JSON object in the shape
the rest of tripwire uses, and appends it to a file the sentinel's Vector
already mounts. Two prefixes, two scopes:

    tripwire-egress          a uid inside a container tried to get out
    tripwire-egress-other    something else on the host did

Two bounds, because the input is under somebody else's hand once the VM is
owned. The kernel rate limit in the ruleset bounds lines per minute; the
window here bounds events per line, so a container in a reconnect loop costs
one event a minute rather than one an attempt.

The line is a string the kernel built, but the numbers in it came from a
socket somebody else opened. So: one anchored regular expression, every
field coerced and range-checked, lengths capped, nothing passed to a shell,
and no attacker-supplied text copied into the event at all -- an egress
event is addresses and integers, and that is the whole of it.

    python3 egress-watch.py --selftest    parses the lines, no journal, no root
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

WINDOW = 60.0                     # seconds one (dst, port, uid) is collapsed over
MAX_BYTES = 10 * 1024 * 1024      # the log is truncated once it passes this
MAX_LINE = 1024                   # a kernel log line is ~200 bytes; this is slack
OUT_DEFAULT = "/var/log/tripwire-egress/egress.jsonl"
JOURNAL = ["journalctl", "-k", "-f", "-n", "0", "-o", "cat"]

# Anchored at the start of the message on purpose: only the kernel writes to
# the `-k` journal, but a rule that matches mid-line would let anything that
# quotes the prefix invent an event. `.match()` anchors as well; the \A says
# so to the reader.
LINE = re.compile(
    r"\Atripwire-egress(?P<other>-other)? "
    r".*?\bSRC=(?P<src>\S+) DST=(?P<dst>\S+)\s"
    r".*?\bPROTO=(?P<proto>\w+)"
    r"(?: SPT=\d+ DPT=(?P<dport>\d+))?"
    r"(?:.*?\bUID=(?P<uid>\d+))?"
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_line(text: str) -> dict | None:
    """One kernel log line to one event, or None if it is not one of ours."""
    match = LINE.match(text[:MAX_LINE])
    if not match:
        return None
    try:
        dst = ipaddress.ip_address(match.group("dst"))
    except ValueError:
        return None

    event: dict[str, object] = {
        "kind": "egress",
        "egress_dst_ip": str(dst),
        "egress_proto": match.group("proto").lower()[:12],
        "egress_scope": "other" if match.group("other") else "container",
    }
    port = match.group("dport")
    if port is not None and 0 <= int(port) <= 65535:
        event["egress_dst_port"] = int(port)
    uid = match.group("uid")
    if uid is not None and int(uid) <= 0xFFFFFFFF:
        event["egress_uid"] = int(uid)
    return event


class Window:
    """One event per (destination, port, uid) per window, with a count.

    No cap on the number of open keys: the ruleset's `limit rate 30/minute`
    on each of the two log rules bounds the input to a couple of dozen
    distinct keys inside any one window, so there is nothing here to bound.
    """

    def __init__(self, window: float = WINDOW) -> None:
        self.window = window
        self.open: dict[tuple, list] = {}

    def add(self, event: dict, now: float) -> None:
        key = (event["egress_dst_ip"],
               event.get("egress_dst_port"),
               event.get("egress_uid"),
               event["egress_scope"])
        slot = self.open.get(key)
        if slot is None:
            self.open[key] = [event, 1, now, now_iso()]
        else:
            slot[1] += 1

    def due(self, now: float) -> list[dict]:
        """Every window that has closed, as a finished event."""
        ready = []
        for key, (event, count, started, stamp) in list(self.open.items()):
            if now - started >= self.window:
                ready.append({"ts": stamp, **event, "egress_count": count})
                del self.open[key]
        return ready


class LineBuffer:
    """Split a raw byte stream into lines.

    The pipe has to be read raw. `select()` reports a descriptor ready, but
    a buffered `readline()` pulls whatever else has arrived into Python's
    own buffer and hands back one line; `select()` then calls the descriptor
    quiet while the rest of the burst is sitting in userspace. On a host
    being scanned the burst is the interesting part.

    The tail cap is the hostile half. Once the VM is owned, something can
    write to the journal without ever writing a newline, so an unterminated
    tail past MAX_LINE is dropped along with everything up to the next
    newline rather than grown.
    """

    def __init__(self, max_line: int = MAX_LINE) -> None:
        self.max_line = max_line
        self.tail = b""
        self.skipping = False

    def feed(self, chunk: bytes) -> list[str]:
        parts = (self.tail + chunk).split(b"\n")
        self.tail = parts.pop()
        lines = []
        for part in parts:
            if self.skipping:          # the remainder of an over-long line
                self.skipping = False
                continue
            lines.append(part.decode("utf-8", "replace"))
        if len(self.tail) > self.max_line:
            self.tail = b""
            self.skipping = True
        return lines


class Out:
    """Append JSONL for Vector to tail.

    # ponytail: one file, truncated when it passes MAX_BYTES. Rotate
    # properly if this ever holds anything worth keeping across the reset.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)

    def write(self, event: dict) -> None:
        try:
            if os.path.exists(self.path) and os.path.getsize(self.path) > MAX_BYTES:
                open(self.path, "w", encoding="utf-8").close()
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(event) + "\n")
        except OSError as exc:
            print(f"egress-watch: cannot write {self.path}: {exc}", file=sys.stderr)


def follow(args) -> int:
    import select

    window = Window(args.window)
    out = Out(args.out)
    buffer = LineBuffer()
    # Binary and unbuffered: see LineBuffer for why readline() loses bursts.
    proc = subprocess.Popen(JOURNAL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, bufsize=0)
    fd = proc.stdout.fileno()
    try:
        while True:
            if proc.poll() is not None:
                print("egress-watch: journalctl exited", file=sys.stderr)
                return 1
            # A one-second wait rather than a blocking read, so a window
            # still closes on a quiet host.
            ready, _, _ = select.select([fd], [], [], 1.0)
            if ready:
                chunk = os.read(fd, 65536)
                if not chunk:
                    print("egress-watch: journalctl closed its pipe",
                          file=sys.stderr)
                    return 1
                for line in buffer.feed(chunk):
                    event = parse_line(line)
                    if event is not None:
                        window.add(event, time.monotonic())
            for finished in window.due(time.monotonic()):
                out.write(finished)
    except KeyboardInterrupt:
        return 0
    finally:
        proc.terminate()


CONTAINER = ("tripwire-egress IN= OUT=eth0 SRC=192.0.2.10 DST=198.51.100.7 "
             "LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=4242 DF PROTO=TCP "
             "SPT=51234 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0 "
             "UID=100000 GID=100000")
OTHER = ("tripwire-egress-other IN= OUT=eth0 SRC=192.0.2.10 DST=198.51.100.9 "
         "LEN=76 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=UDP SPT=51820 "
         "DPT=51820 LEN=56")
ICMP = ("tripwire-egress IN= OUT=eth0 SRC=192.0.2.10 DST=198.51.100.1 LEN=84 "
        "TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=ICMP TYPE=8 CODE=0 ID=7 "
        "SEQ=1 UID=1000 GID=1000")
ICMPV6 = ("tripwire-egress IN= OUT=eth0 SRC=2001:db8::10 DST=2001:db8::1 "
          "LEN=64 TC=0 HOPLIMIT=64 FLOWLBL=0 PROTO=ICMPv6 TYPE=128 CODE=0 "
          "UID=1000 GID=1000")


def selftest() -> int:
    event = parse_line(CONTAINER)
    assert event == {"kind": "egress", "egress_dst_ip": "198.51.100.7",
                     "egress_proto": "tcp", "egress_scope": "container",
                     "egress_dst_port": 443, "egress_uid": 100000}, event

    other = parse_line(OTHER)
    assert other is not None and other["egress_scope"] == "other", other
    # The WireGuard handshake carries no socket owner: no uid key at all,
    # rather than a zero that would read as root.
    assert "egress_uid" not in other, other
    assert other["egress_dst_port"] == 51820, other

    icmp = parse_line(ICMP)
    assert icmp is not None and "egress_dst_port" not in icmp, icmp
    assert icmp["egress_proto"] == "icmp" and icmp["egress_uid"] == 1000, icmp

    six = parse_line(ICMPV6)
    assert six is not None and six["egress_dst_ip"] == "2001:db8::1", six
    assert six["egress_proto"] == "icmpv6" and "egress_dst_port" not in six, six

    assert parse_line("") is None
    assert parse_line("random kernel chatter about a USB device") is None
    assert parse_line(CONTAINER.replace("198.51.100.7", "not-an-ip")) is None
    # Only the kernel writes the -k journal, but the anchor is the reason a
    # line that merely quotes the prefix cannot manufacture an event.
    assert parse_line("audit: " + CONTAINER) is None

    window = Window(60.0)
    for _ in range(500):
        parsed = parse_line(CONTAINER)
        assert parsed is not None
        window.add(parsed, 100.0)
    assert window.due(150.0) == []
    closed = window.due(161.0)
    assert len(closed) == 1, closed
    assert closed[0]["egress_count"] == 500, closed[0]
    assert closed[0]["egress_dst_ip"] == "198.51.100.7"
    assert closed[0]["kind"] == "egress"
    assert "ip" not in closed[0] and "egress_src_ip" not in closed[0]
    assert window.due(999.0) == []

    # Distinct destinations are distinct events.
    window = Window(60.0)
    window.add(parse_line(CONTAINER), 0.0)
    window.add(parse_line(ICMP), 0.0)
    assert len(window.due(61.0)) == 2

    # A burst arrives as one read, not as one line per select().
    burst = LineBuffer()
    chunk = (CONTAINER + "\n").encode() * 30
    got = burst.feed(chunk)
    assert len(got) == 30, len(got)
    assert all(parse_line(line) is not None for line in got)
    assert burst.tail == b""

    # A line cut in half by the pipe is one line, once the rest arrives.
    split = LineBuffer()
    half = CONTAINER[:40].encode()
    assert split.feed(half) == []
    assert split.feed(CONTAINER[40:].encode() + b"\n") == [CONTAINER]

    # Something writing without newlines does not grow the buffer, and the
    # remains of the over-long line do not become an event of their own.
    hostile = LineBuffer()
    assert hostile.feed(b"A" * 5000) == []
    assert len(hostile.tail) <= MAX_LINE
    assert hostile.feed(b"\n" + CONTAINER.encode() + b"\n") == [CONTAINER]

    print("selftest ok")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Report outbound connections the firewall refused.")
    parser.add_argument("--selftest", action="store_true",
                        help="parse the known line shapes and exit")
    parser.add_argument("--out", default=OUT_DEFAULT, help="JSONL to append to")
    parser.add_argument("--window", type=float, default=WINDOW,
                        help="seconds one destination is collapsed over")
    args = parser.parse_args(argv)
    return selftest() if args.selftest else follow(args)


if __name__ == "__main__":
    sys.exit(main())
