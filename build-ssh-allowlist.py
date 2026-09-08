#!/usr/bin/env python3
"""Build a Hetzner Cloud Firewall source list for the sentinel's admin port.

The sentinel needs port 22 for the SSH sensor, so administrative sshd moves
elsewhere. That port is then restricted by source, because camouflage alone
does not work: RFC 4253 requires sshd to announce "SSH-2.0-<software>" before
key exchange, so any port it listens on is one `nmap -sV` away from being
labelled correctly. The only thing that hides sshd is the packet not arriving.

Country-level filtering is the obvious idea and usually does not fit. A
mid-sized country's RIPE delegation runs to thousands of IPv4 ranges against a
Hetzner ceiling of roughly 500 effective entries. It is also the weaker
control: a whole country is millions of hosts, every compromised router among
them, and anyone can rent a VPS inside it for three euros. Allowlisting the
few networks an administrator actually connects from is smaller and tighter.

Which networks those are is deployment-specific, so it is not in this file.
Put it in `allowlist.local.json`, which is untracked. See allowlist.example.json.

    ./build-ssh-allowlist.py --check          # verify you are inside the set
    ./build-ssh-allowlist.py --format hcloud  # commands to apply it

Prefix allocations churn. Re-run this when a login fails from a network that
used to work, and before assuming the box is down.

Read-only against public routing data. Applies nothing; the hcloud commands
are printed for you to run deliberately.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

CONFIG = "allowlist.local.json"

# Hetzner documents 100 CIDRs per rule and 500 "effective" rules per firewall,
# where effective counts expansion across entries and address families. The
# exact arithmetic is not published, so treat this as advisory: the API is the
# real authority and will reject an oversized ruleset.
BUDGET = 450

RIPESTAT = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{}"

TEMPLATE = """{
 "asns":     { "64496": "why this network is allowed" },
 "optional": { "64497": "included only with --with-mobile" }
}"""


def load_config(path: Path) -> tuple[dict, dict]:
    """Read the ASN list, or explain how to write one.

    Source it from a per-country eyeball ranking rather than guessing. Holder
    names change hands and stale notes on the internet outlive them, so
    confirm each ASN's current holder before trusting a number you found
    somewhere. Note also that such rankings order by residential user
    population, which means a network you use during the working day may not
    appear in one at all and has to be added by hand.
    """
    if not path.is_file():
        sys.exit(f"error: no {path.name}. It holds the networks you connect "
                 f"from, which are deployment-specific and stay untracked.\n\n"
                 f"Write {path.name} like this:\n\n{TEMPLATE}\n")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        sys.exit(f"error: {path.name} is not valid JSON: {exc}")

    asns = {int(k): v for k, v in (raw.get("asns") or {}).items()}
    optional = {int(k): v for k, v in (raw.get("optional") or {}).items()}
    if not asns:
        sys.exit(f"error: {path.name} lists no ASNs under \"asns\". An empty "
                 "allowlist applied to the firewall is a lockout.")
    return asns, optional


def fetch(url: str, timeout: int = 45):
    request = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def prefixes_for(asn: int) -> list:
    """Announced prefixes for one ASN, or abort.

    Failing closed matters more than usual here. An empty or partial answer
    silently produces a short allowlist, and a short allowlist applied to the
    firewall is a lockout -- discovered at the worst possible moment, from a
    network that no longer matches.
    """
    try:
        data = fetch(RIPESTAT.format(asn))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        sys.exit(f"error: could not fetch AS{asn} from RIPEstat: {exc}\n"
                 "Refusing to emit a partial list. Applying one would lock you out.")

    nets = []
    for entry in data["data"]["prefixes"]:
        try:
            nets.append(ipaddress.ip_network(entry["prefix"], strict=False))
        except ValueError:
            continue
    if not nets:
        sys.exit(f"error: AS{asn} announced no prefixes. That is not plausible; "
                 "RIPEstat is probably degraded. Try again later.")
    return nets


def build(asns: dict) -> tuple[list, list]:
    nets = []
    for asn, why in asns.items():
        got = prefixes_for(asn)
        print(f"AS{asn}: {len(got)} announced  ({why})", file=sys.stderr)
        nets.extend(got)

    v4 = sorted(ipaddress.collapse_addresses([n for n in nets if n.version == 4]))
    v6 = sorted(ipaddress.collapse_addresses([n for n in nets if n.version == 6]))

    # A default route in the output means the allowlist allows everyone, which
    # looks like a working firewall and is not one. Cheap to check, and the
    # failure is silent otherwise.
    for net in v4 + v6:
        if net.prefixlen == 0:
            sys.exit(f"error: {net} is in the output. That would allow the whole "
                     "internet to the admin port. Refusing to emit.")

    total = len(v4) + len(v6)
    print(f"aggregated: {len(v4)} IPv4 + {len(v6)} IPv6 = {total} entries",
          file=sys.stderr)
    if total > BUDGET:
        sys.exit(f"error: {total} entries is over the {BUDGET} working budget. "
                 "Drop an ASN, or apply it and let the API arbitrate.")
    return v4, v6


def check_membership(v4: list, v6: list) -> int:
    """Confirm this machine's address is inside the set before it is applied.

    Deliberately reports membership and the covering prefix, never the address
    itself. The point of the allowlist is knowing whether you are inside it,
    which does not require printing where you are into a transcript.
    """
    worst = 0
    for family, url, pool in (("IPv4", "https://api.ipify.org", v4),
                              ("IPv6", "https://api6.ipify.org", v6)):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(request, timeout=15) as response:
                addr = ipaddress.ip_address(response.read().decode().strip())
        except Exception:
            print(f"  {family}: no answer, so no {family} egress from here. "
                  f"Nothing to verify.", file=sys.stderr)
            continue

        covering = next((n for n in pool if addr in n), None)
        if covering:
            print(f"  {family}: COVERED by {covering}", file=sys.stderr)
            continue

        worst = 1
        try:
            info = fetch(f"https://stat.ripe.net/data/network-info/data.json?resource={addr}")
            asn = (info["data"].get("asns") or ["?"])[0]
            over = fetch(f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}")
            holder = over["data"].get("holder", "?")
            print(f"  {family}: NOT COVERED. You are on AS{asn} ({holder}). "
                  f"Add it to {CONFIG} or you will be locked out.", file=sys.stderr)
        except Exception:
            print(f"  {family}: NOT COVERED, and the owning ASN could not be "
                  f"looked up. Do not apply this.", file=sys.stderr)
    return worst


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the admin-port source allowlist for the sentinel.")
    parser.add_argument("--format", choices=("json", "hcloud", "plain"),
                        default="json")
    parser.add_argument("--port", type=int, default=10022,
                        help="administrative sshd port (default: 10022)")
    parser.add_argument("--firewall", default="sentinel",
                        help="hcloud firewall name, for --format hcloud")
    parser.add_argument("--config", default=None,
                        help=f"path to the ASN list (default: {CONFIG} next to "
                             "this script)")
    parser.add_argument("--with-mobile", action="store_true",
                        help="also include the ASNs listed under \"optional\", "
                             "so tethering works. Costs whatever they cost.")
    parser.add_argument("--check", action="store_true",
                        help="verify this machine falls inside the set. Reports "
                             "the covering prefix, never your address.")
    args = parser.parse_args()

    path = Path(args.config) if args.config else Path(__file__).with_name(CONFIG)
    asns, optional = load_config(path)
    if args.with_mobile:
        asns.update(optional)

    v4, v6 = build(asns)

    if args.check:
        print("coverage check:", file=sys.stderr)
        return check_membership(v4, v6)

    if args.format == "json":
        print(json.dumps({"v4": [str(n) for n in v4],
                          "v6": [str(n) for n in v6]}, indent=1))
    elif args.format == "plain":
        for net in v4 + v6:
            print(net)
    else:
        # hcloud takes at most 100 sources per rule, so the list is chunked.
        # Every chunk is a separate rule for the same port; together they are
        # one allowlist.
        entries = [str(n) for n in v4 + v6]
        chunks = [entries[i:i + 100] for i in range(0, len(entries), 100)]
        print(f"# {len(entries)} entries in {len(chunks)} rule(s). Run --check first.")
        print("# These ADD rules. hcloud firewall add-rule does not remove the")
        print("# sensor rules, but confirm the full ruleset afterwards with")
        print(f"# 'hcloud firewall describe {args.firewall}'.")
        for chunk in chunks:
            sources = " ".join(f"--source-ips {c}" for c in chunk)
            print(f"hcloud firewall add-rule {args.firewall} --direction in "
                  f"--protocol tcp --port {args.port} {sources}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
