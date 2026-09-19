#!/usr/bin/env python3
"""Check generated mappings and monitors without contacting a cluster."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main():
    script = (ROOT / "bootstrap-opensearch.sh").read_text(encoding="utf-8")
    template = json.loads(re.search(r"tripwire_template=\"\$\(cat <<'EOF'\n(.*?)\nEOF", script, re.S)[1])
    # Execute the real generator on the real base template, not a stand-in.
    generate = re.search(r"fakevm_template=.*?python3 -c '(.*?)'\)", script, re.S)[1]
    result = subprocess.run([sys.executable, "-c", generate], input=json.dumps(template),
                            capture_output=True, text=True, check=True)
    fakevm = json.loads(result.stdout)
    assert fakevm["index_patterns"] == ["tripwire-fakevm-*"]
    assert fakevm["template"]["settings"]["plugins.index_state_management.rollover_alias"] == "tripwire-fakevm"
    mapping = fakevm["template"]["mappings"]
    assert mapping["dynamic"] is False and "dynamic_templates" not in mapping
    assert mapping["properties"]["source"]["properties"]["port"]["type"] == "integer"
    fields = mapping["properties"]["fakevm"]["properties"]
    for field in ("command", "output"):
        assert fields[field]["type"] == "text"
        assert fields[field]["fields"]["keyword"]["ignore_above"] == 1024
    live = json.loads(re.search(r'''/_mapping" '(\{.*?\})' \|\| true''', script, re.S)[1])
    assert live["properties"]["fakevm"]["properties"] == fields
    policy = json.loads(re.search(r"api PUT /_plugins/_ism/policies/tripwire-fakevm '(.*?)' >", script, re.S)[1])
    states = policy["policy"]["states"]
    assert states[-1]["actions"] == [{"delete": {}}]
    assert all(any(t["state_name"] == "delete" and t["conditions"]["min_index_age"] == "30d"
                   for t in s["transitions"]) for s in states[:-1])
    role = json.loads(re.search(r"api PUT /_plugins/_security/api/roles/sentinel-writer '(.*?)' >", script, re.S)[1])
    permission = role["index_permissions"][0]
    assert "tripwire-fakevm*" in permission["index_patterns"]
    assert not any("read" in a or "create" in a for a in permission["allowed_actions"])

    os.environ.update(OS_URL="https://opensearch.invalid", OS_PASS="dummy", NTFY_URL="https://ntfy.invalid", NTFY_TOKEN="dummy")
    import alerts
    import dashboards
    import enrich
    import droppers
    bait = next(m for m in alerts.MONITORS if m["name"] == "tripwire-bait-used")
    assert bait["inputs"][0]["search"]["indices"] == ["tripwire-fakevm-*"]
    assert {"term": {"fakevm.status": "start"}} in bait["inputs"][0]["search"]["query"]["query"]["bool"]["filter"]
    digest = next(m for m in alerts.MONITORS if m["name"] == "tripwire-digest")
    assert "tripwire-fakevm-*" in digest["inputs"][0]["search"]["indices"]
    assert "tripwire-fakevm-*" in enrich.EVENT_INDICES and "tripwire-fakevm-*" in droppers.INDICES
    assert "fakevm.command" in droppers.FIELDS
    dashboards.selftest()
    print("PASS actual template generator, closed mappings, live mapping parity, retention, writer permissions, alerts and index consumers")


if __name__ == "__main__":
    main()
