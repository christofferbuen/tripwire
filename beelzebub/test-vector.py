#!/usr/bin/env python3
"""Test the real Vector config against real synthetic engine log lines.

Run test-local.py first. No production data or real secrets are read.
"""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

from render import HERE
from importlib.util import spec_from_file_location, module_from_spec

spec = spec_from_file_location("local_test", HERE / "test-local.py")
local = module_from_spec(spec)
spec.loader.exec_module(local)
podman = local.podman
ROOT = HERE.parent


def tests():
    lines = [json.loads(line) for line in (HERE / "capture.local.logs/beelzebub.log").read_text().splitlines()]
    events = {line["event"]["Status"]: line for line in lines if "event" in line}
    output = []

    def test(name, line, condition=None):
        output.extend(["[[tests]]", "name = " + json.dumps(name)])
        if condition is None:
            output.append('no_outputs_from = ["fakevm_events"]')
        output.extend(['[[tests.inputs]]', 'insert_at = "fakevm_events"', 'type = "log"',
                       "log_fields.message = " + json.dumps(json.dumps(line))])
        if condition:
            output.extend(['[[tests.outputs]]', 'extract_from = "fakevm_events"',
                           '[[tests.outputs.conditions]]', 'type = "vrl"',
                           "source = " + json.dumps(condition)])

    test("real_start", events["Start"], 'assert!(.bait.credential_used == true)\nassert!(.event.module == "fakevm")')
    test("real_interaction", events["Interaction"], 'assert!(.fakevm.status == "interaction")\nassert!(!exists(.event.evil))')
    test("real_end_without_ip", events["End"], 'assert!(.fakevm.status == "end")\nassert!(!exists(.source.ip))')
    test("real_login", events["Stateless"], 'assert!(.fakevm.status == "stateless")\nassert!(!exists(.bait))')
    long = copy.deepcopy(events["Interaction"])
    long["event"]["CommandOutput"] = "x" * 20000
    long["event"]["Command"] = "y" * 5000
    long["event"]["evil"] = {"a": 1}
    long["evil"] = {"a": 1}
    test("bounded_whitelist", long, 'assert!(length(string!(.fakevm.output)) == 8192)\nassert!(length(string!(.fakevm.command)) == 4096)\nassert!(!exists(.evil))\nassert!(!exists(.fakevm.evil))\nassert!(!exists(.event.evil))\nassert!(!exists(.message))')
    invalid = copy.deepcopy(events["Start"])
    invalid["event"]["SourceIp"] = "not-an-ip"
    test("invalid_ip", invalid)
    invalid["event"]["SourceIp"] = ""
    test("missing_start_ip", invalid)
    invalid["event"]["SourceIp"] = "2001:db8::1"
    test("ipv6", invalid, 'assert!(.source.ip == "2001:db8::1")')
    invalid["event"]["Status"] = "unexpected"
    test("invalid_status", invalid)
    test("startup", {"msg": "startup"})
    return "\n".join(output) + "\n"


def main():
    content = tests()  # Fail before starting containers when engine evidence is absent.
    prefix = "tw-fakevm-vector-" + uuid.uuid4().hex[:10]
    volume, helper, vector = prefix + "-data", prefix + "-helper", prefix + "-vector"
    try:
        podman("volume", "create", volume)
        podman("run", "-d", "--network", "none", "--name", helper,
               "-v", volume + ":/work", "localhost/tripwire-beelzebub-test:local", "sleep", "300")
        with tempfile.TemporaryDirectory(prefix="tripwire-vector-") as directory:
            path = Path(directory)
            (path / "tests.toml").write_text(content, encoding="utf-8")
            (path / ".env").write_text("OPENSEARCH_INITIAL_ADMIN_PASSWORD=dummy-test-password\n")
            for name in ("vector-sentinel.toml", "vector-fakevm.toml", "setup-logging.sh"):
                (path / name).write_text((ROOT / name).read_text(), encoding="utf-8", newline="\n")
            podman("cp", str(path) + "/.", helper + ":/work")
        podman("exec", "-w", "/work", helper, "bash", "setup-logging.sh")
        # Add the sentinel endpoint to real generated secrets, keeping every value a string.
        code = "import json; p='/work/vector-secrets.json'; d=json.load(open(p)); d['opensearch_endpoint']='https://opensearch.invalid:9200'; json.dump(d,open('/work/secrets.json','w'))"
        podman("exec", helper, "python3", "-c", code)
        result = podman("run", "--rm", "--name", vector, "--network", "none",
                        "-v", volume + ":/etc/vector:ro", "docker.io/timberio/vector:0.58.0-alpine",
                        "test", "/etc/vector/vector-sentinel.toml", "/etc/vector/vector-fakevm.toml",
                        "/etc/vector/tests.toml")
        print(result.stdout)
    finally:
        podman("rm", "-f", vector, helper, check=False)
        podman("volume", "rm", volume, check=False)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print("FAIL " + ascii(str(exc)), file=sys.stderr)
        sys.exit(1)
