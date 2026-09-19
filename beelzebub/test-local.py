#!/usr/bin/env python3
"""Run with local Podman. Pull/build requires internet; tests use --internal.

No host ports, no real key, no deployment. Unique resources are removed on
exit. Uses podman cp rather than host mounts to support Windows remote Podman.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

from render import HERE, PERSONAS, selftest, write_config

IMAGE = "docker.io/m4r10/beelzebub:v3.9.1@sha256:f8e6acbc67a3838a9aa52c0473ac20e04aed8be02e1f131d6188acc0b6ff17f7"


def podman(*args, check=True, timeout=180):
    result = subprocess.run(["podman", *map(str, args)], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("podman " + str(args[0]) + ": " + ascii((result.stderr + result.stdout)[:6000]))
    return result


def main():
    selftest()
    podman("info")
    podman("pull", IMAGE)
    helper_image = "localhost/tripwire-beelzebub-test:local"
    print("Building disposable SSH client and model stub", flush=True)
    podman("build", "-t", helper_image, "-f", HERE / "tests/Containerfile", HERE / "tests", timeout=300)
    prefix = "tw-fakevm-test-" + uuid.uuid4().hex[:10]
    network, helper, engine = prefix + "-net", prefix + "-client", prefix + "-engine"
    config, logs = prefix + "-config", prefix + "-logs"
    created_containers, created_volumes = [], []
    made_network = False
    try:
        podman("network", "create", "--internal", network)
        made_network = True
        for volume in (config, logs):
            podman("volume", "create", volume)
            created_volumes.append(volume)
        podman("run", "-d", "--name", helper, "--network", network,
               "--network-alias", "stub", "-v", config + ":/configurations",
               "-v", logs + ":/logs", helper_image)
        created_containers.append(helper)
        env = dict(BAIT_PASSWORD="Deploy-2026.ok+x", SERVER_NAME="test.invalid",
                   LLM_MODEL="stub", LLM_ENDPOINT="http://stub:8000/v1/chat/completions")
        with tempfile.TemporaryDirectory(prefix="tripwire-fakevm-") as directory:
            staging = Path(directory)

            def configure(deadline=600):
                write_config(env | {"DEADLINE": str(deadline)}, staging, local_stub=True)
                (staging / "banner.txt").write_text(str(PERSONAS["ubuntu-web"]["ssh_ident"]))
                (staging / "prompt.txt").write_text((HERE / "prompt.txt").read_text())
                podman("cp", str(staging) + "/.", helper + ":/configurations")

            def start(key=True):
                args = ["run", "-d", "--name", engine, "--network", network,
                        "--read-only", "--tmpfs", "/tmp:size=16m,noexec,nosuid,nodev",
                        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                        "--memory", "256m", "--pids-limit", "64", "--cpus", "0.5",
                        "-v", config + ":/configurations:ro", "-v", logs + ":/logs"]
                if key:
                    args += ["-e", "OPEN_AI_SECRET_KEY=stub-not-a-real-key"]
                podman(*args, IMAGE)
                created_containers.append(engine)
                info = json.loads(podman("inspect", engine).stdout)[0]
                address = info["NetworkSettings"]["Networks"][network]["IPAddress"]
                # Listener readiness is probed from inside the isolated network.
                probe = "import socket,sys; socket.create_connection((sys.argv[1],2222),1).close()"
                for _ in range(40):
                    if podman("exec", helper, "python3", "-c", probe, address, check=False).returncode == 0:
                        return address
                    time.sleep(0.2)
                raise RuntimeError("engine did not become ready: " + ascii(podman("logs", engine).stdout))

            def stop():
                podman("rm", "-f", engine)
                created_containers.remove(engine)

            def client(address, mode):
                result = podman("exec", helper, "python3", "/tests/client.py", address, mode, timeout=45)
                print(result.stdout, end="", flush=True)

            configure()
            address = start()
            before = podman("top", engine, "comm").stdout
            baseline_diff = podman("diff", engine).stdout
            client(address, "basic")
            client(address, "forwarding")
            assert podman("top", engine, "comm").stdout == before, "process list changed"
            after_diff = podman("diff", engine).stdout
            assert after_diff == baseline_diff, "root filesystem changed: " + ascii(after_diff)
            marker = podman("exec", helper, "sh", "-c", "test ! -e /logs/tripwire-test-marker", check=False)
            assert marker.returncode == 0
            print("PASS process list and root filesystem unchanged", flush=True)
            if baseline_diff.strip():
                print("OBSERVED container-runtime baseline diff: " + ascii(baseline_diff), flush=True)
            # Inspect the engine's tmpfs through its mounted filesystem, not a
            # command in the scratch image (which has no shell).
            podman("cp", engine + ":/etc/ssl/certs/ca-certificates.crt", staging / "ca-check.crt")
            result = podman("cp", engine + ":/tmp/tripwire-test-marker", staging / "marker", check=False)
            assert result.returncode != 0, "text command created a file"
            print("PASS text command created no tmpfs file", flush=True)
            keyscan = podman("exec", helper, "ssh-keyscan", "-p", "2222", address).stdout
            stop()
            address = start()
            client(address, "rate")
            next_scan = podman("exec", helper, "ssh-keyscan", "-p", "2222", address).stdout
            old_keys = [line.split()[1:] for line in keyscan.splitlines() if not line.startswith("#")]
            new_keys = [line.split()[1:] for line in next_scan.splitlines() if not line.startswith("#")]
            assert old_keys and new_keys, "host key probe returned no keys"
            print("OBSERVED host key persists: " + str(old_keys == new_keys), flush=True)
            stop()
            configure(deadline=5)
            address = start()
            client(address, "deadline")
            stop()
            configure()
            address = start(key=False)
            client(address, "no-key")
            # Real, synthetic test logs for subsequent Vector tests, ignored by git.
            captured = HERE / "capture.local.logs"
            captured.mkdir(exist_ok=True)
            podman("cp", helper + ":/logs/.", captured)
            print("PASS local engine tests; synthetic logs saved for Vector validation", flush=True)
    finally:
        for container in reversed(created_containers):
            podman("rm", "-f", container, check=False)
        for volume in reversed(created_volumes):
            podman("volume", "rm", volume, check=False)
        if made_network:
            podman("network", "rm", network, check=False)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, AssertionError, subprocess.TimeoutExpired) as exc:
        print("FAIL " + ascii(str(exc)), file=sys.stderr)
        sys.exit(1)
