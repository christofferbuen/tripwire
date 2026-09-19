#!/usr/bin/env python3
"""Validate the actual Compose document using dummy env values; start nothing."""
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="tripwire-compose-") as directory:
        base = Path(directory)
        (base / "beelzebub").mkdir()
        env = base / "beelzebub/.env"
        env.write_text("FAKEVM_PORT=2222\nOPEN_AI_SECRET_KEY=stub-not-a-real-key\n")
        compose = base / "compose.fakevm.yaml"
        compose.write_text((ROOT / compose.name).read_text())
        result = subprocess.run(["podman", "compose", "--env-file", str(env),
                                 "-f", str(compose), "config", "--format", "json"],
                                capture_output=True, text=True, check=True)
        service = json.loads(result.stdout)["services"]["fakevm"]
        assert service["read_only"] and service["cap_drop"] == ["ALL"]
        assert "no-new-privileges" in service["security_opt"]
        assert "@sha256:" in service["image"]
        assert len(service["ports"]) == 1
        assert service["ports"][0]["host_ip"] == "127.0.0.1"
        assert service["ports"][0]["target"] == 2222
        assert service["pids_limit"] == 64 and service["mem_limit"] == "268435456"
        assert any(v["target"] == "/configurations" and v["read_only"] for v in service["volumes"])
        print("PASS actual Compose: pinned image, loopback-only SSH, read-only config/root, resource limits")
