#!/usr/bin/env python3
"""Render only data, never source an env file. Output contains the bait secret.

Run on the VM with --env FILE --out runtime.local.config. No provider key
is rendered. --local-stub permits HTTP only for isolated development tests.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from sentinel import PERSONAS

BAIT_RE = re.compile(r"[A-Za-z0-9_.+-]{12,64}")
MARKER = re.compile(r"@@([A-Z_]+)@@")
KEYS = {"BAIT_PASSWORD", "SERVER_NAME", "LLM_MODEL", "LLM_ENDPOINT",
        "FAKEVM_PORT", "FAKEVM_BIND", "DEADLINE", "RATE_REQUESTS",
        "RATE_WINDOW", "OPEN_AI_SECRET_KEY"}


def password_regex(bait: str) -> str:
    if not BAIT_RE.fullmatch(bait):
        raise ValueError("BAIT_PASSWORD must be 12-64 letters, digits or _.+-")
    return "^" + re.escape(bait) + "$"


def render(template: str, values: dict[str, str | int]) -> str:
    # JSON scalars are also YAML scalars. Substitution cannot create YAML keys.
    for value in values.values():
        if isinstance(value, str) and (any(ord(c) < 32 for c in value)
                                      or any(c in value for c in ('"', "'", "@@"))):
            raise ValueError("template value contains forbidden characters")

    def replace(match):
        if match[1] not in values:
            raise ValueError("missing template key: " + match[1])
        return json.dumps(values[match[1]], ensure_ascii=True)

    result = MARKER.sub(replace, template)
    if "@@" in result:
        raise ValueError("unresolved template marker")
    return result


def read_env(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or key not in KEYS or key in values:
            raise ValueError("invalid, unknown or duplicate env key")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def configuration(env: dict[str, str], local_stub=False) -> str:
    name = env.get("SERVER_NAME", "")
    if not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?", name):
        raise ValueError("SERVER_NAME must be a hostname")
    model = env.get("LLM_MODEL", "deepseek/deepseek-v4-flash")
    if not re.fullmatch(r"[a-zA-Z0-9_./:+-]{1,128}", model):
        raise ValueError("LLM_MODEL is required; select a verified provider model")
    endpoint = env.get("LLM_ENDPOINT", "https://openrouter.ai/api/v1/chat/completions")
    parsed = urlsplit(endpoint)
    if (parsed.scheme not in ({"https", "http"} if local_stub else {"https"})
            or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise ValueError("LLM_ENDPOINT must be an HTTPS endpoint without credentials or query")
    values = {"SERVER_NAME": name,
              # gliderlabs/ssh adds SSH-2.0- itself.
              "SERVER_VERSION": str(PERSONAS["ubuntu-web"]["ssh_ident"]).removeprefix("SSH-2.0-"),
              "PASSWORD_REGEX": password_regex(env.get("BAIT_PASSWORD", "")),
              "LLM_MODEL": model, "LLM_ENDPOINT": endpoint,
              "PROMPT": HERE.joinpath("prompt.txt").read_text(encoding="utf-8").strip(),
              "UNAME": "Linux " + name + " 5.4.0-216-generic #236-Ubuntu SMP x86_64 GNU/Linux"}
    for key, default, upper in (("DEADLINE", 600, 3600), ("RATE_REQUESTS", 10, 100),
                                ("RATE_WINDOW", 60, 86400), ("FAKEVM_PORT", 2222, 65535)):
        raw = str(env.get(key, default))
        if not raw.isascii() or not raw.isdecimal() or not 1 <= int(raw) <= upper:
            raise ValueError(key + " is outside its allowed range")
        if key != "FAKEVM_PORT":
            values[key] = int(raw)
    return render(HERE.joinpath("ssh.yaml.tmpl").read_text(encoding="utf-8"), values)


def write_config(env: dict[str, str], out: Path, local_stub=False):
    service = configuration(env, local_stub)
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    services = out / "services"
    services.mkdir(exist_ok=True, mode=0o700)
    if any(p.name != "ssh.yaml" for p in services.iterdir()):
        raise ValueError("output services directory must contain only ssh.yaml")
    for dest, content in ((services / "ssh.yaml", service),
                          (out / "beelzebub.yaml", HERE.joinpath("beelzebub.yaml").read_text())):
        fd, temp = tempfile.mkstemp(dir=dest.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
            os.replace(temp, dest)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)


def selftest():
    assert password_regex("Deploy-2026.ok+x") == r"^Deploy\-2026\.ok\+x$"
    for bad in ("", "a" * 11, "a b c d e f g h", "a" * 65, "a" * 12 + "\n"):
        try:
            password_regex(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid password accepted")
    for template, values in (("@@MISSING@@", {}), ("@@X@@", {"X": 'a"b'}),
                             ("@@X@@", {"X": "a\nb"}), ("@@X@@", {"X": "@@Y@@"})):
        try:
            render(template, values)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid template accepted")
    env = dict(BAIT_PASSWORD="Deploy-2026.ok+x", SERVER_NAME="test.invalid", LLM_MODEL="stub")
    generated = configuration(env)
    assert "SSH-2.0-" not in generated and "OpenSSH_8.2p1" in generated
    assert "openAISecretKey" not in generated and "@@" not in generated
    for key, value in (("RATE_REQUESTS", "0"), ("DEADLINE", "-1"),
                       ("LLM_ENDPOINT", "http://stub:8000"), ("SERVER_NAME", "x\ny")):
        try:
            configuration(env | {key: value})
        except ValueError:
            pass
        else:
            raise AssertionError("invalid setting accepted: " + key)
    print("render selftest: passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--local-stub", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    try:
        if args.selftest:
            selftest()
        elif args.env and args.out:
            write_config(read_env(args.env), args.out, args.local_stub)
        else:
            parser.error("provide --env and --out, or --selftest")
    except (ValueError, OSError) as exc:
        print("render: " + ascii(str(exc)), file=sys.stderr)
        sys.exit(1)
