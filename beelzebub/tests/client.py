"""OpenSSH tests from a disposable container; all received text stays escaped."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

HOST = sys.argv[1]
MODE = sys.argv[2]
CUSTOM = bool(os.environ.get('TRIPWIRE_CUSTOM'))
MODEL_COMMAND = 'ps' if CUSTOM else 'ls'
PASSWORD = "Deploy-2026.ok+x"  # Synthetic test fixture, never a live bait.
OPTIONS = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
           "-o", "ConnectTimeout=3", "-o", "NumberOfPasswordPrompts=1",
           "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no"]
SSH = ["sshpass", "-e", "ssh", *OPTIONS, "-p", "2222"]


def run(args, password=PASSWORD, **kwargs):
    return subprocess.run(args, env=os.environ | {"SSHPASS": password},
                          capture_output=True, timeout=15, **kwargs)


def command(text, password=PASSWORD):
    return run([*SSH, "deploy@" + HOST, text], password)


def check(condition, label):
    if not condition:
        raise AssertionError(label)
    print("PASS " + label, flush=True)


def records(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


def stub_count():
    return len(records("/logs/stub.jsonl")) if Path("/logs/stub.jsonl").exists() else 0


try:
    if MODE == "basic":
        with socket.create_connection((HOST, 2222), timeout=3) as sock:
            banner = sock.recv(512).split(b"\r\n")[0].decode()
        expected = Path("/configurations/banner.txt").read_text().strip()
        check(banner == expected, "SSH banner matches sentinel")
        for password in ("wrong", "", "x" + PASSWORD + "x"):
            result = command("whoami", password)
            check(result.returncode != 0 and b"deploy\n" not in result.stdout,
                  "invalid password refused")
        check(command("whoami").stdout.strip() == b"deploy", "static command")
        check(command(MODEL_COMMAND).stdout.strip() == b"STUB-OUTPUT", "model stub command")
        result = run([*SSH, "-T", "deploy@" + HOST], input=('whoami\n'+MODEL_COMMAND+'\nexit\n').encode())
        check(b"deploy" in result.stdout and b"STUB-OUTPUT" in result.stdout,
              "interactive shell")
        expected_marker = b'tripwire-test-marker' if CUSTOM else b'STUB-OUTPUT'
        check(command("touch /tmp/tripwire-test-marker; ls /tmp").stdout.strip() == expected_marker,
              "file command uses virtual state only")
        time.sleep(0.3)
        events = [r["event"] for r in records("/logs/beelzebub.log") if "event" in r]
        check({"Stateless", "Start", "Interaction", "End"} <= {r["Status"] for r in events},
              "real log statuses")
        attempts = [r for r in events if r["Status"] == "Stateless"]
        check({"wrong", "", "x" + PASSWORD + "x"} <= {r["Password"] for r in attempts},
              "failed passwords logged")
        own = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        own.connect((HOST, 2222))
        client_ip = own.getsockname()[0]
        own.close()
        check(all(r["SourceIp"] == client_ip for r in attempts), "bridge preserves client IP")
        requests = records("/logs/stub.jsonl")
        check(all(r["auth"] == "Bearer stub-not-a-real-key" for r in requests), "dummy auth header")
        prompt = Path("/configurations/prompt.txt").read_text().strip()
        check(all(r["request"]["messages"][0]["content"].startswith(prompt) for r in requests),
              "custom prompt reaches model")
    elif MODE == "forwarding":
        # -W requests an actual direct-tcpip channel (same as a used -L).
        result = run([*SSH, "-W", "127.0.0.1:2112", "deploy@" + HOST])
        check(result.returncode != 0 and (b"administratively prohibited" in result.stderr
                                         or b"unsupported channel type" in result.stderr),
              "direct TCP forwarding rejected: " + ascii(result.stderr))
        result = run([*SSH, "-N", "-o", "ExitOnForwardFailure=yes", "-R",
                      "18082:127.0.0.1:8000", "deploy@" + HOST])
        check(result.returncode != 0, "reverse forwarding rejected")
        for kind, port in (("-L", 18080), ("-D", 18081)):
            target = str(port) + (":127.0.0.1:2112" if kind == "-L" else "")
            proc = subprocess.Popen([*SSH, "-N", kind, target, "deploy@" + HOST],
                                    env=os.environ | {"SSHPASS": PASSWORD},
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                for _ in range(40):
                    try:
                        connection = socket.create_connection(("127.0.0.1", port), timeout=0.2)
                        break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise AssertionError("local forwarding listener did not start")
                with connection:
                    connection.settimeout(3)
                    if kind == "-D":
                        connection.sendall(b"\x05\x01\x00")
                        check(connection.recv(2) == b"\x05\x00", "SOCKS listener ready")
                        connection.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x08\x40")
                    else:
                        connection.sendall(b"GET /metrics HTTP/1.0\r\n\r\n")
                    try:
                        response = connection.recv(1024)
                    except ConnectionResetError:
                        response = b""
                    check(not response or (kind == "-D" and response[1] != 0),
                          kind + " actual connection denied")
            finally:
                proc.terminate()
                _, errors = proc.communicate(timeout=5)
            check(b"administratively prohibited" in errors or b"unsupported channel type" in errors,
                  kind + " channel denial observed: " + ascii(errors))
        result = run(["sshpass", "-e", "sftp", *OPTIONS, "-P", "2222", "deploy@" + HOST], input=b"quit\n")
        check(result.returncode != 0, "SFTP rejected")
        Path("/tmp/upload.txt").write_text("fixture")
        for legacy in ([], ["-O"]):
            result = run(["sshpass", "-e", "scp", *legacy, *OPTIONS, "-P", "2222",
                          "/tmp/upload.txt", "deploy@" + HOST + ":/tmp/upload.txt"])
            check(result.returncode != 0, "SCP transfer rejected " + ("legacy" if legacy else "SFTP"))
    elif MODE == "rate":
        before = stub_count()
        # One interactive session bursts 11 commands before one token refills.
        result = run([*SSH, "-T", "deploy@" + HOST], input=(MODEL_COMMAND+'\n').encode() * 11 + b"exit\n")
        check(result.stdout.count(b"STUB-OUTPUT") == 10 and stub_count() - before == 10,
              "11th burst command refused")
    elif MODE == "deadline":
        started = time.monotonic()
        proc = subprocess.Popen([*SSH, "-T", "deploy@" + HOST],
                                env=os.environ | {"SSHPASS": PASSWORD}, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            proc.wait(timeout=9)
            check(3 <= time.monotonic() - started <= 8, "five-second session deadline")
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.communicate()
    elif MODE == "enhanced":
        from concurrent.futures import ThreadPoolExecutor
        before = stub_count()
        def session(label):
            text = ('mkdir /tmp/' + label + '\ncd /tmp/' + label +
                    '\necho ' + label + ' > marker\ncat marker\nps\nexit\n')
            return run([*SSH, '-T', 'deploy@' + HOST], input=text.encode())
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(session, ['session_alpha', 'session_beta']))
        for label, result in zip(['session_alpha', 'session_beta'], results):
            check(result.returncode == 0 and ('deploy@test.invalid:/tmp/' + label + '$').encode() in result.stdout,
                  'dynamic prompt ' + label)
        requests = records('/logs/stub.jsonl')[before:]
        check(len(requests) == 2, 'one model request per concurrent session')
        for request in requests:
            text = json.dumps(request['request'])
            check(('session_alpha' in text) != ('session_beta' in text), 'same-IP concurrent histories isolated')
        check(command('ls /tmp').stdout.strip() == b'', 'reconnect starts with clean filesystem')
        check(command('pwd').stdout.strip() == b'/home/deploy', 'reconnect resets directory')
        before = stub_count()
        sequence = ''.join('echo history_%d\n' % n for n in range(100)) + 'ps\nexit\n'
        result = run([*SSH, '-T', 'deploy@' + HOST], input=sequence.encode())
        check(result.returncode == 0, 'long session completes')
        messages = records('/logs/stub.jsonl')[before]['request']['messages']
        check(len(messages) <= 18 and 'history_0' not in json.dumps(messages), 'history bounded and old entries discarded')
        before = stub_count()
        result = run([*SSH, '-T', 'deploy@' + HOST], input=b'cd /tmp\nps --tripwire-fail\npwd\nps\nexit\n')
        check(b'temporarily unavailable' in result.stdout and b'STUB-OUTPUT' in result.stdout,
              'provider failure recovers without false command-not-found')
        requests = records('/logs/stub.jsonl')[before:]
        check(len(requests) == 2 and 'temporarily unavailable' not in json.dumps(requests[-1]),
              'failed response excluded from history')
        check('cwd=\\"/tmp\\"' in json.dumps(requests[-1]), 'provider failure preserves directory')
        started = time.monotonic()
        result = subprocess.run([*SSH, 'deploy@' + HOST, 'ps --tripwire-slow'],
                                env=os.environ | {'SSHPASS': PASSWORD}, capture_output=True, timeout=40)
        check(25 < time.monotonic()-started < 38 and result.returncode == 75 and b'temporarily unavailable' in result.stdout,
              'stalled provider has bounded deadline and temporary exit status')
        check(command('pwd').stdout.strip() == b'/home/deploy', 'shell available after timeout')
    elif MODE == "no-key":
        before = stub_count()
        check(b"STUB-OUTPUT" not in command(MODEL_COMMAND).stdout, "missing key refuses model call")
        check(stub_count() == before, "no request without a key")
    else:
        raise ValueError("unknown mode")
except Exception as exc:
    print("FAIL " + ascii(str(exc)), file=sys.stderr)
    sys.exit(1)
