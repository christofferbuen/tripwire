#!/usr/bin/env python3
"""Exercise the optional HTTP bait over real loopback connections."""
import asyncio
import base64
import contextlib
import io
from pathlib import Path
import tempfile

from render import PERSONAS
from sentinel import Identity, Sentinel, main


async def checks(directory):
    bait = directory / "bait.local.env"
    payload = b"TEST_TOKEN=synthetic-test-value\n"
    bait.write_bytes(payload)
    identity = Identity(directory / "identity.json", "ubuntu-web", "test.invalid")
    sensor = Sentinel(None, PERSONAS["ubuntu-web"], identity, True, False, bait_env=bait)

    async def probe(data, instance=sensor, allow_bait=True):
        finished = asyncio.get_running_loop().create_future()
        note = {}

        async def handle(reader, writer):
            try:
                await instance.do_http(reader, writer, note, 80, allow_bait=allow_bait)
                finished.set_result(None)
            except Exception as exc:
                finished.set_exception(exc)
            finally:
                writer.close()
                await writer.wait_closed()

        async with await asyncio.start_server(handle, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                writer.write(data)
                await writer.drain()
                response = await asyncio.wait_for(reader.read(), 5)
                await asyncio.wait_for(finished, 5)
                return response, note
            finally:
                writer.close()
                await writer.wait_closed()

    def request(method="GET", path="/.env", extra=b"", body=b""):
        return (f"{method} {path} HTTP/1.1\r\nHost: test.invalid\r\nConnection: close\r\n".encode()
                + extra + b"\r\n" + body)

    response, note = await probe(request(path="/.env?x=1"))
    headers, body = response.split(b"\r\n\r\n", 1)
    assert response.startswith(b"HTTP/1.1 200") and body == payload
    assert b"Content-Type: application/octet-stream" in headers
    assert b"Accept-Ranges: bytes" in headers and b"Last-Modified:" in headers
    assert f'ETag: "{int(bait.stat().st_mtime):x}-{len(payload):x}"'.encode() in headers
    assert note["bait_served"] == "env"
    response, _ = await probe(request("HEAD"))
    assert response.endswith(b"\r\n\r\n") and payload not in response
    assert f"Content-Length: {len(payload)}".encode() in response
    for target in ("/.env/", "/foo/.env", "/%2eenv", "http://test.invalid/.env"):
        response, note = await probe(request(path=target))
        assert response.startswith(b"HTTP/1.1 404") and "bait_served" not in note
    response, _ = await probe(request(), allow_bait=False)
    assert response.startswith(b"HTTP/1.1 404"), "HTTPS must keep old response"
    for instance in (Sentinel(None, PERSONAS["ubuntu-web"], identity, True, False),
                     Sentinel(None, PERSONAS["debian-lamp"], identity, True, False, bait_env=bait)):
        response, note = await probe(request(), instance)
        assert response.startswith(b"HTTP/1.1 404") and "bait_served" not in note
    response, note = await probe(b"GET / HTTP/1.1\r\nHost: test.invalid\r\n\r\n" + request())
    assert response.count(b"HTTP/1.1 200") == 2 and response.endswith(payload)
    assert note["bait_served"] == "env"
    basic = base64.b64encode(b"deploy:synthetic-test-value")
    for data in (request(path="/synthetic-test-value"),
                 request(extra=b"Authorization: Basic " + basic + b"\r\n"),
                 request("POST", "/", extra=b"Content-Length: 20\r\n", body=b"synthetic-test-value")):
        _, note = await probe(data)
        assert note["bait_credential_used"] is True
    _, note = await probe(request(extra=b"Authorization: Basic !!!\r\n"))
    assert "bait_credential_used" not in note
    for bad in (directory / "absent", directory / "oversized"):
        if bad.name == "oversized":
            bad.write_bytes(b"x" * 8193)
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            result = main(["--bait-env", str(bad), "--hostname", "test.invalid",
                           "--log", str(directory / "test.jsonl"), "--identity", str(identity.path)])
        assert result == 2 and "ERROR: bait file" in errors.getvalue()
    print("PASS HTTP bait: default/Apache/HTTPS unchanged, GET/HEAD, exact path, keep-alive, token reuse, invalid files")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="tripwire-bait-") as directory:
        asyncio.run(checks(Path(directory)))
