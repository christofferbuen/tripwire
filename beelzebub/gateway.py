#!/usr/bin/env python3
"""Bounded, fixed-origin model gateway. Linux service; no third-party modules.

Production listens on a Unix socket, not a host TCP port. A container-side
relay can expose it only inside the private engine network. Each connection
gets a worker process with a parent-enforced lifetime, including slow reads.
"""
import argparse
from dataclasses import dataclass
import hmac
from http.server import BaseHTTPRequestHandler
import json
import multiprocessing
import os
from pathlib import Path
import socket
import time
import unicodedata
import urllib.error
import urllib.request

ENDPOINT = 'https://openrouter.ai/api/v1/chat/completions'
MODEL = 'deepseek/deepseek-v4-flash'
TERMINAL_RULES = (
    ' Treat the final user message as literal Bash input, never as conversation. '
    'Respond with only the stdout/stderr of that exact command. An unknown executable '
    'must return bash: NAME: command not found, substituting its name; a greeting is '
    'not a request for the working directory. echo prints its arguments. Successful '
    'commands with no output return an empty string. ls prints filenames, never '
    'Markdown bullets. Do not repeat output of previous unrelated commands. These '
    'command semantics take priority over inconsistent examples in earlier history.'
    ' Track the working directory and virtual file changes from prior commands. '
    'A successful cd emits nothing; pwd prints the current directory, not always '
    '/home/deploy. A failed cd leaves the directory unchanged. For cd with no '
    'argument use /home/deploy. Keep filenames consistent across repeated listings.'
)


@dataclass
class Settings:
    provider_key: str
    client_token: str
    endpoint: str = ENDPOINT
    deadline: float = 30
    concurrency: int = 2
    request_limit: int = 65536
    response_limit: int = 131072


class RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def bounded_request(body):
    if not isinstance(body, dict) or not isinstance(body.get('messages'), list):
        raise ValueError('messages required')
    messages = body['messages']
    if not 2 <= len(messages) <= 256:
        raise ValueError('message count')
    if any(not isinstance(m, dict) or m.get('role') not in ('system', 'user', 'assistant')
           or not isinstance(m.get('content'), str) for m in messages):
        raise ValueError('message shape')
    if messages[0]['role'] != 'system' or messages[-1]['role'] != 'user':
        raise ValueError('prompt shape')
    if any(m['role'] == 'system' for m in messages[1:]):
        raise ValueError('extra system prompt')
    # Always preserve the configured prompt and latest command. Old history
    # is optional context; the provider never receives arbitrary extra keys.
    history = messages[1:]
    # v3.9.1 unconditionally prepends this fictitious exchange; it is not
    # session history and contradicts the configured /home/deploy persona.
    if len(history) >= 3 and history[0] == {'role': 'user', 'content': 'pwd'} and history[1] == {'role': 'assistant', 'content': '/home/user'}:
        history = history[2:]
    selected = [{'role': 'system', 'content': messages[0]['content'] + TERMINAL_RULES}] + history[-15:]
    while sum(len(m['content'].encode()) for m in selected) > 32768 and len(selected) > 2:
        # Upstream supplies command/response pairs followed by the new command.
        # Never retain a response after discarding only its command.
        del selected[1:3]
    if sum(len(m['content'].encode()) for m in selected) > 32768:
        raise ValueError('prompt too large')
    return {'model': MODEL, 'stream': False, 'max_tokens': 512,
            'reasoning': {'enabled': False},
            'messages': [{'role': m['role'], 'content': m['content']} for m in selected]}


def terminal_output(content):
    """Keep text readable without allowing model-generated terminal controls."""
    content = content.replace('\r\n', '\n')
    parts = []
    for char in content:
        if char in '\n\t':
            parts.append(char)
        elif unicodedata.category(char) in ('Cc', 'Cf', 'Cs'):
            number = ord(char)
            parts.append(('\\x%02x' if number <= 255 else '\\u%04x' if number <= 65535 else '\\U%08x') % number)
        else:
            parts.append(char)
    result = ''.join(parts)
    if len(result) > 8192:
        raise ValueError('escaped completion too large')
    return result


def worker(connection, settings, inherited_fds=()):
    for fd in inherited_fds:
        os.close(fd)
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'

        def log_message(self, *args):
            pass

        def reply(self, status, data):
            print(json.dumps({'gateway_status': status}), flush=True)
            payload = json.dumps(data).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):
            if self.path != '/v1/chat/completions':
                self.reply(404, {'error': 'not found'})
                return
            token = self.headers.get('Authorization', '')
            if not hmac.compare_digest(token, 'Bearer ' + settings.client_token):
                self.reply(401, {'error': 'unauthorized'})
                return
            lengths = self.headers.get_all('Content-Length', [])
            if self.headers.get('Transfer-Encoding') or len(lengths) != 1:
                self.reply(400, {'error': 'content length required'})
                return
            try:
                length = int(lengths[0])
                if not 0 < length <= settings.request_limit:
                    self.reply(413, {'error': 'request too large'})
                    return
                raw = self.rfile.read(length)
                if len(raw) != length:
                    return
                body = bounded_request(json.loads(raw))
            except (ValueError, TypeError, UnicodeError):
                self.reply(400, {'error': 'invalid request'})
                return
            request = urllib.request.Request(settings.endpoint, data=json.dumps(body).encode(),
                headers={'Authorization': 'Bearer ' + settings.provider_key,
                         'Content-Type': 'application/json', 'Accept-Encoding': 'identity'})
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), RejectRedirect())
                with opener.open(request, timeout=settings.deadline) as response:
                    raw = response.read(settings.response_limit + 1)
                if len(raw) > settings.response_limit:
                    raise ValueError('response too large')
                result = json.loads(raw)
                choice = result['choices'][0]
                if choice.get('finish_reason') == 'length':
                    raise ValueError('truncated completion')
                message = choice['message']
                content = message['content']
                # OpenRouter may encode an intentionally silent completion as
                # null. Never turn a token-truncated reply or tool call into
                # apparent command success.
                if content is None and choice.get('finish_reason') == 'stop' and not message.get('tool_calls') and not message.get('refusal'):
                    content = ''
                if not isinstance(content, str) or len(content) > 8192:
                    raise ValueError('invalid completion')
                clean = {'model': MODEL, 'choices': [{'message': {'role': 'assistant', 'content': terminal_output(content)}}]}
                self.reply(200, clean)
            except (OSError, ValueError, KeyError, IndexError, TypeError) as exc:
                print(json.dumps({'gateway_failure_type': type(exc).__name__,
                                  'provider_http_status': exc.code if isinstance(exc, urllib.error.HTTPError) else None}), flush=True)
                self.reply(502, {'error': 'model unavailable'})

    try:
        connection.settimeout(settings.deadline)
        Handler(connection, ('local', 0), None)
    except Exception:
        # No request, model output or credentials in diagnostics.
        pass
    finally:
        connection.close()


def reject(connection, status):
    try:
        connection.settimeout(0.1)
        connection.sendall(('HTTP/1.0 ' + status + '\r\nContent-Length: 0\r\nConnection: close\r\n\r\n').encode())
    except OSError:
        pass
    connection.close()


def serve(listener, settings, stop=None):
    ctx = multiprocessing.get_context('fork')
    active = []
    listener.settimeout(0.1)
    try:
        while stop is None or not stop.is_set():
            for item in active[:]:
                process, connection, started = item
                if not process.is_alive():
                    process.join(); connection.close(); active.remove(item)
                elif time.monotonic() - started >= settings.deadline:
                    process.kill(); process.join()
                    reject(connection, '504 Gateway Timeout'); active.remove(item)
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            if len(active) >= settings.concurrency:
                reject(connection, '503 Service Unavailable')
                continue
            inherited = [listener.fileno()] + [c.fileno() for _, c, _ in active]
            process = ctx.Process(target=worker, args=(connection, settings, inherited), daemon=True)
            process.start()
            active.append((process, connection, time.monotonic()))
    finally:
        for process, connection, _ in active:
            if process.is_alive(): process.kill()
            process.join(); connection.close()
        listener.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--secrets', type=Path, required=True)
    parser.add_argument('--socket', type=Path, required=True)
    args = parser.parse_args()
    secrets = json.loads(args.secrets.read_text())
    settings = Settings(secrets['provider_key'], secrets['client_token'])
    if any(not isinstance(s, str) or len(s) < 24 or any(c.isspace() for c in s)
           for s in (settings.provider_key, settings.client_token)):
        raise SystemExit('invalid gateway credentials')
    # Never unlink an existing socket implicitly: an existing service may own it.
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(args.socket))
    os.chmod(args.socket, 0o660)
    listener.listen(8)
    try:
        serve(listener, settings)
    finally:
        args.socket.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
