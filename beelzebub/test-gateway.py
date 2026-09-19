"""Adversarial local gateway tests, run in a Linux Podman helper."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import multiprocessing
from pathlib import Path
import socket
import tempfile
import threading
import time

from gateway import Settings, bounded_request, serve, terminal_output

CTX = multiprocessing.get_context('fork')


def upstream(listener, events):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            events.put((body, self.headers.get('Authorization')))
            command = body['messages'][-1]['content']
            if command == 'slow': time.sleep(3)
            if command == 'redirect':
                self.send_response(302); self.send_header('Location', '/forbidden'); self.end_headers(); return
            if command == 'error': self.send_error(500); return
            payload = json.dumps({'choices': [{'message': {'content': 'reply'}}]}).encode()
            if command == 'silent': payload = json.dumps({'choices': [{'message': {'content': ''}}]}).encode()
            if command == 'silent-null': payload = json.dumps({'choices': [{'finish_reason': 'stop', 'message': {'content': None}}]}).encode()
            if command == 'incomplete': payload = json.dumps({'choices': [{'finish_reason': 'length', 'message': {'content': None}}]}).encode()
            if command == 'controls': payload = json.dumps({'choices': [{'message': {'content': '\x1b]52;c;secret\x07\rhidden\u202etext\n'}}]}).encode()
            if command == 'large': payload = b'x' * 140000
            self.send_response(200); self.send_header('Content-Length', str(len(payload))); self.end_headers()
            try:
                if command == 'trickle':
                    for byte in payload:
                        self.wfile.write(bytes([byte])); self.wfile.flush(); time.sleep(.15)
                else: self.wfile.write(payload)
            except OSError: pass

        def do_GET(self):
            events.put(('redirect-followed', None)); self.send_error(500)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler, bind_and_activate=False)
    server.socket.close(); server.socket = listener
    server.server_address = listener.getsockname()
    server.serve_forever()


def main():
    upstream_socket = socket.socket(); upstream_socket.bind(('127.0.0.1', 0)); upstream_socket.listen(8)
    port = upstream_socket.getsockname()[1]
    events = CTX.Queue()
    provider = CTX.Process(target=upstream, args=(upstream_socket, events)); provider.start()
    stop = CTX.Event()
    with tempfile.TemporaryDirectory() as directory:
        address = str(Path(directory) / 'gateway.sock')
        listener = socket.socket(socket.AF_UNIX); listener.bind(address); listener.listen(8)
        settings = Settings('provider-fixture', 'client-fixture', endpoint=f'http://127.0.0.1:{port}/completion', deadline=.8)
        gateway = CTX.Process(target=serve, args=(listener, settings, stop)); gateway.start()

        def request(command='normal', token='client-fixture', extras=None, raw=None):
            body = {'messages': [{'role': 'system', 'content': 'terminal'}, {'role': 'user', 'content': command}]}
            body.update(extras or {})
            data = json.dumps(body).encode() if raw is None else raw
            client = http.client.HTTPConnection('local', timeout=4)
            client.sock = socket.socket(socket.AF_UNIX); client.sock.settimeout(4); client.sock.connect(address)
            try:
                client.request('POST', '/v1/chat/completions', body=data,
                               headers={'Authorization': 'Bearer ' + token})
                response = client.getresponse(); result = response.status, response.read()
                # Reaping is on a 100 ms loop; sequential correctness tests
                # must not accidentally turn into the separate overload test.
                time.sleep(.15)
                return result
            finally: client.close()

        try:
            status, body = request(extras={'model': 'wrong', 'max_tokens': 999999, 'tools': [{}], 'url': 'http://forbidden'})
            assert status == 200 and json.loads(body)['choices'][0]['message']['content'] == 'reply'
            forwarded, token = events.get(timeout=2)
            assert forwarded['model'] == 'deepseek/deepseek-v4-flash' and forwarded['max_tokens'] == 512
            assert forwarded['reasoning'] == {'enabled': False}
            assert set(forwarded) == {'model', 'messages', 'max_tokens', 'stream', 'reasoning'} and token == 'Bearer provider-fixture'
            assert request(token='wrong')[0] == 401
            assert request(raw=b'x' * 65537)[0] == 413
            assert request(raw=b'{')[0] == 400
            status, body = request('silent'); assert status == 200
            assert json.loads(body)['choices'][0]['message']['content'] == ''; events.get(timeout=2)
            status, body = request('silent-null'); assert status == 200
            assert json.loads(body)['choices'][0]['message']['content'] == ''; events.get(timeout=2)
            assert request('incomplete')[0] == 502; events.get(timeout=2)
            status, body = request('controls'); assert status == 200
            clean = json.loads(body)['choices'][0]['message']['content']
            assert '\x1b' not in clean and '\x07' not in clean and '\r' not in clean and '\u202e' not in clean
            assert '\\x1b' in clean and '\\u202e' in clean; events.get(timeout=2)
            for command in ('large', 'redirect', 'error'):
                assert request(command)[0] == 502, command
                forwarded, _ = events.get(timeout=2); assert forwarded != 'redirect-followed'
            for command in ('slow', 'trickle'):
                started = time.monotonic(); status = request(command)[0]
                assert (status == 504 if command == 'trickle' else status in (502, 504)), (command, status)
                assert time.monotonic() - started < 1.8
                events.get(timeout=2)
            # Holding an incomplete header must consume at most the same deadline.
            stalled = socket.socket(socket.AF_UNIX); stalled.settimeout(3); stalled.connect(address)
            stalled.sendall(b'POST /v1/chat/completions HTTP/1.0\r\nX: ')
            assert b'504' in stalled.recv(1024); stalled.close()
            outcomes = []
            threads = [threading.Thread(target=lambda: outcomes.append(request('slow')[0])) for _ in range(2)]
            for thread in threads: thread.start()
            events.get(timeout=2); events.get(timeout=2)
            assert request()[0] == 503
            for thread in threads: thread.join()
            assert len(outcomes) == 2 and all(status in (502, 504) for status in outcomes), outcomes
            time.sleep(.2)
            assert request()[0] == 200; events.get(timeout=2)
            time.sleep(.2)
            children = Path(f'/proc/{gateway.pid}/task/{gateway.pid}/children').read_text().strip()
            assert not children, 'workers leaked after completed requests'
            long = {'messages': [{'role': 'system', 'content': 'prompt'}] +
                    [{'role': 'user', 'content': 'x' * 3000} for _ in range(30)]}
            bounded = bounded_request(long)
            assert len(bounded['messages']) <= 16 and sum(len(m['content']) for m in bounded['messages']) <= 32768
            assert bounded['messages'][0]['content'].startswith('prompt')
            seeded = bounded_request({'messages': [
                {'role': 'system', 'content': 'terminal'},
                {'role': 'user', 'content': 'pwd'},
                {'role': 'assistant', 'content': '/home/user'},
                {'role': 'user', 'content': 'hello'}]})
            assert len(seeded['messages']) == 2 and seeded['messages'][-1]['content'] == 'hello'
            pairs = [{'role': 'system', 'content': 'terminal'}]
            for _ in range(12): pairs += [{'role': 'user', 'content': 'x'*3000}, {'role': 'assistant', 'content': 'y'*3000}]
            pairs += [{'role': 'user', 'content': 'pwd'}]
            trimmed = bounded_request({'messages': pairs})['messages'][1:]
            assert [m['role'] for m in trimmed] == ['user' if i%2==0 else 'assistant' for i in range(len(trimmed))]
            assert terminal_output('café\r\n中文\t') == 'café\n中文\t'
            print('PASS fixed model/key, auth, request/history/response caps, redirect denial, provider failures, total deadlines, stalled headers, overload and worker cleanup')
        finally:
            stop.set(); gateway.join(3)
            if gateway.is_alive(): gateway.kill(); gateway.join()
            listener.close(); provider.terminate(); provider.join(); upstream_socket.close()


if __name__ == '__main__': main()
