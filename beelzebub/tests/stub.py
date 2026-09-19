"""Fixed model response on the isolated test network; never runs input."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading

LOCK = threading.Lock()


class Stub(BaseHTTPRequestHandler):
    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size < 1024 * 1024:
            self.send_error(413)
            return
        request = json.loads(self.rfile.read(size))
        with LOCK, Path("/logs/stub.jsonl").open("a") as stream:
            # This is always a deliberately fake credential.
            stream.write(json.dumps({"auth": self.headers.get("Authorization"),
                                     "request": request}) + "\n")
        response = json.dumps({"choices": [{"message": {
            "role": "assistant", "content": "STUB-OUTPUT"}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8000), Stub).serve_forever()
