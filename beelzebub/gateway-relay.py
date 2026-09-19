"""Private-network TCP to Unix-socket relay; no external destinations or key."""
import argparse
import select
import socket
import threading
import time


def relay(client, path, slots):
    upstream = socket.socket(socket.AF_UNIX)
    try:
        upstream.settimeout(2)
        upstream.connect(path)
        client.settimeout(2)
        started = time.monotonic()
        total = 0
        while time.monotonic() - started < 35:
            ready, _, _ = select.select([client, upstream], [], [], .25)
            for source in ready:
                data = source.recv(16384)
                if not data: return
                total += len(data)
                if total > 262144: return
                (upstream if source is client else client).sendall(data)
    except OSError:
        pass
    finally:
        client.close(); upstream.close(); slots.release()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--socket', required=True)
    args = parser.parse_args()
    slots = threading.BoundedSemaphore(8)
    with socket.create_server(('0.0.0.0', 8080), backlog=8) as listener:
        while True:
            client, _ = listener.accept()
            if not slots.acquire(blocking=False):
                client.close()
                continue
            threading.Thread(target=relay, args=(client, args.socket, slots), daemon=True).start()


if __name__ == '__main__': main()
