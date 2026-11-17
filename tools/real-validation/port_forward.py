#!/usr/bin/env python3
"""Optional loopback-only byte relay for Docker engines that do not publish internal networks.

TLS stays end-to-end between IRMind and Elasticsearch. This developer helper
neither reads certificates/credentials nor grants the container outbound access.
"""
import socket
import socketserver
import subprocess
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMAND = [
    'docker', 'compose', '--env-file', str(ROOT / 'target/real-validation/compose.env'),
    '-f', str(ROOT / 'tools/real-validation/compose.yml'),
    'exec', '-T', 'es', '/usr/bin/nc', '-i', '60', '127.0.0.1', '9200',
]


def relay(connection, child, lifetime=60):
    """Copy opaque bytes in bounded chunks; close both directions on exit."""
    finished = threading.Event()
    connection.settimeout(lifetime)

    def incoming():
        try:
            while data := connection.recv(65536):
                child.stdin.write(data)
                child.stdin.flush()
        except (OSError, ValueError):
            pass
        finally:
            finished.set()

    def outgoing():
        try:
            while data := child.stdout.read1(65536):
                connection.sendall(data)
        except (OSError, ValueError):
            pass
        finally:
            finished.set()

    workers = [threading.Thread(target=fn, daemon=True) for fn in (incoming, outgoing)]
    try:
        for worker in workers:
            worker.start()
        finished.wait(lifetime)
    finally:
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        child.terminate()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
        for worker in workers:
            worker.join(2)
        child.stdin.close()
        child.stdout.close()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        with subprocess.Popen(COMMAND, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL) as child:
            relay(self.request, child)


class Forwarder(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self):
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(('127.0.0.1', 9200), Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


if __name__ == '__main__':
    try:
        with Forwarder() as server:
            print('Developer TLS relay on 127.0.0.1:9200; Ctrl+C stops it.', flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        pass
    except OSError:
        raise SystemExit('Cannot bind the loopback lab port. Stop the other listener; do not change TLS verification.') from None
