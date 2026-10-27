#!/usr/bin/env python3
"""Reproducible VPS -> Omarchy WAN benchmark; never label it a cellular test."""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
from pathlib import Path
import subprocess
import tempfile
import threading

from cli_smoke import first_json
from lab_env import binary, lab
from node_egress_smoke import stop

BINARY = binary()
RELAY = lab("RELAY_URL")
PAYLOAD = bytes(range(256)) * 4096


class Fixture(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        body = PAYLOAD if self.path == "/bulk" else b"omabridge-perf"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    fixture = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="omabridge-wan-perf-host-") as temp:
            root = Path(temp)
            log = (root / "process.private.log").open("wb")
            state = root / "host"
            host = subprocess.Popen([BINARY, "--state-dir", str(state), "--name", "perf-omarchy",
                                     "--bind", "[::]:0", "--relay-url", RELAY,
                                     "serve", "--service", f"perf=127.0.0.1:{fixture.server_port}"],
                                    stdout=subprocess.PIPE, stderr=log, text=True)
            client = None
            try:
                ready = first_json(host, limit=20)
                invite = root / "host.invite.json"
                result = subprocess.run([BINARY, "--state-dir", str(state), "invite", "--service", "perf",
                                         "--ttl", "300", "--output", str(invite)],
                                        capture_output=True, timeout=15)
                assert result.returncode == 0 and invite.stat().st_mode & 0o077 == 0
                client = subprocess.Popen(["ssh", "-T", "-o", "BatchMode=yes", lab("EXIT_HOST"),
                    f"ssh -T -o BatchMode=yes {lab('VPS')} "
                    "'cd /opt/omabridge-test && python3 -u tests/wan_perf_client.py'"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
                assert client.stdin is not None and client.stdout is not None
                client.stdin.write(json.dumps({"invite": base64.b64encode(invite.read_bytes()).decode(),
                                               "host_id": ready["id"], "relay": RELAY,
                                               "payload_sha256": hashlib.sha256(PAYLOAD).hexdigest()}) + "\n")
                client.stdin.flush()
                pending = first_json(client, limit=30)
                assert pending["event"] == "pair_pending"
                result = subprocess.run([BINARY, "--state-dir", str(state), "approve", pending["id"]],
                                        capture_output=True, timeout=15)
                assert result.returncode == 0
                client.stdin.write(json.dumps({"approved": True}) + "\n")
                client.stdin.flush()
                measured = first_json(client, limit=150)
                assert measured["status"] == "pass" and client.wait(timeout=20) == 0
                if args.output:
                    with args.output.open("x") as output:
                        output.write(json.dumps(measured, indent=2) + "\n")
                print(json.dumps(measured), flush=True)
            finally:
                stop(client)
                stop(host)
                log.close()
    finally:
        fixture.shutdown()
        fixture.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    main()
