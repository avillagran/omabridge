#!/usr/bin/env python3
"""VPS test driver: measure OmaBridge to an isolated Omarchy HTTP fixture, not cellular."""
import base64
import hashlib
import http.client
import json
import math
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

from cli_smoke import first_json

BINARY = "/opt/omabridge-test/omabridge"


def summary(values):
    ordered = sorted(values)
    return {"samples": len(values), "median": round(statistics.median(values), 2),
            "p95": round(ordered[math.ceil(0.95 * len(ordered)) - 1], 2),
            "min": round(ordered[0], 2), "max": round(ordered[-1], 2)}


def main():
    message = json.loads(sys.stdin.readline())
    with tempfile.TemporaryDirectory(prefix="omabridge-wan-perf-") as temp:
        root = Path(temp)
        state = root / "client"
        invite = root / "host.invite.json"
        invite.write_bytes(base64.b64decode(message["invite"]))
        invite.chmod(0o600)
        common = [BINARY, "--state-dir", str(state), "--bind", "[::]:0", "--relay-url", message["relay"]]

        def call(*args):
            result = subprocess.run(common + list(args), capture_output=True, text=True, timeout=18)
            assert result.returncode == 0, "OmaBridge setup failed"
            return json.loads(result.stdout.splitlines()[0])

        pending = call("pair", "--invite-file", str(invite))
        assert pending["status"] == "pending"
        print(json.dumps({"event": "pair_pending", "id": pending["id"]}), flush=True)
        assert json.loads(sys.stdin.readline())["approved"]
        assert call("pair", "--invite-file", str(invite))["status"] == "approved"
        log = (root / "forward.private.log").open("wb")
        before = time.perf_counter()
        forward = subprocess.Popen(common + ["forward", "--peer", message["host_id"], "--service", "perf"],
                                   stdout=subprocess.PIPE, stderr=log, text=True)
        connection = None
        try:
            local = first_json(forward, limit=20)["listen"]
            setup_ms = (time.perf_counter() - before) * 1000
            host, port = local.rsplit(":", 1)

            def request(connection, path):
                start = time.perf_counter()
                connection.request("GET", path)
                response = connection.getresponse()
                payload = response.read()
                assert response.status == 200
                if path == "/ping":
                    assert payload == b"omabridge-perf"
                else:
                    assert hashlib.sha256(payload).hexdigest() == message["payload_sha256"]
                return (time.perf_counter() - start), len(payload)

            connection = http.client.HTTPConnection(host, int(port), timeout=15)
            first_seconds, _ = request(connection, "/ping")
            persistent = [request(connection, "/ping")[0] * 1000 for _ in range(20)]
            bulk = []
            size = 0
            for _ in range(3):
                seconds, size = request(connection, "/bulk")
                bulk.append(size * 8 / seconds / 1000000)
            connection.close()
            connection = None
            fresh = []
            for _ in range(10):
                connection = http.client.HTTPConnection(host, int(port), timeout=15)
                fresh.append(request(connection, "/ping")[0] * 1000)
                connection.close()
                connection = None
            print(json.dumps({"status": "pass", "direction": "VPS -> Omarchy",
                              "network": "WAN from VPS, NOT cellular", "cellular_verified": False,
                              "upstream": "controlled loopback HTTP fixture, NOT T3",
                              "relay_configured": message["relay"], "selected_path_instrumented": False,
                              "forward_ready_ms": round(setup_ms, 2),
                              "first_request_ms": round(first_seconds * 1000, 2),
                              "persistent_tcp_request_ms": summary(persistent),
                              "new_tcp_request_ms": summary(fresh),
                              "bulk_download_mbps": summary(bulk), "bulk_bytes_per_sample": size}), flush=True)
        finally:
            if connection is not None:
                connection.close()
            if forward.poll() is None:
                forward.terminate()
                try:
                    forward.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    forward.kill()
                    forward.wait(timeout=5)
            log.close()


if __name__ == "__main__":
    main()
