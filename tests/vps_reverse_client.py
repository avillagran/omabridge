#!/usr/bin/env python3
"""Disposable VPS client for exit-host OmaBridge HTTPS egress."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.request import ProxyHandler, build_opener

from cli_smoke import first_json

BINARY = os.environ.get("OMABRIDGE_BINARY", "/opt/omabridge-test/omabridge")
RELAY = os.environ["OMABRIDGE_RELAY_URL"]


def command(state, *args):
    result = subprocess.run([BINARY, "--state-dir", str(state), "--bind", "[::]:0",
                             "--relay-url", RELAY, *args],
                            capture_output=True, text=True, timeout=18)
    assert result.returncode == 0, f"{args[0]} failed: {result.stderr[:130]}"
    return json.loads(result.stdout.splitlines()[0])


def main():
    message = json.loads(sys.stdin.readline())
    owned = Path("/opt/omabridge-test/.test-state")
    owned.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vps-client-", dir=owned) as temp:
        root = Path(temp)
        invite = root / "node.invite.json"
        invite.write_bytes(base64.b64decode(message["invite"]))
        invite.chmod(0o600)
        state = root / "vps"
        pending = command(state, "pair", "--invite-file", str(invite))
        print(json.dumps({"event": "pair_pending", "id": pending["id"]}), flush=True)
        approval = json.loads(sys.stdin.readline())
        assert approval["approved"]
        assert command(state, "pair", "--invite-file", str(invite))["status"] == "approved"
        log = (root / "forward.private.log").open("wb")
        forward = subprocess.Popen([BINARY, "--state-dir", str(state), "--bind", "[::]:0",
                                    "--relay-url", RELAY,
                                    "forward", "--peer", message["host_id"], "--service", "egress"],
                                   stdout=subprocess.PIPE, stderr=log, text=True)
        try:
            local = first_json(forward, limit=20)["listen"]
            with build_opener(ProxyHandler({})).open(f"http://{local}/?format=json", timeout=18) as response:
                actual = json.loads(response.read())["ip"]
            assert actual == message["expected_ip"], (actual, message["expected_ip"])
            print(json.dumps({"status": "pass", "direction": "VPS -> exit host -> external HTTPS",
                              "external_ip": actual, "real_ai_key_used": False}), flush=True)
        finally:
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
