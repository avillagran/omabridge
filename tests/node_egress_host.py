#!/usr/bin/env python3
"""Isolated exit-host-side test host for OmaBridge HTTPS egress; JSON control via SSH stdin."""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from cli_smoke import first_json


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)

    parser.add_argument("--bind", default="0.0.0.0:0")
    parser.add_argument("--relay-url")
    args = parser.parse_args()
    owned = Path(__file__).resolve().parents[1] / ".test-state"
    owned.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="node-egress-", dir=owned) as tmp:
        root = Path(tmp)
        log = (root / "host.private.log").open("wb")
        node = None
        try:
            node_state = root / "node"
            binary = str(Path(args.binary).resolve())
            server_args = [binary, "--state-dir", str(node_state), "--name", "node-egress",
                           "--bind", args.bind]
            if args.relay_url:
                server_args.extend(["--relay-url", args.relay_url])
            node = subprocess.Popen(server_args + ["egress", "--origin", "https://api.ipify.org"],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=log, text=True)
            ready = first_json(node, limit=20)
            print(json.dumps({"event": "ready", "id": ready["id"],
                              "address": ready["address"]}), flush=True)
            for line in sys.stdin:
                request = {}
                try:
                    request = json.loads(line)
                    op = request["op"]
                    if op == "invite":
                        path = root / "pair.invite.json"
                        result = subprocess.run([binary, "--state-dir", str(node_state), "invite",
                                                 "--service", "egress", "--ttl", "120",
                                                 "--output", str(path)], capture_output=True,
                                                text=True, timeout=15)
                        assert result.returncode == 0 and path.stat().st_mode & 0o077 == 0
                        reply = {"invite": base64.b64encode(path.read_bytes()).decode()}
                    elif op == "approve":
                        result = subprocess.run([binary, "--state-dir", str(node_state),
                                                 "approve", request["id"]],
                                                capture_output=True, text=True, timeout=15)
                        assert result.returncode == 0
                        reply = {"approved": True}
                    elif op == "revoke":
                        result = subprocess.run([binary, "--state-dir", str(node_state),
                                                 "revoke", request["id"]],
                                                capture_output=True, text=True, timeout=15)
                        assert result.returncode == 0
                        reply = {"revoked": True}
                    elif op == "public_ip":
                        result = subprocess.run(["curl", "--noproxy", "*", "-fsS", "--max-time", "10",
                                                 "https://api.ipify.org?format=json"],
                                                capture_output=True, text=True, timeout=15)
                        assert result.returncode == 0
                        reply = {"ip": json.loads(result.stdout)["ip"]}
                    elif op == "stop":
                        reply = {"stopping": True}
                    else:
                        reply = {"error": "unknown operation"}
                except (AssertionError, KeyError, ValueError, OSError, subprocess.TimeoutExpired) as error:
                    reply = {"error": f"exit host lab control {type(error).__name__}"}
                print(json.dumps(reply), flush=True)
                if request.get("op") == "stop":
                    break
        finally:
            stop(node)
            log.close()


if __name__ == "__main__":
    main()
