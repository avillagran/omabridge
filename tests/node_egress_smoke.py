#!/usr/bin/env python3
"""Disposable desktop -> exit host -> fixed public HTTPS API test, no AI credentials."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.request import ProxyHandler, build_opener
from urllib.error import URLError

from cli_smoke import first_json
from lab_env import binary, lab

BINARY = binary()
REMOTE = lab("EXIT_HOST")  # user@host that performs the HTTPS egress
REMOTE_ROOT = lab("EXIT_ROOT")  # checkout on that host


def rpc(host, op, **fields):
    host.stdin.write(json.dumps({"op": op, **fields}) + "\n")
    host.stdin.flush()
    line = host.stdout.readline()
    result = json.loads(line)
    assert "error" not in result, f"exit host rejected {op}: {result.get('error')}"
    return result


def command(binary, root, *args):
    result = subprocess.run([binary, "--state-dir", str(root), *args],
                            capture_output=True, text=True, timeout=18)
    assert result.returncode == 0, f"OmaBridge failed ({args[0]}): {result.stderr[:160]}"
    return json.loads(result.stdout.splitlines()[0])


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main():
    assert Path(BINARY).is_file(), "build ARM64 binary first"
    loopback_http = build_opener(ProxyHandler({}))
    with tempfile.TemporaryDirectory(prefix="omabridge-node-egress-") as tmp:
        root = Path(tmp)
        log = (root / "node.private.log").open("wb")
        host = subprocess.Popen(["ssh", "-T", "-o", "BatchMode=yes", REMOTE,
            f"cd {REMOTE_ROOT} && python3 -u tests/node_egress_host.py --binary target/debug/omabridge"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
        forward = None
        try:
            ready = first_json(host, limit=30)
            assert ready["event"] == "ready"
            invite = root / "node.invite.json"
            invite.write_bytes(base64.b64decode(rpc(host, "invite")["invite"]))
            invite.chmod(0o600)
            state = root / "omarchy"
            assert command(BINARY, state, "pair", "--invite-file", str(invite))["status"] == "pending"
            peer_id = command(BINARY, state, "init")["id"]
            assert rpc(host, "approve", id=peer_id)["approved"]
            assert command(BINARY, state, "pair", "--invite-file", str(invite))["status"] == "approved"
            forward = subprocess.Popen([BINARY, "--state-dir", str(state), "forward",
                                        "--peer", ready["id"], "--service", "egress"],
                                       stdout=subprocess.PIPE, stderr=(root / "forward.private.log").open("wb"),
                                       text=True)
            local = first_json(forward, limit=20)["listen"]
            with loopback_http.open(f"http://{local}/?format=json", timeout=15) as response:
                routed = json.loads(response.read())
            expected = rpc(host, "public_ip")["ip"]
            assert routed == {"ip": expected}, "remote API did not observe the exit host's public egress"
            assert rpc(host, "revoke", id=peer_id)["revoked"]
            try:
                with loopback_http.open(f"http://{local}/?format=json", timeout=8) as response:
                    raise AssertionError(f"revoked device still reached egress: {response.status}")
            except (OSError, URLError):
                pass
            print(json.dumps({"status": "pass", "origin": "https://api.ipify.org",
                              "transport": "OmaBridge direct encrypted peer stream",
                              "checks": ["omarchy_to_node_scoped_pairing", "node_owned_https_request",
                                         "external_api_reports_node_public_ip", "revocation_blocks_next_request",
                                         "no_ai_key_sent_or_used"],
                              "node_egress_ip": expected}), flush=True)
        finally:
            stop(forward)
            if host.poll() is None:
                try:
                    rpc(host, "stop")
                    host.wait(timeout=10)
                except (OSError, ValueError, AssertionError, subprocess.TimeoutExpired):
                    stop(host)
            else:
                stop(host)
            log.close()


if __name__ == "__main__":
    main()
