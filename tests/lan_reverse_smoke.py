#!/usr/bin/env python3
"""Real desktop host -> second LAN machine client over physical LAN, no relay."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from cli_smoke import first_json
from lab_env import binary, lab

BINARY = binary()
T3 = lab("T3_BINARY")
REMOTE = lab("REMOTE")  # user@host of the second LAN machine
REMOTE_ROOT = lab("REMOTE_ROOT")  # checkout on that machine


def rpc(control, operation, **params):
    request = json.dumps({"op": operation, **params}) + "\n"
    result = subprocess.run([sys.executable, "tests/lan_rpc.py", "--socket", control], input=request, capture_output=True, text=True, timeout=16)
    assert result.returncode == 0, f"Omarchy control socket failed: {result.stderr[:180]}"
    response = json.loads(result.stdout)
    assert "error" not in response, f"Omarchy rejected {operation}: {response.get('error')}"
    return response


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def main():
    assert Path(BINARY).is_file() and Path(T3).is_file()
    with tempfile.TemporaryDirectory(prefix="omabridge-omarchy-lan-") as tmp:
        root = Path(tmp)
        host_log = (root / "host.private.log").open("wb")
        client_log = (root / "client.private.log").open("wb")
        host = subprocess.Popen([sys.executable, "tests/lan_host.py", "--binary", BINARY, "--t3-binary", T3, "--udp-port", "8080"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=host_log, text=True)
        client = None
        control = None
        try:
            ready = first_json(host, limit=40)
            control = ready["control"]
            assert any(lab("HOST_IP") in json.dumps(addr) for addr in ready["address"]["addrs"])
            assert all("Relay" not in json.dumps(addr) for addr in ready["address"]["addrs"])
            invitation = rpc(control, "invite")["invite"]
            assert base64.b64decode(invitation)
            t3 = rpc(control, "t3_credential")["credential"]
            client = subprocess.Popen(["ssh", "-T", "-o", "BatchMode=yes", REMOTE, f"cd {REMOTE_ROOT} && python3 -u tests/lan_reverse_client.py --binary target/debug/omabridge"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=client_log, text=True)
            assert client.stdin is not None and client.stdout is not None
            client.stdin.write(json.dumps({"invite": invitation, "credential": t3, "host_id": ready["id"]}) + "\n")
            client.stdin.flush()
            client.stdin.close()
            pending = first_json(client, limit=20)
            assert pending["event"] == "pair_pending"
            assert rpc(control, "approve", id=pending["id"])["approved"]
            result = json.loads(client.stdout.readline())
            assert client.wait(timeout=30) == 0
            assert result["status"] == "pass"
            print(json.dumps(result), flush=True)
        finally:
            if client is not None:
                stop(client)
            if control and host.poll() is None:
                try:
                    rpc(control, "stop")
                    host.wait(timeout=8)
                except (AssertionError, subprocess.TimeoutExpired):
                    stop(host)
            else:
                stop(host)
            host_log.close()
            client_log.close()


if __name__ == "__main__":
    main()
