#!/usr/bin/env python3
"""exit host -> VPS direct iroh -> VPS-owned HTTPS API, disposable WAN smoke."""
import base64
import json
from pathlib import Path
import subprocess
import tempfile
from urllib.request import ProxyHandler, build_opener

from cli_smoke import first_json
from lab_env import binary, lab
from node_egress_smoke import rpc, command, stop

BINARY = binary()
VPS = lab("VPS")  # user@host of the remote VPS


def main():
    assert Path(BINARY).is_file()
    http = build_opener(ProxyHandler({}))
    with tempfile.TemporaryDirectory(prefix="omabridge-node-vps-") as temp:
        root = Path(temp)
        log = (root / "vps.private.log").open("wb")
        vps = subprocess.Popen(["ssh", "-T", "-o", "BatchMode=yes", VPS,
            "cd /opt/omabridge-test && python3 -u tests/node_egress_host.py "
            "--binary /opt/omabridge-test/omabridge "
            "--bind 0.0.0.0:41234"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=log, text=True)
        forward = None
        try:
            ready = first_json(vps, limit=20)
            assert ready["event"] == "ready"
            assert lab("VPS_IP") in json.dumps(ready["address"]), "VPS public route absent"
            invite = root / "vps.invite.json"
            invite.write_bytes(base64.b64decode(rpc(vps, "invite")["invite"]))
            invite.chmod(0o600)
            state = root / "node"
            assert command(BINARY, state, "pair", "--invite-file", str(invite))["status"] == "pending"
            peer = command(BINARY, state, "init")["id"]
            assert rpc(vps, "approve", id=peer)["approved"]
            assert command(BINARY, state, "pair", "--invite-file", str(invite))["status"] == "approved"
            fwd_log = (root / "forward.private.log").open("wb")
            forward = subprocess.Popen([BINARY, "--state-dir", str(state), "forward",
                                        "--peer", ready["id"], "--service", "egress"],
                                       stdout=subprocess.PIPE, stderr=fwd_log, text=True)
            local = first_json(forward, limit=20)["listen"]
            with http.open(f"http://{local}/?format=json", timeout=18) as response:
                routed = json.loads(response.read())["ip"]
            expected = rpc(vps, "public_ip")["ip"]
            assert routed == expected == lab("VPS_IP"), (routed, expected)
            print(json.dumps({"status":"pass", "direction":"exit host -> VPS -> external HTTPS",
                              "external_ip": routed, "transport":"direct iroh QUIC over WAN",
                              "real_ai_key_used": False}), flush=True)
        finally:
            stop(forward)
            if vps.poll() is None:
                try:
                    rpc(vps, "stop")
                    vps.wait(timeout=10)
                except (OSError, ValueError, AssertionError, subprocess.TimeoutExpired):
                    stop(vps)
            else:
                stop(vps)
            log.close()


if __name__ == "__main__":
    main()
