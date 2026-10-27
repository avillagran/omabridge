#!/usr/bin/env python3
"""Exit-host HTTPS egress requested from a remote VPS through OmaBridge."""
import json
from pathlib import Path
import subprocess
import tempfile

from cli_smoke import first_json
from lab_env import binary, lab
from node_egress_smoke import rpc, stop

BINARY = binary()
VPS = lab("VPS")  # user@host of the remote VPS


def main():
    with tempfile.TemporaryDirectory(prefix="omabridge-vps-reverse-") as temp:
        root = Path(temp)
        host_log = (root / "node.private.log").open("wb")
        client_log = (root / "vps.private.log").open("wb")
        host = subprocess.Popen(["python3", "-u", "tests/node_egress_host.py",
                                 "--binary", BINARY, "--bind", "[::]:41235",
                                 "--relay-url", lab("RELAY_URL")],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=host_log, text=True)
        client = None
        try:
            ready = first_json(host, limit=20)
            assert lab("EXIT_IPV6_PREFIX") in json.dumps(ready["address"]), "exit host IPv6 route not published"
            invitation = rpc(host, "invite")["invite"]
            expected_ip = rpc(host, "public_ip")["ip"]
            client = subprocess.Popen(["ssh", "-T", "-o", "BatchMode=yes", VPS,
                                       "cd /opt/omabridge-test && python3 -u tests/vps_reverse_client.py"],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=client_log, text=True)
            assert client.stdin is not None and client.stdout is not None
            client.stdin.write(json.dumps({"invite": invitation, "host_id": ready["id"],
                                           "expected_ip": expected_ip}) + "\n")
            client.stdin.flush()
            try:
                pending = first_json(client, limit=25)
            except AssertionError as error:
                client_log.flush()
                text = (root / "vps.private.log").read_text(errors="replace")
                category = next((item for item in (
                    "connection setup deadline reached", "no route allowed", "Network is unreachable",
                    "pair failed", "python3: can't open file") if item in text), "unclassified")
                raise AssertionError(f"VPS could not pair with the exit host (category: {category})") from error
            assert pending["event"] == "pair_pending"
            assert rpc(host, "approve", id=pending["id"])["approved"]
            client.stdin.write(json.dumps({"approved": True}) + "\n")
            client.stdin.flush()
            result = json.loads(client.stdout.readline())
            assert client.wait(timeout=35) == 0
            assert result["status"] == "pass"
            print(json.dumps(result), flush=True)
        finally:
            stop(client)
            if host.poll() is None:
                try:
                    rpc(host, "stop")
                    host.wait(timeout=10)
                except (OSError, ValueError, AssertionError, subprocess.TimeoutExpired):
                    stop(host)
            else:
                stop(host)
            host_log.close()
            client_log.close()


if __name__ == "__main__":
    main()
