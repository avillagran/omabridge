#!/usr/bin/env python3
"""Disposable second-machine endpoint. Commands arrive over a private Unix socket via SSH.
Neither invitation bytes nor T3 credentials appear in shell arguments or logs.
"""
import argparse
import base64
import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

from cli_smoke import first_json


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def respond(command, root, host, ready, binary):
    op = command["op"]
    if op == "stop":
        return {"stopping": True}
    if op == "invite":
        destination = root / "pair.invite.json"
        result = subprocess.run([binary, "--state-dir", str(host), "invite", "--service", "t3", "--ttl", "120", "--output", str(destination)], capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, "could not create scoped invitation"
        assert destination.stat().st_mode & 0o077 == 0
        return {"invite": base64.b64encode(destination.read_bytes()).decode()}
    if op == "approve":
        result = subprocess.run([binary, "--state-dir", str(host), "approve", command["id"]], capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, "approval failed"
        return {"approved": True}
    if op == "t3_credential":
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            match = re.search(r"/pair#token=([^\s\x1b\"<>]+)", Path(ready["t3_log"]).read_text())
            if match:
                return {"credential": match.group(1)}
            time.sleep(0.1)
        raise AssertionError("isolated T3 did not issue a pairing token")
    return {"error": "unknown operation"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--t3-binary", required=True)
    parser.add_argument("--udp-port", type=int, default=0)
    args = parser.parse_args()
    owned = Path(__file__).resolve().parents[1] / ".test-state"
    owned.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="lan-host-", dir=owned) as temp:
        root = Path(temp)
        host = root / "host"
        log = (root / "wrapper.stderr").open("wb")
        binary = str(Path(args.binary).resolve())
        t3_binary = str(Path(args.t3_binary).resolve())
        process = subprocess.Popen([binary, "--state-dir", str(host), "--name", "lab-host", "--bind", f"0.0.0.0:{args.udp_port}", "t3", "--t3-binary", t3_binary, "--t3-home", str(root / "t3-home"), "--t3-port", str(free_port())], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=log, text=True, start_new_session=True)
        try:
            ready = first_json(process, limit=40)
            control = root / "control.sock"
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(str(control))
                server.listen(4)
                print(json.dumps({"event": "ready", "id": ready["id"], "address": ready["address"], "control": str(control)}), flush=True)
                while True:
                    with server.accept()[0] as connection:
                        connection.settimeout(15)
                        line = connection.makefile("rb").readline(8192)
                        try:
                            request = json.loads(line)
                            answer = respond(request, root, host, ready, binary)
                        except (KeyError, ValueError, AssertionError) as error:
                            answer = {"error": f"lab control {type(error).__name__}: {str(error)[:80]}"}
                            request = {}
                        connection.sendall(json.dumps(answer).encode() + b"\n")
                        if request.get("op") == "stop":
                            break
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            log.close()


if __name__ == "__main__":
    main()
