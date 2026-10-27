#!/usr/bin/env python3
"""The second LAN machine acts as a phone-like CLI client to a genuine OmaBridge/T3 Omarchy host.
Invitation and temporary T3 bootstrap are read from SSH stdin before spawning work.
"""
import argparse
import base64
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from cli_smoke import first_json
from t3_smoke import receive_frame, send_frame


def invoke(binary, state, *args):
    result = subprocess.run([binary, "--state-dir", str(state), "--name", "lab-phone", *args], capture_output=True, text=True, timeout=16)
    assert result.returncode == 0, f"{args[0]} failed: {result.stderr[:150]}"
    return json.loads(result.stdout)


def verify_t3(base, credential):
    checks = []
    assert json.load(urllib.request.urlopen(base + "/api/auth/session", timeout=8))["authenticated"] is False
    try:
        urllib.request.urlopen(base + "/api/orchestration/shell", timeout=8).close()
    except urllib.error.HTTPError as error:
        assert error.code in (401, 403)
    else:
        raise AssertionError("unauthorized T3 request unexpectedly succeeded")
    checks.append("unauthorized_T3_API_denied")
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    request = urllib.request.Request(base + "/api/auth/browser-session", data=json.dumps({"credential": credential}).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with opener.open(request, timeout=8) as response:
        assert response.status == 200
        response.read()
    with opener.open(base + "/api/auth/session", timeout=8) as response:
        assert json.load(response)["authenticated"] is True
    checks.append("isolated_native_T3_session_authenticated")
    with opener.open(urllib.request.Request(base + "/api/orchestration/shell", headers={"x-t3-orchestration-protocol": "2"}), timeout=8) as response:
        assert response.status == 200
        json.load(response)
    checks.append("native_T3_authenticated_HTTP_read")
    req = urllib.request.Request(base + "/ws")
    jar.add_cookie_header(req)
    cookie = req.get_header("Cookie")
    assert cookie
    host = base.removeprefix("http://")
    with socket.create_connection(("127.0.0.1", int(host.rsplit(":", 1)[1])), timeout=8) as ws:
        ws.sendall((f"GET /ws?orchestrationProtocol=2 HTTP/1.1\r\nHost: {host}\r\nOrigin: {base}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nCookie: {cookie}\r\n\r\n").encode())
        headers = b""
        while not headers.endswith(b"\r\n\r\n"):
            byte = ws.recv(1)
            assert byte
            headers += byte
        assert b"101" in headers.split(b"\r\n")[0]
        send_frame(ws, json.dumps({"_tag": "Request", "id": "1", "tag": "server.getConfig", "payload": {}, "headers": []}).encode())
        for _ in range(30):
            opcode, payload = receive_frame(ws)
            if opcode == 9:
                send_frame(ws, payload, opcode=10)
            elif opcode == 1:
                result = json.loads(payload)
                if result.get("_tag") == "Exit" and result.get("requestId") == "1":
                    assert result["exit"]["_tag"] == "Success"
                    checks.append("native_T3_WebSocket_RPC_server_getConfig")
                    break
        else:
            raise AssertionError("native T3 RPC never returned")
    return checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    payload = json.loads(sys.stdin.buffer.readline(65536))
    source = base64.b64decode(payload["invite"])
    credential = payload["credential"]
    host_id = payload["host_id"]
    owned = Path(__file__).resolve().parents[1] / ".test-state"
    owned.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="lan-client-", dir=owned) as temp:
        root = Path(temp)
        state = root / "guest"
        invite = root / "pair.invite.json"
        descriptor = os.open(invite, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(source)
        binary = str(Path(args.binary).resolve())
        guest_id = invoke(binary, state, "init")["id"]
        first = invoke(binary, state, "pair", "--invite-file", str(invite))
        assert first["status"] == "pending"
        print(json.dumps({"event": "pair_pending", "id": guest_id}), flush=True)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            pair = invoke(binary, state, "pair", "--invite-file", str(invite))
            if pair["status"] == "approved":
                break
            time.sleep(0.15)
        else:
            raise AssertionError("remote administrator did not approve pairing")
        peer = next(p for p in invoke(binary, state, "peers")["peers"] if p["id"] == host_id)
        assert "t3" in peer["remote_services"] and not peer["services"]
        checks = ["cross_host_pairing_and_scoped_grant"]
        error = (root / "forward.stderr").open("wb")
        forward = subprocess.Popen([binary, "--state-dir", str(state), "forward", "--peer", host_id, "--service", "t3", "--listen", "127.0.0.1:0"], stdout=subprocess.PIPE, stderr=error, text=True)
        try:
            ready = first_json(forward, limit=16)
            checks += verify_t3("http://" + ready["listen"], credential)
        finally:
            if forward.poll() is None:
                forward.terminate()
                try:
                    forward.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    forward.kill()
                    forward.wait(timeout=5)
            error.close()
        print(json.dumps({"status": "pass", "transport": "direct iroh QUIC over physical LAN; no configured relay", "local": "Linux ARM64", "remote": "Linux x86_64", "upstream": "genuine isolated T3 headless on Omarchy", "checks": checks, "provider_turns_started": 0}), flush=True)


if __name__ == "__main__":
    main()
