#!/usr/bin/env python3
"""Exercise a genuine, isolated T3 headless runtime through the OmaBridge CLI.
Never uses the user's installed T3 home, providers, credentials or conversations.
"""
import argparse
import base64
import http.cookiejar
import json
from pathlib import Path
import re
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from cli_smoke import first_json


def receive_exact(sock, length):
    data = b""
    while len(data) < length:
        part = sock.recv(length - len(data))
        assert part, "WebSocket frame truncated"
        data += part
    return data


def receive_frame(sock):
    header = receive_exact(sock, 2)
    length = header[1] & 127
    if length == 126:
        length = struct.unpack("!H", receive_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", receive_exact(sock, 8))[0]
    assert not header[1] & 128 and length <= 1024 * 1024
    return header[0] & 15, receive_exact(sock, length)


def send_frame(sock, data, opcode=1):
    mask = b"test"
    length = len(data)
    size = bytes([128 | length]) if length < 126 else b"\xfe" + struct.pack("!H", length)
    sock.sendall(bytes([128 | opcode]) + size + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/debug/omabridge")
    parser.add_argument("--t3-binary", required=True)
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    t3 = str(Path(args.t3_binary).resolve())
    children = []
    checks = []
    with tempfile.TemporaryDirectory(prefix="omabridge-real-t3-") as temp:
        root = Path(temp)
        def call(who, *parts):
            p = subprocess.run([binary, "--state-dir", str(root / who), "--name", who, *parts], capture_output=True, text=True, timeout=20)
            assert p.returncode == 0, f"{parts[0]} failed: {p.stderr[:200]}"
            return json.loads(p.stdout)
        def start(who, *parts):
            error = (root / f"{who}-{len(children)}.stderr").open("wb")
            p = subprocess.Popen([binary, "--state-dir", str(root / who), "--name", who, *parts], stdout=subprocess.PIPE, stderr=error, text=True, start_new_session=True)
            children.append((p, error))
            try:
                return p, first_json(p, limit=40)
            except AssertionError as exc:
                error.flush()
                # OmaBridge stderr carries only a sanitized readiness error; native
                # T3 credentials remain in its separate mode-0600 private log.
                diagnostic = Path(error.name).read_text()[:250]
                raise AssertionError(f"headless readiness failed: {diagnostic}") from exc
        def stop(p):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=5)
        try:
            host_id = call("host", "init")["id"]
            guest_id = call("phone", "init")["id"]
            port_socket = socket.socket()
            port_socket.bind(("127.0.0.1", 0))
            t3_port = port_socket.getsockname()[1]
            port_socket.close()
            host, ready = start("host", "--bind", "127.0.0.1:0", "t3", "--t3-binary", t3, "--t3-home", str(root / "t3-home"), "--t3-port", str(t3_port))
            checks.append("headless_launcher_starts_t3_and_omabridge")
            before_logs = set((root / "host").glob("t3-*.private.log"))
            with socket.socket() as available:
                available.bind(("127.0.0.1", 0))
                second_port = available.getsockname()[1]
            duplicate = subprocess.run([binary, "--state-dir", str(root / "host"), "--name", "host", "--bind", "127.0.0.1:0", "t3", "--t3-binary", t3, "--t3-home", str(root / "t3-home"), "--t3-port", str(second_port)], capture_output=True, text=True, timeout=20)
            assert duplicate.returncode != 0, "second headless instance started against the same identity"
            assert set((root / "host").glob("t3-*.private.log")) == before_logs, "second T3 child spawned before the runtime lock"
            checks.append("second_headless_refused_before_child_spawn")
            # The TCP listener can be ready before T3 finishes printing its QR/link.
            deadline = time.monotonic() + 10
            match = None
            while time.monotonic() < deadline:
                native_log = Path(ready["t3_log"]).read_text()
                # This credential belongs only to this disposable environment.
                match = re.search(r"https?://[^\s\x1b\"<>]+/pair#token=([^\s\x1b\"<>]+)", native_log)
                if match:
                    break
                time.sleep(0.1)
            assert match, "isolated T3 did not issue a startup pairing link"
            credential = urllib.parse.unquote(match.group(1))
            invite = root / "phone.invite.json"
            call("host", "invite", "--service", "t3", "--output", str(invite))
            assert call("phone", "pair", "--invite-file", str(invite))["status"] == "pending"
            call("host", "approve", guest_id)
            assert call("phone", "pair", "--invite-file", str(invite))["status"] == "approved"
            forward, local = start("phone", "forward", "--peer", host_id, "--service", "t3")
            base = f"http://{local['listen']}"
            try:
                urllib.request.urlopen(base + "/api/orchestration/shell", timeout=8).close()
            except urllib.error.HTTPError as error:
                assert error.code in (401, 403), f"unexpected unauthenticated HTTP status {error.code}"
            else:
                raise AssertionError("OmaBridge bypassed T3 authentication")
            checks.append("t3_unauthenticated_api_still_denied")
            jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
            request = urllib.request.Request(base + "/api/auth/browser-session", data=json.dumps({"credential": credential}).encode(), headers={"Content-Type": "application/json"}, method="POST")
            with opener.open(request, timeout=10) as response:
                assert response.status == 200
                response.read()
            with opener.open(base + "/api/auth/session", timeout=8) as response:
                assert json.load(response)["authenticated"] is True
            checks.append("native_t3_pairing_and_browser_session_through_bridge")
            with opener.open(urllib.request.Request(base + "/api/orchestration/shell", headers={"x-t3-orchestration-protocol": "2"}), timeout=8) as response:
                assert response.status == 200
                json.load(response)
            checks.append("authenticated_t3_shell_read")
            request = urllib.request.Request(base + "/ws")
            jar.add_cookie_header(request)
            cookie = request.get_header("Cookie")
            assert cookie
            ws = socket.create_connection(("127.0.0.1", int(local["listen"].rsplit(":", 1)[1])), timeout=10)
            ws.sendall((f"GET /ws?orchestrationProtocol=2 HTTP/1.1\r\nHost: {local['listen']}\r\nOrigin: {base}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nCookie: {cookie}\r\n\r\n").encode())
            headers = b""
            while not headers.endswith(b"\r\n\r\n"):
                headers += receive_exact(ws, 1)
            assert b"101" in headers.split(b"\r\n")[0], "native T3 WebSocket upgrade failed"
            send_frame(ws, json.dumps({"_tag": "Request", "id": "1", "tag": "server.getConfig", "payload": {}, "headers": []}).encode())
            for _ in range(30):
                opcode, payload = receive_frame(ws)
                if opcode == 9:
                    send_frame(ws, payload, opcode=10)
                elif opcode == 1:
                    event = json.loads(payload)
                    if event.get("_tag") == "Exit" and event.get("requestId") == "1":
                        assert event["exit"]["_tag"] == "Success", "T3 read-only RPC failed"
                        checks.append("native_t3_websocket_rpc_server_get_config")
                        break
            else:
                raise AssertionError("T3 RPC did not complete")
            ws.close()
            stop(host)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and Path(f"/proc/{ready['t3_pid']}").exists():
                time.sleep(0.05)
            assert not Path(f"/proc/{ready['t3_pid']}").exists(), "owned T3 process leaked after wrapper exit"
            probe = socket.socket()
            probe.settimeout(1)
            try:
                assert probe.connect_ex(("127.0.0.1", t3_port)) != 0, "owned T3 listener survived wrapper exit"
            finally:
                probe.close()
            checks.append("owned_headless_process_stops_with_wrapper")
        finally:
            for child, error in reversed(children):
                stop(child)
                error.close()
    print(json.dumps({"status": "pass", "upstream": "genuine T3 headless, isolated disposable home", "checks": checks, "provider_turns_started": 0}))


if __name__ == "__main__":
    main()
