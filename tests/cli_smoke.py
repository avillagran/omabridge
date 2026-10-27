#!/usr/bin/env python3
"""Real-process smoke: CLI enrollment, HTTP/WebSocket forwarding, restart, revoke.
The upstream is an explicitly identified test HTTP/WebSocket fixture, not T3.
"""
import argparse
import base64
import hashlib
import gzip
import zlib
import http.server
import json
from pathlib import Path
import selectors
import socket
import subprocess
import tempfile
import threading
import urllib.request


class Fixture(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    fixture_name = "omabridge-http"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() == "websocket":
            accept = base64.b64encode(hashlib.sha1((self.headers["Sec-WebSocket-Key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            compressed = "permessage-deflate" in self.headers.get("Sec-WebSocket-Extensions", "")
            if compressed:
                self.send_header("Sec-WebSocket-Extensions", "permessage-deflate; server_no_context_takeover; client_no_context_takeover")
            self.end_headers()
            while True:
                header = self.rfile.read(2)
                if len(header) != 2:
                    return
                size = header[1] & 127
                if size > 125:
                    return
                mask = self.rfile.read(4)
                data = self.rfile.read(size)
                if len(mask) != 4 or len(data) != size:
                    return
                clear = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
                if compressed and header[0] & 0x40:
                    decoded = zlib.decompressobj(wbits=-15).decompress(clear + b"\x00\x00\xff\xff", 65536)
                    encoder = zlib.compressobj(wbits=-15)
                    clear = (encoder.compress(decoded) + encoder.flush(zlib.Z_SYNC_FLUSH))[:-4]
                    self.wfile.write(bytes([0xc1, len(clear)]) + clear)
                else:
                    self.wfile.write(bytes([0x81, size]) + clear)
                self.wfile.flush()
        else:
            body = json.dumps({"fixture": self.fixture_name, "ok": True}).encode()
            compressed = self.path == "/compressed" and "gzip" in self.headers.get("Accept-Encoding", "")
            if compressed:
                body = gzip.compress(body)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if compressed:
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Vary", "Accept-Encoding")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def first_json(process, limit=15):
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        assert selector.select(limit), "process did not report readiness"
        line = process.stdout.readline()
        assert line, "process exited before readiness"
        return json.loads(line)
    finally:
        selector.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/debug/omabridge")
    parser.add_argument("--compress-t3", action="store_true")
    args = parser.parse_args()
    transport = ["--compress-t3"] if args.compress_t3 else []
    binary = Path(args.binary).resolve()
    assert binary.is_file(), "OmaBridge CLI executable is missing"
    checks = []
    children = []
    fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    fixture.daemon_threads = True
    thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    thread.start()
    replacement = None
    with tempfile.TemporaryDirectory(prefix="omabridge-cli-") as temp:
        root = Path(temp)
        def call(state, *parts, success=True):
            result = subprocess.run([str(binary), *transport, "--state-dir", str(root / state), "--name", state, *parts], capture_output=True, text=True, timeout=15, cwd=root)
            assert (result.returncode == 0) == success, f"unexpected exit for {parts[0]}: {result.returncode}: {result.stderr[:300]}"
            return json.loads(result.stdout) if result.returncode == 0 else {}
        def start(state, *parts):
            error = (root / f"{state}-{len(children)}.stderr").open("wb")
            proc = subprocess.Popen([str(binary), *transport, "--state-dir", str(root / state), "--name", state, *parts], stdout=subprocess.PIPE, stderr=error, text=True, start_new_session=True)
            children.append((proc, error))
            return proc, first_json(proc)
        def stop(proc):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
        try:
            owner = call("owner", "init")["id"]
            guest = call("phone", "init")["id"]
            call("stranger", "init")
            assert call("owner", "init")["id"] == owner
            checks.append("persistent_identity")
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(("127.0.0.1", 0))
            bind = f"127.0.0.1:{udp.getsockname()[1]}"
            udp.close()
            runtime = root / "server-runtime.json"
            runtime.write_text(json.dumps({"port": fixture.server_port}))
            serve = ("--bind", bind, "serve", "--service", f"t3=127.0.0.1:{fixture.server_port}", "--t3-runtime", str(runtime))
            host, ready = start("owner", *serve)
            assert ready["id"] == owner
            invite = root / "pair.invite.json"
            call("owner", "invite", "--service", "t3", "--output", str(invite), "--ttl", "60")
            # A CLI filename relative to its working directory must be atomic too.
            relative = "relative.invite.json"
            call("owner", "invite", "--service", "t3", "--output", relative, "--ttl", "60")
            assert (root / relative).stat().st_mode & 0o077 == 0
            visual = root / "visual.invite.json"
            qr = subprocess.run([str(binary), *transport, "--state-dir", str(root / "owner"), "invite", "--service", "t3", "--output", str(visual), "--qr"], cwd=root, capture_output=True, text=True, timeout=15)
            assert qr.returncode == 0 and any(mark in qr.stdout for mark in ("█", "▀", "▄"))
            assert visual.stat().st_mode & 0o077 == 0
            checks.append("QR_rendered_in_private_terminal")
            assert invite.stat().st_mode & 0o077 == 0
            checks.append("private_invitation_file")
            assert call("phone", "pair", "--invite-file", str(invite))["status"] == "pending"
            checks.append("manual_approval_required")
            pending = call("owner", "pending")["pending"]
            assert any(item["id"] == guest for item in pending)
            call("owner", "approve", guest)
            assert call("phone", "pair", "--invite-file", str(invite))["status"] == "approved"
            call("stranger", "pair", "--invite-file", str(invite), success=False)
            checks.append("invitation_replay_denied")
            peers = call("phone", "peers")["peers"]
            assert any(item["id"] == owner and "t3" in item["remote_services"] and not item["services"] for item in peers)
            checks.append("no_implicit_reverse_grant")
            forward, local = start("phone", "forward", "--peer", owner, "--service", "t3", "--listen", "127.0.0.1:0")
            address = local["listen"]
            with urllib.request.urlopen(f"http://{address}/health", timeout=8) as response:
                assert json.load(response) == {"fixture": "omabridge-http", "ok": True}
            checks.append("http_over_encrypted_bridge")
            compressed_request = urllib.request.Request(f"http://{address}/compressed", headers={"Accept-Encoding": "gzip"})
            with urllib.request.urlopen(compressed_request, timeout=8) as response:
                assert response.headers["Content-Encoding"] == "gzip"
                assert json.loads(gzip.decompress(response.read())) == {"fixture": "omabridge-http", "ok": True}
            checks.append("http_gzip_preserved_without_recompression")
            with socket.create_connection(("127.0.0.1", int(address.rsplit(":", 1)[1])), timeout=8) as compressed_ws:
                compressed_ws.sendall(b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover\r\n\r\n")
                headers = b""
                while not headers.endswith(b"\r\n\r\n"):
                    part = compressed_ws.recv(1)
                    assert part, "compressed WebSocket upgrade truncated"
                    headers += part
                assert b"permessage-deflate" in headers
                message = b"streaming text chunk " * 128
                compressor = zlib.compressobj(wbits=-15)
                compressed = (compressor.compress(message) + compressor.flush(zlib.Z_SYNC_FLUSH))[:-4]
                assert len(compressed) < 126 and len(compressed) < len(message)
                mask = b"mask"
                compressed_ws.sendall(bytes([0xc1, 0x80 | len(compressed)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(compressed)))
                frame = b""
                while len(frame) < 2:
                    chunk = compressed_ws.recv(2 - len(frame))
                    assert chunk
                    frame += chunk
                assert frame[0] == 0xc1
                payload = b""
                while len(payload) < frame[1]:
                    chunk = compressed_ws.recv(frame[1] - len(payload))
                    assert chunk
                    payload += chunk
                assert zlib.decompressobj(wbits=-15).decompress(payload + b"\x00\x00\xff\xff") == message
            checks.append("websocket_deflate_preserved_without_client_changes")

            ws = socket.create_connection(("127.0.0.1", int(address.rsplit(":", 1)[1])), timeout=8)
            ws.sendall(b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
            headers = b""
            while not headers.endswith(b"\r\n\r\n"):
                byte = ws.recv(1)
                assert byte, "WebSocket upgrade truncated"
                headers += byte
            assert b"101" in headers.split(b"\r\n")[0]
            assert b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" in headers
            message, mask = b"real websocket roundtrip", b"mask"
            ws.sendall(bytes([0x81, 0x80 | len(message)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(message)))
            frame = ws.recv(2)
            assert frame == bytes([0x81, len(message)])
            assert ws.recv(len(message)) == message
            checks.append("websocket_upgrade_and_bidirectional_frames")
            class MovedFixture(Fixture):
                fixture_name = "omabridge-http-moved"
            replacement = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MovedFixture)
            replacement.daemon_threads = True
            threading.Thread(target=replacement.serve_forever, daemon=True).start()
            runtime.write_text(json.dumps({"port": replacement.server_port}))
            with urllib.request.urlopen(f"http://{address}/health", timeout=3) as response:
                assert json.load(response)["fixture"] == "omabridge-http-moved"
            # The original WebSocket is still usable; no reconnect or replay occurred.
            ws.sendall(bytes([0x81, 0x80 | len(message)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(message)))
            assert ws.recv(2) == bytes([0x81, len(message)])
            assert ws.recv(len(message)) == message
            checks.append("runtime_port_change_without_restarting_bridge_or_websocket")
            runtime.unlink()
            try:
                urllib.request.urlopen(f"http://{address}/health", timeout=3).close()
            except (OSError, TimeoutError):
                pass
            else:
                raise AssertionError("missing runtime fell back to the old live port")
            runtime.write_text(json.dumps({"port": replacement.server_port}))
            with urllib.request.urlopen(f"http://{address}/health", timeout=3) as response:
                assert json.load(response)["fixture"] == "omabridge-http-moved"
            checks.append("runtime_return_recovers_without_user_action")
            call("owner", "revoke", guest)
            ws.settimeout(3)
            try:
                assert ws.recv(1) == b"", "revoked WebSocket stayed open"
            except ConnectionResetError:
                pass
            finally:
                ws.close()
            checks.append("active_stream_revocation")
            call("phone", "pair", "--invite-file", str(invite), success=False)
            checks.append("revoked_invitation_cannot_readmit")
            stop(host)
            host, again = start("owner", *serve)
            assert again["id"] == owner
            checks.append("server_restart_keeps_identity")
            try:
                urllib.request.urlopen(f"http://{address}/health", timeout=3).close()
            except (OSError, TimeoutError):
                checks.append("revocation_persists_after_restart")
            else:
                raise AssertionError("revoked device reopened the service")
        finally:
            for proc, error in reversed(children):
                stop(proc)
                error.close()
            fixture.shutdown()
            fixture.server_close()
            if replacement is not None:
                replacement.shutdown()
                replacement.server_close()
    print(json.dumps({"status": "pass", "upstream": "HTTP/WebSocket test fixture, not T3", "checks": checks}))


if __name__ == "__main__":
    main()
