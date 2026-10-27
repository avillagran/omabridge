#!/usr/bin/env python3
"""Isolated negative lifecycle probes; fake T3 contains no real user state."""
import argparse
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time

FAKE = '''#!/usr/bin/env python3
import os,sys,socket,time
from pathlib import Path
base=Path(os.environ['HOME']).parent.parent
with (base/'spawned').open('a') as f:
    f.write(str(os.getpid())+'\\n')
if (base/'mode').read_text().strip()=='hang':
    while True: time.sleep(60)
port=int(sys.argv[sys.argv.index('--port')+1])
listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',port));listener.listen()
while True:
    client,_=listener.accept()
    try:
        client.settimeout(1)
        try: client.recv(2048)
        except OSError: pass
        client.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\nContent-Length: 16\\r\\n\\r\\n{"not_t3": true}')
    except OSError: pass
    finally: client.close()
'''


def wait_for(path, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and path.read_text().strip():
            return path.read_text()
        time.sleep(0.02)
    raise AssertionError("disposable child did not start")


def alive(pid):
    proc = Path(f"/proc/{pid}")
    return proc.exists() and "State:\tZ" not in (proc / "status").read_text()


def terminate_owned(pid, script):
    path = Path(f"/proc/{pid}/cmdline")
    if path.exists() and str(script).encode() in path.read_bytes():
        os.kill(pid, signal.SIGTERM)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/debug/omabridge")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    with tempfile.TemporaryDirectory(prefix="omabridge-lifecycle-") as temp:
        root = Path(temp)
        fake = root / "fake_t3.py"
        fake.write_text(FAKE)
        fake.chmod(0o700)
        (root / "mode").write_text("hang")
        with socket.socket() as available:
            available.bind(("127.0.0.1", 0))
            port = available.getsockname()[1]
        command = [binary, "--state-dir", str(root / "state"), "--name", "host", "t3", "--t3-binary", str(fake), "--t3-home", str(root / "t3"), "--t3-port", str(port)]
        wrapper = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            try:
                pid = int(wait_for(root / "spawned").splitlines()[0])
            except AssertionError as exc:
                status = wrapper.poll()
                detail = wrapper.stderr.read(200).decode(errors="replace") if status is not None and wrapper.stderr is not None else "still running"
                raise AssertionError(f"disposable child did not start: wrapper={status}: {detail}") from exc
            assert alive(pid)
            os.kill(wrapper.pid, signal.SIGTERM)
            wrapper.wait(timeout=4)
            deadline = time.monotonic() + 3
            while alive(pid) and time.monotonic() < deadline:
                time.sleep(0.05)
            assert not alive(pid), "owned headless child survived SIGTERM during startup"
        finally:
            if wrapper.poll() is None:
                wrapper.terminate()
                wrapper.wait(timeout=4)
            if (root / "spawned").exists():
                for line in (root / "spawned").read_text().splitlines():
                    terminate_owned(int(line), fake)

        # A TCP listener that returns non-T3 JSON is not a ready T3 backend.
        (root / "mode").write_text("fake-http")
        other = root / "other"
        # Fake takes its mode from its own root. Set it before the child starts.
        other.mkdir()
        (other / "mode").write_text("fake-http")
        with socket.socket() as available:
            available.bind(("127.0.0.1", 0))
            other_port = available.getsockname()[1]
        probe = subprocess.Popen([binary, "--state-dir", str(other / "state"), "--name", "host", "t3", "--t3-binary", str(fake), "--t3-home", str(other / "t3"), "--t3-port", str(other_port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            output, _ = probe.communicate(timeout=12)
            assert probe.returncode != 0 and b'"event":"listening"' not in output, "non-T3 socket was published as a T3 service"
        finally:
            if probe.poll() is None:
                probe.terminate()
                probe.wait(timeout=4)
            if (other / "spawned").exists():
                for line in (other / "spawned").read_text().splitlines():
                    terminate_owned(int(line), fake)
    print('{"status":"pass","checks":["signal_during_startup_reaps_owned_child","non_t3_listener_not_published"]}')


if __name__ == "__main__":
    main()
