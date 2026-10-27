#!/usr/bin/env python3
"""Live gateway test against a real, isolated T3 Code server (official binary).

Never touches ~/.t3: T3 runs with its own --base-dir, HOME and port. Codex is not
logged in there, so runs reach T3's real `failed` state; that still exercises T3's
real orchestration, idempotent command receipts, persistence and MCP OAuth.

Usage: python3 -I tests/mcp_t3_live.py <omabridge-binary> <t3-binary>
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(__file__))
from chatgpt_client import ChatGPTLikeClient, http  # noqa: E402


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class T3:
    def __init__(self, binary, root):
        self.binary, self.root, self.port = binary, root, free_port()
        self.env = {"HOME": f"{root}/rh", "PATH": os.environ["PATH"], "LANG": "C.UTF-8",
                    "XDG_CONFIG_HOME": f"{root}/rh/c", "XDG_CACHE_HOME": f"{root}/rh/k", "XDG_DATA_HOME": f"{root}/rh/d"}
        self.proc = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        log = open(f"{self.root}/t3.log", "a")
        self.proc = subprocess.Popen([self.binary, "serve", "--host", "127.0.0.1", "--port", str(self.port),
                                      "--base-dir", f"{self.root}/home", "--no-browser"],
                                     env=self.env, cwd=f"{self.root}/ws", stdout=log, stderr=log)
        for _ in range(90):
            try:
                if http("GET", self.url + "/.well-known/oauth-authorization-server", timeout=2)[0] == 200:
                    return
            except OSError:
                pass
            time.sleep(1)
        raise RuntimeError("T3 did not start")

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=30)

    def pairing_code(self):
        out = subprocess.run([self.binary, "auth", "pairing", "create", "--base-dir", f"{self.root}/home",
                              "--json", "--ttl", "10m"], env=self.env, capture_output=True, text=True, check=True)
        return json.loads(out.stdout)["credential"]


def omabridge(binary, state, *args, stdin=None):
    out = subprocess.run([binary, "--state-dir", state, "mcp", *args], input=stdin,
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout) if out.stdout.strip().startswith("{") else out.stdout


class DirectT3:
    """Fixture-only raw client for T3's MCP with a separate full-access credential."""

    def __init__(self, url, token):
        self.url, self.headers, self.n = url + "/mcp", {"authorization": "Bearer " + token,
                                                        "accept": "application/json, text/event-stream"}, 0
        _, headers, _ = http("POST", self.url, {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "fixture", "version": "1"}}},
            headers=self.headers)
        self.headers.update({"mcp-session-id": {k.lower(): v for k, v in headers.items()}["mcp-session-id"],
                             "mcp-protocol-version": "2025-06-18"})
        http("POST", self.url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=self.headers)

    def call(self, name, **arguments):
        self.n += 1
        _, _, body = http("POST", self.url, {"jsonrpc": "2.0", "id": self.n, "method": "tools/call",
                                             "params": {"name": name, "arguments": arguments}}, headers=self.headers)
        result = json.loads(body)["result"]
        value = result.get("structuredContent") or json.loads(result["content"][0]["text"])
        assert not result.get("isError"), value
        return value


def main():
    gateway_bin, t3_bin = sys.argv[1], sys.argv[2]
    root = tempfile.mkdtemp(prefix="omabridge-live-")
    os.chmod(root, 0o700)
    for sub in ("rh", "ws/essential", "ws/other"):
        os.makedirs(f"{root}/{sub}")
    subprocess.run(["git", "init", "-q", f"{root}/ws/essential"], check=True)
    t3 = T3(t3_bin, root)
    gateway = None
    results = []

    def check(name, condition, detail=""):
        results.append((name, bool(condition)))
        print(("PASS " if condition else "FAIL ") + name + (f" — {detail}" if detail and not condition else ""))

    try:
        t3.start()
        # Fixture: projects and a session created as the T3 UI would (full-access, setup only).
        fixture_state = f"{root}/fixture"
        omabridge(gateway_bin, fixture_state, "link-t3", "--t3-url", t3.url, "--access", "full-access",
                  stdin=t3.pairing_code())
        direct = DirectT3(t3.url, json.load(open(f"{fixture_state}/mcp/upstream.json"))["token"])
        essential = direct.call("t3_project_create", title="Example Project (fixture)",
                                workspaceRoot=f"{root}/ws/essential")
        other = direct.call("t3_project_create", title="Other", workspaceRoot=f"{root}/ws/other")
        pid = essential.get("project", essential).get("id") or essential.get("projectId")
        other_pid = other.get("project", other).get("id") or other.get("projectId")
        launched = direct.call("t3_thread_launch", projectId=pid, title="Evaluación de cargos 3 factores",
                               modelSelection={"instanceId": "codex", "model": "gpt-5.5-codex"},
                               runtimeMode="approval-required", message="Mensaje inicial desde la UI")
        session = launched.get("threadId") or launched.get("thread", {}).get("threadId")
        check("fixture session created in real T3", session, json.dumps(launched)[:300])

        # The gateway under test: approval-required ceiling.
        state = f"{root}/gateway"
        linked = omabridge(gateway_bin, state, "link-t3", "--t3-url", t3.url, stdin=t3.pairing_code())
        check("gateway linked through T3 MCP OAuth", linked["access"] == "approval-required")
        port = free_port()
        gateway = subprocess.Popen([gateway_bin, "--state-dir", state, "mcp", "serve", "--listen", f"127.0.0.1:{port}"],
                                   stdout=subprocess.PIPE, text=True)
        assert json.loads(gateway.stdout.readline())["event"] == "mcp_listening"
        code = omabridge(gateway_bin, state, "grant", "--project", pid, "--access", "operate")["link_code"]
        client = ChatGPTLikeClient(f"http://127.0.0.1:{port}/mcp")
        init = client.connect(code)
        check("ChatGPT-style discovery + OAuth + initialize", init["serverInfo"]["name"] == "omabridge-t3")

        projects = client.ok("t3_list_projects")["projects"]
        check("lists only granted real T3 project", [p["project_id"] for p in projects] == [pid], projects)
        sessions = client.ok("t3_list_sessions")["sessions"]
        check("lists the existing T3 session with original ID", any(s["session_id"] == session for s in sessions))
        failed, denied = client.call("t3_list_sessions", project_id=other_pid)
        check("rejects ungranted project", failed and denied["error"]["code"] == "forbidden")
        history = client.ok("t3_get_messages", session_id=session)
        check("reads canonical T3 history", any(i["text"] == "Mensaje inicial desde la UI" for i in history["items"]))

        for _ in range(60):  # Let the UI-started run settle (fails: Codex not logged in here).
            if client.ok("t3_get_session_status", session_id=session)["status"] not in ("queued", "running"):
                break
            time.sleep(1)
        sent = client.ok("t3_send_message", session_id=session, message="Desde ChatGPT: revisa el resumen de cargos",
                         client_request_id="live-chatgpt-0001")
        check("send_message returns run_id and status", sent["run_id"] and sent["status"] in
              ("queued", "running", "failed", "completed"), sent)
        again = client.ok("t3_send_message", session_id=session, message="Desde ChatGPT: revisa el resumen de cargos",
                          client_request_id="live-chatgpt-0001")
        check("duplicate client_request_id returns same run", again["run_id"] == sent["run_id"] and again["duplicate"])
        waited = client.ok("t3_wait_run", session_id=session, run_id=sent["run_id"], timeout_seconds=30)
        check("run reaches a terminal T3 state", waited["run"]["terminal"], waited)
        result = client.ok("t3_get_run_result", session_id=session, run_id=sent["run_id"])
        check("run result has normalized status", result["run"]["status"] in ("failed", "completed", "cancelled"), result)
        raw = direct.call("t3_thread_read", threadId=session, view="messages", limit=100)
        same = [i for i in raw["items"] if i["text"] == "Desde ChatGPT: revisa el resumen de cargos"]
        check("message is in the same canonical T3 thread exactly once", len(same) == 1, len(same))
        events = client.ok("t3_get_events", session_id=session)
        cursor = events["next_cursor"]
        check("event feed returns finished events", len(events["events"]) > 0)

        # T3 restart: history persists; the gateway re-initializes its MCP session.
        t3.stop()
        failed, unavailable = client.call("t3_get_session", session_id=session)
        check("T3 down is reported as tool error, not crash", failed and unavailable["error"]["code"] == "upstream_unavailable")
        t3.start()
        after = client.ok("t3_get_messages", session_id=session, limit=100)
        check("history survives T3 restart", any(i["text"] == "Desde ChatGPT: revisa el resumen de cargos"
                                                 for i in after["items"]))
        resumed = client.ok("t3_get_events", session_id=session, cursor=cursor)
        check("event cursor resumes without duplicates", all(e["position"] > cursor for e in resumed["events"]))

        # Gateway restart: token and ledger persist.
        gateway.terminate(); gateway.wait()
        gateway = subprocess.Popen([gateway_bin, "--state-dir", state, "mcp", "serve", "--listen", f"127.0.0.1:{port}"],
                                   stdout=subprocess.PIPE, text=True)
        gateway.stdout.readline()
        replay = client.ok("t3_send_message", session_id=session, message="Desde ChatGPT: revisa el resumen de cargos",
                           client_request_id="live-chatgpt-0001")
        check("dedupe survives gateway restart", replay["run_id"] == sent["run_id"])

        grant = omabridge(gateway_bin, state, "grants")["grants"][0]["id"]
        omabridge(gateway_bin, state, "revoke", grant)
        try:
            client.rpc("tools/list")
            revoked = False
        except PermissionError as error:
            revoked = error.args[0] == 401
        check("revoked grant is rejected immediately", revoked)
        audit = open(f"{state}/mcp/audit.jsonl").read()
        check("audit has actions but no message text or tokens",
              "t3_send_message" in audit and "revisa el resumen" not in audit and client.token not in audit)
    finally:
        if gateway:
            gateway.terminate()
        if t3.proc:
            t3.stop()
        if all(ok for _, ok in results):
            shutil.rmtree(root, ignore_errors=True)
        else:
            print("kept", root)
    print(json.dumps({"passed": sum(ok for _, ok in results), "total": len(results)}))
    sys.exit(0 if results and all(ok for _, ok in results) else 1)


if __name__ == "__main__":
    main()
