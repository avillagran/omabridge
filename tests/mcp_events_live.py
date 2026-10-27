#!/usr/bin/env python3
"""Live MCP Events test against a real, isolated T3 Code server (official binary).

Never touches ~/.t3: T3 runs with its own --base-dir, HOME and port. Codex is not
logged in there, so runs end in T3's real `failed` state, which is exactly a
`t3.run.finished` event with status `failed`. A local webhook receiver plays
ChatGPT: it echoes the verification challenge and checks every Standard Webhooks
signature. The gateway runs with --insecure-loopback-callbacks for that receiver.

Usage: python3 -I tests/mcp_events_live.py <omabridge-binary> <t3-binary>
"""
import base64
import hashlib
import hmac
import http.server as webserver
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(__file__))
from chatgpt_client import ChatGPTLikeClient, http  # noqa: E402
from mcp_t3_live import T3, DirectT3, free_port, omabridge  # noqa: E402

SECRET = "whsec_" + base64.b64encode(secrets.token_bytes(32)).decode()


def valid_signature(headers, raw):
    key = base64.b64decode(SECRET[len("whsec_"):])
    signed = f"{headers['webhook-id']}.{headers['webhook-timestamp']}.".encode() + raw
    expected = "v1," + base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
    return any(hmac.compare_digest(expected, s) for s in headers["webhook-signature"].split(" "))


class Receiver(webserver.BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        raw = self.rfile.read(int(self.headers["content-length"]))
        body = json.loads(raw)
        headers = {k.lower(): v for k, v in self.headers.items()}
        Receiver.seen.append({"headers": headers, "body": body, "signed": valid_signature(headers, raw)})
        reply = json.dumps({"challenge": body["challenge"]} if body.get("type") == "verification" else {}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *args):
        pass


def modern(url, token, method, params):
    params = dict(params, _meta={"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                 "io.modelcontextprotocol/clientInfo": {"name": "dots-like", "version": "1"}})
    headers = {"authorization": "Bearer " + token, "accept": "application/json, text/event-stream",
               "mcp-protocol-version": "2026-07-28", "mcp-method": method}
    if method == "tools/call":
        headers["mcp-name"] = params["name"]
    status, _, body = http("POST", url, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                           headers=headers)
    return status, json.loads(body)


def main():
    gateway_bin, t3_bin = sys.argv[1], sys.argv[2]
    root = tempfile.mkdtemp(prefix="omabridge-events-live-")
    os.chmod(root, 0o700)
    for sub in ("rh", "ws/essential"):
        os.makedirs(f"{root}/{sub}")
    subprocess.run(["git", "init", "-q", f"{root}/ws/essential"], check=True)
    t3 = T3(t3_bin, root)
    gateway = None
    receiver = webserver.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    threading.Thread(target=receiver.serve_forever, daemon=True).start()
    hook = f"http://127.0.0.1:{receiver.server_address[1]}/dots/callback"
    results = []

    def check(name, condition, detail=""):
        results.append((name, bool(condition)))
        print(("PASS " if condition else "FAIL ") + name + (f" — {detail}" if detail and not condition else ""))

    def events(name):
        return [r for r in Receiver.seen if r["body"].get("name") == name]

    def wait(predicate, seconds=60):
        for _ in range(seconds * 4):
            if predicate():
                return True
            time.sleep(0.25)
        return False

    try:
        t3.start()
        fixture_state = f"{root}/fixture"
        omabridge(gateway_bin, fixture_state, "link-t3", "--t3-url", t3.url, "--access", "full-access",
                  stdin=t3.pairing_code())
        direct = DirectT3(t3.url, json.load(open(f"{fixture_state}/mcp/upstream.json"))["token"])
        project = direct.call("t3_project_create", title="Example Project (fixture)",
                              workspaceRoot=f"{root}/ws/essential")
        pid = project.get("project", project).get("id") or project.get("projectId")
        launched = direct.call("t3_thread_launch", projectId=pid, title="Events fixture",
                               modelSelection={"instanceId": "codex", "model": "gpt-5.5-codex"},
                               runtimeMode="approval-required", message="First message from the UI")
        session = launched.get("threadId") or launched.get("thread", {}).get("threadId")
        check("fixture session created in real T3", session, json.dumps(launched)[:300])

        state = f"{root}/gateway"
        omabridge(gateway_bin, state, "link-t3", "--t3-url", t3.url, stdin=t3.pairing_code())
        port = free_port()
        gateway = subprocess.Popen([gateway_bin, "--state-dir", state, "mcp", "serve", "--listen", f"127.0.0.1:{port}",
                                    "--events-poll-seconds", "1", "--events-host", "example-host",
                                    "--insecure-loopback-callbacks"], stdout=subprocess.PIPE, text=True)
        assert json.loads(gateway.stdout.readline())["event"] == "mcp_listening"
        code = omabridge(gateway_bin, state, "grant", "--project", pid, "--access", "operate")["link_code"]
        url = f"http://127.0.0.1:{port}/mcp"
        client = ChatGPTLikeClient(url)
        client.connect(code)
        token = client.token

        status, discover = modern(url, token, "server/discover", {})
        check("server/discover advertises events on 2026-07-28",
              status == 200 and discover["result"]["capabilities"].get("events") == {}
              and "2026-07-28" in discover["result"]["supportedVersions"], discover)

        settled = wait(lambda: client.ok("t3_get_session_status", session_id=session)["status"]
                       not in ("queued", "running"))
        check("UI-started run settles before subscribing", settled)

        delivery = {"mode": "webhook", "url": hook, "secret": SECRET}
        status, subscribed = modern(url, token, "events/subscribe",
                                    {"name": "t3.run.finished", "arguments": {"session_id": session},
                                     "delivery": delivery, "cursor": None})
        sub_id = subscribed.get("result", {}).get("id")
        check("events/subscribe accepted with a sub_ id", status == 200 and str(sub_id).startswith("sub_"), subscribed)
        verification = [r for r in Receiver.seen if r["body"].get("type") == "verification"]
        check("callback verified with a signed challenge", len(verification) == 1 and verification[0]["signed"])
        time.sleep(3)
        check("runs finished before subscribing are not reported", not events("t3.run.finished"))

        sent = client.ok("t3_send_message", session_id=session, message="From a dot: run the checks",
                         client_request_id="live-events-0001")
        arrived = wait(lambda: any(e["body"]["data"]["run_id"] == sent["run_id"] for e in events("t3.run.finished")))
        check("real T3 run end is delivered as t3.run.finished", arrived, Receiver.seen[-3:])
        if arrived:
            event = next(e for e in events("t3.run.finished") if e["body"]["data"]["run_id"] == sent["run_id"])
            data = event["body"]["data"]
            check("delivery is signed with the subscription secret", event["signed"])
            check("webhook-id equals eventId and names the subscription",
                  event["headers"]["webhook-id"] == event["body"]["eventId"]
                  and event["headers"]["x-mcp-subscription-id"] == sub_id)
            check("payload names host, project, session, outcome and where to look",
                  data["host"] == "example-host" and data["project_id"] == pid and data["session_id"] == session
                  and data["status"] in ("failed", "completed", "cancelled")
                  and data["detail"]["tool"] == "t3_get_run_result"
                  and data["started_by_this_connection"] is True, data)
        time.sleep(4)
        check("each run end is delivered once",
              len([e for e in events("t3.run.finished") if e["body"]["data"]["run_id"] == sent["run_id"]]) == 1)

        status, _ = modern(url, token, "events/unsubscribe",
                           {"name": "t3.run.finished", "arguments": {"session_id": session},
                            "delivery": {"mode": "webhook", "url": hook}})
        before = len(events("t3.run.finished"))
        second = client.ok("t3_send_message", session_id=session, message="From a dot: once more",
                           client_request_id="live-events-0002")
        client.ok("t3_wait_run", session_id=session, run_id=second["run_id"], timeout_seconds=30)
        time.sleep(4)
        check("unsubscribe stops delivery", status == 200 and len(events("t3.run.finished")) == before)
        audit = open(f"{state}/mcp/audit.jsonl").read()
        check("audit records deliveries without the secret or message text",
              '"outcome":"delivered"' in audit and SECRET[6:] not in audit and "run the checks" not in audit)
    finally:
        if gateway:
            gateway.terminate()
        if t3.proc:
            t3.stop()
        receiver.shutdown()
        if all(ok for _, ok in results):
            shutil.rmtree(root, ignore_errors=True)
        else:
            print("kept", root)
    print(json.dumps({"passed": sum(ok for _, ok in results), "total": len(results)}))
    sys.exit(0 if results and all(ok for _, ok in results) else 1)


if __name__ == "__main__":
    main()
