#!/usr/bin/env python3
"""Bot mailbox end to end: ChatGPT-style client -> OmaBridge gateway -> a real, isolated o3-server.

Never touches ~/.t3 or any installed service: o3-server runs with its own T3CODE_HOME, HOME and
port, and the gateway with its own state directory. The thread that "asks" is created through
o3-server's own MCP (its run fails for lack of a provider login, which does not matter here); the
O3 agent side is played by an operator MCP credential calling t3_bot_inbox_post.

Usage: python3 -I tests/mcp_inbox_o3_live.py <omabridge-binary> <o3-server-binary>
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(__file__))
from chatgpt_client import ChatGPTLikeClient, http  # noqa: E402
from mcp_t3_live import DirectT3, free_port, omabridge  # noqa: E402


def main():
    gateway_bin, o3_bin = sys.argv[1], sys.argv[2]
    root = tempfile.mkdtemp(prefix="omabridge-inbox-live-")
    os.chmod(root, 0o700)
    for sub in ("rh", "ws/project", "home"):
        os.makedirs(f"{root}/{sub}")
    subprocess.run(["git", "init", "-q", f"{root}/ws/project"], check=True)
    env = {"HOME": f"{root}/rh", "PATH": os.environ["PATH"], "LANG": "C.UTF-8",
           "XDG_CONFIG_HOME": f"{root}/rh/c", "XDG_CACHE_HOME": f"{root}/rh/k", "XDG_DATA_HOME": f"{root}/rh/d",
           "T3CODE_HOME": f"{root}/home"}
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    log = open(f"{root}/o3.log", "a")
    server = gateway = None
    results = []

    def check(name, condition, detail=""):
        results.append((name, bool(condition)))
        print(("PASS " if condition else "FAIL ") + name + (f" — {detail}" if detail and not condition else ""))

    def o3(*args):
        out = subprocess.run([o3_bin, *args], env=env, capture_output=True, text=True, timeout=60)
        assert out.returncode == 0, out.stderr
        return out.stdout.strip()

    try:
        server = subprocess.Popen([o3_bin, "serve", "--host", "127.0.0.1", "--port", str(port)],
                                  env=env, cwd=f"{root}/ws", stdout=log, stderr=log)
        environment = None
        for _ in range(90):
            try:
                status, _, body = http("GET", base + "/.well-known/t3/environment", timeout=2)
                if status == 200:
                    environment = json.loads(body)["environmentId"]
                    break
            except OSError:
                pass
            time.sleep(1)
        assert environment, "o3-server did not start"

        operator = DirectT3(base, o3("auth", "mcp", "issue", "--access", "full-access", "--token-only"))
        project = operator.call("t3_project_create", title="Inbox project", workspaceRoot=f"{root}/ws/project")
        pid = project.get("project", project).get("id") or project.get("projectId")
        launched = operator.call("t3_thread_launch", projectId=pid, title="Requester thread",
                                 modelSelection={"instanceId": "codex", "model": "gpt-5.5-codex"},
                                 runtimeMode="full-access", message="Context for the bot request")
        thread = launched.get("threadId") or launched.get("thread", {}).get("threadId")
        check("fixture thread exists in o3-server", thread, json.dumps(launched)[:300])

        # The gateway reaches o3-server with an operator credential, as in production.
        state = f"{root}/gateway"
        for directory in (state, f"{state}/mcp", f"{state}/mcp/environment-{environment}", f"{state}/mcp/environment-{environment}/mcp"):
            os.makedirs(directory, exist_ok=True)
            os.chmod(directory, 0o700)
        credential = o3("auth", "mcp", "issue", "--access", "full-access", "--ttl", "30d", "--token-only")
        path = f"{state}/mcp/environment-{environment}/mcp/upstream.json"
        with open(path, "w", opener=lambda p, f: os.open(p, f, 0o600)) as handle:
            json.dump({"url": base, "token": credential, "access": "full-access",
                       "expires": int(time.time()) + 86400 * 30}, handle)
        gport = free_port()
        gateway = subprocess.Popen([gateway_bin, "--state-dir", state, "mcp", "serve", "--listen", f"127.0.0.1:{gport}"],
                                   stdout=subprocess.PIPE, text=True)
        assert json.loads(gateway.stdout.readline())["event"] == "mcp_listening"

        # A grant without a mailbox sees no inbox tools; one bound to "dot" does.
        plain = omabridge(gateway_bin, state, "grant", "--environment", environment, "--all-projects",
                          "--access", "operate", "--label", "plain")["link_code"]
        unbound = ChatGPTLikeClient(f"http://127.0.0.1:{gport}/mcp")
        unbound.connect(plain)
        names = [t["name"] for t in unbound.rpc("tools/list")["tools"]]
        check("no inbox tools without a mailbox", not any(n.startswith("t3_inbox_") for n in names), names)

        code = omabridge(gateway_bin, state, "grant", "--environment", environment, "--all-projects",
                         "--access", "operate", "--label", "dot", "--bot-id", "dot")["link_code"]
        dot = ChatGPTLikeClient(f"http://127.0.0.1:{gport}/mcp")
        dot.connect(code)
        names = [t["name"] for t in dot.rpc("tools/list")["tools"]]
        check("inbox tools offered to the bound grant", all(n in names for n in ("t3_inbox_wait", "t3_inbox_ack", "t3_inbox_reply")), names)
        wait_tool = next(t for t in dot.rpc("tools/list")["tools"] if t["name"] == "t3_inbox_wait")
        check("environment_id is required like every federated tool",
              "environment_id" in wait_tool["inputSchema"]["required"])

        failed, empty = dot.call("t3_inbox_wait", environment_id=environment, timeout_seconds=1)
        check("an empty mailbox times out", not failed and empty["timed_out"] and empty["messages"] == [], empty)
        failed, named = dot.call("t3_inbox_wait", environment_id=environment, bot_id="other", timeout_seconds=0)
        check("a caller cannot name another mailbox", failed and named["error"]["code"] == "invalid_arguments", named)

        # The O3 agent posts while DOT is already waiting: the long poll must wake early.
        woke = {}

        def waiter():
            started = time.time()
            woke["result"] = dot.call("t3_inbox_wait", environment_id=environment, timeout_seconds=30)
            woke["seconds"] = time.time() - started

        thread_wait = threading.Thread(target=waiter)
        thread_wait.start()
        time.sleep(1.5)
        posted = operator.call("t3_bot_inbox_post", botId="dot", threadId=thread,
                               body="What is the invoice number for order 4471?", correlationId="sodexo-1")
        thread_wait.join(timeout=40)
        failed, got = woke["result"]
        message = got["messages"][0] if got["messages"] else {}
        check("the waiting long poll wakes on the post", not failed and message.get("message_id") == posted["messageId"]
              and woke["seconds"] < 15, (got, woke.get("seconds")))
        check("the request carries its session and correlation id",
              message.get("session_id") == thread and message.get("correlation_id") == "sodexo-1"
              and message.get("body", "").startswith("What is the invoice"), message)
        check("posting started no turn in the asking thread",
              not [i for i in operator.call("t3_thread_read", threadId=thread)["items"]
                   if i.get("type") == "user_message" and "invoice" in (i.get("text") or "")])

        # Pending until answered; afterCursor skips what was seen.
        failed, again = dot.call("t3_inbox_wait", environment_id=environment, timeout_seconds=0)
        check("an unanswered request is delivered again", len(again["messages"]) == 1, again)
        failed, seen = dot.call("t3_inbox_wait", environment_id=environment, timeout_seconds=0,
                                after_cursor=got["next_cursor"])
        check("after_cursor skips seen requests", seen["messages"] == [], seen)

        # Reply: reaches the asking thread exactly once, even if retried.
        args = dict(environment_id=environment, message_id=message["message_id"], body="INV-4471",
                    client_request_id="reply-live-0001")
        failed, first = dot.call("t3_inbox_reply", **args)
        check("reply is accepted", not failed and first.get("replied_to") == message["message_id"], first)
        failed, second = dot.call("t3_inbox_reply", **args)
        check("a retried reply is the same message", not failed and second["message_id"] == first["message_id"], second)
        texts = [i["text"] for i in operator.call("t3_thread_read", threadId=thread)["items"]
                 if i.get("type") == "user_message" and "INV-4471" in (i.get("text") or "")]
        check("the reply reached the asking thread once, tagged with the correlation id",
              len(texts) == 1 and "sodexo-1" in texts[0], texts)
        failed, after = dot.call("t3_inbox_wait", environment_id=environment, timeout_seconds=0)
        check("a reply acknowledges the request", after["messages"] == [], after)
        log_rows = operator.call("t3_bot_inbox_read", botId="dot")["messages"]
        check("both directions are recorded for audit",
              [m["direction"] for m in log_rows] == ["to_bot", "from_bot"], log_rows)

        # Acknowledge without answering.
        quiet = operator.call("t3_bot_inbox_post", botId="dot", threadId=thread, body="FYI only")
        failed, acked = dot.call("t3_inbox_ack", environment_id=environment, message_ids=[quiet["messageId"]])
        check("ack without a reply", not failed and acked["acked"] == 1, acked)

        # Revoking the grant ends access at once.
        grants = omabridge(gateway_bin, state, "grants")["grants"]
        dot_grant = next(g for g in grants if g["label"] == "dot")
        omabridge(gateway_bin, state, "revoke", dot_grant["id"])
        try:
            dot.call("t3_inbox_wait", environment_id=environment, timeout_seconds=0)
            check("a revoked grant is refused", False)
        except PermissionError:
            check("a revoked grant is refused", True)
    finally:
        for process in (gateway, server):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
        # Only the fresh fixture directory created above.
        if os.path.basename(root).startswith("omabridge-inbox-live-") and not os.path.islink(root):
            shutil.rmtree(root, ignore_errors=True)
    failed = [name for name, ok in results if not ok]
    print(f"{len(results) - len(failed)}/{len(results)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
