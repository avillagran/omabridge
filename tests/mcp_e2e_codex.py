#!/usr/bin/env python3
"""End-to-end: ChatGPT-equivalent client → OmaBridge MCP → T3 Code → Codex → T3 → MCP → client.

Runs against an already linked gateway state (`omabridge mcp link-t3`) and an EXISTING
T3 session that uses Codex. It grants only that project+session, serves on loopback,
signs in with the same OAuth flow ChatGPT uses, reads history, sends one message with a
client_request_id, waits for Codex and fetches the result from the same T3 thread.

Usage: python3 -I tests/mcp_e2e_codex.py <omabridge-binary> <gateway-state-dir> <project-id> <session-id> [message]
"""
import json
import os
import socket
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(__file__))
from chatgpt_client import ChatGPTLikeClient  # noqa: E402


def main():
    binary, state, project, session = sys.argv[1:5]
    message = sys.argv[5] if len(sys.argv) > 5 else (
        "Prueba OmaBridge desde ChatGPT. No ejecutes comandos ni edites archivos. "
        "Responde solo con el texto: E2E-CHATGPT-OK")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = subprocess.Popen([binary, "--state-dir", state, "mcp", "serve", "--listen", f"127.0.0.1:{port}"],
                              stdout=subprocess.PIPE, text=True)
    try:
        assert json.loads(server.stdout.readline())["event"] == "mcp_listening"
        grant = subprocess.run([binary, "--state-dir", state, "mcp", "grant", "--project", project, "--session", session,
                                "--access", "operate", "--label", "e2e-chatgpt", "--ttl-days", "1"],
                               capture_output=True, text=True, check=True)
        client = ChatGPTLikeClient(f"http://127.0.0.1:{port}/mcp")
        client.connect(json.loads(grant.stdout)["link_code"])
        sessions = client.ok("t3_list_sessions")["sessions"]
        target = next(s for s in sessions if s["session_id"] == session)
        print("session:", json.dumps({k: target[k] for k in ("session_id", "title", "agent", "model", "status")}, ensure_ascii=False))
        history = client.ok("t3_get_messages", session_id=session, limit=100)
        print("history items before:", len(history["items"]))
        request_id = "e2e-" + uuid.uuid4().hex
        sent = client.ok("t3_send_message", session_id=session, message=message, client_request_id=request_id)
        print("sent:", json.dumps(sent))
        replay = client.ok("t3_send_message", session_id=session, message=message, client_request_id=request_id)
        assert replay["run_id"] == sent["run_id"] and replay["duplicate"]
        deadline = time.time() + 600
        while time.time() < deadline:
            # Short waits: a ChatGPT turn need not hold a connection open for minutes.
            waited = client.ok("t3_wait_run", session_id=session, run_id=sent["run_id"], timeout_seconds=20)
            print("status:", waited["run"]["status"])
            if waited["run"]["terminal"] or waited["run"]["status"] == "waiting_for_approval":
                break
        result = client.ok("t3_get_run_result", session_id=session, run_id=sent["run_id"])
        print("result:", json.dumps({"status": result["run"]["status"], "final_text": result["final_text"]}, ensure_ascii=False))
        events = client.ok("t3_get_events", session_id=session, run_id=sent["run_id"])
        print("events:", [e["kind"] for e in events["events"]])
        assert result["run"]["status"] == "completed" and result["final_text"], result
        print(json.dumps({"e2e": "passed", "session_id": session, "run_id": sent["run_id"]}))
    finally:
        server.terminate()
        server.wait()


if __name__ == "__main__":
    main()
