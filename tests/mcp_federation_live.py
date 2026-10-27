#!/usr/bin/env python3
"""Real isolated T3 MCP/OAuth federation; no desktop credentials or provider login.

Usage: python3 -I tests/mcp_federation_live.py <omabridge-binary> <t3-binary>
This checks canonical sends, not a model reply or real Dot communication.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import threading
import shlex
import uuid
import http.server as webserver

sys.path.insert(0, os.path.dirname(__file__))
from chatgpt_client import ChatGPTLikeClient, http
from mcp_t3_live import DirectT3, T3, free_port, omabridge
from mcp_events_live import Receiver, SECRET, modern


class RemoteT3(T3):
    """Optional real second host reached only through an explicit SSH test target."""
    def __init__(self, binary, root):
        super().__init__(binary, root)
        self.host = os.environ["OMABRIDGE_TEST_SSH_HOST"]
        self.remote_binary = os.environ["OMABRIDGE_TEST_REMOTE_T3"]
        self.unit = "omabridge-mcp-test-" + uuid.uuid4().hex
        self.started = False

    def ssh(self, args):
        return subprocess.run(["ssh", self.host, shlex.join(args)], capture_output=True, text=True, check=True)

    def start(self):
        self.remote_port = int(self.ssh(["python3", "-c", "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1])"]).stdout)
        self.ssh(["mkdir", "-p", self.root + "/rh", self.root + "/ws"])
        self.ssh(["chmod", "700", self.root])
        self.ssh(["git", "init", "-q", self.root + "/ws"])
        command = ["systemd-run", "--quiet", "--unit=" + self.unit,
                   "--property=WorkingDirectory=" + self.root + "/ws",
                   "--property=RuntimeMaxSec=300"]
        for key, value in self.env.items():
            if key != "PATH": command.append("--setenv=" + key + "=" + value)
        command += [self.remote_binary, "serve", "--host", "127.0.0.1", "--port", str(self.remote_port),
                    "--base-dir", self.root + "/home", "--no-browser"]
        self.ssh(command)
        self.started = True
        self.proc = subprocess.Popen(["ssh", "-N", "-o", "ExitOnForwardFailure=yes", "-L",
                                      f"127.0.0.1:{self.port}:127.0.0.1:{self.remote_port}", self.host],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(90):
            try:
                if http("GET", self.url + "/.well-known/oauth-authorization-server", timeout=2)[0] == 200: return
            except OSError: pass
            time.sleep(0.5)
        raise RuntimeError("isolated remote T3 did not start")

    def pairing_code(self):
        out = self.ssh(["env"] + [key + "=" + value for key,value in self.env.items() if key != "PATH"] + [self.remote_binary,"auth","pairing","create","--base-dir",self.root+"/home","--json","--ttl","10m"])
        return json.loads(out.stdout)["credential"]

    def stop(self):
        if self.started:
            self.ssh(["systemctl","stop",self.unit])
            self.started = False
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=30)
        # Only the fresh fixture root, never an installed T3 home.
        self.ssh(["rm","-rf","--",self.root])


def main():
    binary, t3_binary = sys.argv[1:3]
    root = tempfile.mkdtemp(prefix="omabridge-federation-live-")
    os.chmod(root, 0o700)
    hosts, gateway = [], None
    state = f"{root}/gateway"
    Receiver.seen = []
    receiver = webserver.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    threading.Thread(target=receiver.serve_forever, daemon=True).start()
    hook = f"http://127.0.0.1:{receiver.server_address[1]}/federation"

    try:
        fixtures = []
        for index in range(2):
            path = f"{root}/host-{index}"
            os.makedirs(f"{path}/ws")
            os.makedirs(f"{path}/rh")
            subprocess.run(["git", "init", "-q", f"{path}/ws"], check=True)
            fixture_class = RemoteT3 if index == 1 and os.environ.get("OMABRIDGE_TEST_SSH_HOST") else T3
            t3 = fixture_class(t3_binary, path)
            hosts.append(t3)
            t3.start()
            descriptor = json.loads(http("GET", t3.url + "/.well-known/t3/environment")[2])
            environment = descriptor["environmentId"]
            fixture_state = f"{path}/fixture"
            omabridge(binary, fixture_state, "link-t3", "--t3-url", t3.url,
                      "--access", "full-access", stdin=t3.pairing_code())
            with open(f"{fixture_state}/mcp/upstream.json") as source:
                direct = DirectT3(t3.url, json.load(source)["token"])
            project = direct.call("t3_project_create", title="Communication fixture",
                                  workspaceRoot=f"{path}/ws")
            project_id = project.get("project", project).get("id") or project.get("projectId")
            launched = direct.call("t3_thread_launch", projectId=project_id,
                                  title="Isolated communication probe",
                                  modelSelection={"instanceId": "codex", "model": "gpt-6.1-sol"},
                                  runtimeMode="approval-required")
            session = launched.get("threadId") or launched.get("thread", {}).get("threadId")
            assert session
            omabridge(binary, state, "link-t3", "--environment", environment,
                      "--t3-url", t3.url, stdin=t3.pairing_code())
            if index == 0:
                runtime = f"{path}/home/userdata/server-runtime.json"
                assert os.path.isfile(runtime), "official fixture runtime missing"
                omabridge(binary, state, "follow-t3-runtime", "--environment-slot", "--environment", environment, "--runtime", runtime)
            fixtures.append((environment, session, direct))
        port = free_port()
        gateway = subprocess.Popen([binary, "--state-dir", state, "mcp", "serve",
                                    "--listen", f"127.0.0.1:{port}", "--events-poll-seconds", "1",
                                    "--insecure-loopback-callbacks"], stdout=subprocess.PIPE, text=True)
        assert json.loads(gateway.stdout.readline())["event"] == "mcp_listening"
        managed = bool(os.environ.get("OMABRIDGE_TEST_MANAGED_CATALOG"))
        project_ids = {environment: direct.call("t3_thread_read", threadId=session, limit=1)["thread"]["projectId"] for environment, session, direct in fixtures} if managed else {}
        if managed:
            omabridge(binary, state, "policy-create", "--policy", "live", "--access", "operate")
            environment, session, _ = fixtures[0]
            omabridge(binary, state, "policy-allow", "--policy", "live", "--environment", environment, "--project", project_ids[environment], "--session", session)
        args = ["grant", "--all-projects", "--access", "operate", "--label", "isolated-federation"]
        for environment, _, _ in fixtures:
            args += ["--environment", environment]
        if managed:
            args = ["grant", "--managed-catalog", "live", "--access", "operate", "--label", "isolated-managed"]
        code = omabridge(binary, state, *args)["link_code"]
        client = ChatGPTLikeClient(f"http://127.0.0.1:{port}/mcp")
        client.connect(code)
        if managed:
            original_token = client.token
            assert len(client.ok("t3_list_environments")["environments"]) == 1
            environment, session, _ = fixtures[1]
            assert client.call("t3_get_session", environment_id=environment, session_id=session)[0]
            omabridge(binary, state, "policy-allow", "--policy", "live", "--environment", environment, "--project", project_ids[environment], "--session", session)
            assert client.token == original_token
        listed = client.ok("t3_list_environments")["environments"]
        assert {row["environment_id"] for row in listed} == {row[0] for row in fixtures}
        assert client.call("t3_list_projects")[0]
        assert client.call("t3_list_projects", environment_id="ffffffff-ffff-4fff-8fff-ffffffffffff")[0]
        for environment, session, _ in fixtures:
            status, result = modern(client.url if hasattr(client,"url") else f"http://127.0.0.1:{port}/mcp", client.token,
                                    "events/subscribe", {"name":"t3.run.finished", "arguments":{"environment_id":environment,"session_id":session},
                                    "delivery":{"mode":"webhook","url":hook,"secret":SECRET}})
            assert status == 200 and result.get("result",{}).get("id"), result
        time.sleep(1.5)  # Initial baseline; preexisting runs are not events.
        for environment, session, direct in fixtures:
            args = dict(environment_id=environment, session_id=session,
                        message="Communication correlation: isolated-federation-0001",
                        client_request_id="isolated-federation-0001")
            sent = client.ok("t3_send_message", **args)
            assert sent["environment_id"] == environment
            replay = client.ok("t3_send_message", **args)
            assert replay["duplicate"] and replay["run_id"] == sent["run_id"]
            deadline = time.monotonic() + 60
            while True:
                history = direct.call("t3_thread_read", threadId=session, view="messages", limit=100)
                count = sum(item.get("text") == args["message"] for item in history["items"])
                if count:
                    assert count == 1, "duplicate canonical message"
                    break
                assert time.monotonic() < deadline, json.dumps({
                    "failure": "accepted message absent from canonical history",
                    "delivery": sent.get("delivery"),
                    "thread_status": history.get("thread", {}).get("status"),
                    "runs": [{"status": run.get("status"), "runId": run.get("runId")}
                             for run in history.get("recentRuns", [])],
                    "items": [{"type": item.get("type"), "text_chars": len(item.get("text") or "")}
                              for item in history.get("items", [])]})
                time.sleep(0.2)
        deadline = time.monotonic() + 60
        while True:
            received = [r for r in Receiver.seen if r["body"].get("name") == "t3.run.finished"]
            if {r["body"]["data"]["environment_id"] for r in received} == {f[0] for f in fixtures}:
                assert len(received) == 2
                assert all(r["signed"] and r["body"]["data"]["status"] == "failed" for r in received)
                assert all(r["body"]["data"]["detail"]["arguments"]["environment_id"] == r["body"]["data"]["environment_id"] for r in received)
                break
            assert time.monotonic() < deadline, "missing signed federated terminal events"
            time.sleep(0.2)
        if managed:
            environment, session, _ = fixtures[1]
            omabridge(binary, state, "policy-remove", "--policy", "live", "--environment", environment)
            assert client.call("t3_get_messages", environment_id=environment, session_id=session)[0]
            assert client.call("t3_send_message", environment_id=environment, session_id=session, message="Communication correlation: isolated-federation-0001", client_request_id="isolated-federation-0001")[0]
            assert len(client.ok("t3_list_environments")["environments"]) == 1
            omabridge(binary, state, "policy-allow", "--policy", "live", "--environment", environment, "--project", project_ids[environment], "--session", session)
            assert client.token == original_token
        hosts[0].stop()
        assert client.call("t3_list_projects", environment_id=fixtures[0][0])[0]
        assert client.ok("t3_list_projects", environment_id=fixtures[1][0])["projects"]
        old_port = hosts[0].port
        hosts[0].port = free_port()
        hosts[0].start()  # Same home/identity/consent, different official runtime port.
        restarted = json.loads(http("GET", hosts[0].url + "/.well-known/t3/environment")[2])
        assert restarted["environmentId"] == fixtures[0][0]
        assert client.ok("t3_list_projects", environment_id=fixtures[0][0])["projects"]
        recovered = client.ok("t3_get_messages", environment_id=fixtures[0][0], session_id=fixtures[0][1])
        assert "isolated-federation-0001" in json.dumps(recovered), "canonical history lost after real port change"
        stale_path = f"{root}/stale-port-replacement"
        os.makedirs(f"{stale_path}/ws")
        os.makedirs(f"{stale_path}/rh")
        subprocess.run(["git", "init", "-q", f"{stale_path}/ws"], check=True)
        stale = T3(t3_binary, stale_path)
        stale.port = old_port
        hosts.append(stale)
        stale.start()
        assert json.loads(http("GET", stale.url + "/.well-known/t3/environment")[2])["environmentId"] != fixtures[0][0]
        assert client.ok("t3_list_projects", environment_id=fixtures[0][0])["projects"], "stale port hijacked route"
        stale.stop()
        # A real crash leaves the official runtime behind; a different T3 then takes its port.
        hosts[0].proc.kill()
        hosts[0].proc.wait(timeout=30)
        assert os.path.isfile(f"{hosts[0].root}/home/userdata/server-runtime.json")
        replacement_path = f"{root}/replacement"
        os.makedirs(f"{replacement_path}/ws")
        os.makedirs(f"{replacement_path}/rh")
        subprocess.run(["git", "init", "-q", f"{replacement_path}/ws"], check=True)
        replacement = T3(t3_binary, replacement_path)
        replacement.port = hosts[0].port
        hosts.append(replacement)
        replacement.start()
        changed = json.loads(http("GET", replacement.url + "/.well-known/t3/environment")[2])
        assert changed["environmentId"] != fixtures[0][0]
        failed, refused = client.call("t3_list_projects", environment_id=fixtures[0][0])
        assert failed and "identity" in json.dumps(refused).lower()
        assert client.ok("t3_list_projects", environment_id=fixtures[1][0])["projects"]
        grant_id = omabridge(binary, state, "grants")["grants"][0]["id"]
        assert omabridge(binary, state, "revoke", grant_id)["revoked"]
        try:
            client.rpc("tools/list")
        except PermissionError as error:
            assert error.args[0] == 401
        else:
            raise AssertionError("revoked OAuth token still accepted")
        print(json.dumps({"federation": "passed", "real_t3_hosts": 2,
                          "remote_ssh_host": bool(os.environ.get("OMABRIDGE_TEST_SSH_HOST")),
                          "oauth": True, "managed_catalog_same_token": managed, "canonical_sends": 2, "duplicate_sends": 0,
                          "offline_isolation": True, "identity_change_denied": True, "revoked_oauth_denied": True,
                          "runtime_port_reconnected": True, "stale_port_replacement_ignored": True,
                          "signed_federated_events": 2, "dot_tested": False}))
    finally:
        receiver.shutdown()
        if gateway is not None:
            gateway.terminate()
            gateway.wait(timeout=30)
        for host in hosts:
            if (host.proc is not None and host.proc.poll() is None) or getattr(host,"started",False):
                host.stop()
        shutil.rmtree(root)


if __name__ == "__main__":
    main()
