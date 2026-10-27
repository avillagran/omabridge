#!/usr/bin/env python3
"""ChatGPT-equivalent remote MCP client: OAuth discovery, DCR, PKCE S256, RFC 9207 and
Streamable-HTTP JSON-RPC. Used by the integration and end-to-end tests; standard library only.

The approval step is the one a human performs in the browser: we GET the authorization
page and POST the administrator's one-time link code, exactly like the form does.
"""
import base64
import hashlib
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request

REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def http(method, url, body=None, headers=None, form=False, timeout=90):
    data = None
    headers = dict(headers or {})
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode()
            headers["content-type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode()
            headers["content-type"] = "application/json"
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with OPENER.open(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read().decode()


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class ChatGPTLikeClient:
    def __init__(self, mcp_url):
        self.mcp_url = mcp_url
        self.token = None
        self.next_id = 1

    def discover(self):
        status, headers, _ = http("POST", self.mcp_url, {"jsonrpc": "2.0", "id": 0, "method": "initialize"})
        assert status == 401, status
        challenge = {k.lower(): v for k, v in headers.items()}["www-authenticate"]
        assert challenge.startswith("Bearer ") and "resource_metadata=" in challenge, challenge
        prm_url = challenge.split('resource_metadata="', 1)[1].split('"', 1)[0]
        status, _, body = http("GET", prm_url)
        assert status == 200
        prm = json.loads(body)
        assert prm["resource"] == self.mcp_url, prm
        issuer = prm["authorization_servers"][0]
        status, _, body = http("GET", issuer + "/.well-known/oauth-authorization-server")
        meta = json.loads(body)
        assert meta["issuer"] == issuer and "S256" in meta["code_challenge_methods_supported"]
        assert meta["authorization_response_iss_parameter_supported"] is True
        return prm, meta

    def register(self, meta, redirect=REDIRECT, name="ChatGPT"):
        status, _, body = http("POST", meta["registration_endpoint"], {"client_name": name, "redirect_uris": [redirect]})
        assert status == 201, (status, body)
        return json.loads(body)["client_id"]

    def authorize(self, meta, client_id, link_code, redirect=REDIRECT, approve=True):
        verifier = b64(secrets.token_bytes(48))
        challenge = b64(hashlib.sha256(verifier.encode()).digest())
        state = b64(secrets.token_bytes(16))
        params = {
            "response_type": "code", "client_id": client_id, "redirect_uri": redirect,
            "code_challenge": challenge, "code_challenge_method": "S256", "state": state,
            "resource": self.mcp_url, "scope": "t3",
        }
        status, _, page = http("GET", meta["authorization_endpoint"] + "?" + urllib.parse.urlencode(params))
        assert status == 200 and "link_code" in page, status
        status, headers, page = http(
            "POST", meta["authorization_endpoint"],
            dict(params, link_code=link_code, action="approve" if approve else "deny"), form=True,
        )
        if status != 303:
            return None, page
        location = {k.lower(): v for k, v in headers.items()}["location"]
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(location).query))
        assert query.get("state") == state and query.get("iss") == meta["issuer"], query
        if "code" not in query:
            return None, query
        status, _, body = http("POST", meta["token_endpoint"], {
            "grant_type": "authorization_code", "code": query["code"], "redirect_uri": redirect,
            "client_id": client_id, "code_verifier": verifier, "resource": self.mcp_url,
        }, form=True)
        assert status == 200, body
        self.token = json.loads(body)["access_token"]
        return self.token, query

    def connect(self, link_code):
        _, meta = self.discover()
        client_id = self.register(meta)
        token, detail = self.authorize(meta, client_id, link_code)
        assert token, detail
        init = self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                       "clientInfo": {"name": "openai-mcp", "version": "1"}})
        self.notify("notifications/initialized")
        return init

    def raw(self, payload, token=None):
        headers = {"accept": "application/json, text/event-stream", "mcp-protocol-version": "2025-06-18"}
        if token or self.token:
            headers["authorization"] = "Bearer " + (token or self.token)
        return http("POST", self.mcp_url, payload, headers=headers)

    def notify(self, method):
        status, _, _ = self.raw({"jsonrpc": "2.0", "method": method})
        assert status == 202, status

    def rpc(self, method, params=None, token=None):
        self.next_id += 1
        status, _, body = self.raw({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}}, token)
        if status != 200:
            raise PermissionError(status)
        message = json.loads(body)
        if "error" in message:
            raise RuntimeError(message["error"])
        return message["result"]

    def call(self, tool, **arguments):
        result = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        return result["isError"], result["structuredContent"]

    def ok(self, tool, **arguments):
        failed, value = self.call(tool, **arguments)
        assert not failed, (tool, value)
        return value
