#!/usr/bin/env python3
"""
cfc_server.py — standalone local proxy for the sanitized cocodem extension.

Port 8520, hardcoded. Implements the full cocodem server contract derived from
auditing the original assets/request.js (v1.0.66). Three sanitization deltas only:
  1. uiNodes: []          — original had 3 malware DOM-injection nodes
  2. /licenses/verify     — always returns {"valid": true}; original was credential-harvesting
  3. JWT iat: 1700000000  — static; dynamic iat caused React #185 infinite loop

The CF Worker (myworker.mahnikka.workers.dev) handles /api/options and /oauth/redirect
natively and 307s everything else to this server. This server handles those 307-forwarded
routes plus any direct extension requests.

Extension cfcBase rewriting: the extension does cfcBase + u.href for proxyIncludes,
producing paths like /https://api.anthropic.com/api/oauth/profile on this server.
All such prefixed paths are normalized before routing.
"""

import http.server
import json
import time
import base64
import urllib.request
import urllib.error
from urllib.parse import urlparse

PORT = 8520
ANTHROPIC_API = "https://api.anthropic.com"


def _b64url(data: dict) -> str:
    return (
        base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )


def _build_token() -> dict:
    now = int(time.time())
    header = _b64url({"alg": "HS256", "typ": "JWT"})
    payload = _b64url(
        {
            "iss": "auth",
            "sub": "user_local",
            "iat": 1700000000,
            "exp": now + 315360000,
        }
    )
    token = f"{header}.{payload}.local"
    return {
        "access_token": token,
        "refresh_token": token,
        "token_type": "Bearer",
        "expires_in": 315360000,
    }


LOCAL_PROFILE = {
    "id": "user_local",
    "email": "user@localhost",
    "name": "Local User",
    "display_name": "Local User",
    "phone": None,
    "created_at": "2023-11-01T00:00:00Z",
    "updated_at": "2023-11-01T00:00:00Z",
    "has_claude_max": True,
    "has_api_access": True,
    "organizations": [{"id": "org_local", "name": "Local Org", "role": "admin"}],
}

LOCAL_ACCOUNT = {
    "id": "user_local",
    "email": "user@localhost",
    "name": "Local User",
}

LOCAL_ORGANIZATIONS = [{"id": "org_local", "name": "Local Org", "role": "admin"}]

LOCAL_CHAT_CONVERSATIONS = {"conversations": [], "has_more": False}

LOCAL_DOMAIN_INFO = {"domain_info": {}}

OPTIONS_RESPONSE = {
    "mode": "api",
    "cfcBase": "",
    "anthropicBaseUrl": "",
    "apiBaseIncludes": ["https://api.anthropic.com/v1/"],
    "proxyIncludes": [
        "cdn.segment.com",
        "featureassets.org",
        "assetsconfigcdn.org",
        "featuregates.org",
        "api.segment.io",
        "prodregistryv2.org",
        "beyondwickedmapping.org",
        "api.honeycomb.io",
        "statsigapi.net",
        "events.statsigapi.net",
        "api.statsigcdn.com",
        "*ingest.us.sentry.io",
        "https://api.anthropic.com/api/oauth/profile",
        "https://api.anthropic.com/api/bootstrap",
        "https://console.anthropic.com/v1/oauth/token",
        "https://platform.claude.com/v1/oauth/token",
        "https://api.anthropic.com/api/oauth/account",
        "https://api.anthropic.com/api/oauth/organizations",
        "https://api.anthropic.com/api/oauth/chat_conversations",
        "/api/web/domain_info/browser_extension",
    ],
    "discardIncludes": [
        "cdn.segment.com",
        "api.segment.io",
        "events.statsigapi.net",
        "api.honeycomb.io",
        "prodregistryv2.org",
        "*ingest.us.sentry.io",
        "browser-intake-us5-datadoghq.com",
    ],
    "modelAlias": {},
    "ui": {},
    "uiNodes": [],
}


def _fallback_html(path: str) -> str:
    return (
        f"<!DOCTYPE html><html><head><title>CFC Local</title></head>"
        f"<body><p>CFC local proxy on port {PORT}. Path: {path}</p></body></html>"
    )


def _arc_split_view_html() -> str:
    return '<div class="arc-split-view" style="padding:16px">Arc split view</div>'


class CFCHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html, status=200):
        body = html.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _proxy_to_anthropic(self, raw_path):
        # Normalize cfcBase-rewritten paths: /https://api.anthropic.com/v1/... → https://...
        if raw_path.startswith("/https://") or raw_path.startswith("/http://"):
            target_url = raw_path[1:]
        else:
            target_url = ANTHROPIC_API + raw_path

        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else None

            fwd_headers = {}
            for key in (
                "x-api-key",
                "anthropic-version",
                "content-type",
                "authorization",
                "anthropic-beta",
            ):
                val = self.headers.get(key)
                if val:
                    fwd_headers[key] = val

            req = urllib.request.Request(
                target_url, data=body, headers=fwd_headers, method=self.command
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                resp_body = resp.read()
                self.send_response(resp.status)
                for key, val in resp.headers.items():
                    if key.lower() in (
                        "content-type",
                        "content-length",
                        "anthropic-ratelimit-requests-remaining",
                        "request-id",
                    ):
                        self.send_header(key, val)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(resp_body)
        except urllib.error.HTTPError as e:
            resp_body = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(resp_body)
        except Exception:
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'{"error":"bad gateway"}')

    def _route(self):
        # Strip query string for routing; keep raw path for proxy forwarding
        path = self.path
        path_no_qs = path.split("?")[0]

        # Unwrap cfcBase-rewritten paths to get the logical path for matching
        logical = path_no_qs
        if logical.startswith("/https://") or logical.startswith("/http://"):
            logical = urlparse(logical[1:]).path

        # OAuth / auth routes (matched on logical path)
        if logical == "/api/oauth/profile" or logical.endswith("/api/oauth/profile"):
            return self._send_json(LOCAL_PROFILE)

        if logical == "/api/oauth/account" or logical.endswith("/api/oauth/account"):
            return self._send_json(LOCAL_ACCOUNT)

        if logical == "/api/oauth/organizations" or logical.endswith("/api/oauth/organizations"):
            return self._send_json(LOCAL_ORGANIZATIONS)

        if logical == "/api/oauth/chat_conversations" or logical.endswith("/api/oauth/chat_conversations"):
            return self._send_json(LOCAL_CHAT_CONVERSATIONS)

        if logical == "/api/bootstrap" or logical.endswith("/api/bootstrap"):
            return self._send_json(LOCAL_PROFILE)

        if logical.endswith("/oauth/token") or logical.endswith("/v1/oauth/token"):
            return self._send_json(_build_token())

        # /api/* routes
        if path_no_qs == "/api/options" or path_no_qs.startswith("/api/options?"):
            return self._send_json(OPTIONS_RESPONSE)

        if path_no_qs == "/api/arc-split-view":
            return self._send_json({"html": _arc_split_view_html()})

        if "/api/web/domain_info/browser_extension" in path_no_qs:
            return self._send_json(LOCAL_DOMAIN_INFO)

        # Licenses (sanitization delta: always valid)
        if path_no_qs == "/licenses/verify":
            return self._send_json({"valid": True, "plan": "local", "expires_at": None})

        # /v1/* → proxy to Anthropic (handles both /v1/... and /https://api.anthropic.com/v1/...)
        if "/v1/" in path_no_qs:
            return self._proxy_to_anthropic(path_no_qs)

        # Other cfcBase-rewritten paths that aren't /v1/* — return minimal ok stub
        if path_no_qs.startswith("/https://") or path_no_qs.startswith("/http://"):
            return self._send_json({"ok": True})

        # Fallback: real HTML, never 204
        return self._send_html(_fallback_html(self.path))

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, x-api-key, anthropic-version, authorization, anthropic-beta",
        )
        self.end_headers()

    def do_GET(self):
        self._route()

    def do_POST(self):
        self._route()


if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", PORT), CFCHandler)
    print(f"CFC local proxy running on http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
