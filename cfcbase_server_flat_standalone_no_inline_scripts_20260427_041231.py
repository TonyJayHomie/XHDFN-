#!/usr/bin/env python3
"""
Standalone CFCBASE server -- FLATTENED from the OUTPUTS wrapper chain.

Source chain (newest -> oldest), all collapsed into this single file:
  1. cfcbase_server_proxy_pages_12py_options_payload_empty_ui_20260426_131300.py
       -> safe_ui_nodes() returns [] ; options_payload() forces ui={} uiNodes=[]
  2. cfcbase_server_proxy_pages_from_12py_20260426_124457.py
       -> /backend_settings serves the dark 12.py-style page
       -> /oauth/authorize serves the cocodem-styled gate
  3. cfcbase_server_only_20260426_025208.py
       -> the actual server: routes, /v1/* forwarding, /api/{options,identity,backends}
          /oauth/{authorize,redirect}, /licenses/verify, telemetry 204, static asset
          serving from the generated extension folder.

Differences vs the wrapper chain:
  *  NO INLINE <script> blocks anywhere.  All JavaScript is served from
     dedicated routes (/_cfc/<name>.js) and referenced via <script src="...">.
     This keeps every page MV3-CSP friendly and makes the server portion
     safely droppable into the mnmf.py extension toolchain (where the
     options.html / sidepanel.html inline-script stripper would otherwise
     have to be re-run).

CFCBASE coverage (matches both halves of the cocodem stack):
  Worker side  (replaces openclaude.111724.xyz + cfc.aroic.workers.dev)
    /api/options          -> live CFC options contract (ui={}, uiNodes=[])
    /api/identity         -> GET/POST source-of-truth identity
    /api/backends         -> GET/POST backend list
    /api/arc-split-view   -> arc panel HTML
    /oauth/authorize      -> local sign-in gate (no remote login)
    /oauth/redirect       -> local code exchange page
    /oauth/token          -> local JWT (iss=cfc)
    /oauth/profile        -> local profile
    /oauth/account        -> local account
    /oauth/organizations  -> local org list
    /bootstrap            -> local bootstrap payload
    /licenses/verify      -> always valid (cocodem aroic worker replacement)
    telemetry domains     -> 204
  Local dev side (replaces http://localhost:8787/)
    same routes -- this is the same contract; the difference is only the
    base URL the extension is configured to talk to.

Run:
  python cfcbase_server_flat_standalone_no_inline_scripts_20260427_041231.py
"""

import base64
import json
import mimetypes
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import TCPServer, ThreadingMixIn
from urllib.parse import parse_qs, urlencode, urlparse


STAMP        = "20260427_041231"
EXTENSION_ID = "fcoeoabgfenejglbffodgkkbkcdhcgfn"

SCRIPT_PATH    = Path(__file__).resolve()
WORKSPACE_DIR  = SCRIPT_PATH.parent

LOCAL_PORT  = int(os.environ.get("CFC_LOCAL_PORT", "8520"))
LOCAL_HOST  = os.environ.get("CFC_LOCAL_HOST", "localhost")
LOCAL_BASE  = f"http://{LOCAL_HOST}:{LOCAL_PORT}/"
LOCAL_BIND  = os.environ.get("CFC_BIND_HOST", "127.0.0.1")

REMOTE_BASE = os.environ.get(
    "CFC_REMOTE_BASE",
    "https://myworker.mahnikka.workers.dev/",
).rstrip("/") + "/"

DEFAULT_BACKEND_URL  = os.environ.get("CFC_DEFAULT_BACKEND_URL", "http://127.0.0.1:1234/v1")
BACKEND_SETTINGS_URL = LOCAL_BASE + "backend_settings"

STATE_IDENTITY_FILE = WORKSPACE_DIR / f"cfc_identity_{STAMP}.json"
STATE_BACKENDS_FILE = WORKSPACE_DIR / f"cfc_backends_{STAMP}.json"

# Default sanitized-extension folder to serve static assets from.  May be
# overridden by env var CFC_GENERATED_EXTENSION_DIR.
GENERATED_EXTENSION_DIR = Path(
    os.environ.get(
        "CFC_GENERATED_EXTENSION_DIR",
        str(WORKSPACE_DIR / "claude-sanitized-20260425-212051"),
    )
)
GENERATED_ASSETS_DIR = GENERATED_EXTENSION_DIR / "assets"

USER_UUID = "ac507011-00b5-56c4-b3ec-ad820dbafbc1"
ORG_UUID  = "1b61ee4a-d0ce-50b5-8b67-7eec034d3d08"


# ---------------------------------------------------------------------------
# Telemetry, proxy / discard sets (verbatim from base server)
# ---------------------------------------------------------------------------

TELEMETRY_DOMAINS = [
    "segment.com",
    "statsig",
    "statsigapi.net",
    "honeycomb",
    "sentry",
    "datadoghq",
    "featureassets",
    "assetsconfigcdn",
    "featuregates",
    "prodregistryv2",
    "beyondwickedmapping",
    "fpjs.dev",
    "openfpcdn.io",
    "api.fpjs.io",
    "googletagmanager",
    "googletag",
]

PROXY_INCLUDES = [
    "https://api.anthropic.com/v1/",
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
    "/api/web/url_hash_check/browser_extension",
    "cfc.aroic.workers.dev",
]

DISCARD_INCLUDES = [
    "cdn.segment.com",
    "api.segment.io",
    "events.statsigapi.net",
    "api.honeycomb.io",
    "prodregistryv2.org",
    "*ingest.us.sentry.io",
    "browser-intake-us5-datadoghq.com",
    "fpjs.dev",
    "openfpcdn.io",
    "api.fpjs.io",
    "googletagmanager.com",
]


# ---------------------------------------------------------------------------
# Persistent identity / backends -- proxy is the source of truth.
# ---------------------------------------------------------------------------

DEFAULT_IDENTITY = {
    "apiBaseUrl":     DEFAULT_BACKEND_URL,
    "apiKey":         "",
    "authToken":      "",
    "email":          "user@local",
    "username":       "local-user",
    "licenseKey":     "",
    "blockAnalytics": True,
    "modelAliases":   {},
    "mode":           "",
}

DEFAULT_BACKENDS = [
    {
        "name":       "Default",
        "url":        DEFAULT_BACKEND_URL,
        "key":        "",
        "models":     [],
        "modelAlias": {},
        "enabled":    True,
    }
]


def read_json_file(path, fallback):
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, type(fallback)):
                return data
        except Exception:
            pass
    return json.loads(json.dumps(fallback))


IDENTITY = read_json_file(STATE_IDENTITY_FILE, DEFAULT_IDENTITY)
BACKENDS = read_json_file(STATE_BACKENDS_FILE, DEFAULT_BACKENDS)


def write_json_file(path, data):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Local JWT + profile / bootstrap / org payloads
# ---------------------------------------------------------------------------

def jwt(payload):
    header = {"alg": "none", "typ": "JWT"}
    h = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).rstrip(b"=").decode("ascii")
    b = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("ascii")
    return h + "." + b + ".local"


def local_token():
    now = int(time.time())
    return {
        "access_token":  jwt({"iss": "cfc", "sub": USER_UUID, "exp": now + 315360000, "iat": 1700000000}),
        "token_type":    "bearer",
        "expires_in":    315360000,
        "refresh_token": "local-refresh",
        "scope":         "user:profile user:inference user:chat",
    }


LOCAL_ACCOUNT = {
    "uuid":                     USER_UUID,
    "id":                       USER_UUID,
    "email_address":            "user@local",
    "email":                    "user@local",
    "full_name":                "Local User",
    "name":                     "Local User",
    "display_name":             "Local User",
    "has_password":             True,
    "has_completed_onboarding": True,
    "preferred_language":       "en-US",
    "has_claude_pro":           True,
    "created_at":               "2024-01-01T00:00:00Z",
    "updated_at":               "2024-01-01T00:00:00Z",
    "settings":                 {"theme": "system", "language": "en-US"},
}

LOCAL_ORG = {
    "uuid":              ORG_UUID,
    "id":                ORG_UUID,
    "name":              "Local",
    "role":              "admin",
    "organization_type": "personal",
    "billing_type":      "self_serve",
    "capabilities":      ["chat", "claude_pro_plan", "api", "computer_use", "claude_for_chrome"],
    "rate_limit_tier":   "default_claude_pro",
    "settings":          {},
    "created_at":        "2024-01-01T00:00:00Z",
}


def profile_payload():
    account = dict(LOCAL_ACCOUNT)
    account["email_address"] = IDENTITY.get("email") or "user@local"
    account["email"]         = account["email_address"]
    account["full_name"]     = IDENTITY.get("username") or "Local User"
    account["name"]          = account["full_name"]
    account["display_name"]  = account["full_name"]
    return {
        **account,
        "account":                 account,
        "organization":            LOCAL_ORG,
        "memberships":             [{"organization": LOCAL_ORG, "role": "admin", "joined_at": "2024-01-01T00:00:00Z"}],
        "active_organization_uuid": ORG_UUID,
    }


def bootstrap_payload():
    prof = profile_payload()
    return {
        **prof,
        "account_uuid":  USER_UUID,
        "organizations": [LOCAL_ORG],
        "statsig": {
            "user":   {"userID": USER_UUID, "custom": {"organization_uuid": ORG_UUID}},
            "values": {"feature_gates": {}, "dynamic_configs": {}, "layer_configs": {}},
        },
        "flags":         {},
        "features":      [],
        "active_flags":  {},
        "active_subscription": {
            "plan":                  "claude_pro",
            "status":                "active",
            "type":                  "claude_pro",
            "billing_period":        "monthly",
            "current_period_start":  "2024-01-01T00:00:00Z",
            "current_period_end":    "2099-12-31T23:59:59Z",
        },
        "has_claude_pro":   True,
        "chat_enabled":     True,
        "capabilities":     ["chat", "claude_pro_plan", "api", "computer_use", "claude_for_chrome"],
        "rate_limit_tier":  "default_claude_pro",
        "settings":         {"theme": "system", "language": "en-US"},
    }


def merged_model_aliases():
    out = {}
    aliases = IDENTITY.get("modelAliases") or {}
    if isinstance(aliases, dict):
        out.update(aliases)
    for backend in BACKENDS:
        backend_alias = backend.get("modelAlias") or {}
        if backend.get("enabled", True) and isinstance(backend_alias, dict):
            out.update(backend_alias)
    return out


# ---------------------------------------------------------------------------
# safe_ui_nodes / options_payload
#   Flattened from cfcbase_server_proxy_pages_12py_options_payload_empty_ui_20260426_131300.py
#   Net effect: NO UI replacement / injection at all -- ui={}, uiNodes=[].
# ---------------------------------------------------------------------------

def safe_ui_nodes():
    """Most-recent-wrapper override: empty list. The CFC server never replaces
    Permissions, Shortcuts, Options, Microphone, Log out, sidepanel login,
    beta warnings, or arbitrary buttons in cocodem's options.html."""
    return []


def options_payload():
    """Live CFC options contract. Built from IDENTITY + BACKENDS at request
    time. ui and uiNodes are forced empty per the most-recent wrapper."""
    discard = list(DISCARD_INCLUDES) if IDENTITY.get("blockAnalytics", True) else []
    return {
        "mode":             IDENTITY.get("mode", "") or "",
        "cfcBase":          LOCAL_BASE,
        "remoteCfcBase":    REMOTE_BASE,
        "anthropicBaseUrl": "",
        "apiBaseUrl":       IDENTITY.get("apiBaseUrl") or DEFAULT_BACKEND_URL,
        "apiKey":           IDENTITY.get("apiKey", ""),
        "authToken":        IDENTITY.get("authToken", ""),
        "identity": {
            "email":      IDENTITY.get("email", "user@local"),
            "username":   IDENTITY.get("username", "local-user"),
            "licenseKey": IDENTITY.get("licenseKey", ""),
        },
        "backends":         BACKENDS,
        "apiBaseIncludes":  [],
        "proxyIncludes":    list(PROXY_INCLUDES),
        "discardIncludes":  discard,
        "modelAlias":       merged_model_aliases(),
        # ui and uiNodes are EMPTY -- 12.py contract enforced.
        "ui":               {},
        "uiNodes":          [],
        "blockAnalytics":   bool(IDENTITY.get("blockAnalytics", True)),
    }


def auth_payload(path):
    if "/licenses/verify"        in path: return {"valid": True, "license": "local", "tier": "pro", "expires": "2099-12-31"}
    if "/mcp/v2/bootstrap"       in path: return {"servers": [], "tools": [], "enabled": False}
    if "/spotlight"              in path: return {"items": [], "total": 0}
    if "/features/"              in path: return {"enabled": True, "features": {}}
    if "/oauth/account/settings" in path: return {"settings": {"theme": "system", "language": "en-US"}}
    if "/oauth/profile"          in path: return profile_payload()
    if "/oauth/account"          in path: return profile_payload()
    if "/oauth/token"            in path: return local_token()
    if "/bootstrap"              in path: return bootstrap_payload()
    if "/oauth/organizations"    in path:
        tail = path.split("/oauth/organizations/", 1)[1] if "/oauth/organizations/" in path else ""
        if "/" in tail: return {}
        if tail:        return LOCAL_ORG
        return [LOCAL_ORG]
    if "/chat_conversations"     in path: return {"conversations": [], "limit": 0, "has_more": False, "cursor": None}
    if "/domain_info"            in path: return {"domain": "local", "allowed": True}
    if "/url_hash_check"         in path: return {"allowed": True}
    if "/usage"                  in path: return {"usage": {}, "limit": None}
    if "/entitlements"           in path: return {"entitlements": []}
    if "/flags"                  in path: return {}
    return {}


def pick_backends(model):
    enabled   = [b for b in BACKENDS if b.get("enabled", True)]
    exact     = [b for b in enabled if b.get("models") and model in b.get("models", [])]
    catch_all = [b for b in enabled if not b.get("models")]
    preferred = exact or catch_all or enabled
    if not preferred:
        return []
    first = preferred[0]
    rest  = [b for b in enabled if b is not first]
    return [first] + rest


# ---------------------------------------------------------------------------
# Backend Settings page (12.py-style dark UI)
#   Flattened from cfcbase_server_proxy_pages_from_12py_20260426_124457.py
#   The original wrapper inlined the page JS; here it is split out into a
#   separate /_cfc/backend_settings_proxy.js endpoint.  Zero inline <script>.
# ---------------------------------------------------------------------------

def proxy_backend_settings_html():
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Backend Settings</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#19182c;color:#f5f3ee;margin:0;padding:32px 20px;min-height:100vh}}
.wrap{{max-width:980px;margin:0 auto}}
h1{{font-size:28px;color:#ff4568;margin:0 0 4px;font-weight:800}}
.sub{{color:#7f82a8;margin:0 0 28px}}
.panel{{background:#142447;border:1px solid #20345f;border-radius:12px;padding:22px;margin:18px auto;max-width:760px}}
.panel h2{{font-size:16px;color:#ff4568;margin:0 0 16px}}
.backend{{border:1px dashed #243963;border-radius:10px;padding:14px;margin:10px 0;background:#121c36}}
.grid{{display:grid;grid-template-columns:160px 1fr;gap:12px;align-items:center;margin:10px 0}}
label{{color:#7f82a8;font-size:14px}}
input,textarea,select{{width:100%;background:#17172b;color:#f5f3ee;border:1px solid #ef4565;border-radius:6px;padding:11px;font-size:14px;font-family:monospace}}
input:focus,textarea:focus,select:focus{{outline:none;box-shadow:0 0 0 2px rgba(239,69,101,.15)}}
.muted{{color:#7f82a8}}
.actions{{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}}
button{{background:#ef4565;color:white;border:0;border-radius:6px;padding:10px 16px;font-weight:700;cursor:pointer}}
button.secondary{{background:#202842;color:#d8d7e8;border:1px solid #303b62}}
button.danger{{background:#3a1730;color:#ff4568;border:1px solid #73304c}}
.save{{display:block;max-width:760px;margin:18px auto 0;width:100%;font-size:18px;padding:16px;border-radius:8px}}
.status{{display:none;margin:0 auto 16px;max-width:760px;padding:12px 16px;border-radius:8px;font-weight:700}}
.ok{{display:block;background:#164f36;color:#9af0ba}}
.err{{display:block;background:#4b1b2b;color:#ff9bb0}}
.arch{{background:#17172b;border:1px solid #2b2a44;border-radius:8px;padding:14px;color:#7f82a8;font-family:monospace;font-size:13px;line-height:1.7}}
code{{background:#0f1a32;color:#7ff0b2;border-radius:4px;padding:2px 5px}}
</style>
<script src="/_cfc/backend_settings_proxy.js" defer></script>
</head>
<body><div class="wrap">
  <h1>OpenClaw -- Backend Setup</h1>
  <p class="sub">Configure backends &middot; test connections &middot; connect to extension</p>
  <div id="status" class="status"></div>
  <section class="panel">
    <h2>API Backends</h2>
    <div id="backendList"></div>
    <button class="secondary" id="btnAddBackend">+ Add Backend</button>
  </section>
  <section class="panel">
    <h2>Extension Routing &amp; Auth Bypass</h2>
    <div class="grid"><label>cfcBase URL</label><input id="cfcBase" value="{LOCAL_BASE}"></div>
    <div class="grid"><label>apiBaseUrl</label><input id="apiBaseUrl" value="{IDENTITY.get('apiBaseUrl') or DEFAULT_BACKEND_URL}"></div>
    <div class="grid"><label>Mode</label><select id="mode"><option value="">api -- local / custom backend</option><option value="claude">claude -- official</option></select></div>
    <div class="grid"><label>Access Token</label><input id="authToken" value="{IDENTITY.get('authToken','')}" placeholder="blank = auto-generate bypass token"></div>
  </section>
  <section class="panel">
    <h2>Quick Actions</h2>
    <div class="actions">
      <button id="btnTestAll">Test All Backends</button>
      <button id="btnFetchModels">Fetch All Models</button>
      <button class="secondary" id="btnResetDefaults">Reset to Defaults</button>
      <button class="danger" id="btnClearData">Clear All Data &amp; Reload</button>
    </div>
  </section>
  <section class="panel">
    <h2>Architecture</h2>
    <div class="arch">
      <b>OpenClaw Gateway:</b> {DEFAULT_BACKEND_URL}<br>
      <b>CFCBASE Local:</b> {LOCAL_BASE}<br>
      <b>CFCBASE Remote:</b> {REMOTE_BASE}<br><br>
      <code>localStorage.apiBaseUrl</code> takes priority over all routing in request.js.<br>
      Bypass token uses <code>iss:&quot;cfc&quot;</code> and is served locally by the proxy.
    </div>
  </section>
  <button class="save" id="btnSaveConfig">Save Config &amp; Connect to Extension -&gt;</button>
</div></body></html>"""


def proxy_backend_settings_js():
    """Bootstraps the backend-settings page. Loaded from
    /_cfc/backend_settings_proxy.js. No inline script in the HTML."""
    backends_json = json.dumps(BACKENDS)
    return r"""(() => {
  const INITIAL_BACKENDS = __BACKENDS_JSON__;
  let backends = JSON.parse(JSON.stringify(INITIAL_BACKENDS));

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? "" : s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/"/g,"&quot;");

  function status(msg, ok) {
    const el = $("status");
    el.textContent = msg;
    el.className = "status " + (ok === false ? "err" : "ok");
  }

  function renderBackends() {
    const list = $("backendList");
    list.innerHTML = "";
    backends.forEach((b, i) => {
      const node = document.createElement("div");
      node.className = "backend";
      node.innerHTML =
        '<div class="grid"><label>Name</label><input class="bn" value="' + esc(b.name||"") + '"></div>' +
        '<div class="grid"><label>Base URL</label><input class="bu" value="' + esc(b.url||"") + '"></div>' +
        '<div class="grid"><label>API Key</label><input class="bk" type="password" value="' + esc(b.key||"") + '"></div>' +
        '<div class="grid"><label>Models</label><textarea class="bm">' + esc((b.models||[]).join(", ")) + '</textarea></div>' +
        '<div class="actions"><button class="secondary bt">Test</button>' +
          (backends.length > 1 ? '<button class="danger br">Remove</button>' : '') +
        '</div>' +
        '<div class="muted bs"></div>';
      const idx = i;
      node.querySelector(".bn").onchange = (e) => { backends[idx].name = e.target.value; };
      node.querySelector(".bu").onchange = (e) => { backends[idx].url  = e.target.value; };
      node.querySelector(".bk").onchange = (e) => { backends[idx].key  = e.target.value; };
      node.querySelector(".bm").onchange = (e) => {
        backends[idx].models = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
      };
      node.querySelector(".bt").onclick = () => testBackend(idx, node.querySelector(".bs"));
      const rm = node.querySelector(".br");
      if (rm) rm.onclick = () => { backends.splice(idx, 1); renderBackends(); };
      list.appendChild(node);
    });
  }

  async function testBackend(i, statusEl) {
    const b = backends[i];
    statusEl.textContent = "Testing...";
    try {
      const headers = b.key ? {"Authorization": "Bearer " + b.key} : {};
      const r = await fetch((b.url || "").replace(/\/v1\/?$/, "") + "/v1/models", { headers });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const d = await r.json();
      const ids = (d.data || []).map((m) => m.id).slice(0, 5).join(", ");
      statusEl.textContent = "Connected! Models: " + (ids || "OK");
    } catch (e) {
      statusEl.textContent = "Failed: " + e.message;
    }
  }

  async function testAll() {
    const nodes = document.querySelectorAll("#backendList .backend");
    for (let i = 0; i < backends.length; i++) {
      await testBackend(i, nodes[i].querySelector(".bs"));
    }
    status("Backend tests complete");
  }

  function resetDefaults() {
    backends = [{ name: "Default", url: "http://127.0.0.1:1234/v1", key: "", models: [], enabled: true, modelAlias: {} }];
    renderBackends();
    status("Defaults restored");
  }

  function clearData() {
    try { localStorage.removeItem("apiBaseUrl"); } catch (e) {}
    status("Local browser routing data cleared");
  }

  async function saveConfig() {
    const identity = {
      apiBaseUrl: $("apiBaseUrl").value,
      authToken:  $("authToken").value,
      mode:       $("mode").value,
    };
    try {
      const br = await fetch("/api/backends", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ backends }),
      });
      const ir = await fetch("/api/identity", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(identity),
      });
      try { localStorage.setItem("apiBaseUrl", identity.apiBaseUrl); } catch (e) {}
      if (br.ok && ir.ok) status("Saved config and connected to extension");
      else status("Save failed", false);
    } catch (e) {
      status("Save failed: " + e.message, false);
    }
  }

  $("btnAddBackend").onclick    = () => { backends.push({ name:"", url:"http://127.0.0.1:1234/v1", key:"", models:[], enabled:true, modelAlias:{} }); renderBackends(); };
  $("btnTestAll").onclick       = testAll;
  $("btnFetchModels").onclick   = testAll;
  $("btnResetDefaults").onclick = resetDefaults;
  $("btnClearData").onclick     = clearData;
  $("btnSaveConfig").onclick    = saveConfig;

  renderBackends();
})();
""".replace("__BACKENDS_JSON__", backends_json)


# ---------------------------------------------------------------------------
# OAuth gate page (cocodem-styled) -- inline JS extracted out
# ---------------------------------------------------------------------------

def authorize_gate_html(query):
    """Cocodem-looking sign-in gate with Enter / Skip. Loads gate JS from
    /_cfc/oauth_authorize_gate.js and reads the query string from the URL."""
    return """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Authenticating...</title>
<style>
body{background:#f9f8f3;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;color:#1d1b16}
.box{background:white;border:1px solid #e5e2d9;border-radius:32px;padding:40px;max-width:420px;width:100%;text-align:center;box-shadow:0 12px 40px rgba(0,0,0,.04)}
.logo{width:72px;height:72px;border-radius:20px;border:1px solid #e5e2d9;margin:0 auto 20px;display:flex;align-items:center;justify-content:center;color:#d97757;font-size:38px}
h1{font-family:"Iowan Old Style",Georgia,serif;font-weight:400;margin:0 0 10px;font-size:28px}
p{color:#6b6651;font-size:14px;line-height:1.5;margin:0 0 24px}
button{height:44px;padding:0 24px;background:#c45f3d;color:white;border:0;border-radius:12px;font-size:15px;font-weight:800;cursor:pointer}
</style>
<script src="/_cfc/oauth_authorize_gate.js" defer></script>
</head>
<body><div class="box">
  <div class="logo">&#10042;</div>
  <h1>Claude in Chrome</h1>
  <p>Local CFC authentication is ready. No real login is required.</p>
  <button id="enter">Enter / Skip</button>
</div></body></html>"""


def oauth_authorize_gate_js():
    """Click handler for the OAuth gate. Reads ?redirect_uri= and ?state=
    from window.location and forwards to /oauth/redirect with them
    preserved. Lives at /_cfc/oauth_authorize_gate.js."""
    return r"""(() => {
  const btn = document.getElementById("enter");
  if (!btn) return;
  btn.addEventListener("click", () => {
    const params = new URLSearchParams(window.location.search);
    const redirectUri = params.get("redirect_uri") || "";
    const state       = params.get("state") || "";
    const u = new URL("/oauth/redirect", window.location.origin);
    if (redirectUri) u.searchParams.set("redirect_uri", redirectUri);
    if (state)       u.searchParams.set("state", state);
    window.location.href = u.toString();
  });
})();
"""


# ---------------------------------------------------------------------------
# Base server's simple landing pages (kept verbatim from the base) - no JS
# ---------------------------------------------------------------------------

def html_page(title, body):
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{title}</title>"
        "<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
        "background:#f9f8f3;color:#2f2a1f;margin:0;padding:32px}"
        ".box{max-width:760px;margin:0 auto;background:white;border:1px solid #e5e2d9;"
        "border-radius:18px;padding:28px;box-shadow:0 10px 30px rgba(0,0,0,.04)}"
        "a,.btn{display:inline-flex;align-items:center;height:40px;padding:0 16px;"
        "background:#c45f3d;color:white;text-decoration:none;border-radius:10px;"
        "font-weight:700;border:0;cursor:pointer}code{background:#f4f1ea;padding:2px 5px;"
        "border-radius:5px}</style></head><body><div class='box'>"
        f"{body}</div></body></html>"
    )


def root_html():
    body = (
        "<h1>CFCBASE Server</h1>"
        f"<p>Local base: <code>{LOCAL_BASE}</code></p>"
        f"<p>Remote base: <code>{REMOTE_BASE}</code></p>"
        "<p>Standalone server -- exposes the CFC route contract without editing request.js.</p>"
        f"<p><a href='{BACKEND_SETTINGS_URL}'>Backend Settings</a></p>"
        "<ul>"
        "<li><code>/api/options</code></li>"
        "<li><code>/api/identity</code></li>"
        "<li><code>/api/backends</code></li>"
        "<li><code>/oauth/authorize</code> and <code>/oauth/redirect</code></li>"
        "<li><code>/v1/*</code> backend proxy</li>"
        "</ul>"
    )
    return html_page("CFCBASE Server", body)


def redirect_html(query):
    """OAuth redirect landing -- the base's static page (no JS).
    The handler still issues a code via the URL so the form-driven authorize
    flow keeps working even with JS disabled."""
    params       = parse_qs(query, keep_blank_values=True)
    redirect_uri = params.get("redirect_uri", [""])[0]
    state        = params.get("state", [""])[0]
    code         = params.get("code", [f"cfc-local-{int(time.time())}"])[0]
    final_uri    = redirect_uri
    if final_uri:
        joiner    = "&" if "?" in final_uri else "?"
        final_uri = final_uri + joiner + urlencode({"code": code, "state": state})
    body = (
        "<h1>Signed in locally</h1>"
        "<p>The CFCBASE server issued a local test code. No remote credentials were requested.</p>"
        f"<p><code>{final_uri or code}</code></p>"
        "<p>You can close this tab.</p>"
    )
    return html_page("Local Redirect", body)


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = f"CFCBASE-FLAT/{STAMP}"

    def log_message(self, fmt, *args):
        try:
            line = fmt % args
        except Exception:
            line = " ".join(str(a) for a in args)
        print(f"[{time.strftime('%H:%M:%S')}] {self.command} {self.path} - {line}")

    # --- response helpers --------------------------------------------------

    def cors(self):
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Cache-Control, Accept, Authorization, x-api-key, "
            "anthropic-version, anthropic-beta, anthropic-client-platform, "
            "anthropic-client-version, x-app, x-service-name",
        )
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age", "86400")

    def send_bytes(self, data, content_type="application/octet-stream", status=200):
        self.send_response(status)
        self.send_header("Content-Type",   content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection",     "close")
        self.cors()
        self.end_headers()
        try:
            self.wfile.write(data)
        except OSError:
            pass

    def send_json(self, data, status=200):
        self.send_bytes(json.dumps(data).encode("utf-8"), "application/json", status)

    def send_html(self, html, status=200):
        self.send_bytes(html.encode("utf-8"), "text/html; charset=utf-8", status)

    def send_js(self, js, status=200):
        self.send_bytes(js.encode("utf-8"), "application/javascript; charset=utf-8", status)

    def send_204(self):
        self.send_response(204)
        self.send_header("Connection", "close")
        self.cors()
        self.end_headers()

    # --- route matchers ----------------------------------------------------

    def is_telemetry(self, path):
        return any(domain in path for domain in TELEMETRY_DOMAINS)

    def is_v1(self, path):
        if "/v1/oauth" in path:
            return False
        return path.startswith("/v1/") or (
            "/v1/" in path and (
                "api.anthropic.com" in path or
                path.startswith("/https://api.anthropic.com/")
            )
        )

    def is_auth(self, path):
        if path.startswith("/https://") or path.startswith("/http://") or path.startswith("/chrome-extension://"):
            return True
        markers = [
            "/oauth/", "/bootstrap", "/domain_info", "/chat_conversations",
            "/organizations", "/url_hash_check", "/api/web/", "/features/",
            "/spotlight", "/usage", "/entitlements", "/flags", "/mcp/v2/",
            "/licenses/",
        ]
        return any(marker in path for marker in markers)

    def serve_static(self, path):
        rel = path.lstrip("/").split("?", 1)[0]
        candidates = []
        if rel == "assets/backend_settings_ui.js":
            candidates.append(GENERATED_ASSETS_DIR / "backend_settings_ui.js")
        if rel.startswith("assets/"):
            candidates.append(GENERATED_ASSETS_DIR / rel[len("assets/"):])
        candidates.append(GENERATED_EXTENSION_DIR / rel)
        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                content_type = mimetypes.guess_type(str(candidate))[0] or "application/octet-stream"
                if candidate.suffix == ".js":  content_type = "application/javascript; charset=utf-8"
                if candidate.suffix == ".css": content_type = "text/css; charset=utf-8"
                self.send_bytes(candidate.read_bytes(), content_type)
                return True
        return False

    def v1_suffix(self, path):
        if path.startswith("/v1/"):
            return path[3:]
        idx = path.find("/v1/")
        if idx >= 0:
            return path[idx + 3:]
        return path

    def read_body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length) if length else b""

    # --- /v1/* forwarding --------------------------------------------------

    def forward_v1(self, method, body):
        """Forward /v1/* to the best available backend with failover.
        Order: exact-model match > catch-all > rest. Per-backend modelAlias
        applied. Per-backend key beats IDENTITY.apiKey beats inbound auth."""
        model = ""
        if body:
            try:
                model = json.loads(body.decode("utf-8")).get("model", "")
            except Exception:
                model = ""
        suffix     = self.v1_suffix(self.path)
        last_error = None
        allowed_headers = {
            "content-type", "accept", "authorization",
            "anthropic-version", "anthropic-beta",
            "anthropic-client-platform", "anthropic-client-version",
            "x-api-key", "x-service-name",
        }
        base_headers = {k: v for k, v in self.headers.items() if k.lower() in allowed_headers}

        for backend in pick_backends(model):
            target  = backend.get("url", DEFAULT_BACKEND_URL).rstrip("/") + suffix
            headers = dict(base_headers)
            if backend.get("key"):
                headers["Authorization"] = "Bearer " + backend["key"]
            elif IDENTITY.get("apiKey"):
                headers["Authorization"] = "Bearer " + IDENTITY["apiKey"]
            send_body = body
            if send_body and method in ("POST", "PUT", "PATCH"):
                try:
                    parsed  = json.loads(send_body.decode("utf-8"))
                    aliases = {**merged_model_aliases(), **(backend.get("modelAlias") or {})}
                    if parsed.get("model") in aliases:
                        parsed["model"] = aliases[parsed["model"]]
                        send_body       = json.dumps(parsed).encode("utf-8")
                except Exception:
                    pass
            try:
                request  = urllib.request.Request(target, data=send_body or None, headers=headers, method=method)
                response = urllib.request.urlopen(request, timeout=300)
                data         = response.read()
                content_type = response.headers.get("Content-Type") or "application/json"
                self.send_bytes(data, content_type, response.status)
                return
            except urllib.error.HTTPError as exc:
                data = exc.read() or b""
                if exc.code < 500:
                    self.send_bytes(data, exc.headers.get("Content-Type") or "application/json", exc.code)
                    return
                last_error = f"HTTP {exc.code}"
            except Exception as exc:
                last_error = str(exc)

        self.send_json({"error": {"type": "proxy_error", "message": "All backends failed. Last: " + str(last_error)}}, 502)

    # --- HTTP verbs --------------------------------------------------------

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Connection", "close")
        self.cors()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path

        # 1. telemetry -- always 204 first
        if self.is_telemetry(self.path):
            self.send_204(); return

        # 2. external JS for our HTML pages (no inline <script> anywhere)
        if path == "/_cfc/backend_settings_proxy.js":
            self.send_js(proxy_backend_settings_js()); return
        if path == "/_cfc/oauth_authorize_gate.js":
            self.send_js(oauth_authorize_gate_js());   return

        # 3. static assets from the generated extension folder (icons / JS / etc)
        if self.serve_static(path):
            return

        # 4. /v1/* API proxy
        if self.is_v1(self.path):
            self.forward_v1("GET", b""); return

        # 5. CFC contract JSON
        if path == "/" or path == "":
            self.send_html(root_html()); return
        if path.startswith("/api/options"):
            self.send_json(options_payload()); return
        if path.startswith("/api/identity"):
            self.send_json(IDENTITY); return
        if path.startswith("/api/backends"):
            self.send_json({"backends": BACKENDS}); return
        if path.startswith("/api/arc-split-view"):
            self.send_json({"html": "<div id='cfc-arc'>Local CFC arc split view</div>"}); return
        if path.startswith("/discard"):
            self.send_204(); return

        # 6. UI pages (12.py-style dark backend settings + cocodem-styled gate)
        if path.startswith("/backend_settings"):
            self.send_html(proxy_backend_settings_html()); return
        if path.startswith("/oauth/authorize"):
            self.send_html(authorize_gate_html(parsed.query)); return
        if path.startswith("/oauth/redirect"):
            self.send_html(redirect_html(parsed.query)); return

        # 7. auth / bootstrap / license
        if self.is_auth(self.path):
            self.send_json(auth_payload(self.path)); return

        # 8. fallback -- never 204 for unknown routes
        self.send_html(html_page("CFCBASE Route", f"<h1>CFCBASE Route</h1><p><code>{self.path}</code></p>"))

    def do_POST(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        body   = self.read_body()

        if self.is_telemetry(self.path):
            self.send_204(); return

        # Identity update -- proxy is source of truth
        if path.startswith("/api/identity"):
            try:
                data = json.loads(body.decode("utf-8") or "{}")
                for key in ["apiBaseUrl", "apiKey", "authToken", "email", "username",
                            "licenseKey", "blockAnalytics", "modelAliases", "mode"]:
                    if key in data:
                        IDENTITY[key] = data[key]
                if not isinstance(IDENTITY.get("modelAliases"), dict):
                    IDENTITY["modelAliases"] = {}
                write_json_file(STATE_IDENTITY_FILE, IDENTITY)
                self.send_json({"ok": True, "identity": IDENTITY})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, 400)
            return

        # Backend list update
        if path.startswith("/api/backends"):
            try:
                data = json.loads(body.decode("utf-8") or "{}")
                bs   = data.get("backends")
                if not isinstance(bs, list) or not bs:
                    raise ValueError("backends must be a non-empty list")
                for b in bs:
                    b.setdefault("name",       "")
                    b.setdefault("url",        DEFAULT_BACKEND_URL)
                    b.setdefault("key",        "")
                    b.setdefault("models",     [])
                    b.setdefault("modelAlias", {})
                    b.setdefault("enabled",    True)
                BACKENDS[:] = bs
                write_json_file(STATE_BACKENDS_FILE, BACKENDS)
                self.send_json({"ok": True, "backends": BACKENDS})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, 400)
            return

        if self.is_v1(self.path):
            self.forward_v1("POST", body); return
        if self.is_auth(self.path):
            self.send_json(auth_payload(self.path)); return
        self.send_json({"ok": True})

    def do_PUT(self):
        body = self.read_body()
        if self.is_v1(self.path):   self.forward_v1("PUT", body);     return
        if self.is_auth(self.path): self.send_json(auth_payload(self.path)); return
        self.send_json({"ok": True})

    def do_PATCH(self):
        body = self.read_body()
        if self.is_v1(self.path):   self.forward_v1("PATCH", body);   return
        if self.is_auth(self.path): self.send_json(auth_payload(self.path)); return
        self.send_json({"ok": True})

    def do_DELETE(self):
        body = self.read_body()
        if self.is_v1(self.path):   self.forward_v1("DELETE", body);  return
        if self.is_auth(self.path): self.send_json(auth_payload(self.path)); return
        self.send_json({"ok": True})


# ---------------------------------------------------------------------------
# Server entry
# ---------------------------------------------------------------------------

class Server(ThreadingMixIn, TCPServer):
    allow_reuse_address = True
    daemon_threads      = True


def main():
    print("=" * 72)
    print(f"Standalone CFCBASE server -- flat build {STAMP}")
    print("=" * 72)
    print("Local:  "          + LOCAL_BASE)
    print("Remote: "          + REMOTE_BASE)
    print("Options: "         + LOCAL_BASE + "api/options")
    print("Identity: "        + LOCAL_BASE + "api/identity")
    print("Backends: "        + LOCAL_BASE + "api/backends")
    print("Backend Settings: " + BACKEND_SETTINGS_URL)
    print("OAuth Authorize: " + LOCAL_BASE + "oauth/authorize")
    print("Identity state:   " + str(STATE_IDENTITY_FILE))
    print("Backends state:   " + str(STATE_BACKENDS_FILE))
    print("Inline scripts:   none (all JS served from /_cfc/*.js)")
    print()
    with Server((LOCAL_BIND, LOCAL_PORT), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print("Server running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping server.")
            server.shutdown()


if __name__ == "__main__":
    main()
