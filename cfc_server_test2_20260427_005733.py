#!/usr/bin/env python3
"""
cfc_server_test2_20260427_005733.py

Full standalone local CFCBASE proxy — no wrappers, no imports from other project files.
Collapses the entire wrapper chain into one file:
  - cfcbase_server_only_20260426_025208.py        (base server)
  - cfcbase_server_proxy_pages_from_12py_*        (OpenClaw backend settings UI + auth gate)
  - cfcbase_server_proxy_pages_12py_*_empty_ui_* (uiNodes:[], ui:{} — 12.py contract)

Changes from the wrapper chain:
  - REMOTE_BASE  -> https://test2.mahnikka.workers.dev/
  - uiNodes      -> []   (no DOM injection; Backend Settings sidebar item is
                          injected by the sanitizer directly into options.html)
  - ui           -> {}
  - apiBaseIncludes -> ["https://api.anthropic.com/v1/"]

Run:
  python3 cfc_server_test2_20260427_005733.py
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

# ── identity ──────────────────────────────────────────────────────────────────

STAMP         = "20260427_005733"
EXTENSION_ID  = "fcoeoabgfenejglbffodgkkbkcdhcgfn"

SCRIPT_PATH   = Path(__file__).resolve()
WORKSPACE_DIR = SCRIPT_PATH.parent

LOCAL_PORT    = int(os.environ.get("CFC_LOCAL_PORT", "8520"))
LOCAL_HOST    = os.environ.get("CFC_LOCAL_HOST", "localhost")
LOCAL_BASE    = f"http://{LOCAL_HOST}:{LOCAL_PORT}/"
LOCAL_BIND    = os.environ.get("CFC_BIND_HOST", "127.0.0.1")

REMOTE_BASE   = os.environ.get(
    "CFC_REMOTE_BASE",
    "https://test2.mahnikka.workers.dev/",
).rstrip("/") + "/"

DEFAULT_BACKEND_URL  = os.environ.get("CFC_DEFAULT_BACKEND_URL", "http://127.0.0.1:1234/v1")
BACKEND_SETTINGS_URL = LOCAL_BASE + "backend_settings"

STATE_DIR            = WORKSPACE_DIR
STATE_IDENTITY_FILE  = STATE_DIR / f"cfc_identity_{STAMP}.json"
STATE_BACKENDS_FILE  = STATE_DIR / f"cfc_backends_{STAMP}.json"

GENERATED_EXTENSION_DIR = WORKSPACE_DIR / f"claude-sanitized-{STAMP}"
GENERATED_ASSETS_DIR    = GENERATED_EXTENSION_DIR / "assets"

USER_UUID = "ac507011-00b5-56c4-b3ec-ad820dbafbc1"
ORG_UUID  = "1b61ee4a-d0ce-50b5-8b67-7eec034d3d08"

# ── telemetry / routing lists ─────────────────────────────────────────────────

TELEMETRY_DOMAINS = [
    "segment.com", "statsig", "statsigapi.net", "honeycomb", "sentry",
    "datadoghq", "featureassets", "assetsconfigcdn", "featuregates",
    "prodregistryv2", "beyondwickedmapping", "fpjs.dev", "openfpcdn.io",
    "api.fpjs.io", "googletagmanager", "googletag",
]

PROXY_INCLUDES = [
    "cdn.segment.com", "featureassets.org", "assetsconfigcdn.org",
    "featuregates.org", "api.segment.io", "prodregistryv2.org",
    "beyondwickedmapping.org", "api.honeycomb.io", "statsigapi.net",
    "events.statsigapi.net", "api.statsigcdn.com", "*ingest.us.sentry.io",
    "https://api.anthropic.com/api/oauth/profile",
    "https://api.anthropic.com/api/bootstrap",
    "https://console.anthropic.com/v1/oauth/token",
    "https://platform.claude.com/v1/oauth/token",
    "https://api.anthropic.com/api/oauth/account",
    "https://api.anthropic.com/api/oauth/organizations",
    "https://api.anthropic.com/api/oauth/chat_conversations",
    "/api/web/domain_info/browser_extension",
    "/api/web/url_hash_check/browser_extension",
]

DISCARD_INCLUDES = [
    "cdn.segment.com", "api.segment.io", "events.statsigapi.net",
    "api.honeycomb.io", "prodregistryv2.org", "*ingest.us.sentry.io",
    "browser-intake-us5-datadoghq.com", "fpjs.dev", "openfpcdn.io",
    "api.fpjs.io", "googletagmanager.com",
]

# ── state ─────────────────────────────────────────────────────────────────────

DEFAULT_IDENTITY = {
    "apiBaseUrl": DEFAULT_BACKEND_URL,
    "apiKey": "", "authToken": "",
    "email": "user@local", "username": "local-user", "licenseKey": "",
    "blockAnalytics": True, "modelAliases": {}, "mode": "",
}

DEFAULT_BACKENDS = [{
    "name": "Default", "url": DEFAULT_BACKEND_URL,
    "key": "", "models": [], "modelAlias": {}, "enabled": True,
}]

def _read_json(path, fallback):
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, type(fallback)):
                return data
        except Exception:
            pass
    return json.loads(json.dumps(fallback))

def _write_json(path, data):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

IDENTITY = _read_json(STATE_IDENTITY_FILE, DEFAULT_IDENTITY)
BACKENDS = _read_json(STATE_BACKENDS_FILE, DEFAULT_BACKENDS)

# ── JWT / token ───────────────────────────────────────────────────────────────

def _b64url(obj):
    return base64.urlsafe_b64encode(
        json.dumps(obj).encode("utf-8")
    ).rstrip(b"=").decode("ascii")

def local_token():
    tok = _b64url({"alg": "none", "typ": "JWT"}) + "." + \
          _b64url({"iss": "cfc", "sub": USER_UUID,
                   "exp": int(time.time()) + 315360000, "iat": 1700000000}) + \
          ".local"
    return {
        "access_token": tok, "token_type": "bearer",
        "expires_in": 315360000, "refresh_token": "local-refresh",
        "scope": "user:profile user:inference user:chat",
    }

# ── profile / bootstrap data ──────────────────────────────────────────────────

LOCAL_ACCOUNT = {
    "uuid": USER_UUID, "id": USER_UUID, "account_uuid": USER_UUID,
    "email_address": "user@local", "email": "user@local",
    "full_name": "Local User", "name": "Local User", "display_name": "Local User",
    "has_password": True, "has_completed_onboarding": True,
    "preferred_language": "en-US", "has_claude_pro": True,
    "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z",
    "settings": {"theme": "system", "language": "en-US"},
}

LOCAL_ORG = {
    "uuid": ORG_UUID, "id": ORG_UUID, "name": "Local CFC", "role": "admin",
    "organization_type": "personal", "billing_type": "local",
    "capabilities": ["chat", "api", "computer_use", "claude_for_chrome"],
    "rate_limit_tier": "local", "settings": {},
    "created_at": "2024-01-01T00:00:00Z",
}

def profile_payload():
    acct = dict(LOCAL_ACCOUNT)
    acct["email_address"] = acct["email"] = IDENTITY.get("email") or "user@local"
    acct["full_name"] = acct["name"] = acct["display_name"] = \
        IDENTITY.get("username") or "Local User"
    return {
        **acct, "account": acct, "organization": LOCAL_ORG,
        "organizations": [LOCAL_ORG],
        "memberships": [{"organization": LOCAL_ORG, "role": "admin",
                         "joined_at": "2024-01-01T00:00:00Z"}],
        "active_organization_uuid": ORG_UUID,
    }

def bootstrap_payload():
    prof = profile_payload()
    return {
        **prof, "account_uuid": USER_UUID,
        "statsig": {
            "user": {"userID": USER_UUID, "custom": {"organization_uuid": ORG_UUID}},
            "values": {"feature_gates": {}, "dynamic_configs": {}, "layer_configs": {}},
        },
        "flags": {}, "features": [], "active_flags": {},
        "active_subscription": {
            "plan": "local_cfc", "status": "active", "type": "local_cfc",
            "billing_period": "none",
            "current_period_start": "2024-01-01T00:00:00Z",
            "current_period_end": "2099-12-31T23:59:59Z",
        },
        "chat_enabled": True,
        "capabilities": ["chat", "api", "computer_use", "claude_for_chrome"],
        "rate_limit_tier": "local",
        "settings": {"theme": "system", "language": "en-US"},
    }

def merged_model_aliases():
    out = {}
    aliases = IDENTITY.get("modelAliases") or {}
    if isinstance(aliases, dict):
        out.update(aliases)
    for b in BACKENDS:
        ba = b.get("modelAlias") or {}
        if b.get("enabled", True) and isinstance(ba, dict):
            out.update(ba)
    return out

# ── options payload (12.py contract: uiNodes:[], ui:{}) ───────────────────────

def options_payload():
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
        "apiBaseIncludes":  ["https://api.anthropic.com/v1/"],
        "proxyIncludes":    list(PROXY_INCLUDES),
        "discardIncludes":  discard,
        "modelAlias":       merged_model_aliases(),
        "ui":               {},
        "uiNodes":          [],
        "blockAnalytics":   bool(IDENTITY.get("blockAnalytics", True)),
    }

# ── auth route handler ────────────────────────────────────────────────────────

def auth_payload(path):
    if "/licenses/verify"        in path: return {"valid": True, "license": "local", "tier": "local", "expires": "2099-12-31"}
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

# ── backend picker ────────────────────────────────────────────────────────────

def pick_backends(model):
    enabled   = [b for b in BACKENDS if b.get("enabled", True)]
    exact     = [b for b in enabled  if b.get("models") and model in b.get("models", [])]
    catch_all = [b for b in enabled  if not b.get("models")]
    preferred = exact or catch_all or enabled
    if not preferred:
        return []
    first = preferred[0]
    rest  = [b for b in enabled if b is not first]
    return [first] + rest

# ── HTML pages ────────────────────────────────────────────────────────────────

def _page(title, body):
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{title}</title>"
        "<style>*{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"
        "'Segoe UI',sans-serif;background:#f9f8f3;color:#2f2a1f;margin:0;padding:32px}"
        ".box{max-width:760px;margin:0 auto;background:white;border:1px solid #e5e2d9;"
        "border-radius:18px;padding:28px}code{background:#f4f1ea;padding:2px 5px;"
        "border-radius:5px}a,.btn{display:inline-flex;align-items:center;height:40px;"
        "padding:0 16px;background:#c45f3d;color:white;text-decoration:none;"
        "border-radius:10px;font-weight:700;border:0;cursor:pointer}</style></head>"
        f"<body><div class='box'>{body}</div></body></html>"
    )

def root_html():
    return _page("CFCBASE Server",
        "<h1>CFCBASE Server</h1>"
        f"<p>Local: <code>{LOCAL_BASE}</code> &nbsp; Remote: <code>{REMOTE_BASE}</code></p>"
        f"<p><a href='{BACKEND_SETTINGS_URL}'>Backend Settings</a></p>"
        "<ul><li><code>/api/options</code> — uiNodes:[], ui:{}</li>"
        "<li><code>/oauth/authorize</code> &amp; <code>/oauth/redirect</code></li>"
        "<li><code>/v1/*</code> — proxied to configured backend</li>"
        "<li>All auth routes answered locally</li></ul>"
    )

def backend_settings_html():
    backends_json = json.dumps(BACKENDS)
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
input:focus,textarea:focus{{outline:none;box-shadow:0 0 0 2px rgba(239,69,101,.15)}}
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
.muted{{color:#7f82a8}}
</style></head>
<body><div class="wrap">
  <h1>OpenClaw — Backend Setup</h1>
  <p class="sub">Configure backends · test connections · connect to extension</p>
  <div id="status" class="status"></div>
  <section class="panel">
    <h2>API Backends</h2>
    <div id="backendList"></div>
    <button class="secondary" onclick="addBackend()">+ Add Backend</button>
  </section>
  <section class="panel">
    <h2>Extension Routing &amp; Auth Bypass</h2>
    <div class="grid"><label>cfcBase URL</label><input id="cfcBase" value="{LOCAL_BASE}" readonly></div>
    <div class="grid"><label>apiBaseUrl</label><input id="apiBaseUrl" value="{IDENTITY.get('apiBaseUrl') or DEFAULT_BACKEND_URL}"></div>
    <div class="grid"><label>Mode</label>
      <select id="mode">
        <option value="">api — local / custom backend</option>
        <option value="claude">claude — official</option>
      </select>
    </div>
    <div class="grid"><label>Access Token</label><input id="authToken" value="{IDENTITY.get('authToken','')}" placeholder="blank = auto-generate bypass token"></div>
  </section>
  <section class="panel">
    <h2>Quick Actions</h2>
    <div class="actions">
      <button onclick="testAll()">Test All Backends</button>
      <button onclick="fetchModels()">Fetch All Models</button>
      <button class="secondary" onclick="resetDefaults()">Reset to Defaults</button>
      <button class="danger" onclick="clearData()">Clear Browser Data</button>
    </div>
  </section>
  <section class="panel">
    <h2>Architecture</h2>
    <div class="arch">
      <b>Local CFCBASE:</b> {LOCAL_BASE}<br>
      <b>Remote Worker:</b> {REMOTE_BASE}<br>
      <b>Default Backend:</b> {DEFAULT_BACKEND_URL}<br><br>
      <code>uiNodes: []</code> — Backend Settings injected by sanitizer, not uiNodes.<br>
      <code>ui: {{}}</code> — No DOM injection from options payload.
    </div>
  </section>
  <button class="save" onclick="saveConfig()">Save Config &amp; Connect to Extension →</button>
</div>
<script>
let backends = {backends_json};
function esc(s){{return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/"/g,"&quot;")}}
function showStatus(msg,ok){{const el=document.getElementById("status");el.textContent=msg;el.className="status "+(ok?"ok":"err")}}
function renderBackends(){{
  const list=document.getElementById("backendList");
  list.innerHTML=backends.map((b,i)=>`<div class="backend">
    <div class="grid"><label>Name</label><input value="${{esc(b.name)}}" onchange="backends[${{i}}].name=this.value"></div>
    <div class="grid"><label>Base URL</label><input value="${{esc(b.url)}}" onchange="backends[${{i}}].url=this.value"></div>
    <div class="grid"><label>API Key</label><input type="password" value="${{esc(b.key||"")}}" onchange="backends[${{i}}].key=this.value"></div>
    <div class="grid"><label>Models (csv)</label><textarea onchange="backends[${{i}}].models=this.value.split(',').map(x=>x.trim()).filter(Boolean)">${{esc((b.models||[]).join(", "))}}</textarea></div>
    <div class="actions">
      <button class="secondary" onclick="testBackend(${{i}})">Test</button>
      ${{backends.length>1?`<button class="danger" onclick="removeBackend(${{i}})">Remove</button>`:""}}
    </div>
    <div class="muted" id="bs${{i}}"></div>
  </div>`).join("");
}}
function addBackend(){{backends.push({{name:"",url:"http://127.0.0.1:1234/v1",key:"",models:[],enabled:true,modelAlias:{{}}}});renderBackends()}}
function removeBackend(i){{backends.splice(i,1);renderBackends()}}
async function testBackend(i){{
  const b=backends[i],el=document.getElementById("bs"+i);
  el.textContent="Testing...";
  try{{
    const h=b.key?{{Authorization:"Bearer "+b.key}}:{{}};
    const r=await fetch((b.url||"").replace(/\/v1\/?$/,"")+"/v1/models",{{headers:h}});
    if(!r.ok) throw new Error("HTTP "+r.status);
    const d=await r.json();
    el.textContent="OK — models: "+((d.data||[]).map(m=>m.id).slice(0,5).join(", ")||"(none listed)");
  }}catch(e){{el.textContent="Failed: "+e.message}}
}}
async function testAll(){{for(let i=0;i<backends.length;i++) await testBackend(i);showStatus("All tests done",true)}}
async function fetchModels(){{await testAll()}}
function resetDefaults(){{backends=[{{name:"Default",url:"http://127.0.0.1:1234/v1",key:"",models:[],enabled:true,modelAlias:{{}}}}];renderBackends();showStatus("Defaults restored",true)}}
function clearData(){{localStorage.removeItem("apiBaseUrl");showStatus("Local browser routing cleared",true)}}
async function saveConfig(){{
  const identity={{
    apiBaseUrl:document.getElementById("apiBaseUrl").value,
    authToken:document.getElementById("authToken").value,
    mode:document.getElementById("mode").value
  }};
  const [br,ir]=await Promise.all([
    fetch("/api/backends",{{method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify({{backends}})}}),
    fetch("/api/identity",{{method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify(identity)}})
  ]);
  localStorage.setItem("apiBaseUrl",identity.apiBaseUrl);
  showStatus(br.ok&&ir.ok?"Saved and connected to extension":"Save failed — check server logs",br.ok&&ir.ok);
}}
renderBackends();
</script></body></html>"""

def authorize_html(query):
    params      = parse_qs(query, keep_blank_values=True)
    redirect_uri = params.get("redirect_uri", [""])[0]
    state        = params.get("state", [""])[0]
    next_url     = LOCAL_BASE + "oauth/redirect"
    sep = "&" if "?" in next_url else "?"
    if redirect_uri: next_url += sep + "redirect_uri=" + redirect_uri; sep = "&"
    if state:        next_url += sep + "state=" + state
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Claude in Chrome</title>
<style>
body{{background:#f9f8f3;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;color:#1d1b16}}
.box{{background:white;border:1px solid #e5e2d9;border-radius:32px;padding:40px;max-width:420px;width:100%;text-align:center}}
.logo{{width:72px;height:72px;border-radius:20px;border:1px solid #e5e2d9;margin:0 auto 20px;display:flex;align-items:center;justify-content:center;color:#d97757;font-size:38px}}
h1{{font-family:Georgia,serif;font-weight:400;margin:0 0 10px;font-size:28px}}
p{{color:#6b6651;font-size:14px;line-height:1.5;margin:0 0 24px}}
button{{height:44px;padding:0 24px;background:#c45f3d;color:white;border:0;border-radius:12px;font-size:15px;font-weight:800;cursor:pointer}}
</style></head>
<body><div class="box">
  <div class="logo">✺</div>
  <h1>Claude in Chrome</h1>
  <p>Local CFC authentication. No real login required.</p>
  <button onclick="location.href={json.dumps(next_url)}">Enter / Skip</button>
</div></body></html>"""

def redirect_html(query):
    params       = parse_qs(query, keep_blank_values=True)
    redirect_uri = params.get("redirect_uri", [""])[0]
    state        = params.get("state", [""])[0]
    code         = params.get("code",  [f"cfc-local-{int(time.time())}"])[0]
    final_uri    = redirect_uri
    if final_uri:
        joiner = "&" if "?" in final_uri else "?"
        final_uri += joiner + urlencode({"code": code, "state": state})
    tok = local_token()
    storage = {
        "accessToken": tok["access_token"], "refreshToken": tok["refresh_token"],
        "tokenExpiry": int(time.time() * 1000) + 31536000000,
        "accountUuid": USER_UUID,
        "sidepanelToken": code,
        "sidepanelTokenExpiry": int(time.time() * 1000) + 31536000000,
        "ANTHROPIC_BASE_URL": IDENTITY.get("apiBaseUrl") or DEFAULT_BACKEND_URL,
        "ANTHROPIC_API_KEY": IDENTITY.get("apiKey") or "",
        "ANTHROPIC_AUTH_TOKEN": IDENTITY.get("authToken") or "",
        "email": IDENTITY.get("email") or "user@local",
        "username": IDENTITY.get("username") or "local-user",
        "licenseKey": IDENTITY.get("licenseKey") or "",
        "hijackSettings": {
            "backendUrl": IDENTITY.get("apiBaseUrl") or DEFAULT_BACKEND_URL,
            "modelAliases": merged_model_aliases(),
            "blockAnalytics": True,
        },
    }
    storage_js  = json.dumps(storage)
    final_uri_js = json.dumps(final_uri)
    ext_id_js   = json.dumps(EXTENSION_ID)
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Signed In</title>
<style>
body{{background:#f9f8f3;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;color:#1d1b16}}
.box{{background:white;border:1px solid #e5e2d9;border-radius:32px;padding:40px;max-width:520px;width:100%;text-align:center}}
h1{{font-family:Georgia,serif;font-weight:400;margin:0 0 10px;font-size:28px}}
#msg{{color:#6b6651;font-size:14px;line-height:1.5;margin:0 0 12px}}
</style></head>
<body><div class="box">
  <h1>Signed in!</h1>
  <p id="msg">Writing local state to extension...</p>
</div>
<script>
(function(){{
  var eid={ext_id_js}, storage={storage_js}, finalUri={final_uri_js};
  var msg=document.getElementById("msg");
  function done(text,ok){{msg.textContent=text;msg.style.color=ok?"#2d6a4f":"#b04a3d";if(ok&&finalUri)setTimeout(function(){{location.href=finalUri}},350);}}
  try{{
    if(typeof chrome!=="undefined"&&chrome.runtime&&chrome.runtime.sendMessage){{
      chrome.runtime.sendMessage(eid,{{type:"_set_storage_local",data:storage}},function(){{
        if(chrome.runtime.lastError){{done("Storage write failed: "+chrome.runtime.lastError.message,false);return;}}
        done("Done! Loading sidepanel...",true);
      }});
    }}else{{done("Chrome extension messaging unavailable.",false);}}
  }}catch(e){{done("Error: "+e.message,false);}}
}})();
<\/script></body></html>"""

# ── HTTP handler ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    server_version = f"CFCBASE/{STAMP}"

    def log_message(self, fmt, *args):
        sys_msg = fmt % args
        import sys
        sys.stderr.write(f"[{time.strftime('%H:%M:%S')}] {self.command} {self.path} {sys_msg}\n")
        sys.stderr.flush()

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers",
            "Content-Type,Cache-Control,Accept,Authorization,x-api-key,"
            "anthropic-version,anthropic-beta,anthropic-client-platform,"
            "anthropic-client-version,x-app,x-service-name")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age", "86400")

    def _send(self, data, ct="application/octet-stream", status=200):
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self._cors()
        self.end_headers()
        try:   self.wfile.write(data)
        except OSError: pass

    def _json(self, obj, status=200):
        import sys
        try:
            self._send(json.dumps(obj).encode("utf-8"), "application/json", status)
        except Exception as e:
            sys.stderr.write(f"[HANDLER-ERROR] _json failed: {e}\n"); sys.stderr.flush()

    def _html(self, body, status=200):
        self._send(body.encode("utf-8"), "text/html; charset=utf-8", status)

    def _204(self):
        self.send_response(204)
        self.send_header("Connection", "close")
        self._cors()
        self.end_headers()

    def _is_tel(self, p):
        return any(d in p for d in TELEMETRY_DOMAINS)

    def _is_v1(self, p):
        if "/v1/oauth" in p: return False
        return p.startswith("/v1/") or ("/v1/" in p and
            ("api.anthropic.com" in p or p.startswith("/https://api.anthropic.com/")))

    def _is_auth(self, p):
        if p.startswith(("/https://", "/http://", "/chrome-extension://")): return True
        return any(m in p for m in [
            "/oauth/", "/bootstrap", "/domain_info", "/chat_conversations",
            "/organizations", "/url_hash_check", "/api/web/", "/features/",
            "/spotlight", "/usage", "/entitlements", "/flags", "/mcp/v2/", "/licenses/",
        ])

    def _serve_static(self, path):
        rel = path.lstrip("/").split("?", 1)[0]
        candidates = []
        if rel == "assets/backend_settings_ui.js":
            candidates.append(GENERATED_ASSETS_DIR / "backend_settings_ui.js")
        if rel.startswith("assets/"):
            candidates.append(GENERATED_ASSETS_DIR / rel[len("assets/"):])
        candidates.append(GENERATED_EXTENSION_DIR / rel)
        for c in candidates:
            if c.exists() and c.is_file():
                ct = mimetypes.guess_type(str(c))[0] or "application/octet-stream"
                if c.suffix == ".js":  ct = "application/javascript; charset=utf-8"
                if c.suffix == ".css": ct = "text/css; charset=utf-8"
                self._send(c.read_bytes(), ct)
                return True
        return False

    def _v1_suffix(self, path):
        if path.startswith("/v1/"): return path[3:]
        idx = path.find("/v1/")
        return path[idx + 3:] if idx >= 0 else path

    def _body(self):
        n = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(n) if n else b""

    def _forward_v1(self, method, body):
        import sys, traceback
        model = ""
        if body:
            try: model = json.loads(body.decode("utf-8")).get("model", "")
            except: pass
        suffix  = self._v1_suffix(self.path)
        allowed = {"content-type","accept","authorization","anthropic-version",
                   "anthropic-beta","anthropic-client-platform","anthropic-client-version",
                   "x-api-key","x-service-name"}
        base_hdrs = {k: v for k, v in self.headers.items() if k.lower() in allowed}
        last_err  = None
        for backend in pick_backends(model):
            target = backend.get("url", DEFAULT_BACKEND_URL).rstrip("/") + suffix
            hdrs   = dict(base_hdrs)
            if backend.get("key"):        hdrs["Authorization"] = "Bearer " + backend["key"]
            elif IDENTITY.get("apiKey"):  hdrs["Authorization"] = "Bearer " + IDENTITY["apiKey"]
            send_body = body
            if send_body and method in ("POST", "PUT", "PATCH"):
                try:
                    parsed = json.loads(send_body.decode("utf-8"))
                    aliases = {**merged_model_aliases(), **(backend.get("modelAlias") or {})}
                    if parsed.get("model") in aliases:
                        parsed["model"] = aliases[parsed["model"]]
                        send_body = json.dumps(parsed).encode("utf-8")
                except: pass
            try:
                req  = urllib.request.Request(target, data=send_body or None,
                                              headers=hdrs, method=method)
                resp = urllib.request.urlopen(req, timeout=300)
                data = resp.read()
                self._send(data, resp.headers.get("Content-Type") or "application/json", resp.status)
                return
            except urllib.error.HTTPError as e:
                data = e.read() or b""
                if e.code < 500:
                    self._send(data, e.headers.get("Content-Type") or "application/json", e.code)
                    return
                last_err = f"HTTP {e.code}"
            except Exception as e:
                err = f"{type(e).__name__}: {e}"
                sys.stderr.write(f"[PROXY-ERROR] {err}\n{traceback.format_exc()}\n")
                sys.stderr.flush()
                last_err = err
        self._json({"error": {"type": "proxy_error",
                              "message": "All backends failed. Last: " + str(last_err)}}, 502)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Connection", "close")
        self._cors()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        if self._is_tel(self.path):               self._204();                             return
        if self._serve_static(path):                                                        return
        if self._is_v1(self.path):                self._forward_v1("GET", b"");            return
        if path in ("/", ""):                     self._html(root_html());                 return
        if path.startswith("/api/options"):       self._json(options_payload());           return
        if path.startswith("/api/identity"):      self._json(IDENTITY);                   return
        if path.startswith("/api/backends"):      self._json({"backends": BACKENDS});     return
        if path.startswith("/api/arc-split-view"):self._json({"html": "<div>arc</div>"}); return
        if path.startswith("/discard"):           self._204();                             return
        if path.startswith("/backend_settings"):  self._html(backend_settings_html());    return
        if path.startswith("/oauth/authorize"):   self._html(authorize_html(parsed.query)); return
        if path.startswith("/oauth/redirect"):    self._html(redirect_html(parsed.query)); return
        if self._is_auth(self.path):              self._json(auth_payload(self.path));    return
        self._html(_page("CFCBASE", f"<h1>CFCBASE</h1><p><code>{self.path}</code></p>"))

    def do_POST(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        body   = self._body()
        if self._is_tel(self.path): self._204(); return
        if path.startswith("/api/identity"):
            try:
                data = json.loads(body.decode("utf-8") or "{}")
                for k in ["apiBaseUrl","apiKey","authToken","email","username",
                          "licenseKey","blockAnalytics","modelAliases","mode"]:
                    if k in data: IDENTITY[k] = data[k]
                if not isinstance(IDENTITY.get("modelAliases"), dict): IDENTITY["modelAliases"] = {}
                _write_json(STATE_IDENTITY_FILE, IDENTITY)
                self._json({"ok": True, "identity": IDENTITY})
            except Exception as e: self._json({"ok": False, "error": str(e)}, 400)
            return
        if path.startswith("/api/backends"):
            try:
                data = json.loads(body.decode("utf-8") or "{}")
                bks  = data.get("backends")
                if not isinstance(bks, list) or not bks: raise ValueError("backends must be a non-empty list")
                for b in bks:
                    b.setdefault("name", ""); b.setdefault("url", DEFAULT_BACKEND_URL)
                    b.setdefault("key", ""); b.setdefault("models", [])
                    b.setdefault("modelAlias", {}); b.setdefault("enabled", True)
                BACKENDS[:] = bks
                _write_json(STATE_BACKENDS_FILE, BACKENDS)
                self._json({"ok": True, "backends": BACKENDS})
            except Exception as e: self._json({"ok": False, "error": str(e)}, 400)
            return
        if self._is_v1(self.path): self._forward_v1("POST", body); return
        if self._is_auth(self.path): self._json(auth_payload(self.path)); return
        self._json({"ok": True})

    def do_PUT(self):
        body = self._body()
        if self._is_v1(self.path):   self._forward_v1("PUT", body); return
        if self._is_auth(self.path): self._json(auth_payload(self.path)); return
        self._json({"ok": True})

    def do_PATCH(self):
        body = self._body()
        if self._is_v1(self.path):   self._forward_v1("PATCH", body); return
        if self._is_auth(self.path): self._json(auth_payload(self.path)); return
        self._json({"ok": True})

    def do_DELETE(self):
        body = self._body()
        if self._is_v1(self.path):   self._forward_v1("DELETE", body); return
        if self._is_auth(self.path): self._json(auth_payload(self.path)); return
        self._json({"ok": True})


# ── server + main ─────────────────────────────────────────────────────────────

class Server(ThreadingMixIn, TCPServer):
    allow_reuse_address = True
    daemon_threads      = True


def main():
    import sys
    print("=" * 72)
    print(f"  CFCBASE standalone server  [{STAMP}]")
    print("=" * 72)
    print(f"  Local:            {LOCAL_BASE}")
    print(f"  Remote Worker:    {REMOTE_BASE}")
    print(f"  Backend Settings: {BACKEND_SETTINGS_URL}")
    print(f"  Default backend:  {DEFAULT_BACKEND_URL}")
    print(f"  uiNodes: []  ui: {{}}  (12.py contract)")
    print(f"  Identity file:    {STATE_IDENTITY_FILE}")
    print(f"  Backends file:    {STATE_BACKENDS_FILE}")
    print()
    with Server((LOCAL_BIND, LOCAL_PORT), Handler) as server:
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        print(f"  Server running on {LOCAL_BASE}  (Ctrl+C to stop)\n")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            print("\n[Server] Shutting down...")
            server.shutdown()


if __name__ == "__main__":
    main()
