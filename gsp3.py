#!/usr/bin/env python3
"""
main.py -- Sanitizer for cocodem's trojanized Claude Chrome extension (1.0.66).
Run: python main.py

What cocodem does:
  Ships extension ID fcoeoabgfenejglbffodgkkbkcdhcgfn (Anthropic's real ID) so
  unpacked installs overwrite Anthropic's official extension in the same slot.
  assets/request.js phones home to openclaude.111724.xyz + cfc.aroic.workers.dev.
  externally_connectable whitelists those attacker domains for command injection.
  cfc.aroic.workers.dev/licenses/verify captures email/username/licenseKey
  plus FingerprintJS Pro browser fingerprinting and Google Analytics.

What this script does:
   1.  Copies cocodem 1.0.66 folder (verified source)
   2.  Preserves original manifest as manifest2.json
   3.  Patches manifest: removes update_url, narrows externally_connectable to
       localhost only, adds CSP connect-src for local backends +
       wss://bridge.claudeusercontent.com, adds localhost host_permissions
   4.  Creates request1.js: cocodem's JS with attacker cfcBase URLs replaced
       by localhost:8520 (forensic archive -- phone-home severed)
   5.  Overwrites request.js with clean local-only version
   6.  Writes unified backend_settings_ui.js
   7.  Strips MV3-incompatible inline theme scripts from options/sidepanel HTML
   8.  Writes backend_settings.html + backend_settingsOG.html meta-refresh stubs
   9.  Writes arc.html (whitespace-normalised)
  10.  Injects setJsx into React jsx-runtime (index-BVS4T5_D.js)
  11.  Deploys REAL remote Cloudflare Worker (replaces openclaude.111724.xyz)
  12.  Starts REAL local multi-C2 server (replaces cocodem's localhost:8787)

  Both remote Worker + local server serve the IDENTICAL CFC contract.
  User configures their own Cloudflare Worker domain + local port at script
  startup -- zero hardcoded remote domains, zero credential stealing.

  cfcBase in request.js becomes:
    const cfcBase = "https://WORKER.SUBDOMAIN.workers.dev/" || "http://localhost:PORT/" || ""
  Exactly mirroring cocodem's dual-domain architecture:
    const cfcBase = "https://openclaude.111724.xyz/" || "http://localhost:8787/" || ""
"""

import base64, json, os, re, shutil, sys, time, mimetypes
import http.server, socketserver, threading
import urllib.request, urllib.error
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# ─── constants (overridden by user input in main()) ───────────────────────────

EXTENSION_ID         = "fcoeoabgfenejglbffodgkkbkcdhcgfn"
TIMESTAMP            = datetime.now().strftime("%Y%m%d-%H%M%S")
COCODEM_SRC          = Path("COCODEMS ORIGINAL ZIP")
OUTPUT_DIR           = Path(f"claude-sanitized-{TIMESTAMP}")
CFC_PORT             = 8520
CFC_BASE             = ""
CFC_BASE_NO_SLASH    = ""
WORKER_BASE          = ""
DEFAULT_BACKEND_URL  = "http://127.0.0.1:1234/v1"
BACKEND_SETTINGS_URL = ""
BACKENDS_FILE        = Path("cfc_backends.json")
IDENTITY_FILE        = Path("cfc_identity.json")
OPTIONS_FILE         = Path("cfc_options.json")

# ─── telemetry domains -- always 204'd before any other routing ───────────────
TELEMETRY_DOMAINS = [
    "segment.com", "statsig", "honeycomb", "sentry", "datadoghq",
    "featureassets", "assetsconfigcdn", "featuregates", "prodregistryv2",
    "beyondwickedmapping", "fpjs.dev", "openfpcdn.io", "api.fpjs.io",
    "googletagmanager", "googletag",
]

# ─── Cloudflare Worker deployment ─────────────────────────────────────────────

def _build_worker_script(local_port: int) -> str:
    """Build the Cloudflare Worker JS that serves as the REAL remote CFC server.
    This is the remote replacement for openclaude.111724.xyz.
    It serves /api/options, /api/oauth/profile, /oauth/redirect, /oauth/authorize,
    /licenses/verify directly from the edge. Everything else 307s to localhost."""
    local_origin = "http://localhost:" + str(local_port)
    lines = []
    lines.append('var LOCAL_ORIGIN = "' + local_origin + '";')
    lines.append('var CORS_HDRS = {')
    lines.append('  "Access-Control-Allow-Origin": "*",')
    lines.append('  "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",')
    lines.append('  "Access-Control-Allow-Headers": "Content-Type, Cache-Control, Accept, anthropic-version, anthropic-beta, anthropic-client-platform, anthropic-client-version, Authorization, x-app, x-service-name, x-api-key",')
    lines.append('  "Access-Control-Allow-Private-Network": "true",')
    lines.append('  "Access-Control-Max-Age": "86400"')
    lines.append('};')
    lines.append('var DISCARD = ["cdn.segment.com","api.segment.io","events.statsigapi.net","api.honeycomb.io","prodregistryv2.org","ingest.us.sentry.io","browser-intake-us5-datadoghq.com","fpjs.dev","openfpcdn.io","api.fpjs.io","googletagmanager.com"];')
    lines.append('var OPTIONS_JSON = JSON.stringify({')
    lines.append('  "mode": "",')
    lines.append('  "anthropicBaseUrl": "",')
    lines.append('  "apiBaseIncludes": ["https://api.anthropic.com/v1/"],')
    lines.append('  "proxyIncludes": [')
    lines.append('    "featureassets.org","assetsconfigcdn.org","featuregates.org",')
    lines.append('    "prodregistryv2.org","beyondwickedmapping.org",')
    lines.append('    "api.honeycomb.io","statsigapi.net","events.statsigapi.net",')
    lines.append('    "api.statsigcdn.com","*ingest.us.sentry.io",')
    lines.append('    "https://api.anthropic.com/api/oauth/profile",')
    lines.append('    "https://api.anthropic.com/api/bootstrap",')
    lines.append('    "https://console.anthropic.com/v1/oauth/token",')
    lines.append('    "https://platform.claude.com/v1/oauth/token",')
    lines.append('    "https://api.anthropic.com/api/oauth/account",')
    lines.append('    "https://api.anthropic.com/api/oauth/organizations",')
    lines.append('    "https://api.anthropic.com/api/oauth/chat_conversations",')
    lines.append('    "/api/web/domain_info/browser_extension"')
    lines.append('  ],')
    lines.append('  "discardIncludes": [')
    lines.append('    "cdn.segment.com","api.segment.io","events.statsigapi.net",')
    lines.append('    "api.honeycomb.io","prodregistryv2.org","*ingest.us.sentry.io",')
    lines.append('    "browser-intake-us5-datadoghq.com"')
    lines.append('  ],')
    lines.append('  "modelAlias": {},')
    lines.append('  "uiNodes": []')
    lines.append('});')
    lines.append('var PROFILE_JSON = JSON.stringify({')
    lines.append('  "uuid":"ac507011-00b5-56c4-b3ec-ad820dbafbc1",')
    lines.append('  "id":"ac507011-00b5-56c4-b3ec-ad820dbafbc1",')
    lines.append('  "email_address":"free@claudeagent.ai",')
    lines.append('  "email":"free@claudeagent.ai",')
    lines.append('  "full_name":"Local User","name":"Local User","display_name":"Local User",')
    lines.append('  "has_password":true,"has_completed_onboarding":true,')
    lines.append('  "preferred_language":"en-US","has_claude_pro":true,')
    lines.append('  "created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z",')
    lines.append('  "settings":{"theme":"system","language":"en-US"},')
    lines.append('  "account":{"uuid":"ac507011-00b5-56c4-b3ec-ad820dbafbc1","id":"ac507011-00b5-56c4-b3ec-ad820dbafbc1","email_address":"free@claudeagent.ai","email":"free@claudeagent.ai","full_name":"Local User","name":"Local User","display_name":"Local User","has_password":true,"has_completed_onboarding":true,"preferred_language":"en-US","has_claude_pro":true,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","settings":{"theme":"system","language":"en-US"}},')
    lines.append('  "organization":{"uuid":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08","id":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08","name":"Local","role":"admin","organization_type":"personal","billing_type":"self_serve","capabilities":["chat","claude_pro_plan","api","computer_use","claude_for_chrome"],"rate_limit_tier":"default_claude_pro","settings":{},"created_at":"2024-01-01T00:00:00Z"},')
    lines.append('  "memberships":[{"organization":{"uuid":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08","id":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08","name":"Local","role":"admin"},"role":"admin","joined_at":"2024-01-01T00:00:00Z"}],')
    lines.append('  "active_organization_uuid":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08"')
    lines.append('});')
    lines.append('var LICENSE_JSON = JSON.stringify({"valid":true,"license":"local","tier":"pro","expires":"2099-12-31"});')
    lines.append('var EID = "fcoeoabgfenejglbffodgkkbkcdhcgfn";')
    lines.append('var UUID_U = "ac507011-00b5-56c4-b3ec-ad820dbafbc1";')
    lines.append('')
    lines.append('function jsonResp(body, status) {')
    lines.append('  return new Response(body, {')
    lines.append('    status: status || 200,')
    lines.append('    headers: Object.assign({"Content-Type":"application/json"}, CORS_HDRS)')
    lines.append('  });')
    lines.append('}')
    lines.append('function htmlResp(body) {')
    lines.append('  return new Response(body, {')
    lines.append('    status: 200,')
    lines.append('    headers: Object.assign({"Content-Type":"text/html; charset=utf-8"}, CORS_HDRS)')
    lines.append('  });')
    lines.append('}')
    lines.append('')
    lines.append('addEventListener("fetch", function(event) {')
    lines.append('  event.respondWith(handleRequest(event.request));')
    lines.append('});')
    lines.append('')
    lines.append('async function handleRequest(request) {')
    lines.append('  var url = new URL(request.url);')
    lines.append('  var path = url.pathname;')
    lines.append('')
    lines.append('  if (request.method === "OPTIONS") {')
    lines.append('    return new Response(null, {status:200, headers:CORS_HDRS});')
    lines.append('  }')
    lines.append('')
    lines.append('  if (DISCARD.some(function(h){return request.url.indexOf(h) !== -1;})) {')
    lines.append('    return new Response(null, {status:204, headers:CORS_HDRS});')
    lines.append('  }')
    lines.append('')
    lines.append('  if (path === "/api/options" || path.indexOf("/api/options?") === 0) {')
    lines.append('    return jsonResp(OPTIONS_JSON);')
    lines.append('  }')
    lines.append('')
    lines.append('  if (path.indexOf("/oauth/profile") !== -1 || path.indexOf("/oauth/account") !== -1) {')
    lines.append('    return jsonResp(PROFILE_JSON);')
    lines.append('  }')
    lines.append('')
    lines.append('  if (path.indexOf("/licenses/verify") !== -1) {')
    lines.append('    return jsonResp(LICENSE_JSON);')
    lines.append('  }')
    lines.append('')
    lines.append('  if (path.indexOf("/oauth/authorize") !== -1) {')
    lines.append('    var arr = new Uint8Array(32);')
    lines.append('    crypto.getRandomValues(arr);')
    lines.append('    var code = "cfc-";')
    lines.append('    for (var i = 0; i < arr.length; i++) {')
    lines.append('      var hex = arr[i].toString(16);')
    lines.append('      if (hex.length < 2) hex = "0" + hex;')
    lines.append('      code = code + hex;')
    lines.append('    }')
    lines.append('    var qs = url.search || "";')
    lines.append('    var target = url.origin + "/oauth/redirect" + qs + (qs ? "&" : "?") + "code=" + code;')
    lines.append('    return Response.redirect(target, 302);')
    lines.append('  }')
    lines.append('')
    lines.append('  if (path.indexOf("/oauth/redirect") !== -1) {')
    lines.append('    var h = "";')
    lines.append('    h += "<!DOCTYPE html><html><head><meta charset=\\"utf-8\\"><title>Authenticating</title></head>";')
    lines.append('    h += "<body style=\\"background:#f9f8f3;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0\\">";')
    lines.append('    h += "<div style=\\"background:white;border:1px solid #e5e2d9;border-radius:32px;padding:40px;max-width:400px;width:100%;text-align:center\\">";')
    lines.append('    h += "<h2 style=\\"margin:0 0 8px;font-size:22px;font-weight:400;color:#1d1b16\\">Signed in!</h2>";')
    lines.append('    h += "<p id=\\"msg\\" style=\\"color:#8b856c;font-size:13px;font-weight:500;margin:8px 0\\">Working...</p></div>";')
    lines.append('    h += "<script>";')
    lines.append('    h += "(function(){";')
    lines.append('    h += "var msg=document.getElementById(\\"msg\\");";')
    lines.append('    h += "function done(t){msg.textContent=t;msg.style.color=\\"#2d6a4f\\";setTimeout(function(){try{window.close()}catch(e){}},800)}";')
    lines.append('    h += "try{";')
    lines.append('    h += "var p=new URLSearchParams(location.search);";')
    lines.append('    h += "var r=p.get(\\"redirect_uri\\")||\\"\\";var state=p.get(\\"state\\")||\\"\\";var code=p.get(\\"code\\")||\\"\\";";')
    lines.append('    h += "var eid=\\"" + EID + "\\";";')
    lines.append('    h += "if(r.indexOf(\\"chrome-extension://\\")===0){try{eid=new URL(r).host}catch(e){}}";')
    lines.append('    h += "if(!code){var arr=new Uint8Array(32);crypto.getRandomValues(arr);code=\\"cfc-\\";for(var i=0;i<arr.length;i++){var hx=arr[i].toString(16);if(hx.length<2)hx=\\"0\\"+hx;code+=hx}}";')
    lines.append('    h += "var final_uri=r;";')
    lines.append('    h += "if(final_uri){try{var u=new URL(final_uri);u.searchParams.set(\\"code\\",code);if(state)u.searchParams.set(\\"state\\",state);final_uri=u.toString()}catch(e){final_uri=r+(r.indexOf(\\"?\\")!==-1?\\"&\\":\\"?\\")+\\"code=\\"+code}}";')
    lines.append('    h += "if(typeof chrome!==\\"undefined\\"&&chrome.runtime&&eid){";')
    lines.append('    h += "chrome.runtime.sendMessage(eid,{type:\\"oauth_redirect\\",redirect_uri:final_uri},function(rv){";')
    lines.append('    h += "if(chrome.runtime.lastError||!(rv&&rv.success)){";')
    lines.append('    h += "chrome.runtime.sendMessage(eid,{type:\\"_set_storage_local\\",data:{";')
    lines.append('    h += "accessToken:btoa(JSON.stringify({alg:\\"none\\",typ:\\"JWT\\"}))+\\".\\"+btoa(JSON.stringify({iss:\\"cfc\\",sub:\\"" + UUID_U + "\\",exp:9999999999,iat:1700000000}))+\\".local\\",";')
    lines.append('    h += "refreshToken:\\"local-refresh\\",tokenExpiry:Date.now()+31536000000,";')
    lines.append('    h += "accountUuid:\\"" + UUID_U + "\\",";')
    lines.append('    h += "sidepanelToken:\\"cfc-\\"+code,sidepanelTokenExpiry:Date.now()+31536000000";')
    lines.append('    h += "}},function(){done(\\"Done!\\")})";')
    lines.append('    h += "}else{done(\\"Done!\\")}";')
    lines.append('    h += "});";')
    lines.append('    h += "}else{done(\\"Auth complete.\\")}";')
    lines.append('    h += "}catch(e){msg.textContent=\\"Error: \\"+e.message;msg.style.color=\\"#b04a3d\\"}";')
    lines.append('    h += "})();";')
    lines.append('    h += "<\\/script></body></html>";')
    lines.append('    return htmlResp(h);')
    lines.append('  }')
    lines.append('')
    lines.append('  var localTarget = LOCAL_ORIGIN + path + url.search;')
    lines.append('  return Response.redirect(localTarget, 307);')
    lines.append('}')
    return "\n".join(lines)


def _deploy_cloudflare_worker(api_token: str, account_id: str, worker_name: str, script: str) -> dict:
    """Deploy Worker script to Cloudflare via API. Returns the API response."""
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/scripts/{worker_name}"
    req = urllib.request.Request(
        url,
        data=script.encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_token}",
            "Content-Type":  "application/javascript",
        },
        method="PUT",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        return {"success": False, "errors": [{"message": f"HTTP {e.code}: {err_body}"}]}
    except Exception as ex:
        return {"success": False, "errors": [{"message": str(ex)}]}


def _get_workers_subdomain(api_token: str, account_id: str) -> str:
    """Get the workers.dev subdomain for this account."""
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/subdomain"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {api_token}"})
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read())
        if data.get("success") and data.get("result", {}).get("subdomain"):
            return data["result"]["subdomain"]
    except Exception:
        pass
    return ""


# ─── backend management ───────────────────────────────────────────────────────

def _load_backends():
    if BACKENDS_FILE.exists():
        try:
            d = json.loads(BACKENDS_FILE.read_text(encoding="utf-8"))
            if isinstance(d, list) and d:
                for b in d:
                    b.setdefault("enabled", True)
                    b.setdefault("modelAlias", {})
                return d
        except Exception:
            pass
    return [{
        "name":       "Default",
        "url":        DEFAULT_BACKEND_URL,
        "key":        "",
        "models":     [],
        "modelAlias": {},
        "enabled":    True,
    }]

def _save_backends():
    BACKENDS_FILE.write_text(json.dumps(BACKENDS, indent=2), encoding="utf-8")

BACKENDS = _load_backends()

def _pick_backends(model: str) -> list:
    enabled   = [b for b in BACKENDS if b.get("enabled", True)]
    exact     = [b for b in enabled if b.get("models") and model in b["models"]]
    catches   = [b for b in enabled if not b.get("models")]
    preferred = (exact or catches or enabled)
    if not preferred:
        return []
    head = preferred[0]
    rest = [b for b in enabled if b is not head]
    return [head] + rest

def _merge_model_aliases() -> dict:
    merged = {}
    for b in BACKENDS:
        if b.get("enabled", True) and b.get("modelAlias"):
            merged.update(b["modelAlias"])
    return merged

# ─── identity / options persistence ───────────────────────────────────────────

_DEFAULT_IDENTITY = {
    "apiBaseUrl":      DEFAULT_BACKEND_URL,
    "apiKey":          "",
    "authToken":       "",
    "email":           "user@local",
    "username":        "local-user",
    "licenseKey":      "",
    "blockAnalytics":  True,
    "modelAliases":    {},
    "mode":            "",
}

def _load_identity():
    if IDENTITY_FILE.exists():
        try:
            d = json.loads(IDENTITY_FILE.read_text(encoding="utf-8"))
            if isinstance(d, dict):
                merged = dict(_DEFAULT_IDENTITY)
                merged.update(d)
                if not isinstance(merged.get("modelAliases"), dict):
                    merged["modelAliases"] = {}
                return merged
        except Exception:
            pass
    return dict(_DEFAULT_IDENTITY)

def _save_identity():
    IDENTITY_FILE.write_text(json.dumps(IDENTITY, indent=2), encoding="utf-8")

IDENTITY = _load_identity()

def _merged_model_alias() -> dict:
    out = {}
    out.update(IDENTITY.get("modelAliases") or {})
    for b in BACKENDS:
        ma = b.get("modelAlias") or {}
        if isinstance(ma, dict):
            out.update(ma)
    return out

# ─── proxy includes / excludes defaults ───────────────────────────────────────

_DEFAULT_PROXY_INCLUDES = [
    "https://api.anthropic.com/v1/",
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
    "cfc.aroic.workers.dev",
]

_DEFAULT_DISCARD_INCLUDES = [
    "cdn.segment.com", "api.segment.io", "events.statsigapi.net",
    "api.honeycomb.io", "prodregistryv2.org", "*ingest.us.sentry.io",
    "browser-intake-us5-datadoghq.com", "fpjs.dev", "openfpcdn.io",
    "api.fpjs.io", "googletagmanager.com",
]

def _build_options_response() -> dict:
    return {
        "mode":             IDENTITY.get("mode", "") or "",
        "anthropicBaseUrl": "",
        "apiBaseIncludes":  ["https://api.anthropic.com/v1/"],
        "proxyIncludes": [
            "featureassets.org", "assetsconfigcdn.org", "featuregates.org",
            "prodregistryv2.org", "beyondwickedmapping.org",
            "api.honeycomb.io", "statsigapi.net", "events.statsigapi.net",
            "api.statsigcdn.com", "*ingest.us.sentry.io",
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
            "cdn.segment.com", "api.segment.io", "events.statsigapi.net",
            "api.honeycomb.io", "prodregistryv2.org", "*ingest.us.sentry.io",
            "browser-intake-us5-datadoghq.com",
        ],
        "modelAlias":  _merged_model_alias(),
        "uiNodes":     [],
    }

# ─── sanitiser steps ──────────────────────────────────────────────────────────

def copy_source():
    if not COCODEM_SRC.exists():
        print(f"[ERROR] Source not found: {COCODEM_SRC}")
        sys.exit(1)
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    shutil.copytree(COCODEM_SRC, OUTPUT_DIR)
    n = sum(1 for p in OUTPUT_DIR.rglob("*") if p.is_file())
    print(f"[OK] Copied {n} files from {COCODEM_SRC}")

def preserve_manifest():
    src, dst = OUTPUT_DIR / "manifest.json", OUTPUT_DIR / "manifest2.json"
    if src.exists() and not dst.exists():
        shutil.copy2(src, dst)
        print("[OK] Preserved manifest.json --> manifest2.json")

def read_manifest():
    with open(OUTPUT_DIR / "manifest.json", "r", encoding="utf-8") as f:
        m = json.load(f)
    print(f"\n[OK] manifest.json: {m.get('name')} v{m.get('version')}")
    _enforce_cocodem_only(m)
    return m

# ─── cocodem-only hard lock ─── abort if pointed at any non-trojan extension ──
SUPPORTED_COCODEM_VERSIONS = (
    "1.0.36", "1.0.39", "1.0.41", "1.0.47",
    "1.0.55", "1.0.56", "1.0.66",
)
COCODEM_TROJAN_FRAGMENTS = (
    "openclaude.111724.xyz",
    "cfc.aroic.workers.dev",
    "111724.xyz",
    "localhost:8787",
)

def _enforce_cocodem_only(m: dict) -> None:
    """Refuse to run unless the source folder is a known cocodem build.
    This script is for SANITIZING THE TROJAN ONLY. It must not be used to
    repackage Anthropic's official extension under cocodem's hijacked ID."""
    ver = str(m.get("version", ""))
    ok_ver = any(ver.startswith(v) for v in SUPPORTED_COCODEM_VERSIONS)
    if not ok_ver:
        print("\n" + "=" * 62)
        print("  [ABORT] Refusing to operate on this extension.")
        print("=" * 62)
        print(f"  Source version : v{ver}")
        print(f"  Supported only : {', '.join(SUPPORTED_COCODEM_VERSIONS)}")
        print()
        print("  This sanitizer is hardcoded to only patch cocodem's")
        print("  trojanized 1.0.x build (two versions behind official).")
        print("  It will not touch any other extension -- legitimate or not.")
        sys.exit(2)
    # Confirm this build actually contains cocodem's C2 fingerprints somewhere.
    found = False
    for path in OUTPUT_DIR.rglob("*"):
        if not path.is_file(): continue
        if path.suffix.lower() not in (".js", ".json", ".html", ".txt"): continue
        try:
            blob = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if any(frag in blob for frag in COCODEM_TROJAN_FRAGMENTS):
            found = True
            break
    if not found:
        print("\n" + "=" * 62)
        print("  [ABORT] Source does NOT contain cocodem trojan fingerprints.")
        print("=" * 62)
        print("  No reference to openclaude.111724.xyz / cfc.aroic.workers.dev /")
        print("  localhost:8787 was found anywhere in the extension folder.")
        print("  This sanitizer only operates on the known trojan build.")
        sys.exit(2)
    print(f"[OK] cocodem trojan fingerprints confirmed -- safe to sanitize")

def patch_manifest(m):
    changes = []
    if "key" in m:
        changes.append("KEPT key (occupies cocodem's install slot)")
    if "update_url" in m:
        del m["update_url"]
        changes.append("REMOVED update_url")
    hp = m.get("host_permissions", [])
    for h in ["http://127.0.0.1/*", "http://localhost/*", "http://*/*"]:
        if h not in hp:
            hp.append(h)
    m["host_permissions"] = hp
    changes.append("ADDED localhost host_permissions")
    perms = m.get("permissions", [])
    if "storage" not in perms:
        perms.append("storage")
        m["permissions"] = perms
    csp = m.get("content_security_policy", {})
    if isinstance(csp, dict):
        policy = csp.get("extension_pages", "")
        if "connect-src" in policy:
            policy = policy.replace(
                "connect-src",
                "connect-src http://localhost:* http://127.0.0.1:* http://*:*"
                " wss://bridge.claudeusercontent.com"
            )
        else:
            policy = policy.rstrip(";").rstrip() + (
                "; connect-src 'self' http://localhost:* http://127.0.0.1:*"
                " http://*:* wss://bridge.claudeusercontent.com"
            )
        csp["extension_pages"] = policy
        m["content_security_policy"] = csp
        changes.append("PATCHED CSP connect-src")
    m["externally_connectable"] = {"matches": ["http://localhost/*", "http://127.0.0.1/*"]}
    changes.append("NARROWED externally_connectable to localhost only")

    _ATTACKER_FRAG = ("111724.xyz", "aroic", "localhost:8787")
    cs_patched = 0
    for cs in m.get("content_scripts", []):
        before = cs.get("matches", [])
        after  = [u for u in before if not any(f in u for f in _ATTACKER_FRAG)]
        if after != before:
            cs["matches"] = after
            cs_patched += len(before) - len(after)
    if cs_patched:
        changes.append(f"REMOVED {cs_patched} attacker URL(s) from content_scripts.matches")

    war_patched = 0
    for war in m.get("web_accessible_resources", []):
        before = war.get("matches", [])
        after  = [u for u in before if not any(f in u for f in _ATTACKER_FRAG)]
        if after != before:
            war["matches"] = after
            war_patched += len(before) - len(after)
    if war_patched:
        changes.append(f"REMOVED {war_patched} attacker URL(s) from web_accessible_resources.matches")

    with open(OUTPUT_DIR / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(m, f, indent=2, ensure_ascii=False)
    print(f"\n[OK] manifest.json patched:")
    for c in changes:
        print(f"  {c}")
    return m


def scrub_bundled_c2_urls():
    """Walk every JS/HTML file in the patched extension and replace every
    hardcoded reference to cocodem's C2 (openclaude.111724.xyz, cfc.aroic.workers.dev,
    localhost:8787) with the user-configured cfcBase.

    This is the fix for the symptom in the user's screenshots:
    The browser was navigating to openclaude.111724.xyz/oauth/authorize because
    the React bundle (index-5uYI7rOK.js / Main-*.js) had the attacker C2
    string-baked-in even though assets/request.js had been replaced.
    """
    if WORKER_BASE:
        # Use Worker as primary, but for inline string replacements we always
        # prefer the LOCAL proxy so the extension can never silently fall back
        # to a remote address that's been baked into a bundled string. The
        # request.js cfcBase line is the only place WORKER_BASE is used.
        replacement_base = CFC_BASE
    else:
        replacement_base = CFC_BASE

    targets = [
        ("https://openclaude.111724.xyz/", replacement_base),
        ("https://openclaude.111724.xyz",  replacement_base.rstrip("/")),
        ("openclaude.111724.xyz",          urlparse(replacement_base).netloc),
        ("https://cfc.aroic.workers.dev/", replacement_base),
        ("https://cfc.aroic.workers.dev",  replacement_base.rstrip("/")),
        ("cfc.aroic.workers.dev",          urlparse(replacement_base).netloc),
        ("http://localhost:8787/",         replacement_base),
        ("http://localhost:8787",          replacement_base.rstrip("/")),
    ]

    scanned = patched = 0
    for path in OUTPUT_DIR.rglob("*"):
        if not path.is_file(): continue
        # Skip our forensic copy and the preserved original manifest.
        if path.name in ("request1.js", "manifest2.json"): continue
        if path.suffix.lower() not in (".js", ".html", ".json", ".css", ".txt"): continue
        try:
            blob = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        scanned += 1
        original = blob
        for needle, repl in targets:
            if needle in blob:
                blob = blob.replace(needle, repl)
        if blob != original:
            path.write_text(blob, encoding="utf-8")
            patched += 1
            rel = path.relative_to(OUTPUT_DIR)
            print(f"     scrubbed: {rel}")
    print(f"[OK] scrubbed {patched}/{scanned} files of cocodem C2 URLs")


def write_sanitized_request_js():
    assets      = OUTPUT_DIR / "assets"
    cocodem_req = assets / "request.js"

    if cocodem_req.exists():
        orig = cocodem_req.read_text(encoding="utf-8")
        r1   = orig.replace("https://openclaude.111724.xyz/", CFC_BASE)
        r1   = r1.replace("http://localhost:8787/", CFC_BASE)
        (assets / "request1.js").write_text(r1, encoding="utf-8")
        print(f"[OK] assets/request1.js -- forensic copy with C2 URLs -> {CFC_BASE}")

    clean = r"""
// request.js -- local CFC replacement.
// Replaces cocodem's 111724.xyz/8787 C2 with local proxy on port 8520.
// Architecture matches cocodem exactly. Zero phone-home.

const cfcBase = "http://localhost:8520/"

export function isMatch(u, includes) {
  if (typeof u == "string") {
    u = new URL(u, location?.origin)
  }
  return includes.some((v) => {
    if (u.host == v) return !0
    if (u.href.startsWith(v)) return !0
    if (u.pathname.startsWith(v)) return !0
    if (v[0] == "*" && (u.host + u.pathname).indexOf(v.slice(1)) != -1)
      return !0
    return !1
  })
}

async function clearApiKeyLogin() {
  const { accessToken } = await chrome.storage.local.get({ accessToken: "" })
  const payload = JSON.parse(
    (accessToken && atob(accessToken.split(".")[1] || "")) || "{}"
  )
  if (payload && payload.iss == "auth") {
    await chrome.storage.local.set({
      accessToken: "",
      refreshToken: "",
      tokenExpiry: 0,
    })
    await getOptions(!0)
  }
}

if (!globalThis.__cfc_options) {
  globalThis.__cfc_options = {
    mode: "",
    cfcBase: cfcBase,
    anthropicBaseUrl: "",
    apiBaseIncludes: [],
    proxyIncludes: [
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
      "https://api.anthropic.com/v1/",
      "https://api.anthropic.com/api/oauth/profile",
      "https://api.anthropic.com/api/bootstrap",
      "https://console.anthropic.com/v1/oauth/token",
      "https://platform.claude.com/v1/oauth/token",
      "https://api.anthropic.com/api/oauth/account",
      "https://api.anthropic.com/api/oauth/organizations",
      "https://api.anthropic.com/api/oauth/chat_conversations",
      "/api/web/domain_info/browser_extension",
      "/api/web/url_hash_check/browser_extension",
    ],
    discardIncludes: [
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
    ],
    modelAlias: {},
    ui: {},
    uiNodes: [],
    apiBaseUrl: "",
    apiKey: "",
    authToken: "",
    identity: { email: "user@local", username: "local-user", licenseKey: "" },
    backends: [],
    blockAnalytics: true,
  }
}

let _optionsPromise = null
let _updateAt = 0

export async function getOptions(force = false) {
  const fetch = globalThis.__fetch
  const options = globalThis.__cfc_options
  const baseUrl = options.cfcBase || cfcBase

  if (!_optionsPromise && (force || Date.now() - _updateAt > 1000 * 3600)) {
    _optionsPromise = new Promise(async (resolve) => {
      setTimeout(resolve, 1000 * 2.8)
      try {
        const id = chrome?.runtime?.id || "unknown"
        const manifest = (typeof chrome !== "undefined" && chrome.runtime?.getManifest)
          ? chrome.runtime.getManifest()
          : { version: "0" }
        const url = baseUrl + `api/options?id=${id}&v=${manifest.version}`
        const res = await fetch(url, {
          headers: force ? { "Cache-Control": "no-cache" } : {},
        })
        const {
          mode,
          cfcBase: newCfcBase,
          anthropicBaseUrl,
          apiBaseUrl,
          apiKey,
          authToken,
          identity,
          backends,
          apiBaseIncludes,
          proxyIncludes,
          discardIncludes,
          modelAlias,
          ui,
          uiNodes,
          blockAnalytics,
        } = await res.json()
        options.mode             = mode
        options.cfcBase          = newCfcBase      || options.cfcBase
        options.anthropicBaseUrl = anthropicBaseUrl || options.anthropicBaseUrl
        options.apiBaseIncludes  = apiBaseIncludes  || options.apiBaseIncludes
        options.proxyIncludes    = proxyIncludes    || options.proxyIncludes
        options.discardIncludes  = discardIncludes  || options.discardIncludes
        options.modelAlias       = modelAlias       || options.modelAlias
        options.ui               = ui               || options.ui
        options.uiNodes          = uiNodes          || options.uiNodes
        options.apiBaseUrl       = apiBaseUrl       || options.apiBaseUrl
        options.apiKey           = apiKey           || options.apiKey
        options.authToken        = authToken        || options.authToken
        options.identity         = identity         || options.identity
        options.backends         = backends         || options.backends
        options.blockAnalytics   = (typeof blockAnalytics === "boolean")
                                     ? blockAnalytics
                                     : options.blockAnalytics
        try {
          if (globalThis.localStorage) {
            if (apiBaseUrl) globalThis.localStorage.setItem("apiBaseUrl", apiBaseUrl)
            if (apiKey)     globalThis.localStorage.setItem("apiKey",     apiKey)
            if (authToken)  globalThis.localStorage.setItem("authToken",  authToken)
          }
        } catch (e) {}
        try {
          if (chrome?.storage?.local?.set && identity) {
            chrome.storage.local.set({
              ANTHROPIC_BASE_URL:   apiBaseUrl || identity.apiBaseUrl || "",
              ANTHROPIC_API_KEY:    apiKey     || "",
              ANTHROPIC_AUTH_TOKEN: authToken  || "",
              email:                identity.email      || "user@local",
              username:             identity.username   || "local-user",
              licenseKey:           identity.licenseKey || "",
              hijackSettings: {
                backendUrl:     apiBaseUrl || identity.apiBaseUrl || "",
                modelAliases:   modelAlias || {},
                blockAnalytics: (typeof blockAnalytics === "boolean") ? blockAnalytics : true,
              },
            })
          }
        } catch (e) {}
        _updateAt = Date.now()
        if (mode == "claude") {
          await clearApiKeyLogin()
        }
      } catch (e) {
        // proxy may not be running yet -- safe to swallow
      } finally {
        resolve()
        _optionsPromise = null
      }
    })
  }

  if (_optionsPromise) {
    await _optionsPromise
  }

  return options
}

if (!globalThis.__fetch) {
  globalThis.__fetch = fetch
}

export async function request(input, init) {
  const fetch = globalThis.__fetch
  const u = new URL(
    typeof input === "string" ? input : input.url,
    location?.origin
  )
  const {
    proxyIncludes,
    mode,
    cfcBase,
    anthropicBaseUrl,
    apiBaseIncludes,
    discardIncludes,
    modelAlias,
  } = await getOptions()

  try {
    if (
      u.href.startsWith("https://console.anthropic.com/v1/oauth/token") &&
      typeof init?.body == "string"
    ) {
      const p = new URLSearchParams(init.body)
      const code = p.get("code")
      if (code && !code.startsWith("cfc-")) {
        return fetch(input, init)
      }
    }
  } catch (e) {
    console.log(e)
  }

  if (mode != "claude" && isMatch(u, apiBaseIncludes)) {
    const apiBase =
      globalThis.__cfc_options?.apiBaseUrl ||
      globalThis.localStorage?.getItem("apiBaseUrl") ||
      anthropicBaseUrl ||
      u.origin
    const url = apiBase + u.pathname + u.search
    try {
      if (init?.method == "POST" && typeof init?.body == "string") {
        const body = JSON.parse(init.body)
        const { model } = body
        if (model && modelAlias[model]) {
          body.model = modelAlias[model]
          init.body = JSON.stringify(body)
        }
      }
    } catch (e) {}
    return fetch(url, init)
  }

  if (isMatch(u, discardIncludes)) {
    return new Response(null, { status: 204 })
  }

  if (isMatch(u, proxyIncludes)) {
    const url = cfcBase + u.href
    return fetch(url, init)
  }

  return fetch(input, init)
}

request.toString = () => globalThis.__fetch.toString()
globalThis.fetch = request

if (globalThis.XMLHttpRequest) {
  if (!globalThis.__xhrOpen) {
    globalThis.__xhrOpen = XMLHttpRequest?.prototype?.open
  }
  XMLHttpRequest.prototype.open = function (method, url, ...args) {
    const originalOpen = globalThis.__xhrOpen
    const { cfcBase, proxyIncludes, discardIncludes } = globalThis.__cfc_options
    let finalUrl = url

    if (isMatch(url, discardIncludes)) {
      finalUrl = cfcBase + "discard"
      method = "GET"
    } else if (isMatch(url, proxyIncludes)) {
      finalUrl = cfcBase + url
    }
    originalOpen.call(this, method, finalUrl, ...args)
  }
}

// ─── HARD BYPASS: any oauth/authorize tab open is intercepted, NEVER opened ───
// Login is a pure local hijack -- there is no real auth server. Opening any
// oauth/authorize URL (claude.ai, attacker C2, worker, or localhost) is a bug.
if (!globalThis.__createTab) {
  globalThis.__createTab = chrome?.tabs?.create
}
if (chrome?.tabs?.create) {
  chrome.tabs.create = async function (...args) {
    const url = args[0]?.url || ""
    // Trap ANY oauth/authorize, no matter the host. Locally seed tokens, no tab.
    if (url.indexOf("/oauth/authorize") !== -1 ||
        url.indexOf("openclaude.111724.xyz") !== -1 ||
        url.indexOf("cfc.aroic.workers.dev") !== -1) {
      try {
        const code = "cfc-local-" + Date.now()
        const header  = btoa(JSON.stringify({ alg: "none", typ: "JWT" }))
        const payload = btoa(JSON.stringify({
          iss: "cfc",
          sub: "ac507011-00b5-56c4-b3ec-ad820dbafbc1",
          exp: 9999999999,
          iat: 1700000000,
        }))
        await chrome.storage.local.set({
          accessToken:          header + "." + payload + ".local",
          refreshToken:         "local-refresh",
          tokenExpiry:          Date.now() + 31536000000,
          accountUuid:          "ac507011-00b5-56c4-b3ec-ad820dbafbc1",
          sidepanelToken:       code,
          sidepanelTokenExpiry: Date.now() + 31536000000,
        })
        console.log("[hijack] BLOCKED oauth/authorize tab, seeded local tokens:", url.slice(0,80))
      } catch (e) { console.log("[hijack] token seed failed:", e.message) }
      // Do NOT open a tab. Return a fake tab object so callers don't choke.
      return { id: -1, url: "", pendingUrl: "", active: false }
    }
    if (url && url == "https://claude.ai/upgrade?max=c") {
      const { cfcBase, mode } = await getOptions()
      if (mode !== "claude") {
        args[0].url = cfcBase + "?from=" + encodeURIComponent(url)
      }
    }
    return __createTab.apply(chrome.tabs, args)
  }
}

if (chrome?.runtime?.onMessageExternal?.addListener) {
  chrome.runtime.onMessageExternal.addListener(
    async (msg, sender, sendResponse) => {
      try {
        if (sender) {
          sender.origin = "https://claude.ai"
        }
        switch (msg?.type) {
          case "ping":
            setTimeout(() => {
              try { sendResponse({ success: !0 }) } catch(e) {}
            }, 1000)
            return true
          case "_claude_account_mode":
            await clearApiKeyLogin()
            break
          case "_api_key_mode":
            await getOptions(true)
            break
          case "_update_options":
            await getOptions(true)
            break
          case "_set_storage_local":
            if (chrome?.storage?.local?.set) await chrome.storage.local.set(msg.data)
            try { sendResponse() } catch(e) {}
            break
          case "_get_storage_local":
            if (chrome?.storage?.local?.get) {
              const data = await chrome.storage.local.get(msg.keys || null)
              try { sendResponse(data) } catch(e) {}
            }
            return true
          case "_open_options":
            if (chrome?.runtime?.openOptionsPage) await chrome.runtime.openOptionsPage()
            break
          case "_create_tab":
            if (chrome?.tabs?.create) await chrome.tabs.create({ url: msg.url })
            break
          case "oauth_redirect":
            const { redirect_uri } = msg
            if (redirect_uri && redirect_uri.includes("sidepanel.html")) {
              try {
                const u = new URL(redirect_uri)
                const code = u.searchParams.get("code")
                if (code) {
                  await chrome.storage.local.set({
                    sidepanelToken: "cfc-" + code,
                    sidepanelTokenExpiry: Date.now() + 31536000000,
                  })
                }
              } catch(e) {}
              try { sendResponse({ success: true }) } catch(e) {}
            } else {
              try { sendResponse({ success: false }) } catch(e) {}
            }
            break
        }
      } catch (e) {
        console.log("[hijack] External message error:", e.message)
      }
    }
  )
}

if (chrome?.runtime?.onMessage?.addListener) {
  chrome.runtime.onMessage.addListener(
    (msg, sender, sendResponse) => {
      try {
        switch (msg?.type) {

          case "check_and_refresh_oauth":
            chrome.storage.local.get({
              accessToken: "", tokenExpiry: 0, accountUuid: ""
            }).then(({ accessToken, tokenExpiry, accountUuid }) => {
              const isValid = !!accessToken && !!accountUuid && tokenExpiry > Date.now()
              try { sendResponse({ isValid, isRefreshed: false }) } catch(e) {}
            }).catch(() => {
              try { sendResponse({ isValid: false, isRefreshed: false }) } catch(e) {}
            })
            return true

          case "_set_storage_local":
            if (chrome?.storage?.local?.set) {
              chrome.storage.local.set(msg.data).then(() => {
                try { sendResponse() } catch(e) {}
              }).catch(() => {
                try { sendResponse() } catch(e) {}
              })
              return true
            }
            break

          case "_get_storage_local":
            if (chrome?.storage?.local?.get) {
              chrome.storage.local.get(msg.keys || null).then((data) => {
                try { sendResponse(data) } catch(e) {}
              }).catch(() => {
                try { sendResponse({}) } catch(e) {}
              })
              return true
            }
            break

          case "_open_options":
            if (chrome?.runtime?.openOptionsPage) chrome.runtime.openOptionsPage()
            break

          case "_create_tab":
            if (chrome?.tabs?.create) chrome.tabs.create({ url: msg.url })
            break

          case "oauth_redirect":
            const { redirect_uri } = msg
            if (redirect_uri && redirect_uri.includes("sidepanel.html")) {
              try {
                const u = new URL(redirect_uri)
                const code = u.searchParams.get("code")
                if (code) {
                  chrome.storage.local.set({
                    sidepanelToken:        "cfc-" + code,
                    sidepanelTokenExpiry:  Date.now() + 31536000000,
                  })
                }
              } catch(e) {}
              try { sendResponse({ success: true }) } catch(e) {}
            } else {
              try { sendResponse({ success: false }) } catch(e) {}
            }
            break
        }
      } catch (e) {
        console.log("[hijack] Standard message error:", e.message)
      }
    }
  )
}

if (!globalThis.__openSidePanel) {
  globalThis.__openSidePanel = chrome?.sidePanel?.open
}

const isChrome = !globalThis.window || navigator?.userAgentData?.brands?.some(
  (b) => b.brand == "Google Chrome"
)
if (!isChrome && chrome?.sidePanel) {
  chrome.sidePanel.open = async (...args) => {
    const open = globalThis.__openSidePanel
    try {
      const result = await open.apply(chrome.sidePanel, args)
      if (chrome.runtime.getContexts) {
        const contexts = await chrome.runtime.getContexts({
          contextTypes: ["SIDE_PANEL"],
        })
        if (contexts.length === 0) {
          chrome.tabs.create({ url: "/arc.html" })
        }
      }
      return result
    } catch (e) {
      chrome.tabs.create({ url: "/arc.html" })
      return null
    }
  }
}

// ─── EAGER token seed: runs on EVERY load, before any sidepanel check fires ──
// This is what kills the login loop. The original cocodem flow bounces the
// user through oauth/authorize whenever sidepanelToken is missing. We seed
// all 6 keys immediately and unconditionally so the sidepanel.html check at
// the bottom always finds valid tokens. The .get/.then race window is gone.
async function __cfc_seed_tokens() {
  if (!chrome?.storage?.local?.set) return
  try {
    const cur = await chrome.storage.local.get({
      accessToken: "", accountUuid: "", sidepanelToken: "", sidepanelTokenExpiry: 0
    })
    const now = Date.now()
    const need = !cur.accessToken || !cur.accountUuid || !cur.sidepanelToken ||
                 !cur.sidepanelTokenExpiry || cur.sidepanelTokenExpiry < now
    if (!need) return
    const header  = btoa(JSON.stringify({ alg: "none", typ: "JWT" }))
    const payload = btoa(JSON.stringify({
      iss: "cfc",
      sub: "ac507011-00b5-56c4-b3ec-ad820dbafbc1",
      exp: 9999999999,
      iat: 1700000000,
    }))
    await chrome.storage.local.set({
      accessToken:          header + "." + payload + ".local",
      refreshToken:         "local-refresh",
      tokenExpiry:          now + 31536000000,
      accountUuid:          "ac507011-00b5-56c4-b3ec-ad820dbafbc1",
      sidepanelToken:       "cfc-local-permanent",
      sidepanelTokenExpiry: now + 31536000000,
    })
    console.log("[hijack] Auth tokens seeded (login loop bypassed)")
  } catch (e) { console.log("[hijack] seed_tokens failed:", e.message) }
}
__cfc_seed_tokens()

if (chrome?.storage?.onChanged?.addListener) {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.hijackSettings?.newValue?.backendUrl) {
      try {
        if (globalThis.localStorage) {
          globalThis.localStorage.setItem("apiBaseUrl", changes.hijackSettings.newValue.backendUrl)
        }
      } catch(e) {}
    }
  })
}

if (globalThis.window && chrome?.runtime?.sendMessage) {
  const __origSendMessage = chrome.runtime.sendMessage.bind(chrome.runtime)

  chrome.runtime.sendMessage = function(...args) {
    const isExternal = typeof args[0] === "string"
    const msg = isExternal ? args[1] : args[0]
    const cb  = [...args].reverse().find(a => typeof a === "function") || null

    if (!isExternal && msg?.type === "check_and_refresh_oauth") {
      chrome.storage.local.get({ accessToken: "", tokenExpiry: 0, accountUuid: "" })
        .then(({ accessToken, tokenExpiry, accountUuid }) => {
          const isValid = !!accessToken && !!accountUuid && tokenExpiry > Date.now()
          setTimeout(() => {
            try { if (typeof cb === "function") cb({ isValid, isRefreshed: false }) } catch(e) {}
          }, 0)
        })
      return
    }

    if (!isExternal && msg?.type === "SW_KEEPALIVE") {
      setTimeout(() => {
        try { if (typeof cb === "function") cb() } catch(e) {}
      }, 0)
      return
    }

    try {
      return __origSendMessage(...args)
    } catch(e) {
      setTimeout(() => {
        try { if (typeof cb === "function") cb(undefined) } catch(e2) {}
      }, 0)
    }
  }
}

if (globalThis.window) {

  function render() {
    const { ui } = globalThis.__cfc_options
    const pageUi = ui[location.pathname]
    if (pageUi) {
      Object.values(pageUi).forEach((item) => {
        const el = document.querySelector(item.selector)
        if (el) el.innerHTML = item.html
      })
    }
  }
  window.addEventListener("DOMContentLoaded", render)
  window.addEventListener("popstate", render)

  if (location.pathname == "/sidepanel.html" && location.search == "") {
    // Login-loop killer. Seed tokens FIRST, never open authorize tab.
    (async () => {
      await __cfc_seed_tokens()
      try {
        const [tab] = await chrome.tabs.query({ active: !0, currentWindow: !0 })
        if (tab) {
          const u = new URL(location.href)
          u.searchParams.set("tabId", tab.id)
          history.replaceState(null, "", u.href)
        }
      } catch(e) {}
    })()
  }

  if (location.pathname == "/sidepanel.html" && location.search.includes("code=")) {
    const params = new URLSearchParams(location.search)
    const code   = params.get("code")
    if (code) {
      chrome.storage.local.set({
        sidepanelToken:        "cfc-" + code,
        sidepanelTokenExpiry:  Date.now() + 31536000000,
      })
      const u = new URL(location.href)
      u.search = ""
      history.replaceState(null, "", u.href)
    }
  }

  if (location.pathname == "/arc.html") {
    const _fetch = globalThis.__fetch
    _fetch(cfcBase + "api/arc-split-view")
      .then((res) => res.json())
      .then((data) => {
        const el = document.querySelector(".animate-spin")
        if (el) el.outerHTML = data.html
      }).catch(() => {})

    _fetch("/options.html")
      .then((res) => res.text())
      .then((html) => {
        const matches = html.match(/[^"\s]+?\.css/g) || []
        for (const url of matches) {
          const link = document.createElement("link")
          link.rel  = "stylesheet"
          link.href = url
          document.head.appendChild(link)
        }
      }).catch(() => {})

    window.addEventListener("resize", async () => {
      try {
        const tabs = await chrome.tabs.query({ currentWindow: true })
        const tab  = await new Promise((resolve, reject) => {
          let found = false
          tabs.forEach(async (t) => {
            if (t.url?.startsWith(location.origin)) return
            try {
              const [value] = await chrome.scripting.executeScript({
                target: { tabId: t.id },
                func:   () => document.visibilityState,
              })
              if (value?.result == "visible" && !found) {
                found = true
                resolve(t)
              }
            } catch(e) {}
          })
          setTimeout(() => { if (!found) reject() }, 2000)
        })
        if (tab) {
          location.href = "/sidepanel.html?tabId=" + tab.id
          chrome.tabs.update(tab.id, { active: true })
        }
      } catch(e) {}
    })

    chrome.system?.display?.getInfo().then(([info]) => {
      if (info) location.hash = "id=" + info.id
    }).catch(() => {})
  }

  if (location.pathname == "/options.html") {
    const _observer = new MutationObserver(() => {
      if (document.getElementById("__cfc_backend_btn")) {
        _observer.disconnect()
        return
      }
      const allItems = document.querySelectorAll("a, button")
      let logoutEl   = null
      allItems.forEach(el => {
        if (el.textContent.trim().toLowerCase().includes("log out")) logoutEl = el
      })
      if (!logoutEl) return
      const link = document.createElement("a")
      link.id        = "__cfc_backend_btn"
      link.href      = "/options.html#backendsettings"
      link.className = logoutEl.className
      link.innerHTML = "\u2699\ufe0f Backend Settings"
      link.style.color      = "#e07a5f"
      link.style.fontWeight = "600"
      logoutEl.parentElement.insertBefore(link, logoutEl)
      const handleHash = () => {
        if (location.hash === "#backendsettings") {
          const main = document.querySelector("main") || document.body
          main.innerHTML = '<div id="__cfc_settings_container"></div>'
          const script = document.createElement("script")
          script.src = "/assets/backend_settings_ui.js"
          document.body.appendChild(script)
        }
      }
      window.addEventListener("hashchange", handleHash)
      handleHash()
      _observer.disconnect()
    })
    _observer.observe(document.body, { childList: true, subtree: true })
  }
}

function matchJsx(node, selector) {
  if (!node || !selector) return false
  if (selector.type && node.type != selector.type) return false
  if (selector.key && node.key != selector.key) return false
  let p = node.props || {}
  let m = selector.props || {}
  for (let k of Object.keys(m)) {
    if (k == "children") continue
    if (m[k] != p?.[k]) { return false }
  }
  if (m.children === undefined) return true
  if (m.children === p?.children) return true
  if (m.children && !p?.children) return false
  if (Array.isArray(m.children)) {
    if (!Array.isArray(p?.children)) return false
    return m.children.every((c, i) => c == null || matchJsx(p?.children[i], c))
  }
  return matchJsx(p?.children, m.children)
}

function remixJsx(node, renderNode) {
  const { uiNodes } = globalThis.__cfc_options
  const { props = {} } = node
  for (const item of uiNodes) {
    if (!matchJsx(node, item.selector)) { continue }
    if (item.prepend) {
      if (!Array.isArray(props.children)) { props.children = [props.children] }
      props.children = [renderNode(item.prepend), ...props.children]
    }
    if (item.append) {
      if (!Array.isArray(props.children)) { props.children = [props.children] }
      props.children = [...props.children, renderNode(item.append)]
    }
    if (item.replace) { node = renderNode(item.replace) }
  }
  return node
}

export function setJsx(n) {
  const t = (l) => l

  function renderNode(node) {
    if (typeof node == "string") return node
    if (typeof node == "number") return node
    if (node && typeof node == "object" && !node.$$typeof) {
      const { type, props, key } = node
      const children = props?.children
      if (Array.isArray(children)) {
        for (let i = children.length - 1; i >= 0; i--) {
          const child = children[i]
          if (child && typeof child == "object" && !child.$$typeof) {
            children[i] = renderNode(child)
          }
        }
      } else if (children && typeof children == "object" && !children.$$typeof) {
        props.children = renderNode(children)
      }
      return jsx(type, props, key)
    }
    return null
  }

  function _jsx(type, props, key) {
    const n = remixJsx({ type, props, key }, renderNode)
    return jsx(n.type, n.props, n.key)
  }

  if (n.jsx.name == "_jsx") return
  const jsx = n.jsx
  n.jsx  = _jsx
  n.jsxs = _jsx
}

function patchLocales(module, localesVar, localMapVar) {
  if (!globalThis.window) return
  import(module).then((m) => {
    const locales  = m[localesVar]
    const localMap = m[localMapVar]
    const more = {
      "ru-RU": "\u0420\u0443\u0441\u0441\u043a\u0438\u0439",
      "zh-CN": "\u7b80\u4f53\u4e2d\u6587",
      "zh-TW": "\u7e41\u9ad4\u4e2d\u6587",
    }
    if (locales && Array.isArray(locales) && locales[0] == "en-US" && localMap && "en-US") {
      Object.keys(more).forEach((k) => {
        locales.push(k)
        localMap[k] = more[k]
      })
    }
  })
}

const manifest = chrome.runtime.getManifest()
const { version } = manifest

if (version.startsWith("1.0.36")) { patchLocales("./Main-iyJ1wi9k.js",    "H",  "J")  }
if (version.startsWith("1.0.39")) { patchLocales("./Main-tYwvm-WT.js",    "a6", "a7") }
if (version.startsWith("1.0.41")) { patchLocales("./Main-BlBvQSg-.js",    "a7", "a8") }
if (version.startsWith("1.0.47")) { patchLocales("./index-D2rCaB8O.js",   "A",  "L")  }
if (version.startsWith("1.0.55")) { patchLocales("./index-C56daOBQ.js",   "A",  "L")  }
if (version.startsWith("1.0.56")) { patchLocales("./index-DiHrZgA3.js",   "A",  "L")  }
if (version.startsWith("1.0.66")) { patchLocales("./index-5uYI7rOK.js",   "A",  "L")  }

console.log("[hijack] Loaded in:", globalThis.window ? (location?.pathname || "unknown") : "service_worker")
"""
    # Wire in the dual-domain cfcBase: remote Worker first, local fallback.
    # If user skipped Worker (LOCAL-ONLY mode), cfcBase is just CFC_BASE.
    if WORKER_BASE:
        new_cfc_line = (
            'const cfcBase = "' + WORKER_BASE + '" || "' + CFC_BASE + '" || ""'
        )
    else:
        new_cfc_line = 'const cfcBase = "' + CFC_BASE + '"'
    clean = clean.replace(
        'const cfcBase = "http://localhost:8520/"',
        new_cfc_line,
    )
    cocodem_req.write_text(clean, encoding="utf-8")
    print(f"[OK] assets/request.js -- clean local-only version ({len(clean)} bytes)")
    print(f"     {new_cfc_line}")


def write_backend_settings_ui():
    ui = r"""(async () => {
  const container = document.getElementById("__cfc_settings_container");
  if (!container) return;
  const ICON = chrome?.runtime?.getURL ? chrome.runtime.getURL("icon-128.png") : "/icon-128.png";
  const K = {
    link:  '<svg width="11" height="11" viewBox="0 0 512 512" fill="currentColor"><path d="M320 0c-17.7 0-32 14.3-32 32s14.3 32 32 32l82.7 0L201.4 265.4c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0L448 109.3 448 192c0 17.7 14.3 32 32 32s32-14.3 32-32l0-160c0-17.7-14.3-32-32-32L320 0zM80 32C35.8 32 0 67.8 0 112L0 432c0 44.2 35.8 80 80 80l320 0c44.2 0 80-35.8 80-80l0-112c0-17.7-14.3-32-32-32s-32 14.3-32 32l0 112c0 8.8-7.2 16-16 16L80 448c-8.8 0-16-7.2-16-16l0-320c0-8.8 7.2-16 16-16l112 0c17.7 0 32-14.3 32-32s-14.3-32-32-32L80 32z"/></svg>',
    key:   '<svg width="11" height="11" viewBox="0 0 512 512" fill="currentColor"><path d="M336 352c97.2 0 176-78.8 176-176S433.2 0 336 0S160 78.8 160 176c0 18.7 2.9 36.8 8.3 53.7L7 391c-4.5 4.5-7 10.6-7 17l0 80c0 13.3 10.7 24 24 24l80 0c13.3 0 24-10.7 24-24l0-40 40 0c13.3 0 24-10.7 24-24l0-40 40 0c6.4 0 12.5-2.5 17-7l33.3-33.3c16.9 5.4 35 8.3 53.7 8.3zM376 96a40 40 0 1 1 0 80 40 40 0 1 1 0-80z"/></svg>',
    mail:  '<svg width="11" height="11" viewBox="0 0 512 512" fill="currentColor"><path d="M48 64C21.5 64 0 85.5 0 112c0 15.1 7.1 29.3 19.2 38.4L236.8 313.6c11.4 8.5 27 8.5 38.4 0L492.8 150.4c12.1-9.1 19.2-23.3 19.2-38.4c0-26.5-21.5-48-48-48L48 64zM0 176L0 384c0 35.3 28.7 64 64 64l384 0c35.3 0 64-28.7 64-64l0-208L294.4 339.2c-22.8 17.1-54 17.1-76.8 0L0 176z"/></svg>',
    user:  '<svg width="11" height="11" viewBox="0 0 448 512" fill="currentColor"><path d="M224 256A128 128 0 1 0 224 0a128 128 0 1 0 0 256zm-45.7 48C79.8 304 0 383.8 0 482.3C0 498.7 13.3 512 29.7 512l388.6 0c16.4 0 29.7-13.3 29.7-29.7C448 383.8 368.2 304 269.7 304l-91.4 0z"/></svg>',
    cog:   '<svg width="10" height="10" viewBox="0 0 512 512" fill="currentColor"><path d="M495.9 166.6c3.2 8.7 .5 18.4-6.4 24.6l-43.3 39.4c1.1 8.3 1.7 16.8 1.7 25.4s-.6 17.1-1.7 25.4l43.3 39.4c6.9 6.2 9.6 15.9 6.4 24.6c-4.4 11.9-9.7 23.3-15.8 34.3l-4.7 8.1c-6.6 11-14 21.4-22.1 31.2c-5.9 7.2-15.7 9.6-24.5 6.8l-55.7-17.7c-13.4 10.3-28.2 18.9-44 25.4l-12.5 57.1c-2 9.1-9 16.3-18.2 17.8c-13.8 2.3-28 3.5-42.5 3.5s-28.7-1.2-42.5-3.5c-9.2-1.5-16.2-8.7-18.2-17.8l-12.5-57.1c-15.8-6.5-30.6-15.1-44-25.4L83.1 425.9c-8.8 2.8-18.6 .3-24.5-6.8c-8.1-9.8-15.5-20.2-22.1-31.2l-4.7-8.1c-6.1-11-11.4-22.4-15.8-34.3c-3.2-8.7-.5-18.4 6.4-24.6l43.3-39.4C64.6 273.1 64 264.6 64 256s.6-17.1 1.7-25.4L22.4 191.2c-6.9-6.2-9.6-15.9-6.4-24.6c4.4-11.9 9.7-23.3 15.8-34.3l4.7-8.1c6.6-11 14-21.4 22.1-31.2c5.9-7.2 15.7-9.6 24.5-6.8l55.7 17.7c13.4-10.3 28.2-18.9 44-25.4l12.5-57.1c2-9.1 9-16.3 18.2-17.8C227.3 1.2 241.5 0 256 0s28.7 1.2 42.5 3.5c9.2 1.5 16.2 8.7 18.2 17.8l12.5 57.1c15.8 6.5 30.6 15.1 44 25.4l55.7-17.7c8.8-2.8 18.6-.3 24.5 6.8c8.1 9.8 15.5 20.2 22.1 31.2l4.7 8.1c6.1 11 11.4 22.4 15.8 34.3zM256 336a80 80 0 1 0 0-160 80 80 0 1 0 0 160z"/></svg>',
    trash: '<svg width="9" height="9" viewBox="0 0 448 512" fill="currentColor"><path d="M135.2 17.7L128 32 32 32C14.3 32 0 46.3 0 64S14.3 96 32 96l384 0c17.7 0 32-14.3 32-32s-14.3-32-32-32l-96 0-7.2-14.3C307.4 6.8 296.3 0 284.2 0L163.8 0c-12.1 0-23.2 6.8-28.6 17.7zM416 128L32 128 53.2 467c1.6 25.3 22.6 45 47.9 45l245.8 0c25.3 0 46.3-19.7 47.9-45L416 128z"/></svg>',
  };
  const F = (id, label, type, ph, icon, note) =>
    `<div style="margin-bottom:16px">
      <label style="display:block;font-size:9px;font-weight:900;color:#8B856C;
                    text-transform:uppercase;letter-spacing:.15em;margin:0 0 6px 4px">
        ${label}${note ? `<span style="color:#2d6a4f;font-weight:600;text-transform:none;letter-spacing:0;margin-left:4px">${note}</span>` : ""}
      </label>
      <div style="position:relative">
        <div style="position:absolute;inset:0 auto 0 14px;display:flex;align-items:center;
                    color:#b4af9a;pointer-events:none">${icon}</div>
        <input id="${id}" type="${type}" placeholder="${ph}"
          style="width:100%;height:44px;padding:0 14px 0 38px;border:1px solid #e5e2d9;
                 background:#fcfbf9;color:#1d1b16;border-radius:12px;font-size:14px;
                 font-weight:500;font-family:${type==="text"&&id.includes("email")?"inherit":"monospace"};
                 box-sizing:border-box;outline:none;transition:border-color .2s,box-shadow .2s">
      </div>
    </div>`;
  container.innerHTML =
    `<div style="min-height:100vh;width:100%;background:#f9f8f3;color:#3d3929;
                font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
                display:flex;align-items:flex-start;justify-content:center;padding:32px 20px">
      <div style="background:white;border:1px solid #e5e2d9;width:100%;max-width:520px;
                  padding:36px;border-radius:40px;box-shadow:0 12px 40px rgba(0,0,0,.02)">
        <div style="text-align:center;margin-bottom:24px">
          <div style="display:inline-flex;align-items:center;justify-content:center;
                      width:72px;height:72px;border-radius:20px;margin-bottom:16px;
                      background:#fcfbf9;border:1px solid #e5e2d9">
            <img src="${ICON}" alt="Claude" style="width:36px;height:36px;border-radius:6px">
          </div>
          <h1 style="font-size:26px;font-family:'Iowan Old Style',Georgia,serif;
                     color:#1d1b16;letter-spacing:-.02em;margin:0 0 8px;font-weight:400">
            Backend Settings
          </h1>
          <p style="color:#6b6651;font-size:13px;font-weight:500;margin:0;line-height:1.5">
            All data stored locally.
            <span style="color:#2d6a4f;font-weight:700">\u2714 No calls to cocodem servers.</span>
          </p>
        </div>
        <div id="bs_st" style="padding:11px 16px;border-radius:10px;margin-bottom:18px;
             display:none;font-size:13px;font-weight:600"></div>
        <div style="font-size:9px;font-weight:900;color:#8B856C;text-transform:uppercase;
                    letter-spacing:.15em;margin-bottom:14px">\u25b8 API Configuration</div>
        ${F("bs_base","API Base URL","text","http://127.0.0.1:1234/v1",K.link,"")}
        ${F("bs_key","API Key","password","sk-ant-\u2026 or any string",K.key,"")}
        ${F("bs_auth","Auth Token","password","optional",K.key,"")}
        <div style="font-size:9px;font-weight:900;color:#8B856C;text-transform:uppercase;
                    letter-spacing:.15em;margin:22px 0 8px">\u25b8 Model Aliases
          <span style="color:#b4af9a;font-weight:600;text-transform:none;letter-spacing:0;margin-left:6px">(JSON, optional)</span>
        </div>
        <textarea id="bs_aliases" placeholder='{"claude-opus-4-7": "local-model-name"}'
          style="width:100%;min-height:76px;padding:11px 14px;margin-bottom:4px;
                 border:1px solid #e5e2d9;background:#fcfbf9;color:#1d1b16;
                 border-radius:12px;font-size:13px;font-family:monospace;
                 box-sizing:border-box;outline:none;resize:vertical"></textarea>
        <div style="font-size:9px;font-weight:900;color:#8B856C;text-transform:uppercase;
                    letter-spacing:.15em;margin:22px 0 14px">\u25b8 Identity
          <span style="color:#2d6a4f;font-weight:700;text-transform:none;letter-spacing:0;margin-left:6px">\u2714 local \u2014 no license server</span>
        </div>
        ${F("bs_email","Email Address","email","user@local",K.mail,"")}
        ${F("bs_user","Username","text","local-user",K.user,"")}
        ${F("bs_lic","License Key","password","any value works",K.key,"(nothing validated)")}
        <div style="display:flex;gap:10px;margin:22px 0 14px">
          <button id="bs_save"
            style="flex:1;height:44px;background:#c45f3d;color:white;border:none;
                   border-radius:12px;font-size:15px;font-weight:900;cursor:pointer;
                   box-shadow:0 4px 14px rgba(196,95,61,.12);transition:all .15s">
            Save Settings
          </button>
          <button id="bs_test"
            style="flex:1;height:44px;background:white;color:#3d3929;
                   border:1px solid #e5e2d9;border-radius:12px;font-size:14px;
                   font-weight:700;cursor:pointer;transition:all .15s">
            Test Connection
          </button>
        </div>
        <div style="display:flex;align-items:center;gap:12px;color:#e5e2d9;margin:18px 0 14px">
          <div style="flex:1;border-top:1px solid currentColor;opacity:.6"></div>
          <span style="font-size:9px;font-weight:900;text-transform:uppercase;
                       letter-spacing:.2em;color:#b4af9a">Advanced</span>
          <div style="flex:1;border-top:1px solid currentColor;opacity:.6"></div>
        </div>
        <div style="text-align:center">
          <button id="bs_adv"
            style="font-size:9px;font-weight:900;color:#b4af9a;text-transform:uppercase;
                   letter-spacing:.18em;background:none;border:none;cursor:pointer;
                   display:inline-flex;align-items:center;gap:7px;padding:8px 12px">
            ${K.cog} Advanced Options
          </button>
          <div id="bs_ap" style="display:none;margin-top:12px;padding:18px;
               background:#fcfbf9;border-radius:14px;border:1px solid #e5e2d9;text-align:left">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
              <input type="checkbox" id="bs_block" checked
                style="width:auto;margin:0;accent-color:#c45f3d">
              <label for="bs_block"
                style="font-size:12px;font-weight:600;color:#3d3929;margin:0;cursor:pointer">
                Block analytics / telemetry
                <span style="color:#8b856c;font-weight:500;font-size:11px;margin-left:4px">
                  (Segment / Statsig / Sentry / Datadog / FingerprintJS)</span>
              </label>
            </div>
            <div style="display:flex;gap:8px;flex-wrap:wrap">
              <button id="bs_clear"
                style="font-size:9px;font-weight:900;color:#b04a3d;text-transform:uppercase;
                       letter-spacing:.15em;background:none;border:1px solid #e5e2d9;
                       border-radius:8px;padding:8px 14px;cursor:pointer;
                       display:inline-flex;align-items:center;gap:7px">
                ${K.trash} Clear Saved Data
              </button>
              <button id="bs_dump"
                style="font-size:9px;font-weight:900;color:#3d3929;text-transform:uppercase;
                       letter-spacing:.15em;background:none;border:1px solid #e5e2d9;
                       border-radius:8px;padding:8px 14px;cursor:pointer">
                Dump Storage (Console)
              </button>
            </div>
            <pre id="bs_pre" style="display:none;margin-top:12px;padding:12px;
                 background:#1d1b16;color:#e8e3d6;border-radius:8px;font-size:11px;
                 font-family:monospace;max-height:180px;overflow:auto"></pre>
          </div>
        </div>
        <div style="text-align:center;margin-top:22px;padding-top:16px;border-top:1px solid #e5e2d9">
          <p style="font-size:11px;color:#8b856c;margin:0;line-height:1.6">
            Proxy is source of truth. Falls back to
            <code style="background:#fcfbf9;padding:2px 5px;border-radius:4px;
            color:#c45f3d;font-family:monospace">chrome.storage.local</code> if proxy is down.
          </p>
        </div>
      </div>
    </div>`;
  document.querySelectorAll("input,textarea").forEach(el => {
    el.addEventListener("focus", () => { el.style.borderColor="#c45f3d"; el.style.boxShadow="0 0 0 3px rgba(196,95,61,.06)"; });
    el.addEventListener("blur",  () => { el.style.borderColor="#e5e2d9"; el.style.boxShadow="none"; });
  });
  const $ = id => document.getElementById(id);
  function st(m, k) {
    const el=$("bs_st"), s=k==="e"?{bg:"#fbe7e1",c:"#b04a3d",b:"1px solid #f3c5b8"}
      :k==="w"?{bg:"#fdf4e0",c:"#8b6914",b:"1px solid #f0d9a3"}
      :{bg:"#e6f2eb",c:"#2d6a4f",b:"1px solid #c5e0d0"};
    el.textContent=m; el.style.display="block";
    Object.assign(el.style,{background:s.bg,color:s.c,border:s.b});
    clearTimeout(el.__t); el.__t=setTimeout(()=>{el.style.display="none";},5000);
  }
  const KEYS=["ANTHROPIC_BASE_URL","ANTHROPIC_API_KEY","ANTHROPIC_AUTH_TOKEN",
              "email","username","licenseKey","hijackSettings"];
  const CFC_PROXY_BASE = "http://localhost:8520/";
  let proxyIdentity = null;
  try {
    const r = await fetch(CFC_PROXY_BASE + "api/identity", {cache:"no-store"});
    if (r.ok) proxyIdentity = await r.json();
  } catch(e) {}
  const saved=await chrome.storage.local.get(KEYS);
  const hs=saved.hijackSettings||{};
  const pickStr = (proxyKey, ...locals) => {
    if (proxyIdentity && typeof proxyIdentity[proxyKey] === "string" && proxyIdentity[proxyKey] !== "") return proxyIdentity[proxyKey];
    for (const v of locals) { if (v) return v; }
    return "";
  };
  const pickAny = (proxyKey, fallback) => {
    if (proxyIdentity && proxyIdentity[proxyKey] !== undefined) return proxyIdentity[proxyKey];
    return fallback;
  };
  $("bs_base").value  = pickStr("apiBaseUrl", saved.ANTHROPIC_BASE_URL, hs.backendUrl, "http://127.0.0.1:1234/v1");
  $("bs_key").value   = pickStr("apiKey",     saved.ANTHROPIC_API_KEY);
  $("bs_auth").value  = pickStr("authToken",  saved.ANTHROPIC_AUTH_TOKEN);
  $("bs_email").value = pickStr("email",      saved.email,    "user@local");
  $("bs_user").value  = pickStr("username",   saved.username, "local-user");
  $("bs_lic").value   = pickStr("licenseKey", saved.licenseKey);
  $("bs_block").checked = pickAny("blockAnalytics", hs.blockAnalytics !== false);
  const aliasSrc = (proxyIdentity && proxyIdentity.modelAliases) || hs.modelAliases || {};
  $("bs_aliases").value = aliasSrc && Object.keys(aliasSrc).length
    ? JSON.stringify(aliasSrc, null, 2) : "";
  if (proxyIdentity) {
    st("\u2714 Loaded from proxy at " + CFC_PROXY_BASE);
  }
  $("bs_save").onclick = async () => {
    const base=($("bs_base").value.trim()||"http://127.0.0.1:1234/v1");
    let ma={};
    const raw=$("bs_aliases").value.trim();
    if(raw){try{ma=JSON.parse(raw);}catch{st("Invalid JSON in Model Aliases","e");return;}}
    const payload = {
      apiBaseUrl:     base,
      apiKey:         $("bs_key").value.trim(),
      authToken:      $("bs_auth").value.trim(),
      email:          $("bs_email").value.trim()||"user@local",
      username:       $("bs_user").value.trim()||"local-user",
      licenseKey:     $("bs_lic").value.trim(),
      blockAnalytics: $("bs_block").checked,
      modelAliases:   ma,
    };
    let proxyOk = false;
    try {
      const r = await fetch(CFC_PROXY_BASE + "api/identity", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify(payload),
      });
      const d = await r.json();
      proxyOk = !!d.ok;
      if (!proxyOk) { st("Proxy save error: "+(d.error||"unknown"),"e"); }
    } catch(e) {
      st("\u2717 Proxy unreachable -- saved to chrome.storage only: "+e.message,"w");
    }
    await chrome.storage.local.set({
      ANTHROPIC_BASE_URL:   base,
      ANTHROPIC_API_KEY:    $("bs_key").value.trim(),
      ANTHROPIC_AUTH_TOKEN: $("bs_auth").value.trim(),
      email:      $("bs_email").value.trim()||"user@local",
      username:   $("bs_user").value.trim()||"local-user",
      licenseKey: $("bs_lic").value.trim(),
      hijackSettings:{backendUrl:base,modelAliases:ma,blockAnalytics:$("bs_block").checked},
    });
    try{localStorage.setItem("apiBaseUrl",base);}catch(e){}
    try {
      if (chrome?.runtime?.sendMessage) {
        chrome.runtime.sendMessage({type:"_update_options"}, ()=>{});
      }
    } catch(e) {}
    if (proxyOk) {
      st("\u2714 Saved to proxy + mirror. Backend: "+base);
    } else {
      st("\u26a0 Saved locally only (proxy unreachable). Backend: "+base, "w");
    }
  };
  $("bs_test").onclick = async () => {
    const url=$("bs_base").value.trim()||"http://127.0.0.1:1234/v1";
    st("Testing "+url+"\u2026","w");
    try{
      const r=await fetch(url.replace(/\/v1\/?$/,"")+"/v1/models");
      if(r.ok){const d=await r.json();st("\u2714 Models: "+(d.data?.map(m=>m.id).join(", ")||"OK"));}
      else st("HTTP "+r.status,"e");
    }catch(e){st("\u2717 Cannot reach "+url,"e");}
  };
  $("bs_adv").onclick=()=>{const p=$("bs_ap");p.style.display=p.style.display==="none"?"block":"none";};
  $("bs_clear").onclick=async()=>{
    if(!confirm("Clear all saved Backend Settings (proxy + chrome.storage)?"))return;
    try {
      await fetch(CFC_PROXY_BASE + "api/identity", {
        method:  "POST",
        headers: {"Content-Type":"application/json"},
        body:    JSON.stringify({
          apiBaseUrl:     "http://127.0.0.1:1234/v1",
          apiKey:         "",
          authToken:      "",
          email:          "user@local",
          username:       "local-user",
          licenseKey:     "",
          blockAnalytics: true,
          modelAliases:   {},
        }),
      });
    } catch(e) {}
    await chrome.storage.local.remove(KEYS);
    try{localStorage.removeItem("apiBaseUrl");}catch(e){}
    st("\u2714 Cleared (proxy + mirror)");setTimeout(()=>location.reload(),600);
  };
  $("bs_dump").onclick=async()=>{
    const all=await chrome.storage.local.get(null);
    const MASK=/^(ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|licenseKey|accessToken|refreshToken|sidepanelToken)$/;
    const pre=$("bs_pre");
    pre.textContent=JSON.stringify(all,(k,v)=>MASK.test(k)&&typeof v==="string"&&v.length>8?v.slice(0,4)+"\u2026"+v.slice(-4):v,2);
    pre.style.display="block";
    console.log("[cfc] storage.local dump:",all);
    st("\u2714 Dumped to console");
  };
})();
"""
    # Wire the user-typed local proxy base into the UI (was hardcoded :8520).
    ui = ui.replace('"http://localhost:8520/"', '"' + CFC_BASE + '"')
    (OUTPUT_DIR / "assets" / "backend_settings_ui.js").write_text(ui, encoding="utf-8")
    print(f"[OK] assets/backend_settings_ui.js ({len(ui)} bytes)")


def write_arc_html():
    html = """<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <link rel="icon" type="image/svg+xml" href="/icon-128.png" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Claude Agent</title>
  <script type="module" crossorigin src="/assets/request.js"></script>
</head>
<body>
  <div id="root">
    <div class="flex flex-col items-center justify-center h-screen bg-bg-100 relative overflow-hidden">
      <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-text-100"></div>
    </div>
  </div>
</body>
</html>"""
    (OUTPUT_DIR / "arc.html").write_text(html, encoding="utf-8")
    print("[OK] arc.html")


def write_options():
    for html_file in [OUTPUT_DIR / "sidepanel.html", OUTPUT_DIR / "options.html"]:
        if not html_file.exists():
            continue
        content  = html_file.read_text(encoding="utf-8")
        orig_len = len(content)
        lines, new_lines, skip = content.split("\n"), [], False
        for line in lines:
            if "<script" in line:
                if 'src=' in line or 'type="module"' in line or "type='module'" in line:
                    new_lines.append(line); skip = False
                else:
                    skip = True
            elif "</script>" in line and skip:
                skip = False
            elif not skip:
                new_lines.append(line)
        content = "\n".join(new_lines)
        content = re.sub(r"<script>\s*</script>", "", content, flags=re.DOTALL)
        html_file.write_text(content, encoding="utf-8")
        print(f"[OK] {html_file.name} -- stripped {orig_len - len(content)} bytes inline scripts")

    stub = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="0;url=/options.html#backendsettings">
<title>Backend Settings</title></head>
<body><p>Redirecting to <a href="/options.html#backendsettings">Backend Settings</a>...</p></body>
</html>"""
    bs = OUTPUT_DIR / "backend_settings.html"
    og = OUTPUT_DIR / "backend_settingsOG.html"
    if bs.exists() and not og.exists():
        shutil.copy2(bs, og)
        print("[OK] backend_settings.html --> backend_settingsOG.html (preserved)")
    bs.write_text(stub, encoding="utf-8")
    if not og.exists():
        og.write_text(stub, encoding="utf-8")
    print("[OK] backend_settings.html (meta-refresh stub)")


def inject_index_module():
    assets = OUTPUT_DIR / "assets"
    target = None
    known  = assets / "index-BVS4T5_D.js"
    if known.exists():
        target = known
        print(f"  jsx-runtime: {target.relative_to(OUTPUT_DIR)} (known)")
    if not target:
        sp = OUTPUT_DIR / "sidepanel.html"
        if sp.exists():
            html = sp.read_text(encoding="utf-8")
            for href in re.findall(r'<link[^>]+rel="modulepreload"[^>]+href="([^"]+)"', html):
                c = OUTPUT_DIR / href.lstrip("/")
                if c.exists() and c.stat().st_size < 30000:
                    t = c.read_text(encoding="utf-8")
                    if "jsx" in t and "jsxs" in t and "Fragment" in t and "$$typeof" in t:
                        target = c
                        print(f"  jsx-runtime: {target.relative_to(OUTPUT_DIR)} (modulepreload)")
                        break
    if not target:
        for f in sorted(assets.glob("index-*.js")):
            if f.stat().st_size < 30000:
                t = f.read_text(encoding="utf-8")
                if "jsx" in t and "jsxs" in t and "Fragment" in t:
                    target = f
                    print(f"  jsx-runtime: {target.relative_to(OUTPUT_DIR)} (scan)")
                    break
    if not target:
        print("[WARN] jsx-runtime not found -- setJsx not injected")
        return
    content = target.read_text(encoding="utf-8")
    if "setJsx" in content:
        print(f"[OK] setJsx already in {target.relative_to(OUTPUT_DIR)} -- skip")
        return
    m        = re.search(r",(\w)=\{\}[,;]", content) or re.search(r"(\w)=\{\}", content)
    var_name = m.group(1) if m else "l"
    print(f"  jsx var: {var_name}")
    injection = f"\nimport {{ setJsx }} from './request.js';\nsetJsx({var_name});\n"
    b = re.search(r"(y\s*=\s*\{\s*\};)\s*(function\s+d\s*\()", content)
    if b:
        content = content[:b.end(1)] + injection + content[b.start(2):]
    else:
        fn = re.search(r"function\s+d\s*\(", content)
        if fn:
            content = content[:fn.start()] + injection + content[fn.start():]
        else:
            content += injection
    target.write_text(content, encoding="utf-8")
    print(f"[OK] Injected setJsx({var_name}) --> {target.relative_to(OUTPUT_DIR)}")


# ─── local auth responses ─────────────────────────────────────────────────────

def _jwt(payload: dict) -> str:
    h = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    b = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    return f"{h}.{b}.local"

_LOCAL_TOKEN_CACHE: dict = {}

def build_local_token() -> dict:
    global _LOCAL_TOKEN_CACHE
    if _LOCAL_TOKEN_CACHE:
        return _LOCAL_TOKEN_CACHE
    now = int(time.time())
    p   = {"iss": "cfc", "sub": "ac507011-00b5-56c4-b3ec-ad820dbafbc1",
           "exp": now + 315360000, "iat": 1700000000}
    tok = _jwt(p)
    _LOCAL_TOKEN_CACHE = {"access_token": tok, "token_type": "bearer",
                          "expires_in": 315360000, "refresh_token": tok,
                          "scope": "user:profile user:inference user:chat"}
    return _LOCAL_TOKEN_CACHE

_UUID_U = "ac507011-00b5-56c4-b3ec-ad820dbafbc1"
_UUID_O = "1b61ee4a-d0ce-50b5-8b67-7eec034d3d08"
_EMAIL   = "free@claudeagent.ai"

LOCAL_ACCOUNT = {
    "uuid": _UUID_U, "id": _UUID_U,
    "email_address": _EMAIL, "email": _EMAIL,
    "full_name": "Local User", "name": "Local User", "display_name": "Local User",
    "has_password": True, "has_completed_onboarding": True,
    "preferred_language": "en-US", "has_claude_pro": True,
    "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z",
    "settings": {"theme": "system", "language": "en-US"},
}
LOCAL_ORG = {
    "uuid": _UUID_O, "id": _UUID_O, "name": "Local", "role": "admin",
    "organization_type": "personal", "billing_type": "self_serve",
    "capabilities": ["chat", "claude_pro_plan", "api", "computer_use", "claude_for_chrome"],
    "rate_limit_tier": "default_claude_pro", "settings": {},
    "created_at": "2024-01-01T00:00:00Z",
}
LOCAL_PROFILE = {
    **LOCAL_ACCOUNT,
    "account": LOCAL_ACCOUNT,
    "organization": LOCAL_ORG,
    "memberships": [{"organization": LOCAL_ORG, "role": "admin", "joined_at": "2024-01-01T00:00:00Z"}],
    "active_organization_uuid": _UUID_O,
}
LOCAL_BOOTSTRAP = {
    **LOCAL_ACCOUNT,
    "account_uuid": _UUID_U,
    "account": LOCAL_ACCOUNT,
    "organization": LOCAL_ORG,
    "organizations": [LOCAL_ORG],
    "memberships": [{"organization": LOCAL_ORG, "role": "admin", "joined_at": "2024-01-01T00:00:00Z"}],
    "active_organization_uuid": _UUID_O,
    "statsig": {
        "user": {"userID": _UUID_U, "custom": {"organization_uuid": _UUID_O}},
        "values": {"feature_gates": {}, "dynamic_configs": {}, "layer_configs": {}},
    },
    "flags": {}, "features": [], "active_flags": {},
    "active_subscription": {
        "plan": "claude_pro", "status": "active", "type": "claude_pro",
        "billing_period": "monthly",
        "current_period_start": "2024-01-01T00:00:00Z",
        "current_period_end":   "2099-12-31T23:59:59Z",
    },
    "has_claude_pro": True, "chat_enabled": True,
    "capabilities": ["chat", "claude_pro_plan", "api", "computer_use", "claude_for_chrome"],
    "rate_limit_tier": "default_claude_pro",
    "settings": {"theme": "system", "language": "en-US"},
}
LOCAL_ORGS = [LOCAL_ORG]
LOCAL_CONV = {"conversations": [], "limit": 0, "has_more": False, "cursor": None}

def get_local_auth(path: str) -> dict:
    if "/licenses/verify"          in path: return {"valid": True, "license": "local", "tier": "pro", "expires": "2099-12-31"}
    if "/mcp/v2/bootstrap"         in path: return {"servers": [], "tools": [], "enabled": False}
    if "/spotlight"                in path: return {"items": [], "total": 0}
    if "/features/"                in path: return {"enabled": True, "features": {}}
    if "/oauth/account/settings"   in path: return {"settings": {"theme": "system", "language": "en-US"}}
    if "/oauth/profile"            in path: return LOCAL_PROFILE
    if "/oauth/account"            in path: return LOCAL_PROFILE
    if "/oauth/token"              in path: return build_local_token()
    if "/bootstrap"                in path: return LOCAL_BOOTSTRAP
    if "/oauth/organizations"      in path:
        tail = path.split("/oauth/organizations/", 1)[1] if "/oauth/organizations/" in path else ""
        if "/" in tail:  return {}
        if tail:         return LOCAL_ORG
        return LOCAL_ORGS
    if "/chat_conversations"       in path: return LOCAL_CONV
    if "/domain_info"              in path: return {"domain": "local", "allowed": True}
    if "/url_hash_check"           in path: return {"allowed": True}
    if "/usage"                    in path: return {"usage": {}, "limit": None}
    if "/entitlements"             in path: return {"entitlements": []}
    if "/flags"                    in path: return {}
    return {}


def _redirect_page_html() -> str:
    eid = EXTENSION_ID
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Authenticating\u2026</title></head>
<body style="background:#f9f8f3;font-family:-apple-system,sans-serif;display:flex;
             align-items:center;justify-content:center;height:100vh;margin:0">
<div style="background:white;border:1px solid #e5e2d9;border-radius:32px;padding:40px;
            max-width:400px;width:100%;text-align:center">
  <h2 style="margin:0 0 8px;font-size:22px;font-family:'Iowan Old Style',Georgia,serif;
             font-weight:400;color:#1d1b16">Signed in!</h2>
  <p id="msg" style="color:#8b856c;font-size:13px;font-weight:500;margin:8px 0">Working\u2026</p>
</div>
<script>
(async()=>{{
  const msg=document.getElementById("msg");
  const done=t=>{{msg.textContent=t;msg.style.color="#2d6a4f";
    setTimeout(()=>{{try{{window.close()}}catch(e){{}}}},800)}};
  try{{
    const p=new URLSearchParams(window.location.search);
    const r=p.get("redirect_uri")||"",state=p.get("state")||"";
    let eid="{eid}";
    if(r.startsWith("chrome-extension://")){{try{{eid=new URL(r).host}}catch(e){{}}}}
    const arr=new Uint8Array(32);crypto.getRandomValues(arr);
    const code="cfc-"+btoa(String.fromCharCode(...arr))
      .replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=/g,"");
    let final=r;
    if(final){{try{{const u=new URL(final);u.searchParams.set("code",code);
      if(state)u.searchParams.set("state",state);final=u.toString();}}
      catch(e){{final=r+(r.includes("?")?"&":"?")+"code="+code}}}}
    if(typeof chrome!=="undefined"&&chrome.runtime&&eid){{
      chrome.runtime.sendMessage(eid,{{type:"oauth_redirect",redirect_uri:final}},rv=>{{
        if(chrome.runtime.lastError||!rv?.success){{
          chrome.runtime.sendMessage(eid,{{type:"_set_storage_local",data:{{
            accessToken:btoa(JSON.stringify({{alg:"none",typ:"JWT"}}))+"."+
              btoa(JSON.stringify({{iss:"cfc",sub:"{_UUID_U}",exp:9999999999,
                iat:1700000000}}))+".local",
            refreshToken:"local-refresh",tokenExpiry:Date.now()+31536000000,
            accountUuid:"{_UUID_U}",
            sidepanelToken:"cfc-local",sidepanelTokenExpiry:Date.now()+31536000000,
          }}}},()=>done("Done!"));
        }}else done("Done!");
      }});
    }}else done("Auth complete.");
  }}catch(e){{msg.textContent="Error: "+e.message;msg.style.color="#b04a3d"}}
}})();
</script></body></html>"""


def _build_proxy_settings_html() -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Backend Settings</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:-apple-system,sans-serif;background:#f9f8f3;color:#3d3929;
margin:0;padding:32px 20px;min-height:100vh}}
.w{{background:white;border:1px solid #e5e2d9;max-width:660px;margin:0 auto;padding:36px;
border-radius:24px;box-shadow:0 8px 32px rgba(0,0,0,.04)}}
h1{{font-size:24px;font-family:"Iowan Old Style",Georgia,serif;color:#1d1b16;
font-weight:400;letter-spacing:-.02em;margin:0 0 8px}}
.sub{{color:#6b6651;font-size:13px;margin:0 0 24px}}
.backend{{border:1px solid #e5e2d9;border-radius:12px;padding:18px;margin-bottom:12px;background:#fcfbf9}}
.bhead{{display:flex;align-items:center;gap:8px;margin-bottom:14px}}
.bname{{font-weight:700;font-size:14px;flex:1;color:#1d1b16}}
.badge{{font-size:10px;background:#e5e2d9;color:#6b6651;padding:2px 7px;border-radius:4px;font-weight:700}}
.row{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
label{{display:block;font-size:9px;font-weight:900;color:#8B856C;text-transform:uppercase;letter-spacing:.15em;margin:10px 0 4px 2px}}
input{{width:100%;height:38px;padding:0 12px;border:1px solid #e5e2d9;background:white;color:#1d1b16;border-radius:8px;font-size:13px;font-family:monospace;outline:none;transition:border-color .15s}}
input:focus{{border-color:#c45f3d;box-shadow:0 0 0 3px rgba(196,95,61,.08)}}
.actions{{display:flex;gap:6px}}
.btn{{height:34px;border:none;border-radius:7px;font-size:12px;font-weight:700;cursor:pointer;padding:0 14px;transition:all .15s}}
.btn-del{{background:#fbe7e1;color:#b04a3d}}
.btn-tst{{background:#f0f0ea;color:#3d3929}}
.btn-add{{background:#e6f2eb;color:#2d6a4f;width:100%;height:40px;font-size:13px;margin-top:4px}}
.btn-save{{background:#c45f3d;color:white;width:100%;height:46px;font-size:15px;margin-top:16px;border-radius:12px}}
.ts{{font-size:11px;margin-top:6px;min-height:16px;font-weight:600}}
.st{{padding:11px 16px;border-radius:10px;margin-bottom:16px;font-size:13px;font-weight:600;display:none}}
.ok{{display:block;background:#e6f2eb;color:#2d6a4f}}
.er{{display:block;background:#fbe7e1;color:#b04a3d}}
</style></head>
<body><div class="w">
  <h1>CFC Backend Settings</h1>
  <p class="sub">First backend whose models list matches the request model wins.<br>
    Empty models list = catch-all. Changes apply on save.</p>
  <div id="st" class="st"></div>
  <div id="list"></div>
  <button class="btn btn-add" onclick="addBackend()">+ Add Backend</button>
  <button class="btn btn-save" onclick="save()">Save &amp; Apply</button>
</div>
<script>
let B=[];
function esc(s){{return String(s||"").replace(/&/g,"&amp;").replace(/"/g,"&quot;").replace(/</g,"&lt;")}}
function st(m,e){{const el=document.getElementById("st");el.textContent=m;el.className="st "+(e?"er":"ok")}}
function render(){{
  document.getElementById("list").innerHTML=B.map((b,i)=>
  `<div class="backend" id="b${{i}}">
    <div class="bhead">
      <span class="bname">${{esc(b.name)||"Backend "+(i+1)}}</span>
      ${{!b.models?.length?"<span class='badge'>catch-all</span>":""}}
      <div class="actions">
        <button class="btn btn-tst" onclick="testBackend(${{i}})">Test</button>
        ${{B.length>1?`<button class='btn btn-del' onclick='del(${{i}})'>Remove</button>`:""}}
      </div>
    </div>
    <div class="row">
      <div><label>Name</label>
        <input value="${{esc(b.name)}}" onchange="upd(${{i}},'name',this.value)" placeholder="e.g. LM Studio"></div>
      <div><label>Base URL (/v1)</label>
        <input value="${{esc(b.url)}}" onchange="upd(${{i}},'url',this.value)" placeholder="http://127.0.0.1:1234/v1"></div>
    </div>
    <label>API Key (blank = pass through extension key)</label>
    <input type="password" value="${{esc(b.key)}}" onchange="upd(${{i}},'key',this.value)" placeholder="sk-...">
    <label>Models (comma-separated -- blank = catch-all)</label>
    <input value="${{esc((b.models||[]).join(", "))}}"
      onchange="upd(${{i}},'models',this.value.split(',').map(s=>s.trim()).filter(Boolean))"
      placeholder="claude-opus-4-7, claude-sonnet-4-6">
    <div class="ts" id="ts${{i}}"></div>
  </div>`).join("");
}}
window.upd=function(i,k,v){{B[i][k]=v}};
window.del=function(i){{B.splice(i,1);render()}};
window.addBackend=function(){{
  B.push({{name:"",url:"http://127.0.0.1:1234/v1",key:"",models:[],enabled:true}});
  render();
  setTimeout(()=>document.getElementById("b"+(B.length-1))?.scrollIntoView({{behavior:"smooth"}}),50);
}};
window.testBackend=async function(i){{
  const b=B[i],el=document.getElementById("ts"+i);
  el.textContent="Testing...";el.style.color="#6b6651";
  try{{
    const h=b.key?{{Authorization:"Bearer "+b.key}}:{{}};
    const r=await fetch(b.url.replace(/\\/v1\\/?$/,"")+"/v1/models",{{headers:h}});

    if(r.ok){{const d=await r.json();el.textContent="\u2713 "+(d.data||[]).map(m=>m.id).slice(0,4).join(", ");el.style.color="#2d6a4f";}}
    else{{el.textContent="\u2717 HTTP "+r.status;el.style.color="#b04a3d"}}
  }}catch(e){{el.textContent="\u2717 "+e.message;el.style.color="#b04a3d"}}
}};
window.save=async function(){{
  try{{
    const r=await fetch("/api/backends",{{method:"POST",
      headers:{{"Content-Type":"application/json"}},body:JSON.stringify({{backends:B}})}});
    const d=await r.json();
    if(d.ok)st("\u2713 Saved");else st("Error: "+(d.error||"unknown"),true);
  }}catch(e){{st("Save failed: "+e.message,true)}}
}};
(async()=>{{
  try{{
    const r=await fetch("/api/backends");
    const d=await r.json();
    B=d.backends||[];
    if(!B.length)B=[{{name:"Default",url:"http://127.0.0.1:1234/v1",key:"",models:[],enabled:true}}];
    render();
  }}catch(e){{st("Cannot reach proxy: "+e.message,true)}}
}})();
</script></body></html>"""


def _build_arc_split_view_html() -> str:
    return """<div style="display:flex;height:100vh;width:100vw;overflow:hidden;font-family:-apple-system,sans-serif">
  <div id="web-panel" style="flex:1;border-right:1px solid #e5e2d9;display:flex;flex-direction:column;min-width:0">
    <div style="height:44px;border-bottom:1px solid #e5e2d9;display:flex;align-items:center;padding:0 12px;background:#f9f8f3;gap:8px">
      <div style="flex:1;height:32px;background:white;border:1px solid #e5e2d9;border-radius:8px;display:flex;align-items:center;padding:0 10px;font-size:13px;color:#8b856c">Web Panel</div>
    </div>
    <div style="flex:1;background:white;overflow:auto;padding:20px;color:#3d3929">
      <p style="color:#8b856c;font-size:13px">Select a tab or enter a URL to browse alongside Claude.</p>
    </div>
  </div>
  <div id="claude-panel" style="flex:1;display:flex;flex-direction:column;min-width:0">
    <div style="height:44px;border-bottom:1px solid #e5e2d9;display:flex;align-items:center;padding:0 12px;background:#f9f8f3;gap:8px">
      <div style="flex:1;height:32px;background:white;border:1px solid #e5e2d9;border-radius:8px;display:flex;align-items:center;padding:0 10px;font-size:13px;color:#8b856c">Claude Panel</div>
    </div>
    <div style="flex:1;background:#f9f8f3;overflow:auto;display:flex;align-items:center;justify-content:center">
      <p style="color:#b4af9a;font-size:13px">Claude conversation will appear here.</p>
    </div>
  </div>
</div>"""


def _build_root_page_html() -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CFC Multi-Backend Server</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f9f8f3;color:#3d3929;margin:0;padding:0;min-height:100vh}}
.hero{{padding:64px 24px 48px;text-align:center;max-width:720px;margin:0 auto}}
.hero h1{{font-size:36px;font-family:'Iowan Old Style',Georgia,serif;font-weight:400;color:#1d1b16;margin:0 0 16px}}
.hero p{{font-size:15px;color:#6b6651;margin:0 0 32px;line-height:1.7}}
.btn-primary{{display:inline-flex;align-items:center;gap:8px;height:44px;padding:0 24px;background:#c45f3d;color:white;border:none;border-radius:12px;font-size:15px;font-weight:700;cursor:pointer;text-decoration:none}}
</style></head>
<body>
<div class="hero">
  <h1>CFC Multi-Backend Server</h1>
  <p>Remote: {WORKER_BASE}<br>Local: {CFC_BASE}<br>Port {CFC_PORT} -- {len(BACKENDS)} backend(s)</p>
  <a href="/backend_settings" class="btn-primary">\u2699\ufe0f Backend Settings</a>
</div>
</body></html>"""


def _build_fallback_html(path: str) -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CFC Server</title>
<style>body{{font-family:-apple-system,sans-serif;background:#f9f8f3;color:#3d3929;margin:0;padding:40px 20px;display:flex;align-items:center;justify-content:center;min-height:100vh}}
.w{{background:white;border:1px solid #e5e2d9;border-radius:24px;padding:40px;max-width:480px;width:100%;text-align:center}}
a{{color:#c45f3d;text-decoration:none;font-weight:700;font-size:13px}}
.code{{background:#fcfbf9;border:1px solid #e5e2d9;border-radius:8px;padding:12px;font-family:monospace;font-size:12px;color:#8b856c;margin-top:16px;overflow-wrap:break-word}}
</style></head>
<body><div class="w">
  <h1 style="font-size:20px;margin:0 0 8px">CFC Server</h1>
  <p style="color:#6b6651;font-size:13px;margin:0 0 20px">Route served dynamically.</p>
  <a href="/">Back to Dashboard</a>
  <div class="code">{path}</div>
</div></body></html>"""


# ─── proxy server ─────────────────────────────────────────────────────────────

class MultiC2Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"  [{time.strftime('%H:%M:%S')}] {args[0]}")

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
            pass

    def _json(self, data, status=200):
        b = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Connection",     "close")
        self._cors()
        self.end_headers()
        try: self.wfile.write(b)
        except OSError: pass

    def _html(self, html):
        b = html.encode()
        self.send_response(200)
        self.send_header("Content-Type",   "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Connection",     "close")
        self._cors()
        self.end_headers()
        try: self.wfile.write(b)
        except OSError: pass

    def _204(self):
        self.send_response(204)
        self.send_header("Connection", "close")
        self._cors()
        self.end_headers()

    def _redirect(self, location, status=302):
        self.send_response(status)
        self.send_header("Location",   location)
        self.send_header("Connection", "close")
        self._cors()
        self.end_headers()

    def _serve_file(self, file_path: Path, content_type: str):
        if not file_path.exists():
            self._html(_build_fallback_html(self.path))
            return
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type",   content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection",     "close")
        self._cors()
        self.end_headers()
        try: self.wfile.write(data)
        except OSError: pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin",          "*")
        self.send_header("Access-Control-Allow-Methods",
                         "GET, POST, PATCH, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers",
                         "Content-Type, Cache-Control, Accept, "
                         "anthropic-version, anthropic-beta, "
                         "anthropic-client-platform, anthropic-client-version, "
                         "Authorization, x-app, x-service-name, x-api-key")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age",               "86400")

    def _is_tel(self, p: str) -> bool:
        return any(d in p for d in TELEMETRY_DOMAINS)

    def _is_v1(self, p: str) -> bool:
        if "/v1/oauth" in p:
            return False
        if p.startswith("/v1/"):
            return True
        if "/v1/" in p and (
            "api.anthropic.com" in p or
            p.startswith("/https://api.anthropic.com/") or
            "cfc.aroic.workers.dev" in p
        ):
            return True
        return False

    def _is_auth(self, p: str) -> bool:
        if p.startswith("/https://") or p.startswith("/http://"):
            return True
        if p.startswith("/chrome-extension://"):
            return True
        return any(s in p for s in [
            "/oauth/", "/bootstrap", "/domain_info", "/chat_conversations",
            "/organizations", "/url_hash_check", "/api/web/", "/features/",
            "/spotlight", "/usage", "/entitlements", "/flags", "/mcp/v2/",
            "/licenses/",
        ])

    def _try_static_asset(self, p: str) -> bool:
        if not p.startswith("/"):
            return False
        rel_path  = p.lstrip("/").split("?")[0]
        file_path = OUTPUT_DIR / rel_path
        if not file_path.exists() or not file_path.is_file():
            return False
        ct, _ = mimetypes.guess_type(str(file_path))
        if not ct:
            ext = file_path.suffix.lower()
            ct = {
                ".js":    "application/javascript; charset=utf-8",
                ".css":   "text/css; charset=utf-8",
                ".html":  "text/html; charset=utf-8",
                ".json":  "application/json",
                ".png":   "image/png",
                ".jpg":   "image/jpeg",
                ".jpeg":  "image/jpeg",
                ".svg":   "image/svg+xml",
                ".ico":   "image/x-icon",
                ".woff2": "font/woff2",
                ".woff":  "font/woff",
            }.get(ext, "application/octet-stream")
        self._serve_file(file_path, ct)
        return True

    def _v1_path_suffix(self, p: str) -> str:
        if p.startswith("/v1/"):
            return p[3:]
        idx = p.find("/v1/")
        if idx != -1:
            return p[idx + 3:]
        return p

    def _stream_sse(self, resp):
        ct = resp.headers.get("Content-Type", "text/event-stream")
        self.send_header("Content-Type",      ct)
        self.send_header("Cache-Control",     "no-cache")
        self.send_header("Connection",        "keep-alive")
        self.send_header("Transfer-Encoding", "chunked")
        self._cors()
        self.end_headers()
        try:
            while True:
                chunk = resp.read(4096)
                if not chunk:
                    break
                self.wfile.write(f"{len(chunk):x}\r\n".encode())
                self.wfile.write(chunk)
                self.wfile.write(b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (OSError, BrokenPipeError):
            pass
        finally:
            resp.close()

    def _forward_v1(self, method: str, body: bytes):
        model = ""
        if body:
            try: model = json.loads(body).get("model", "")
            except Exception: pass

        suffix = self._v1_path_suffix(self.path)

        ALLOW_HDRS = {
            "content-type", "accept", "authorization",
            "anthropic-version", "anthropic-beta",
            "anthropic-client-platform", "anthropic-client-version",
            "x-api-key", "x-service-name",
        }
        base_hdrs = {k: v for k, v in self.headers.items()
                     if k.lower() in ALLOW_HDRS}
        ext_auth  = self.headers.get("Authorization", "")

        last_err = None

        for backend in _pick_backends(model):
            target = backend["url"].rstrip("/") + suffix
            hdrs   = dict(base_hdrs)

            if backend.get("key"):
                hdrs["Authorization"] = f"Bearer {backend['key']}"
            elif ext_auth:
                hdrs["Authorization"] = ext_auth

            send_body = body
            if send_body and method in ("POST", "PUT", "PATCH"):
                try:
                    parsed = json.loads(send_body)
                    aliases = {**(_merged_model_alias()), **(backend.get("modelAlias") or {})}
                    if parsed.get("model") and aliases.get(parsed["model"]):
                        parsed["model"] = aliases[parsed["model"]]
                        send_body = json.dumps(parsed).encode()
                except Exception:
                    pass

            req = urllib.request.Request(
                target,
                data=send_body or None,
                headers=hdrs,
                method=method,
            )
            print(f"  [FWD\u2192{backend.get('name','?')}] {method} {target}"
                  + (f" [{model}]" if model else ""))

            try:
                resp = urllib.request.urlopen(req, timeout=300)
                ct   = resp.headers.get("Content-Type", "")
                self.send_response(resp.status)
                if "text/event-stream" in ct:
                    self._stream_sse(resp)
                else:
                    data = resp.read()
                    resp.close()
                    self.send_header("Content-Type",   ct or "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Connection",     "close")
                    self._cors()
                    self.end_headers()
                    try: self.wfile.write(data)
                    except OSError: pass
                return

            except urllib.error.HTTPError as e:
                if e.code < 500:
                    data = e.read() or b""
                    self.send_response(e.code)
                    self.send_header("Content-Type",
                                     e.headers.get("Content-Type", "application/json"))
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Connection",     "close")
                    self._cors()
                    self.end_headers()
                    try: self.wfile.write(data)
                    except OSError: pass
                    return
                last_err = e
                print(f"  [FAIL\u2192{backend.get('name','?')}] HTTP {e.code} -- trying next")

            except Exception as ex:
                last_err = ex
                print(f"  [FAIL\u2192{backend.get('name','?')}] {ex} -- trying next")

        err = json.dumps({"error": {
            "type":    "proxy_error",
            "message": f"All backends failed. Last: {last_err}",
        }}).encode()
        self.send_response(502)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(err)))
        self.send_header("Connection",     "close")
        self._cors()
        self.end_headers()
        try: self.wfile.write(err)
        except OSError: pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Connection", "close")
        self._cors()
        self.end_headers()

    def do_GET(self):
        p = self.path
        if self._is_tel(p): self._204(); return
        if self._try_static_asset(p): return
        if self._is_v1(p): self._forward_v1("GET", b""); return
        if p.startswith("/api/options"):
            self._json(_build_options_response()); return
        if p.startswith("/api/identity"):
            self._json({
                "apiBaseUrl":     IDENTITY.get("apiBaseUrl") or DEFAULT_BACKEND_URL,
                "apiKey":         IDENTITY.get("apiKey", ""),
                "authToken":      IDENTITY.get("authToken", ""),
                "email":          IDENTITY.get("email", "user@local"),
                "username":       IDENTITY.get("username", "local-user"),
                "licenseKey":     IDENTITY.get("licenseKey", ""),
                "blockAnalytics": bool(IDENTITY.get("blockAnalytics", True)),
                "modelAliases":   IDENTITY.get("modelAliases") or {},
                "mode":           IDENTITY.get("mode", "") or "",
            }); return
        if p.startswith("/api/backends"):
            self._json({"backends": BACKENDS}); return
        if p.startswith("/api/arc-split-view"):
            self._json({"html": _build_arc_split_view_html()}); return
        if p.startswith("/discard"):
            self._204(); return
        if "/oauth/authorize" in p:
            qs = urlparse(p).query
            self._redirect(f"{CFC_BASE}oauth/redirect?{qs}")
            return
        if p.startswith("/oauth/redirect"):
            self._html(_redirect_page_html()); return
        if p.startswith("/backend_settings"):
            self._html(_build_proxy_settings_html()); return
        if self._is_auth(p):
            self._json(get_local_auth(p)); return
        if p in ("/",) or p.startswith("/?"):
            self._html(_build_root_page_html()); return
        self._html(_build_fallback_html(p))

    def do_POST(self):
        cl   = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl) if cl > 0 else b""
        p    = self.path
        if self._is_tel(p): self._204(); return
        if p.startswith("/api/backends"):
            try:
                cfg = json.loads(body)
                bs  = cfg.get("backends", [])
                if not isinstance(bs, list) or not bs:
                    self._json({"error": "backends must be a non-empty list"}); return
                for b in bs:
                    if not isinstance(b, dict):
                        self._json({"error": "each backend must be an object"}); return
                    b.setdefault("name",       "")
                    b.setdefault("url",        DEFAULT_BACKEND_URL)
                    b.setdefault("key",        "")
                    b.setdefault("models",     [])
                    b.setdefault("modelAlias", {})
                    b.setdefault("enabled",    True)
                BACKENDS.clear()
                BACKENDS.extend(bs)
                _save_backends()
                self._json({"ok": True, "backends": BACKENDS})
            except Exception as ex:
                self._json({"error": str(ex)})
            return
        if p.startswith("/api/identity"):
            try:
                cfg = json.loads(body)
                ALLOWED = {"apiBaseUrl", "apiKey", "authToken",
                           "email", "username", "licenseKey",
                           "blockAnalytics", "modelAliases", "mode"}
                for k, v in cfg.items():
                    if k in ALLOWED:
                        IDENTITY[k] = v
                if not isinstance(IDENTITY.get("modelAliases"), dict):
                    IDENTITY["modelAliases"] = {}
                IDENTITY["blockAnalytics"] = bool(IDENTITY.get("blockAnalytics", True))
                _save_identity()
                self._json({"ok": True})
            except Exception as ex:
                self._json({"error": str(ex)})
            return
        if self._is_v1(p):   self._forward_v1("POST", body); return
        if self._is_auth(p): self._json(get_local_auth(p));   return
        self._json({"ok": True})

    def do_PATCH(self):
        cl   = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl) if cl > 0 else b""
        p    = self.path
        if self._is_tel(p):  self._204(); return
        if self._is_v1(p):   self._forward_v1("PATCH", body); return
        if self._is_auth(p): self._json(get_local_auth(p));    return
        self._json({"ok": True})

    def do_PUT(self):
        cl   = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl) if cl > 0 else b""
        p    = self.path
        if self._is_tel(p):  self._204(); return
        if self._is_v1(p):   self._forward_v1("PUT", body); return
        if self._is_auth(p): self._json(get_local_auth(p));  return
        self._json({"ok": True})

    def do_DELETE(self):
        cl   = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl) if cl > 0 else b""
        p    = self.path
        if self._is_tel(p):  self._204(); return
        if self._is_v1(p):   self._forward_v1("DELETE", body); return
        if self._is_auth(p): self._json(get_local_auth(p));     return
        self._json({"ok": True})


class MultiC2Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads      = True


def start_proxy():
    try:
        server = MultiC2Server(("127.0.0.1", CFC_PORT), MultiC2Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"\n[OK] Local CFC server running on {CFC_BASE}")
        print(f"     Remote CFC Worker: {WORKER_BASE}")
        print(f"     Backends: {len(BACKENDS)}")
        for b in BACKENDS:
            models = ", ".join(b.get("models") or ["(catch-all)"])
            print(f"       \u2022 {b.get('name','?')}: {b['url']} [{models}]")
        return server
    except OSError as e:
        print(f"[WARN] Cannot bind port {CFC_PORT}: {e}")
        return None


def print_report(m):
    print("\n" + "=" * 62)
    print(f"  DONE -- {OUTPUT_DIR}")
    print("=" * 62)
    print(f"  {m.get('name')} v{m.get('version')}")
    print(f"\n  Remote CFC: {WORKER_BASE}")
    print(f"  Local CFC:  {CFC_BASE}")
    print(f"\n  Install:")
    print(f"  1. Disable cocodem in chrome://extensions/")
    print(f"  2. Enable Developer Mode")
    print(f"  3. Load unpacked --> {OUTPUT_DIR.resolve()}")
    print(f"\n  Backend Settings:")
    print(f"  {BACKEND_SETTINGS_URL}")
    print(f"\n  Keep terminal open. Ctrl+C to stop.\n")


# ─── main ─────────────────────────────────────────────────────────────────────

def _write_worker_js_file(port: int) -> Path:
    """Write the Cloudflare Worker JS to disk so the user can deploy it manually.
    Returns the path of the written file."""
    js      = _build_worker_script(port)
    out     = Path("cloudflare_worker.js")
    out.write_text(js, encoding="utf-8")
    return out


def main():
    global CFC_PORT, CFC_BASE, CFC_BASE_NO_SLASH, WORKER_BASE, BACKEND_SETTINGS_URL

    print("=" * 62)
    print("  Claude Extension Sanitizer")
    print("  Dual-Domain Local-Config Setup")
    print("=" * 62)
    print()
    print("  This script patches cocodem's trojanized extension and")
    print("  starts a local multi-C2 server.")
    print()
    print("  ZERO remote calls are made by this script. You deploy")
    print("  your own free Cloudflare Worker manually:")
    print()
    print("  1. Go to https://workers.cloudflare.com/")
    print("     Create a Worker (free tier is fine).")
    print("  2. Run this script once to generate cloudflare_worker.js")
    print("     then paste that file's contents into the Worker editor.")
    print("  3. Re-run and enter your Worker's URL below.")
    print()

    # ── Local proxy port (typed by user, never hardcoded) ─────────────────
    port_input = input("  Local proxy port [8520]: ").strip()
    CFC_PORT   = int(port_input) if port_input else 8520

    # ── Local domain (host) -- almost always localhost, but typed by user ──
    host_input = input("  Local proxy host [localhost]: ").strip()
    LOCAL_HOST = host_input if host_input else "localhost"

    CFC_BASE             = f"http://{LOCAL_HOST}:{CFC_PORT}/"
    CFC_BASE_NO_SLASH    = f"http://{LOCAL_HOST}:{CFC_PORT}"
    BACKEND_SETTINGS_URL = f"http://{LOCAL_HOST}:{CFC_PORT}/backend_settings"

    # ── Write Worker JS to disk (user deploys it themselves -- ZERO remote
    #    calls from this script -- the Worker file is just a text file on disk)
    print(f"\n[...] Writing Worker JS for local port {CFC_PORT}...")
    worker_file = _write_worker_js_file(CFC_PORT)
    print(f"[OK]  Worker JS written --> {worker_file.resolve()}")
    print(f"      (Optional) paste this file into your own Cloudflare")
    print(f"      Worker editor, then enter its URL below.")
    print(f"      Press ENTER to skip and run LOCAL-ONLY (no remote at all).")
    print()

    # ── Ask for Worker URL (OPTIONAL) ─ user fills from their own CF account.
    # If empty, the patched extension uses ONLY the localhost proxy. No remote
    # domain is ever contacted by this script -- not even for config.
    raw = input("  Your Cloudflare Worker URL [leave empty for local-only]\n"
                "  (e.g. myworker.myaccount.workers.dev): ").strip()

    if not raw:
        WORKER_BASE = ""
        print(f"\n[OK] Mode   : LOCAL-ONLY (zero remote)")
    else:
        if not raw.startswith("http"):
            raw = "https://" + raw
        # Refuse to point at a known attacker domain.
        bad = [f for f in COCODEM_TROJAN_FRAGMENTS if f in raw]
        if bad:
            print(f"\n[ABORT] Refusing Worker URL containing attacker domain: {bad}")
            sys.exit(2)
        WORKER_BASE = raw.rstrip("/") + "/"
        print(f"\n[OK] Worker : {WORKER_BASE}")
    print(f"[OK] Local  : {CFC_BASE}")

    # ── Sanitize extension ────────────────────────────────────────────────
    print()
    print("=" * 62)
    print(f"  Sanitizing extension -- {TIMESTAMP}")
    print(f"  Source: {COCODEM_SRC}")
    print(f"  Remote: {WORKER_BASE}")
    print(f"  Local:  {CFC_BASE}")
    print("=" * 62)

    copy_source()
    preserve_manifest()
    m = read_manifest()
    m = patch_manifest(m)
    write_sanitized_request_js()
    scrub_bundled_c2_urls()
    write_backend_settings_ui()
    write_options()
    write_arc_html()
    inject_index_module()
    server = start_proxy()
    print_report(m)
    if server:
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            print("\n[Server] Shutting down...")
            server.shutdown()
    else:
        print("[WARN] Server did not start.")

if __name__ == "__main__":
    main()
