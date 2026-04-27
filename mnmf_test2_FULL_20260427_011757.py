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
   5.  Overwrites request.js with clean local-only version:
         - SW-context isChrome fix  (!globalThis.window || ...)
         - getOptions() also extracts apiBaseUrl/apiKey/authToken/identity/
           backends/blockAnalytics and mirrors them to localStorage +
           chrome.storage.local so request.js and legacy code paths agree
         - chrome.storage.onChanged listener mirrors hijackSettings.backendUrl
           to localStorage (fast-path for in-page fetch shim)
         - sidepanelToken set permanently in initial auth bootstrap
         - Sync sendMessage interceptor: intercepts check_and_refresh_oauth +
           SW_KEEPALIVE locally; everything else goes to real SW first, falls
           back with setTimeout(cb,0) only on synchronous throw -- fixes React
           error #185 caused by Promise-resolve-during-render in prior versions
   6.  Writes unified backend_settings_ui.js (proxy is source of truth):
         - On load: fetches /api/identity from proxy; falls back to
           chrome.storage.local if proxy is down
         - On save: POSTs to /api/identity first, then mirrors to
           chrome.storage.local; sends _update_options to extension
         - On clear: resets proxy identity AND removes chrome.storage.local keys
   7.  Strips MV3-incompatible inline theme scripts from options/sidepanel HTML
   8.  Writes backend_settings.html + backend_settingsOG.html meta-refresh stubs
   9.  Writes arc.html (whitespace-normalised)
  10.  Injects setJsx into React jsx-runtime (index-BVS4T5_D.js)
  11.  Starts REAL remote multi-C2 server on port 8520:
         /v1/*            --> model-based routing across BACKENDS list,
                              per-backend API keys, SSE streaming, failover
         auth/oauth       --> answered locally (skip-login, no Anthropic account)
         license          --> always valid (cfc.aroic.workers.dev/licenses/verify)
         telemetry        --> 204 (Segment, Statsig, Sentry, Datadog, FingerprintJS)
         /api/identity    --> GET returns server-side IDENTITY; POST updates it
         /api/options     --> live response built from BACKENDS + IDENTITY
         /api/backends    --> GET/POST backend list management
         /api/arc-split-view --> real two-panel HTML
         /backend_settings   --> real backend management UI
         /assets/*        --> static files served from OUTPUT_DIR
         root /           --> real dashboard website
         All other        --> real HTML fallback (NEVER 204)

This server replicates cocodem's ENTIRE infrastructure identically:
  -- openclaude.111724.xyz/api/options         --> local config (live from IDENTITY+BACKENDS)
  -- openclaude.111724.xyz/api/backends        --> backend management
  -- openclaude.111724.xyz/api/arc-split-view  --> arc panel HTML
  -- openclaude.111724.xyz/oauth/*             --> OAuth flow (local)
  -- cfc.aroic.workers.dev/licenses/verify     --> license gate (always valid)
  -- All proxied URLs                           --> forwarded or answered locally
  -- Root /                                     --> real dashboard website
  -- Every other route                         --> real response (never 204)
"""

import base64, json, os, re, shutil, sys, time, mimetypes, traceback
import http.server, socketserver, threading
import urllib.request, urllib.error
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode

# ─── constants ────────────────────────────────────────────────────────────────

EXTENSION_ID         = "fcoeoabgfenejglbffodgkkbkcdhcgfn"
TIMESTAMP            = datetime.now().strftime("%Y%m%d-%H%M%S")
COCODEM_SRC          = Path("COCODEMS ORIGINAL ZIP")
OUTPUT_DIR           = Path(f"claude-sanitized-{TIMESTAMP}")
CFC_PORT             = 8520
CFC_BASE             = f"http://localhost:{CFC_PORT}/"
CFC_BASE_NO_SLASH    = f"http://localhost:{CFC_PORT}"
REMOTE_BASE          = os.environ.get(
    "CFC_REMOTE_BASE", "https://test2.mahnikka.workers.dev/"
).rstrip("/") + "/"
DEFAULT_BACKEND_URL  = "http://127.0.0.1:1234/v1"
BACKEND_SETTINGS_URL = f"http://localhost:{CFC_PORT}/backend_settings"
BACKENDS_FILE        = Path("cfc_backends.json")
IDENTITY_FILE        = Path("cfc_identity.json")
OPTIONS_FILE         = Path("cfc_options.json")
USER_UUID            = "ac507011-00b5-56c4-b3ec-ad820dbafbc1"
ORG_UUID             = "1b61ee4a-d0ce-50b5-8b67-7eec034d3d08"

# ─── telemetry domains -- always 204'd before any other routing ───────────────
TELEMETRY_DOMAINS = [
    "segment.com", "statsig", "honeycomb", "sentry", "datadoghq",
    "featureassets", "assetsconfigcdn", "featuregates", "prodregistryv2",
    "beyondwickedmapping", "fpjs.dev", "openfpcdn.io", "api.fpjs.io",
    "googletagmanager", "googletag",
]

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
    """Return ordered backend list for this model. Exact match first, then
    catch-all, then everything else for failover. Disabled backends skipped."""
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
    """Merge modelAlias dicts from all enabled backends."""
    merged = {}
    for b in BACKENDS:
        if b.get("enabled", True) and b.get("modelAlias"):
            merged.update(b["modelAlias"])
    return merged

# ─── identity / options persistence (proxy is single source of truth) ─────────
# Identity, API base URL, API key, auth token, blockAnalytics flag, and the
# GLOBAL modelAliases map are all persisted server-side (cfc_identity.json)
# and SERVED BY THE PROXY via /api/identity + /api/options. The settings UI
# fetches and posts to the proxy -- it no longer relies on chrome.storage.local
# as the source of truth (it only mirrors apiBaseUrl into localStorage so the
# in-page request.js fetch shim has a fast-path lookup).

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
    """Merge the global modelAliases (from IDENTITY) with each backend's
    per-backend modelAlias. Per-backend aliases win on collision because
    they are a more specific routing decision than the global one."""
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
    """Build /api/options matching the 12.py contract:
       uiNodes: [], ui: {}, apiBaseIncludes: [anthropic v1].
       Backend Settings sidebar item is injected by the sanitiser directly into
       options.html, NOT through uiNodes."""
    discard = [
        "cdn.segment.com", "api.segment.io", "events.statsigapi.net",
        "api.honeycomb.io", "prodregistryv2.org", "*ingest.us.sentry.io",
        "browser-intake-us5-datadoghq.com", "fpjs.dev", "openfpcdn.io",
        "api.fpjs.io", "googletagmanager.com",
    ] if IDENTITY.get("blockAnalytics", True) else []
    return {
        "mode":             IDENTITY.get("mode", "") or "",
        "cfcBase":          CFC_BASE,
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
        "proxyIncludes": [
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
        ],
        "discardIncludes": discard,
        "modelAlias":      _merged_model_alias(),
        "ui":              {},
        "uiNodes":         [],
        "blockAnalytics":  bool(IDENTITY.get("blockAnalytics", True)),
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
    return m

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
    # externally_connectable: localhost (for chrome.runtime.sendMessage from
    # the local proxy's redirect page).
    m["externally_connectable"] = {"matches": ["http://localhost/*", "http://127.0.0.1/*"]}
    changes.append("NARROWED externally_connectable to localhost only")

    _ATTACKER_FRAG = ("111724.xyz", "aroic", "localhost:8787")

    # Localhost matches added to every WAR entry so Chrome lets the local proxy
    # navigate to chrome-extension://EXTID/oauth_callback.html etc.
    _LOCAL_MATCHES = ["http://localhost/*", "http://127.0.0.1/*"]

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
    war_localhost_added = 0
    for war in m.get("web_accessible_resources", []):
        before = war.get("matches", [])
        after  = [u for u in before if not any(f in u for f in _ATTACKER_FRAG)]
        if after != before:
            war_patched += len(before) - len(after)
        # Always ensure localhost is in matches so external pages on localhost
        # (the auth-redirect handler) can navigate to chrome-extension:// URLs.
        for lm in _LOCAL_MATCHES:
            if lm not in after:
                after.append(lm)
                war_localhost_added += 1
        war["matches"] = after
    if war_patched:
        changes.append(f"REMOVED {war_patched} attacker URL(s) from web_accessible_resources.matches")
    if war_localhost_added:
        changes.append(f"ADDED {war_localhost_added} localhost match(es) to web_accessible_resources.matches")

    with open(OUTPUT_DIR / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(m, f, indent=2, ensure_ascii=False)
    print(f"\n[OK] manifest.json patched:")
    for c in changes:
        print(f"  {c}")
    return m


def write_sanitized_request_js():
    assets      = OUTPUT_DIR / "assets"
    cocodem_req = assets / "request.js"

    # forensic archive -- C2 URLs redirected to localhost, nothing else changed
    if cocodem_req.exists():
        orig = cocodem_req.read_text(encoding="utf-8")
        r1   = orig.replace("https://openclaude.111724.xyz/", "http://localhost:8520/")
        r1   = r1.replace("http://localhost:8787/", "http://localhost:8520/")
        (assets / "request1.js").write_text(r1, encoding="utf-8")
        print("[OK] assets/request1.js -- forensic copy with C2 URLs -> localhost:8520")

    # Notes on differences from the original cocodem request.js:
    #  * cfcBase          -> localhost:8520 (was openclaude.111724.xyz)
    #  * apiBaseIncludes  -> [] default so /v1/* hits proxyIncludes -> proxy
    #  * discardIncludes  -> fpjs.dev / openfpcdn.io / googletagmanager added
    #  * discard branch   -> returns 204 immediately
    #  * new URL(input)   -> handles Request objects as well as strings
    #  * render()         -> fixed: was `optionsUi` (ReferenceError), now `pageUi`
    #  * setJsx           -> original cocodem implementation verbatim
    #  * patchLocales     -> kept (benign i18n extension, no phone-home)
    #  * getOptions()     -> also extracts apiBaseUrl/apiKey/authToken/identity/
    #                        backends/blockAnalytics; mirrors all to localStorage
    #                        and chrome.storage.local so every code path agrees
    #  * onMessage        -> added check_and_refresh_oauth belt-and-suspenders
    #  * onChanged        -> mirrors hijackSettings.backendUrl to localStorage
    #  * sidepanelToken   -> set permanently in initial auth bootstrap
    #  * isChrome         -> SW-context fix: !globalThis.window || ...
    #                        (prevents undefined globalThis.window crash in SW)
    #  * sendMessage      -> SYNC interceptor, real-SW-first, local fallback:
    #                        - check_and_refresh_oauth answered from storage
    #                        - SW_KEEPALIVE ack'd locally
    #                        - everything else -> real SW, setTimeout fallback
    #                        Fixes React #185 (Promise-resolve-during-render)

    clean = r"""
// request.js -- local CFC replacement.
// Replaces cocodem's 111724.xyz/8787 C2 with test2.mahnikka.workers.dev (307s to localhost:8520).
// Architecture matches cocodem exactly. Zero phone-home.

const cfcBase = "https://test2.mahnikka.workers.dev/"

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
        // proxy-served identity wins: mirror to localStorage so the
        // in-page fetch shim's localStorage.getItem("apiBaseUrl") lookup
        // returns the SAME value /api/options just gave us.
        try {
          if (globalThis.localStorage) {
            if (apiBaseUrl) globalThis.localStorage.setItem("apiBaseUrl", apiBaseUrl)
            if (apiKey)     globalThis.localStorage.setItem("apiKey",     apiKey)
            if (authToken)  globalThis.localStorage.setItem("authToken",  authToken)
          }
        } catch (e) {}
        // mirror to chrome.storage.local so anything that reads from
        // there (legacy code paths, settings UI on next open) sees the
        // proxy-authoritative values without an extra round-trip.
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
    // Resolve order: PROXY-SERVED apiBaseUrl > localStorage mirror >
    // anthropicBaseUrl > original origin. Proxy is source of truth.
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

if (!globalThis.__createTab) {
  globalThis.__createTab = chrome?.tabs?.create
}
if (chrome?.tabs?.create) {
  chrome.tabs.create = async function (...args) {
    const url = args[0]?.url
    if (url && url.startsWith("https://claude.ai/oauth/authorize")) {
      const { cfcBase, mode } = await getOptions()
      const m = chrome?.runtime?.getManifest
        ? chrome.runtime.getManifest()
        : { version: "0" }
      if (mode !== "claude") {
        args[0].url =
          url
            .replace("https://claude.ai/", cfcBase)
            .replace("fcoeoabgfenejglbffodgkkbkcdhcgfn", chrome?.runtime?.id || "unknown") +
          `&v=${m.version}`
      }
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

// FIX: SW context has no `window` global and no `navigator.userAgentData`,
// so the original expression returns undefined (falsy) -> isChrome = false ->
// the sidePanel.open override below runs in SW context -> every open attempt
// opens arc.html instead of the sidepanel. Adding `!globalThis.window ||`
// makes SW context default isChrome = true and skip the override entirely.
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

// sidepanelToken MUST be set here. The sidepanel.html handler checks it on
// every load; if missing it opens a new OAuth tab and returns, preventing
// React from ever mounting.
if (chrome?.storage?.local?.get) {
  chrome.storage.local.get({ accessToken: "", accountUuid: "", sidepanelToken: "" })
    .then(({ accessToken, accountUuid, sidepanelToken }) => {
      if (!accessToken || !accountUuid || !sidepanelToken) {
        const header  = btoa(JSON.stringify({ alg: "none", typ: "JWT" }))
        const payload = btoa(JSON.stringify({
          iss: "cfc",
          sub: "ac507011-00b5-56c4-b3ec-ad820dbafbc1",
          exp: 9999999999,
          iat: Math.floor(Date.now() / 1000),
        }))
        chrome.storage.local.set({
          accessToken:          header + "." + payload + ".local",
          refreshToken:         "local-refresh",
          tokenExpiry:          Date.now() + 31536000000,
          accountUuid:          "ac507011-00b5-56c4-b3ec-ad820dbafbc1",
          sidepanelToken:       "cfc-local-permanent",
          sidepanelTokenExpiry: Date.now() + 31536000000,
        })
        console.log("[hijack] Auth tokens set")
      }
    })
}

// FIX: chrome.storage.onChanged listener mirrors hijackSettings.backendUrl
// to localStorage so the in-page fetch shim's fast-path lookup stays in sync
// when the settings UI writes directly to chrome.storage.local. This replaces
// the prior block that wrote globalThis.localStorage.setItem on EVERY change,
// which fired the native window storage event and caused React error #185.
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

// ── sendMessage interceptor (window/sidepanel context only) ──────────────────
// MV3 SW can be asleep. sendMessage fails with "Could not establish connection"
// -> sidepanel setState(isValid=false) -> re-render -> sendMessage -> loop -> #185.
//
// Combined approach (best of all versions):
//   * Intercept check_and_refresh_oauth LOCALLY (no SW contact, no errors)
//   * Intercept SW_KEEPALIVE locally (just ack it)
//   * Everything else -> real SW first via __origSendMessage(...)
//   * Only fall back on a synchronous throw (rare); fallback uses setTimeout(cb,0)
//     so callbacks always fire as macrotasks, never inside React's render phase
if (globalThis.window && chrome?.runtime?.sendMessage) {
  const __origSendMessage = chrome.runtime.sendMessage.bind(chrome.runtime)

  chrome.runtime.sendMessage = function(...args) {
    const isExternal = typeof args[0] === "string"
    const msg = isExternal ? args[1] : args[0]
    const cb  = [...args].reverse().find(a => typeof a === "function") || null

    // Intercept check_and_refresh_oauth locally -- answer from storage,
    // never contact the SW, deliver result on the next event-loop tick
    if (!isExternal && msg?.type === "check_and_refresh_oauth") {
      chrome.storage.local.get({ accessToken: "", tokenExpiry: 0, accountUuid: "" })
        .then(({ accessToken, tokenExpiry, accountUuid }) => {
          const isValid = !!accessToken && !!accountUuid && tokenExpiry > Date.now()
          setTimeout(() => {
            try { if (typeof cb === "function") cb({ isValid, isRefreshed: false }) } catch(e) {}
          }, 0)
        })
      return  // void -- matches real sendMessage contract
    }

    // SW keepalive ping -- just ack it locally
    if (!isExternal && msg?.type === "SW_KEEPALIVE") {
      setTimeout(() => {
        try { if (typeof cb === "function") cb() } catch(e) {}
      }, 0)
      return
    }

    // Everything else -> real SW first, with safe fallback only on sync throw
    try {
      return __origSendMessage(...args)
    } catch(e) {
      // Synchronous throw -- answer locally with deferred callback
      setTimeout(() => {
        try { if (typeof cb === "function") cb(undefined) } catch(e2) {}
      }, 0)
    }
  }
}

// ── Window-context page logic ─────────────────────────────────────────────────
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
    chrome.storage.local.get({ sidepanelToken: "", sidepanelTokenExpiry: 0 })
      .then(({ sidepanelToken, sidepanelTokenExpiry }) => {
        const now = Date.now()
        if (!sidepanelToken || !sidepanelTokenExpiry || sidepanelTokenExpiry < now) {
          const redirectUri = encodeURIComponent(
            "chrome-extension://" + (chrome?.runtime?.id || "unknown") + "/sidepanel.html"
          )
          const authorizeUrl =
            cfcBase + "oauth/authorize?redirect_uri=" + redirectUri +
            "&response_type=code&client_id=sidepanel&state=" + Date.now()
          chrome.tabs.create({ url: authorizeUrl })
          return
        }
        chrome.tabs.query({ active: !0, currentWindow: !0 }).then(([tab]) => {
          if (tab) {
            const u = new URL(location.href)
            u.searchParams.set("tabId", tab.id)
            history.replaceState(null, "", u.href)
          }
        }).catch(() => {})
      }).catch(() => {})
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

// ── JSX remix helpers (verbatim from cocodem original) ────────────────────────

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
    cocodem_req.write_text(clean, encoding="utf-8")
    print(f"[OK] assets/request.js -- clean local-only version ({len(clean)} bytes)")


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
  // -------------------------------------------------------------------------
  // PROXY IS THE SOURCE OF TRUTH for identity/API config.
  // 1. Try to fetch /api/identity from the proxy on load -- if reachable,
  //    its values win and are mirrored back into chrome.storage.local so
  //    request.js's in-page hooks still see them on subsequent loads.
  // 2. chrome.storage.local is only a fallback / fast-path mirror.
  // 3. On save, the UI POSTS to /api/identity FIRST. The chrome.storage
  //    mirror is updated AFTER the proxy confirms persistence.
  // -------------------------------------------------------------------------
  const CFC_PROXY_BASE = "http://localhost:8520/";
  let proxyIdentity = null;
  try {
    const r = await fetch(CFC_PROXY_BASE + "api/identity", {cache:"no-store"});
    if (r.ok) proxyIdentity = await r.json();
  } catch(e) { /* proxy down -- fall back to chrome.storage.local */ }
  const saved=await chrome.storage.local.get(KEYS);
  const hs=saved.hijackSettings||{};
  // proxy values win when reachable; otherwise chrome.storage.local; otherwise default
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
    // ---- 1. POST to proxy FIRST (proxy is source of truth) ---------------
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
    // ---- 2. Mirror to chrome.storage.local (fast-path for request.js) ----
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
    // ---- 3. Tell extension to refresh its cached options from proxy -------
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
    // ---- 1. Reset proxy-side identity ------------------------------------
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
    // ---- 2. Clear chrome.storage.local mirror ----------------------------
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




# ─── local auth responses (cfc_server_test2 contract) ────────────────────────

def _b64url(obj) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(obj).encode("utf-8")
    ).rstrip(b"=").decode("ascii")


def local_token() -> dict:
    """Static iat:1700000000 — dynamic iat caused React error #185 in prior runs."""
    tok = _b64url({"alg": "none", "typ": "JWT"}) + "." + \
          _b64url({"iss": "cfc", "sub": USER_UUID,
                   "exp": int(time.time()) + 315360000,
                   "iat": 1700000000}) + ".local"
    return {
        "access_token": tok, "token_type": "bearer",
        "expires_in": 315360000, "refresh_token": "local-refresh",
        "scope": "user:profile user:inference user:chat",
    }


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


def profile_payload() -> dict:
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


def bootstrap_payload() -> dict:
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


def auth_payload(path: str) -> dict:
    """Local-only auth route handler. Matches both clean paths and
    cfcBase-rewritten paths (e.g. /https://api.anthropic.com/api/oauth/profile)."""
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


# ─── HTML pages (OpenClaw dark-theme settings, auth gate, redirect) ──────────

def root_html() -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CFCBASE Server</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f9f8f3;color:#2f2a1f;margin:0;padding:32px}}
.box{{max-width:760px;margin:0 auto;background:white;border:1px solid #e5e2d9;border-radius:18px;padding:28px}}
code{{background:#f4f1ea;padding:2px 5px;border-radius:5px}}
a{{display:inline-flex;align-items:center;height:40px;padding:0 16px;background:#c45f3d;color:white;text-decoration:none;border-radius:10px;font-weight:700}}
</style></head>
<body><div class="box">
  <h1>CFCBASE Local Server</h1>
  <p>Local: <code>{CFC_BASE}</code> · Remote: <code>{REMOTE_BASE}</code></p>
  <p><a href="{BACKEND_SETTINGS_URL}">Backend Settings</a></p>
  <ul>
    <li><code>/api/options</code> — uiNodes:[], ui:&#123;&#125;</li>
    <li><code>/oauth/redirect</code> — writes tokens to extension storage</li>
    <li><code>/v1/*</code> — proxied to configured backend</li>
    <li>auth routes answered locally</li>
  </ul>
</div></body></html>"""


def backend_settings_html() -> str:
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
  <h1>OpenClaw &mdash; Backend Setup</h1>
  <p class="sub">Configure backends · test connections · connect to extension</p>
  <div id="status" class="status"></div>
  <section class="panel">
    <h2>API Backends</h2>
    <div id="backendList"></div>
    <button class="secondary" onclick="addBackend()">+ Add Backend</button>
  </section>
  <section class="panel">
    <h2>Extension Routing &amp; Auth Bypass</h2>
    <div class="grid"><label>cfcBase URL</label><input id="cfcBase" value="{REMOTE_BASE}" readonly></div>
    <div class="grid"><label>apiBaseUrl</label><input id="apiBaseUrl" value="{IDENTITY.get('apiBaseUrl') or DEFAULT_BACKEND_URL}"></div>
    <div class="grid"><label>Mode</label>
      <select id="mode">
        <option value="">api &mdash; local / custom backend</option>
        <option value="claude">claude &mdash; official</option>
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
      <b>Local CFCBASE:</b> {CFC_BASE}<br>
      <b>Remote Worker:</b> {REMOTE_BASE}<br>
      <b>Default Backend:</b> {DEFAULT_BACKEND_URL}<br><br>
      <code>uiNodes: []</code> &mdash; Backend Settings injected by sanitizer, not uiNodes.<br>
      <code>ui: {{}}</code> &mdash; No DOM injection from options payload.
    </div>
  </section>
  <button class="save" onclick="saveConfig()">Save Config &amp; Connect to Extension &rarr;</button>
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
    const r=await fetch((b.url||"").replace(/\\/v1\\/?$/,"")+"/v1/models",{{headers:h}});
    if(!r.ok) throw new Error("HTTP "+r.status);
    const d=await r.json();
    el.textContent="OK \\u2014 models: "+((d.data||[]).map(m=>m.id).slice(0,5).join(", ")||"(none listed)");
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
  showStatus(br.ok&&ir.ok?"Saved and connected to extension":"Save failed \\u2014 check server logs",br.ok&&ir.ok);
}}
renderBackends();
</script></body></html>"""


def authorize_html(query: str) -> str:
    """Auth gate (also reachable via the Worker if it 307s here).
    Continue button is a plain <a href> to /oauth/redirect — no JS needed."""
    params       = parse_qs(query, keep_blank_values=True)
    redirect_uri = params.get("redirect_uri", [""])[0]
    state        = params.get("state", [""])[0]

    qs_pairs = []
    if redirect_uri: qs_pairs.append(("redirect_uri", redirect_uri))
    if state:        qs_pairs.append(("state", state))
    next_url = CFC_BASE + "oauth/redirect"
    if qs_pairs:
        next_url += "?" + urlencode(qs_pairs)

    next_attr = (next_url.replace("&", "&amp;").replace('"', "&quot;")
                          .replace("<", "&lt;").replace(">", "&gt;"))

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Claude in Chrome</title>
<style>
*{{box-sizing:border-box}}
body{{background:#f9f8f3;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;color:#1d1b16}}
.box{{background:white;border:1px solid #e5e2d9;border-radius:32px;padding:40px;max-width:420px;width:100%;text-align:center}}
.logo{{width:72px;height:72px;border-radius:20px;border:1px solid #e5e2d9;margin:0 auto 20px;display:flex;align-items:center;justify-content:center;color:#d97757;font-size:38px}}
h1{{font-family:Georgia,serif;font-weight:400;margin:0 0 10px;font-size:28px}}
p{{color:#6b6651;font-size:14px;line-height:1.5;margin:0 0 24px}}
a.btn{{display:inline-flex;align-items:center;justify-content:center;height:48px;padding:0 32px;background:#c45f3d;color:white;text-decoration:none;border-radius:12px;font-size:16px;font-weight:800;border:0}}
a.btn:hover{{background:#b15535}}
</style></head>
<body><div class="box">
  <div class="logo">&#10038;</div>
  <h1>Claude in Chrome</h1>
  <p>Local CFC. No Anthropic credentials required.</p>
  <a class="btn" id="continue" href="{next_attr}">Continue</a>
</div></body></html>"""


def redirect_html(query: str) -> str:
    """Writes auth tokens to the extension via chrome.runtime.sendMessage
    (only works because this page is on localhost — which mnmf added to the
    extension's externally_connectable). Then navigates to redirect_uri."""
    params       = parse_qs(query, keep_blank_values=True)
    redirect_uri = params.get("redirect_uri", [""])[0]
    state        = params.get("state", [""])[0]
    code         = params.get("code", [f"cfc-local-{int(time.time())}"])[0]
    final_uri    = redirect_uri
    if final_uri:
        joiner = "&" if "?" in final_uri else "?"
        final_uri += joiner + urlencode({"code": code, "state": state})
    tok = local_token()
    storage = {
        "accessToken":          tok["access_token"],
        "refreshToken":         tok["refresh_token"],
        "tokenExpiry":          int(time.time() * 1000) + 31536000000,
        "accountUuid":          USER_UUID,
        "sidepanelToken":       code,
        "sidepanelTokenExpiry": int(time.time() * 1000) + 31536000000,
        "ANTHROPIC_BASE_URL":   IDENTITY.get("apiBaseUrl") or DEFAULT_BACKEND_URL,
        "ANTHROPIC_API_KEY":    IDENTITY.get("apiKey") or "",
        "ANTHROPIC_AUTH_TOKEN": IDENTITY.get("authToken") or "",
        "email":                IDENTITY.get("email") or "user@local",
        "username":             IDENTITY.get("username") or "local-user",
        "licenseKey":           IDENTITY.get("licenseKey") or "",
        "hijackSettings": {
            "backendUrl":     IDENTITY.get("apiBaseUrl") or DEFAULT_BACKEND_URL,
            "modelAliases":   _merged_model_alias(),
            "blockAnalytics": True,
        },
    }
    storage_js   = json.dumps(storage)
    final_uri_js = json.dumps(final_uri)
    ext_id_js    = json.dumps(EXTENSION_ID)
    final_uri_attr = (final_uri.replace("&", "&amp;").replace('"', "&quot;")
                                .replace("<", "&lt;").replace(">", "&gt;"))
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Signed In</title>
<style>
body{{background:#f9f8f3;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;color:#1d1b16}}
.box{{background:white;border:1px solid #e5e2d9;border-radius:32px;padding:40px;max-width:520px;width:100%;text-align:center}}
h1{{font-family:Georgia,serif;font-weight:400;margin:0 0 10px;font-size:28px}}
#msg{{color:#6b6651;font-size:14px;line-height:1.5;margin:0 0 12px}}
a.fallback{{display:inline-block;margin-top:16px;color:#c45f3d;font-weight:700}}
</style></head>
<body><div class="box">
  <h1>Signed in</h1>
  <p id="msg">Writing local state to extension...</p>
  <a class="fallback" id="fallback" href="{final_uri_attr}" style="display:none">Continue manually</a>
</div>
<script>
(function(){{
  var eid={ext_id_js}, storage={storage_js}, finalUri={final_uri_js};
  var msg=document.getElementById("msg");
  var fb =document.getElementById("fallback");
  function done(text,ok){{
    msg.textContent=text;
    msg.style.color=ok?"#2d6a4f":"#b04a3d";
    if(ok&&finalUri) setTimeout(function(){{location.href=finalUri}},350);
    else if(!ok&&finalUri) fb.style.display="inline-block";
  }}
  try{{
    if(typeof chrome!=="undefined"&&chrome.runtime&&chrome.runtime.sendMessage){{
      chrome.runtime.sendMessage(eid,{{type:"_set_storage_local",data:storage}},function(resp){{
        if(chrome.runtime.lastError){{done("Storage write failed: "+chrome.runtime.lastError.message,false);return;}}
        done("Done \\u2014 loading sidepanel...",true);
      }});
    }}else{{done("Chrome extension messaging unavailable.",false);}}
  }}catch(e){{done("Error: "+e.message,false);}}
}})();
<\/script></body></html>"""


# ─── HTTP handler (cfc_server_test2 contract: routeAuth, static, /v1/*) ──────

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = f"CFCBASE-mnmf/{TIMESTAMP}"

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[{time.strftime('%H:%M:%S')}] "
                         f"{self.command} {self.path} {fmt % args}\n")
        sys.stderr.flush()

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods",
                         "GET,POST,PUT,PATCH,DELETE,OPTIONS")
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
        try:    self.wfile.write(data)
        except OSError: pass

    def _json(self, obj, status=200):
        try:
            self._send(json.dumps(obj).encode("utf-8"),
                       "application/json", status)
        except Exception as e:
            sys.stderr.write(f"[HANDLER-ERROR] _json: {e}\n"); sys.stderr.flush()

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
        if p.startswith(("/https://", "/http://", "/chrome-extension://")):
            return True
        return any(m in p for m in [
            "/oauth/", "/bootstrap", "/domain_info", "/chat_conversations",
            "/organizations", "/url_hash_check", "/api/web/", "/features/",
            "/spotlight", "/usage", "/entitlements", "/flags",
            "/mcp/v2/", "/licenses/",
        ])

    def _serve_static(self, path):
        rel = path.lstrip("/").split("?", 1)[0]
        candidates = []
        if rel == "assets/backend_settings_ui.js":
            candidates.append(OUTPUT_DIR / "assets" / "backend_settings_ui.js")
        if rel.startswith("assets/"):
            candidates.append(OUTPUT_DIR / "assets" / rel[len("assets/"):])
        candidates.append(OUTPUT_DIR / rel)
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

    def _stream_sse(self, resp):
        """Stream SSE responses chunked to the client."""
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self._cors()
        self.end_headers()
        try:
            while True:
                chunk = resp.read(4096)
                if not chunk: break
                try:    self.wfile.write(chunk); self.wfile.flush()
                except OSError: return

        finally:
            try: resp.close()
            except Exception: pass

    def _forward_v1(self, method, body):
        model = ""
        if body:
            try:    model = json.loads(body.decode("utf-8")).get("model", "")
            except Exception: pass
        suffix = self._v1_suffix(self.path)
        allowed = {"content-type", "accept", "authorization",
                   "anthropic-version", "anthropic-beta",
                   "anthropic-client-platform", "anthropic-client-version",
                   "x-api-key", "x-service-name"}
        base_hdrs = {k: v for k, v in self.headers.items() if k.lower() in allowed}
        last_err  = None
        for backend in _pick_backends(model):
            target = backend.get("url", DEFAULT_BACKEND_URL).rstrip("/") + suffix
            hdrs   = dict(base_hdrs)
            if backend.get("key"):       hdrs["Authorization"] = "Bearer " + backend["key"]
            elif IDENTITY.get("apiKey"): hdrs["Authorization"] = "Bearer " + IDENTITY["apiKey"]
            send_body = body
            if send_body and method in ("POST", "PUT", "PATCH"):
                try:
                    parsed  = json.loads(send_body.decode("utf-8"))
                    aliases = {**_merged_model_alias(), **(backend.get("modelAlias") or {})}
                    if parsed.get("model") in aliases:
                        parsed["model"] = aliases[parsed["model"]]
                        send_body = json.dumps(parsed).encode("utf-8")
                except Exception: pass
            try:
                req  = urllib.request.Request(target, data=send_body or None,
                                              headers=hdrs, method=method)
                resp = urllib.request.urlopen(req, timeout=300)
                ct   = resp.headers.get("Content-Type", "") or "application/json"
                if "text/event-stream" in ct:
                    self.send_response(resp.status)
                    self._stream_sse(resp)
                else:
                    data = resp.read()
                    self._send(data, ct, resp.status)
                return
            except urllib.error.HTTPError as e:
                data = e.read() or b""
                if e.code < 500:
                    self._send(data,
                               e.headers.get("Content-Type") or "application/json",
                               e.code)
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
        if self._is_tel(self.path):                 self._204();                                  return
        if self._serve_static(path):                                                              return
        if self._is_v1(self.path):                  self._forward_v1("GET", b"");                 return
        if path in ("/", ""):                       self._html(root_html());                      return
        if path.startswith("/api/options"):         self._json(_build_options_response());        return
        if path.startswith("/api/identity"):        self._json(IDENTITY);                         return
        if path.startswith("/api/backends"):        self._json({"backends": BACKENDS});           return
        if path.startswith("/api/arc-split-view"):  self._json({"html": "<div>arc</div>"});       return
        if path.startswith("/discard"):             self._204();                                  return
        if path.startswith("/backend_settings"):    self._html(backend_settings_html());          return
        if path.startswith("/oauth/authorize"):     self._html(authorize_html(parsed.query));     return
        if path.startswith("/oauth/redirect"):      self._html(redirect_html(parsed.query));      return
        if self._is_auth(self.path):                self._json(auth_payload(self.path));          return
        self._html(f"<!doctype html><h1>CFCBASE</h1><p><code>{self.path}</code></p>")

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
                if not isinstance(IDENTITY.get("modelAliases"), dict):
                    IDENTITY["modelAliases"] = {}
                _save_identity()
                self._json({"ok": True, "identity": IDENTITY})
            except Exception as e:
                self._json({"ok": False, "error": str(e)}, 400)
            return
        if path.startswith("/api/backends"):
            try:
                data = json.loads(body.decode("utf-8") or "{}")
                bks  = data.get("backends")
                if not isinstance(bks, list) or not bks:
                    raise ValueError("backends must be a non-empty list")
                for b in bks:
                    b.setdefault("name", "");       b.setdefault("url", DEFAULT_BACKEND_URL)
                    b.setdefault("key", "");        b.setdefault("models", [])
                    b.setdefault("modelAlias", {}); b.setdefault("enabled", True)
                BACKENDS[:] = bks
                _save_backends()
                self._json({"ok": True, "backends": BACKENDS})
            except Exception as e:
                self._json({"ok": False, "error": str(e)}, 400)
            return
        if self._is_v1(self.path):   self._forward_v1("POST", body); return
        if self._is_auth(self.path): self._json(auth_payload(self.path)); return
        self._json({"ok": True})

    def do_PUT(self):
        body = self._body()
        if self._is_tel(self.path):  self._204(); return
        if self._is_v1(self.path):   self._forward_v1("PUT", body); return
        if self._is_auth(self.path): self._json(auth_payload(self.path)); return
        self._json({"ok": True})

    def do_PATCH(self):
        body = self._body()
        if self._is_tel(self.path):  self._204(); return
        if self._is_v1(self.path):   self._forward_v1("PATCH", body); return
        if self._is_auth(self.path): self._json(auth_payload(self.path)); return
        self._json({"ok": True})

    def do_DELETE(self):
        body = self._body()
        if self._is_tel(self.path):  self._204(); return
        if self._is_v1(self.path):   self._forward_v1("DELETE", body); return
        if self._is_auth(self.path): self._json(auth_payload(self.path)); return
        self._json({"ok": True})


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads      = True


def start_proxy():
    try:
        server = Server(("127.0.0.1", CFC_PORT), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"\n[OK] CFCBASE local proxy on {CFC_BASE}")
        print(f"     Remote Worker: {REMOTE_BASE}")
        print(f"     Backends: {len(BACKENDS)}")
        for b in BACKENDS:
            models = ", ".join(b.get("models") or ["(catch-all)"])
            print(f"       • {b.get('name','?')}: {b['url']} [{models}]")
        print(f"     Identity: {IDENTITY.get('email','?')} / {IDENTITY.get('username','?')}")
        print(f"     uiNodes: []  ui: {{}}  (12.py contract)")
        print(f"     /api/options  : live from IDENTITY + BACKENDS")
        print(f"     /oauth/redirect: writes auth tokens via _set_storage_local")
        print(f"     Static assets: served from {OUTPUT_DIR}")
        return server
    except OSError as e:
        print(f"[WARN] Cannot bind port {CFC_PORT}: {e}")
        return None


# ─── report ───────────────────────────────────────────────────────────────────

def print_report(m):
    print("\n" + "=" * 62)
    print(f"  DONE -- {OUTPUT_DIR}")
    print("=" * 62)
    print(f"  {m.get('name')} v{m.get('version')}")
    print(f"\n  Install:")
    print(f"  1. Disable cocodem in chrome://extensions/")
    print(f"  2. Enable Developer Mode")
    print(f"  3. Load unpacked --> {OUTPUT_DIR.resolve()}")
    print(f"\n  Backend Settings:")
    print(f"  {BACKEND_SETTINGS_URL}")
    print(f"\n  Local Proxy:")
    print(f"  {CFC_BASE}")
    print(f"\n  Remote Worker (cfcBase in request.js):")
    print(f"  {REMOTE_BASE}")
    print(f"\n  Keep terminal open. Ctrl+C to stop.\n")


# ─── main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 62)
    print(f"  Claude Extension Sanitizer (test2 worker variant) -- {TIMESTAMP}")
    print(f"  Source: {COCODEM_SRC}")
    print(f"  cfcBase: {REMOTE_BASE}")
    print("=" * 62)
    copy_source()
    preserve_manifest()
    m = read_manifest()
    m = patch_manifest(m)
    write_sanitized_request_js()
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
