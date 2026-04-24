#!/usr/bin/env python3
"""
main.py — Sanitizer for cocodem's trojanized Claude Chrome extension (1.0.66).
Run: python main.py
What cocodem does:
  Ships extension ID fcoeoabgfenejglbffodgkkbkcdhcgfn (Anthropic's real ID) so
  unpacked installs overwrite Anthropic's official extension in the same slot.
  assets/request.js phones home to openclaude.111724.xyz + cfc.aroic.workers.dev.
  externally_connectable whitelists those attacker domains for command injection.
  cfc.aroic.workers.dev/licenses/verify captures email/username/licenseKey
  plus FingerprintJS Pro browser fingerprinting and Google Analytics.
What this script does:
  1. Copies cocodem 1.0.66 folder (verified source)
  2. Preserves original manifest as manifest2.json
  3. Patches manifest: removes update_url, narrows externally_connectable to
     localhost only, adds CSP connect-src for local backends +
     wss://bridge.claudeusercontent.com, adds localhost host_permissions
  4. Creates request1.js: cocodem's JS with attacker cfcBase URLs replaced
     by localhost:8520 (forensic archive with phone-home severed)
  5. Overwrites request.js with clean local-only version
  6. Writes unified backend_settings_ui.js (handles API config + identity,
     mirrors cfc.aroic.workers.dev UI but all local, zero network calls)
  7. Strips MV3-incompatible inline theme scripts from options/sidepanel HTML
  8. Writes backend_settings.html + backend_settingsOG.html meta-refresh stubs
  9. Writes arc.html (whitespace-normalized)
 10. Injects setJsx into React jsx-runtime (index-BVS4T5_D.js)
 11. Starts real multi-backend C2 proxy on port 8520 (model-based routing, per-backend keys, failover, zero sinkhole)
Source: COCODEM_SRC (set below) — cocodem 1.0.66 extracted folder.
Verified: 207 files, all SHA256 match fresh GitHub download of claude_1.0.66.zip
(commit dd48e94, SHA256: 2d085a455621f07abb649feded74c85e31b0e6ff937823e679a81475dbf95cac)
"""
import json, os, re, shutil, sys, time
import http.server, socketserver, threading
import urllib.request, urllib.error
import base64
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
EXTENSION_ID = "fcoeoabgfenejglbffodgkkbkcdhcgfn"
TIMESTAMP = datetime.now().strftime("%Y%m%d-%H%M%S")
COCODEM_SRC = Path("COCODEMS ORIGINAL ZIP")
OUTPUT_DIR = Path(f"claude-sanitized-{TIMESTAMP}")
CFC_PORT = 8520
CFC_BASE = f"http://localhost:{CFC_PORT}/"
DEFAULT_BACKEND_URL = "http://127.0.0.1:1234/v1"
BACKEND_SETTINGS_URL = f"http://localhost:{CFC_PORT}/backend_settings"
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
        print("[OK] Preserved manifest.json → manifest2.json")
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
    m["externally_connectable"] = {"matches": ["http://localhost/*", "http://127.0.0.1/*"]}
    changes.append("NARROWED externally_connectable to localhost only")
    with open(OUTPUT_DIR / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(m, f, indent=2, ensure_ascii=False)
    print(f"\n[OK] manifest.json patched:")
    for c in changes:
        print(f" {c}")
    return m
def write_sanitized_request_js():
    assets = OUTPUT_DIR / "assets"
    # request1.js: cocodem original with cfcBase URLs replaced by localhost:8520
    cocodem_req = assets / "request.js"
    if cocodem_req.exists():
        orig = cocodem_req.read_text(encoding="utf-8")
        r1 = orig.replace("https://openclaude.111724.xyz/", "http://localhost:8520/")
        r1 = r1.replace("http://localhost:8787/", "http://localhost:8520/")
        (assets / "request1.js").write_text(r1, encoding="utf-8")
        print("[OK] assets/request1.js — cocodem JS with C2 URLs → localhost:8520")
    # request.js: clean local-only version
    clean = r"""
// request.js — local CFC hijack.
// Replaces cocodem's 111724.xyz/8787 version with local proxy on port 8520.
// Architecture matches cocodem exactly. No phone home.
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
    apiBaseIncludes: ["https://api.anthropic.com/v1/"],
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
    ],
    modelAlias: {},
    ui: {},
    uiNodes: [],
  }
}
let _optionsPromise = null
let _updateAt = 0
export async function getOptions(force = false) {
  const fetch = globalThis.__fetch
  const options = globalThis.__cfc_options
  const baseUrl = options.cfcBase || cfcBase
  if (!_optionsPromise && (force || Date.now() - _updateAt > 1000 * 3600)) {
    // EXACT cocodem pattern: setTimeout resolve as hard timeout,
    // finally block calls resolve() (idempotent) and clears the promise.
    _optionsPromise = new Promise(async (resolve) => {
      setTimeout(resolve, 1000 * 2.8)
      try {
        const id = chrome?.runtime?.id || "unknown"
        const manifest = (typeof chrome !== "undefined" && chrome.runtime?.getManifest)
          ? chrome.runtime.getManifest()
          : { version: "0" }
        const url = baseUrl + "api/options?id=" + id + "&v=" + manifest.version
        const res = await fetch(url, {
          headers: force ? { "Cache-Control": "no-cache" } : {},
        })
        const {
          mode,
          cfcBase: newCfcBase,
          anthropicBaseUrl,
          apiBaseIncludes,
          proxyIncludes,
          discardIncludes,
          modelAlias,
          ui,
          uiNodes,
        } = await res.json()
        options.mode = mode
        options.cfcBase = newCfcBase || options.cfcBase
        options.anthropicBaseUrl = anthropicBaseUrl || options.anthropicBaseUrl
        options.apiBaseIncludes = apiBaseIncludes || options.apiBaseIncludes
        options.proxyIncludes = proxyIncludes || options.proxyIncludes
        options.discardIncludes = discardIncludes || options.discardIncludes
        options.modelAlias = modelAlias || options.modelAlias
        options.ui = ui || options.ui
        options.uiNodes = uiNodes || options.uiNodes
        _updateAt = Date.now()
        if (mode == "claude") {
          await clearApiKeyLogin()
        }
      } catch (e) {
        // local proxy may not be running yet; safe to swallow
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
  // Pass real oauth token exchanges (code not prefixed cfc-) through to Anthropic
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
  // API base: forward to configured local backend
  if (mode != "claude" && isMatch(u, apiBaseIncludes)) {
    const apiBase =
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
    console.log("[hijack] API ->", url)
    return fetch(url, init)
  }
  // Proxy: auth + bootstrap + options → local CFC proxy
  if (isMatch(u, proxyIncludes)) {
    const url = cfcBase + u.href
    return fetch(url, init)
  }
  return fetch(input, init)
}
request.toString = () => globalThis.__fetch.toString()
globalThis.fetch = request
// XHR intercept — same routing logic for legacy XMLHttpRequest callers
if (globalThis.XMLHttpRequest) {
  if (!globalThis.__xhrOpen) {
    globalThis.__xhrOpen = XMLHttpRequest?.prototype?.open
  }
  XMLHttpRequest.prototype.open = function (method, url, ...args) {
    const originalOpen = globalThis.__xhrOpen
    const { cfcBase, proxyIncludes, discardIncludes } = globalThis.__cfc_options
    let finalUrl = url
    if (isMatch(url, proxyIncludes)) {
      finalUrl = cfcBase + url
    }
    originalOpen.call(this, method, finalUrl, ...args)
  }
}
// tabs.create: redirect claude.ai oauth to local proxy
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
          "&v=" + m.version
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
// External message handler — matches cocodem's message protocol exactly
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
            break
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
        console.log("[hijack] Message handler error:", e.message)
      }
    }
  )
}
// Standard message handler for same-extension messages
if (chrome?.runtime?.onMessage?.addListener) {
  chrome.runtime.onMessage.addListener(
    (msg, sender, sendResponse) => {
      try {
        switch (msg?.type) {
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
            if (chrome?.runtime?.openOptionsPage) {
              chrome.runtime.openOptionsPage()
            }
            break
          case "_create_tab":
            if (chrome?.tabs?.create) {
              chrome.tabs.create({ url: msg.url })
            }
            break
          case "oauth_redirect":
            const { redirect_uri } = msg
            if (redirect_uri && redirect_uri.includes("sidepanel.html")) {
              try {
                const u = new URL(redirect_uri)
                const code = u.searchParams.get("code")
                if (code) {
                  chrome.storage.local.set({
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
        console.log("[hijack] Standard message handler error:", e.message)
      }
    }
  )
}
// ── sidePanel.open override: Arc / non-Chrome ONLY ──────────────────────────
// DO NOT override on real Google Chrome — the native API works fine there.
// Overriding it on Chrome causes sidePanel to redirect to arc.html instead
// of opening the side panel, which is the root cause of the blank side panel.
if (!globalThis.__openSidePanel) {
  globalThis.__openSidePanel = chrome?.sidePanel?.open
}
const isChrome = navigator?.userAgentData?.brands?.some(
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
// ── Window context: page-specific logic ─────────────────────────────────────
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
  // ── sidepanel.html: OAuth check + inject REAL tabId — no fake 999999 pre-set ──
  // Pre-setting a fake ID causes React to mount with a non-existent tabId,
  // connecting scripting to tab 999999 which doesn't exist → blank side panel.
  if (location.pathname == "/sidepanel.html" && location.search == "") {
    // Check for valid sidepanel token — if missing, start OAuth flow
    chrome.storage.local.get({ sidepanelToken: "", sidepanelTokenExpiry: 0 }).then(({ sidepanelToken, sidepanelTokenExpiry }) => {
      const now = Date.now()
      if (!sidepanelToken || !sidepanelTokenExpiry || sidepanelTokenExpiry < now) {
        // No valid token — redirect to OAuth authorize endpoint
        const redirectUri = encodeURIComponent(
          "chrome-extension://" + (chrome?.runtime?.id || "unknown") + "/sidepanel.html"
        )
        const authorizeUrl = cfcBase + "oauth/authorize?redirect_uri=" + redirectUri +
          "&response_type=code&client_id=sidepanel&state=" + Date.now()
        chrome.tabs.create({ url: authorizeUrl })
        return // Stop here — wait for OAuth completion
      }
      // Token exists and valid — inject tabId and proceed
      chrome.tabs.query({ active: !0, currentWindow: !0 }).then(([tab]) => {
        if (tab) {
          const u = new URL(location.href)
          u.searchParams.set("tabId", tab.id)
          history.replaceState(null, "", u.href)
        }
      }).catch(() => {})
    }).catch(() => {})
  }
  // Handle OAuth redirect back to sidepanel
  if (location.pathname == "/sidepanel.html" && location.search.includes("code=")) {
    const params = new URLSearchParams(location.search)
    const code = params.get("code")
    if (code) {
      chrome.storage.local.set({
        sidepanelToken: "cfc-" + code,
        sidepanelTokenExpiry: Date.now() + 31536000000,
      })
      const u = new URL(location.href)
      u.search = "" // clear code from URL
      history.replaceState(null, "", u.href)
    }
  }
  // ── arc.html: Arc browser sidepanel fallback ──
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
          link.rel = "stylesheet"
          link.href = url
          document.head.appendChild(link)
        }
      }).catch(() => {})
    window.addEventListener("resize", async () => {
      try {
        const tabs = await chrome.tabs.query({ currentWindow: true })
        const tab = await new Promise((resolve, reject) => {
          let found = false
          tabs.forEach(async (t) => {
            if (t.url?.startsWith(location.origin)) return
            try {
              const [value] = await chrome.scripting.executeScript({
                target: { tabId: t.id },
                func: () => document.visibilityState,
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
  // ── options.html: inject Backend Settings button ──
  // Links to /options.html#backendsettings (chrome-extension:// context, not proxy)
  if (location.pathname == "/options.html") {
    const _observer = new MutationObserver(() => {
      if (document.getElementById("__cfc_backend_btn")) {
        _observer.disconnect()
        return
      }
      const allItems = document.querySelectorAll("a, button")
      let logoutEl = null
      allItems.forEach(el => {
        if (el.textContent.trim().toLowerCase().includes("log out")) logoutEl = el
      })
      if (!logoutEl) return
      const link = document.createElement("a")
      link.id = "__cfc_backend_btn"
      link.href = "/options.html#backendsettings"
      link.className = logoutEl.className
      link.innerHTML = "\u2699\ufe0f Backend Settings"
      link.style.color = "#e07a5f"
      link.style.fontWeight = "600"
      logoutEl.parentElement.insertBefore(link, logoutEl)
      const handleHash = () => {
        if (location.hash === "#backendsettings") {
          const main = document.querySelector("main") || document.body
          main.innerHTML = '<div id="__cfc_settings_container"></div>'
          // Load settings UI as external script (not inline — MV3 CSP compliant)
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
// ── JSX remix helpers ────────────────────────────────────────────────────────
function matchJsx(node, selector) {
  if (!node || !selector) return false
  if (selector.type && node.type != selector.type) return false
  if (selector.key && node.key != selector.key) return false
  let p = node.props || {}
  let m = selector.props || {}
  for (let k of Object.keys(m)) {
    if (k == "children") continue
    if (m[k] != p?.[k]) return false
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
  if (!uiNodes || uiNodes.length === 0) {
    return node
  }
  let { props = {}, type, key } = node
  for (const item of uiNodes) {
    if (!matchJsx({ type, props, key }, item.selector)) continue
    let newProps = { ...props }
    if (item.prepend) {
      let children = Array.isArray(newProps.children)
        ? newProps.children
        : (newProps.children != null ? [newProps.children] : [])
      newProps.children = [renderNode(item.prepend), ...children]
    }
    if (item.append) {
      let children = Array.isArray(newProps.children)
        ? newProps.children
        : (newProps.children != null ? [newProps.children] : [])
      newProps.children = [...children, renderNode(item.append)]
    }
    if (item.replace) {
      const rep = renderNode(item.replace)
      return rep ? rep : { type, props: newProps, key }
    }
    props = newProps
  }
  return { type, props, key }
}
export function setJsx(n) {
  if (!n || !n.jsx) return;
  const originalJsx = n.jsx;
  const originalJsxs = n.jsxs;
  const renderNode = (node) => {
    if (!node || !node.type) return node;
    if (node.$$typeof === Symbol.for("react.element")) {
        return node;
    }
    const { type, props, key } = node;
    const children = props.children ? (Array.isArray(props.children) ? props.children.map(renderNode) : renderNode(props.children)) : [];
    return originalJsx(type, { ...props, children }, key);
  };
  n.jsx = function (type, props, key) {
    const node = remixJsx({ type, props, key }, renderNode);
    return originalJsx(node.type, node.props, node.key);
  };
  n.jsxs = function (type, props, key) {
    const node = remixJsx({ type, props, key }, renderNode);
    return originalJsxs(node.type, node.props, node.key);
  };
}
// ── Auth bootstrap: set local tokens if not already set ─────────────────────
// FIX: Use iss="cfc" - clearApiKeyLogin deletes tokens with iss=="auth"
if (chrome?.storage?.local?.get) {
  chrome.storage.local.get({ accessToken: "", accountUuid: "" }).then(({ accessToken, accountUuid }) => {
    if (!accessToken || !accountUuid) {
      const header = btoa(JSON.stringify({ alg: "none", typ: "JWT" }))
      const payload = btoa(JSON.stringify({
        iss: "cfc",
        sub: "local-user",
        exp: 9999999999,
        iat: Math.floor(Date.now() / 1000),
      }))
      chrome.storage.local.set({
        accessToken: header + "." + payload + ".local",
        refreshToken: "local-refresh",
        tokenExpiry: Date.now() + 31536000000,
        accountUuid: "local-user-uuid",
      })
      console.log("[hijack] Auth tokens and accountUuid set")
    }
  })
}
// Sync apiBaseUrl in localStorage when hijackSettings changes
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
console.log("[hijack] Loaded in:", globalThis.window ? (location?.pathname || "unknown") : "service_worker")
"""
    cocodem_req.write_text(clean, encoding="utf-8")
    print(f"[OK] assets/request.js — clean local-only version ({len(clean)} bytes)")
def write_backend_settings_ui():
    ui = r"""(async () => {
  const container = document.getElementById("__cfc_settings_container");
  if (!container) return;
  const ICON = chrome?.runtime?.getURL ? chrome.runtime.getURL("icon-128.png") : "/icon-128.png";
  const K = {
    link: '<svg width="11" height="11" viewBox="0 0 512 512" fill="currentColor"><path d="M320 0c-17.7 0-32 14.3-32 32s14.3 32 32 32l82.7 0L201.4 265.4c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0L448 109.3 448 192c0 17.7 14.3 32 32 32s32-14.3 32-32l0-160c0-17.7-14.3-32-32-32L320 0zM80 32C35.8 32 0 67.8 0 112L0 432c0 44.2 35.8 80 80 80l320 0c44.2 0 80-35.8 80-80l0-112c0-17.7-14.3-32-32-32s-32 14.3-32 32l0 112c0 8.8-7.2 16-16 16L80 448c-8.8 0-16-7.2-16-16l0-320c0-8.8 7.2-16 16-16l112 0c17.7 0 32-14.3 32-32s-14.3-32-32-32L80 32z"/></svg>',
    key: '<svg width="11" height="11" viewBox="0 0 512 512" fill="currentColor"><path d="M336 352c97.2 0 176-78.8 176-176S433.2 0 336 0S160 78.8 160 176c0 18.7 2.9 36.8 8.3 53.7L7 391c-4.5 4.5-7 10.6-7 17l0 80c0 13.3 10.7 24 24 24l80 0c13.3 0 24-10.7 24-24l0-40 40 0c13.3 0 24-10.7 24-24l0-40 40 0c6.4 0 12.5-2.5 17-7l33.3-33.3c16.9 5.4 35 8.3 53.7 8.3zM376 96a40 40 0 1 1 0 80 40 40 0 1 1 0-80z"/></svg>',
    mail: '<svg width="11" height="11" viewBox="0 0 512 512" fill="currentColor"><path d="M48 64C21.5 64 0 85.5 0 112c0 15.1 7.1 29.3 19.2 38.4L236.8 313.6c11.4 8.5 27 8.5 38.4 0L492.8 150.4c12.1-9.1 19.2-23.3 19.2-38.4c0-26.5-21.5-48-48-48L48 64zM0 176L0 384c0 35.3 28.7 64 64 64l384 0c35.3 0 64-28.7 64-64l0-208L294.4 339.2c-22.8 17.1-54 17.1-76.8 0L0 176z"/></svg>',
    user: '<svg width="11" height="11" viewBox="0 0 448 512" fill="currentColor"><path d="M224 256A128 128 0 1 0 224 0a128 128 0 1 0 0 256zm-45.7 48C79.8 304 0 383.8 0 482.3C0 498.7 13.3 512 29.7 512l388.6 0c16.4 0 29.7-13.3 29.7-29.7C448 383.8 368.2 304 269.7 304l-91.4 0z"/></svg>',
    cog: '<svg width="10" height="10" viewBox="0 0 512 512" fill="currentColor"><path d="M495.9 166.6c3.2 8.7 .5 18.4-6.4 24.6l-43.3 39.4c1.1 8.3 1.7 16.8 1.7 25.4s-.6 17.1-1.7 25.4l43.3 39.4c6.9 6.2 9.6 15.9 6.4 24.6c-4.4 11.9-9.7 23.3-15.8 34.3l-4.7 8.1c-6.6 11-14 21.4-22.1 31.2c-5.9 7.2-15.7 9.6-24.5 6.8l-55.7-17.7c-13.4 10.3-28.2 18.9-44 25.4l-12.5 57.1c-2 9.1-9 16.3-18.2 17.8c-13.8 2.3-28 3.5-42.5 3.5s-28.7-1.2-42.5-3.5c-9.2-1.5-16.2-8.7-18.2-17.8l-12.5-57.1c-15.8-6.5-30.6-15.1-44-25.4L83.1 425.9c-8.8 2.8-18.6 .3-24.5-6.8c-8.1-9.8-15.5-20.2-22.1-31.2l-4.7-8.1c-6.1-11-11.4-22.4-15.8-34.3c-3.2-8.7-.5-18.4 6.4-24.6l43.3-39.4C64.6 273.1 64 264.6 64 256s.6-17.1 1.7-25.4L22.4 191.2c-6.9-6.2-9.6-15.9-6.4-24.6c4.4-11.9 9.7-23.3 15.8-34.3l4.7-8.1c6.6-11 14-21.4 22.1-31.2c5.9-7.2 15.7-9.6 24.5-6.8l55.7 17.7c13.4-10.3 28.2-18.9 44-25.4l12.5-57.1c2-9.1 9-16.3 18.2-17.8C227.3 1.2 241.5 0 256 0s28.7 1.2 42.5 3.5c9.2 1.5 16.2 8.7 18.2 17.8l12.5 57.1c15.8 6.5 30.6 15.1 44 25.4l55.7-17.7c8.8-2.8 18.6-.3 24.5 6.8c8.1 9.8 15.5 20.2 22.1 31.2l4.7 8.1c6.1 11 11.4 22.4 15.8 34.3zM256 336a80 80 0 1 0 0-160 80 80 0 1 0 0 160z"/></svg>',
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
            <span style="color:#2d6a4f;font-weight:700">✔ No calls to cocodem servers.</span>
          </p>
        </div>
        <div id="bs_st" style="padding:11px 16px;border-radius:10px;margin-bottom:18px;
             display:none;font-size:13px;font-weight:600"></div>
        <div style="font-size:9px;font-weight:900;color:#8B856C;text-transform:uppercase;
                    letter-spacing:.15em;margin-bottom:14px">▶ API Configuration</div>
        ${F("bs_base","API Base URL (ANTHROPIC_BASE_URL)","text","http://127.0.0.1:1234/v1",K.link,"")}
        ${F("bs_key","API Key (ANTHROPIC_API_KEY)","password","sk-ant-… or any string",K.key,"")}
        ${F("bs_auth","Auth Token (ANTHROPIC_AUTH_TOKEN)","password","optional",K.key,"")}
        <div style="font-size:9px;font-weight:900;color:#8B856C;text-transform:uppercase;
                    letter-spacing:.15em;margin:22px 0 8px">▶ Model Aliases
          <span style="color:#b4af9a;font-weight:600;text-transform:none;letter-spacing:0;margin-left:6px">(JSON, optional)</span>
        </div>
        <textarea id="bs_aliases" placeholder='{"claude-opus-4-7": "local-model-name"}'
          style="width:100%;min-height:76px;padding:11px 14px;margin-bottom:4px;
                 border:1px solid #e5e2d9;background:#fcfbf9;color:#1d1b16;
                 border-radius:12px;font-size:13px;font-family:monospace;
                 box-sizing:border-box;outline:none;resize:vertical"></textarea>
        <div style="font-size:9px;font-weight:900;color:#8B856C;text-transform:uppercase;
                    letter-spacing:.15em;margin:22px 0 14px">▶ Identity
          <span style="color:#2d6a4f;font-weight:700;text-transform:none;letter-spacing:0;margin-left:6px">✔ local — no license server</span>
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
            Writes to <code style="background:#fcfbf9;padding:2px 5px;border-radius:4px;
            color:#c45f3d;font-family:monospace">chrome.storage.local</code> only.
            No calls to any external C2.
          </p>
        </div>
      </div>
    </div>`;
  document.querySelectorAll("input,textarea").forEach(el => {
    el.addEventListener("focus", () => {
      el.style.borderColor = "#c45f3d";
      el.style.boxShadow = "0 0 0 3px rgba(196,95,61,.06)";
    });
    el.addEventListener("blur", () => {
      el.style.borderColor = "#e5e2d9";
      el.style.boxShadow = "none";
    });
  });
  const $ = id => document.getElementById(id);
  function st(m, k) {
    const el = $("bs_st"), s = k==="e"
      ? {bg:"#fbe7e1",c:"#b04a3d",b:"1px solid #f3c5b8"}
      : k==="w"
      ? {bg:"#fdf4e0",c:"#8b6914",b:"1px solid #f0d9a3"}
      : {bg:"#e6f2eb",c:"#2d6a4f",b:"1px solid #c5e0d0"};
    el.textContent = m;
    el.style.display = "block";
    Object.assign(el.style, {background:s.bg,color:s.c,border:s.b});
    clearTimeout(el.__t);
    el.__t = setTimeout(() => { el.style.display = "none"; }, 5000);
  }
  const KEYS = ["ANTHROPIC_BASE_URL","ANTHROPIC_API_KEY","ANTHROPIC_AUTH_TOKEN",
                "email","username","licenseKey","hijackSettings"];
  const saved = await chrome.storage.local.get(KEYS);
  const hs = saved.hijackSettings || {};
  $("bs_base").value = saved.ANTHROPIC_BASE_URL || hs.backendUrl || "http://127.0.0.1:1234/v1";
  $("bs_key").value = saved.ANTHROPIC_API_KEY || "";
  $("bs_auth").value = saved.ANTHROPIC_AUTH_TOKEN || "";
  $("bs_email").value = saved.email || "user@local";
  $("bs_user").value = saved.username || "local-user";
  $("bs_lic").value = saved.licenseKey || "";
  $("bs_block").checked = hs.blockAnalytics !== false;
  $("bs_aliases").value = hs.modelAliases && Object.keys(hs.modelAliases).length
    ? JSON.stringify(hs.modelAliases, null, 2) : "";
  $("bs_save").onclick = async () => {
    const base = $("bs_base").value.trim() || "http://127.0.0.1:1234/v1";
    let ma = {};
    const raw = $("bs_aliases").value.trim();
    if (raw) {
      try { ma = JSON.parse(raw); }
      catch { st("Invalid JSON in Model Aliases", "e"); return; }
    }
    await chrome.storage.local.set({
      ANTHROPIC_BASE_URL: base,
      ANTHROPIC_API_KEY: $("bs_key").value.trim(),
      ANTHROPIC_AUTH_TOKEN: $("bs_auth").value.trim(),
      email: $("bs_email").value.trim() || "user@local",
      username: $("bs_user").value.trim() || "local-user",
      licenseKey: $("bs_lic").value.trim(),
      hijackSettings: { backendUrl: base, modelAliases: ma,
                        blockAnalytics: $("bs_block").checked },
    });
    try { localStorage.setItem("apiBaseUrl", base); } catch(e) {}
    st("✔ Saved. Backend: " + base);
  };
  $("bs_test").onclick = async () => {
    const url = $("bs_base").value.trim() || "http://127.0.0.1:1234/v1";
    st("Testing " + url + "…", "w");
    try {
      const r = await fetch(url.replace(/\/v1\/?$/, "") + "/v1/models");
      if (r.ok) {
        const d = await r.json();
        st("✔ Connected. Models: " + (d.data?.map(m => m.id).join(", ") || "OK"));
      } else st("HTTP " + r.status, "e");
    } catch(e) { st("✖ Cannot reach " + url, "e"); }
  };
  $("bs_adv").onclick = () => {
    const p = $("bs_ap");
    p.style.display = p.style.display === "none" ? "block" : "none";
  };
  $("bs_clear").onclick = async () => {
    if (!confirm("Clear all saved Backend Settings? (Local only)")) return;
    await chrome.storage.local.remove(KEYS);
    try { localStorage.removeItem("apiBaseUrl"); } catch(e) {}
    st("✔ Cleared");
    setTimeout(() => location.reload(), 600);
  };
  $("bs_dump").onclick = async () => {
    const all = await chrome.storage.local.get(null);
    const MASK = /^(ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|licenseKey|accessToken|refreshToken|sidepanelToken)$/;
    const pre = $("bs_pre");
    pre.textContent = JSON.stringify(all, (k, v) =>
      MASK.test(k) && typeof v === "string" && v.length > 8
        ? v.slice(0, 4) + "…" + v.slice(-4) : v, 2);
    pre.style.display = "block";
    console.log("[cfc] storage.local dump:", all);
    st("✔ Dumped to console");
  };
})();
"""
    (OUTPUT_DIR / "assets" / "backend_settings_ui.js").write_text(ui, encoding="utf-8")
    print(f"[OK] assets/backend_settings_ui.js — unified settings UI ({len(ui)} bytes)")
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
        content = html_file.read_text(encoding="utf-8")
        orig_len = len(content)
        lines, new_lines, skip = content.split("\n"), [], False
        for line in lines:
            if "<script" in line:
                if 'src=' in line or 'type="module"' in line or "type='module'" in line:
                    new_lines.append(line)
                    skip = False
                else:
                    skip = True
            elif "</script>" in line and skip:
                skip = False
            elif not skip:
                new_lines.append(line)
        content = "\n".join(new_lines)
        content = re.sub(r"<script>\s*</script>", "", content, flags=re.DOTALL)
        html_file.write_text(content, encoding="utf-8")
        print(f"[OK] {html_file.name} — stripped {orig_len - len(content)} bytes inline scripts")
    stub = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="0;url=/options.html#backendsettings">
  <title>Backend Settings</title>
</head>
<body>
  <p>Redirecting to <a href="/options.html#backendsettings">Backend Settings</a>...</p>
</body>
</html>"""
    bs = OUTPUT_DIR / "backend_settings.html"
    og = OUTPUT_DIR / "backend_settingsOG.html"
    if bs.exists() and not og.exists():
        shutil.copy2(bs, og)
        print("[OK] backend_settings.html → backend_settingsOG.html (preserved)")
    bs.write_text(stub, encoding="utf-8")
    print("[OK] backend_settings.html (meta-refresh)")
    if not og.exists():
        og.write_text(stub, encoding="utf-8")
def inject_index_module():
    assets = OUTPUT_DIR / "assets"
    target = None
    known = assets / "index-BVS4T5_D.js"
    if known.exists():
        target = known
        print(f" jsx-runtime: {target.relative_to(OUTPUT_DIR)} (known)")
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
                        print(f" jsx-runtime: {target.relative_to(OUTPUT_DIR)} (modulepreload)")
                        break
    if not target:
        for f in sorted(assets.glob("index-*.js")):
            if f.stat().st_size < 30000:
                t = f.read_text(encoding="utf-8")
                if "jsx" in t and "jsxs" in t and "Fragment" in t:
                    target = f
                    print(f" jsx-runtime: {target.relative_to(OUTPUT_DIR)} (scan)")
                    break
    if not target:
        print("[WARN] jsx-runtime not found — setJsx not injected")
        return
    content = target.read_text(encoding="utf-8")
    if "setJsx" in content:
        print(f"[OK] setJsx already in {target.relative_to(OUTPUT_DIR)} — skip")
        return
    m = re.search(r",(\w)=\{\}[,;]", content) or re.search(r"(\w)=\{\}", content)
    var_name = m.group(1) if m else "l"
    print(f" jsx var: {var_name}")
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
    print(f"[OK] Injected setJsx({var_name}) → {target.relative_to(OUTPUT_DIR)}")
# ─── MULTI-BACKEND C2 PROXY (NO SINKHOLE) ─────────────────────────────────────
BACKENDS_FILE = Path("cfc_backends.json")
def _load_backends():
    if BACKENDS_FILE.exists():
        try:
            d = json.loads(BACKENDS_FILE.read_text(encoding="utf-8"))
            if isinstance(d, list) and d:
                return d
        except Exception:
            pass
    return [{"name": "Default", "models": [], "url": DEFAULT_BACKEND_URL, "key": ""}]
def _save_backends():
    BACKENDS_FILE.write_text(json.dumps(BACKENDS, indent=2), encoding="utf-8")
BACKENDS = _load_backends()
def _pick_backends(model):
    # First backend whose models list contains the requested model wins
    # Empty models list = catch-all (must be last)
    preferred = next(
        (b for b in BACKENDS if b.get("models") and model in b["models"]),
        next((b for b in BACKENDS if not b.get("models")), BACKENDS[-1])
    )
    return [preferred] + [b for b in BACKENDS if b is not preferred]
LOCAL_PROFILE = {
    "account": {"uuid":"ac507011-00b5-56c4-b3ec-ad820dbafbc1","email_address":"free@claudeagent.ai","email":"free@claudeagent.ai","full_name":"Local User","name":"Local User","display_name":"Local User","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","id":"ac507011-00b5-56c4-b3ec-ad820dbafbc1","has_password":True,"has_completed_onboarding":True,"preferred_language":"en-US","has_claude_pro":True},
    "organization":{"uuid":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08","id":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08","name":"Local","role":"admin","organization_type":"personal","billing_type":"self_serve","created_at":"2024-01-01T00:00:00Z"},
    "memberships":[{"organization":{"uuid":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08","id":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08","name":"Local","organization_type":"personal","billing_type":"self_serve"},"role":"admin","joined_at":"2024-01-01T00:00:00Z"}],
    "uuid":"ac507011-00b5-56c4-b3ec-ad820dbafbc1","id":"ac507011-00b5-56c4-b3ec-ad820dbafbc1","email":"free@claudeagent.ai","email_address":"free@claudeagent.ai","full_name":"Local User","name":"Local User","display_name":"Local User","has_password":True,"has_completed_onboarding":True,"preferred_language":"en-US","active_organization_uuid":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08","settings":{"theme":"system","language":"en-US"},
}
def _jwt(payload):
    h = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode()
    b = base64.b64encode(json.dumps(payload).encode()).decode()
    return f"{h}.{b}.local"
def build_local_token():
    now = int(time.time())
    p = {"iss":"cfc","sub":"ac507011-00b5-56c4-b3ec-ad820dbafbc1","exp":now+315360000,"iat":now}
    return {"access_token":_jwt(p),"token_type":"bearer","expires_in":315360000,"refresh_token":_jwt(p),"scope":"user:profile user:inference user:chat"}
LOCAL_BOOTSTRAP = {
    "account":{"uuid":"ac507011-00b5-56c4-b3ec-ad820dbafbc1",
        "id":"ac507011-00b5-56c4-b3ec-ad820dbafbc1","email":"free@claudeagent.ai",
        "email_address":"free@claudeagent.ai","full_name":"Local User","name":"Local User",
        "display_name":"Local User","has_password":True,"has_completed_onboarding":True,
        "preferred_language":"en-US","created_at":"2024-01-01T00:00:00Z",
        "updated_at":"2024-01-01T00:00:00Z","settings":{"theme":"system","language":"en-US"}},
    "uuid":"ac507011-00b5-56c4-b3ec-ad820dbafbc1",
    "id":"ac507011-00b5-56c4-b3ec-ad820dbafbc1",
    "account_uuid":"ac507011-00b5-56c4-b3ec-ad820dbafbc1",
    "email":"free@claudeagent.ai","email_address":"free@claudeagent.ai",
    "full_name":"Local User","name":"Local User","display_name":"Local User",
    "has_password":True,"has_completed_onboarding":True,"preferred_language":"en-US",
    "active_organization_uuid":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08",
    "organization":{"uuid":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08",
        "id":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08","name":"Local","role":"admin",
        "organization_type":"personal","billing_type":"self_serve",
        "capabilities":["chat","claude_pro_plan","api","computer_use","claude_for_chrome"],
        "rate_limit_tier":"default_claude_pro","settings":{}},
    "organizations":[{"uuid":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08",
        "id":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08","name":"Local","role":"admin",
        "organization_type":"personal","billing_type":"self_serve",
        "capabilities":["chat","claude_pro_plan","api"],"rate_limit_tier":"default_claude_pro"}],
    "memberships":[{"organization":{"uuid":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08",
        "id":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08","name":"Local",
        "organization_type":"personal","billing_type":"self_serve",
        "capabilities":["chat","api"],"rate_limit_tier":"default_claude_pro"},
        "role":"admin","joined_at":"2024-01-01T00:00:00Z"}],
    "statsig":{"user":{"userID":"ac507011-00b5-56c4-b3ec-ad820dbafbc1",
        "custom":{"organization_uuid":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08"}},
        "values":{"feature_gates":{},"dynamic_configs":{},"layer_configs":{}}},
    "flags":{},"features":[],"active_flags":{},
    "active_subscription":{"plan":"claude_pro","status":"active","type":"claude_pro",
        "billing_period":"monthly","current_period_start":"2024-01-01T00:00:00Z",
        "current_period_end":"2099-12-31T23:59:59Z"},
    "has_claude_pro":True,"chat_enabled":True,
    "capabilities":["chat","claude_pro_plan","api","computer_use","claude_for_chrome"],
    "rate_limit_tier":"default_claude_pro","settings":{"theme":"system","language":"en-US"},
}
LOCAL_ORGS = [{"uuid":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08",
    "id":"1b61ee4a-d0ce-50b5-8b67-7eec034d3d08","name":"Local","role":"admin",
    "organization_type":"personal","billing_type":"self_serve",
    "capabilities":["chat","claude_pro_plan","api"],"rate_limit_tier":"default_claude_pro",
    "settings":{},"created_at":"2024-01-01T00:00:00Z"}]
LOCAL_CONV = {"conversations":[],"limit":0,"has_more":False,"cursor":None}
def get_local_auth(path):
    if "/mcp/v2/bootstrap" in path: return {"servers":[],"tools":[],"enabled":False}
    if "/spotlight" in path: return {"items":[],"total":0}
    if "/features/" in path: return {"enabled":True,"features":{}}
    if "/oauth/account/settings" in path: return {"settings":{"theme":"system","language":"en-US"}}
    if "/oauth/profile" in path: return LOCAL_PROFILE
    if "/oauth/account" in path: return LOCAL_PROFILE
    if "/oauth/token" in path: return build_local_token()
    if "/bootstrap" in path: return LOCAL_BOOTSTRAP
    if "/oauth/organizations" in path:
        tail = path.split("/oauth/organizations/", 1)[1] if "/oauth/organizations/" in path else ""
        if "/" in tail: return {}
        if tail: return LOCAL_ORGS[0] if LOCAL_ORGS else {}
        return LOCAL_ORGS
    if "/chat_conversations" in path: return LOCAL_CONV
    if "/domain_info" in path: return {"domain":"local","allowed":True}
    if "/url_hash_check" in path: return {"allowed":True}
    if "/usage" in path: return {"usage":{},"limit":None}
    if "/entitlements" in path: return {"entitlements":[]}
    if "/flags" in path: return {}
    return {}
def _redirect_page_html():
    eid = EXTENSION_ID
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Authenticating...</title></head>
<body style="background:#f9f8f3;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
<div style="background:white;border:1px solid #e5e2d9;border-radius:32px;padding:40px;max-width:400px;width:100%;text-align:center">
  <h2 style="margin:0 0 8px;font-size:22px;font-family:'Iowan Old Style',Georgia,serif;font-weight:400;color:#1d1b16">Signed in!</h2>
  <p id="msg" style="color:#8b856c;font-size:13px;font-weight:500;margin:8px 0">Working…</p>
</div>
<script>
(async()=>{{
  const msg=document.getElementById("msg");
  const done=t=>{{msg.textContent=t;msg.style.color="#2d6a4f";setTimeout(()=>{{try{{window.close()}}catch(e){{}}}},800)}};
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
              btoa(JSON.stringify({{iss:"cfc",sub:"ac507011-00b5-56c4-b3ec-ad820dbafbc1",exp:9999999999,
                iat:Math.floor(Date.now()/1000)}}))+".local",
            refreshToken:"local-refresh",tokenExpiry:Date.now()+31536000000,
            accountUuid:"ac507011-00b5-56c4-b3ec-ad820dbafbc1",
            sidepanelToken:"cfc-local",sidepanelTokenExpiry:Date.now()+31536000000,
          }}}},()=>done("Done!"));
        }}else done("Done!");
      }});
    }}else done("Auth complete.");
  }}catch(e){{msg.textContent="Error: "+e.message;msg.style.color="#b04a3d"}}
}})();
</script></body></html>"""
def _build_proxy_settings_html():
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
.backend{{border:1px solid #e5e2d9;border-radius:12px;padding:18px;
margin-bottom:12px;background:#fcfbf9;position:relative}}
.bhead{{display:flex;align-items:center;gap:8px;margin-bottom:14px}}
.bname{{font-weight:700;font-size:14px;flex:1;color:#1d1b16}}
.badge{{font-size:10px;background:#e5e2d9;color:#6b6651;padding:2px 7px;
border-radius:4px;font-weight:700;letter-spacing:.05em}}
.row{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
label{{display:block;font-size:9px;font-weight:900;color:#8B856C;text-transform:uppercase;
letter-spacing:.15em;margin:10px 0 4px 2px}}
input{{width:100%;height:38px;padding:0 12px;border:1px solid #e5e2d9;background:white;
color:#1d1b16;border-radius:8px;font-size:13px;font-family:monospace;outline:none;transition:border-color .15s}}
input:focus{{border-color:#c45f3d;box-shadow:0 0 0 3px rgba(196,95,61,.08)}}
.actions{{display:flex;gap:6px}}
.btn{{height:34px;border:none;border-radius:7px;font-size:12px;font-weight:700;cursor:pointer;padding:0 14px;transition:all .15s}}
.btn-del{{background:#fbe7e1;color:#b04a3d}} .btn-del:hover{{background:#f8d5ce}}
.btn-tst{{background:#f0f0ea;color:#3d3929}} .btn-tst:hover{{background:#e5e2d9}}
.btn-add{{background:#e6f2eb;color:#2d6a4f;width:100%;height:40px;font-size:13px;margin-top:4px}}
.btn-add:hover{{background:#d0e8d8}}
.btn-save{{background:#c45f3d;color:white;width:100%;height:46px;font-size:15px;margin-top:16px;border-radius:12px}}
.btn-save:hover{{background:#b0512f}}
.ts{{font-size:11px;margin-top:6px;min-height:16px;font-weight:600}}
.st{{padding:11px 16px;border-radius:10px;margin-bottom:16px;font-size:13px;font-weight:600;display:none}}
.ok{{display:block;background:#e6f2eb;color:#2d6a4f}}
.er{{display:block;background:#fbe7e1;color:#b04a3d}}
</style></head>
<body><div class="w">
  <h1>CFC Backend Settings</h1>
  <p class="sub">First backend whose models list matches the request model wins.<br>
    Empty models list = catch-all (put last). Changes apply instantly on save.</p>
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
  const el=document.getElementById("list");
  el.innerHTML=B.map((b,i)=>
  `<div class="backend" id="b${{i}}">
    <div class="bhead">
      <span class="bname">${{esc(b.name)||"Backend "+(i+1)}}</span>
      ${{!b.models?.length?"<span class='badge'>catch-all</span>":""}}
      <div class="actions">
        <button class="btn btn-tst" onclick="testBackend(${{i}})">Test</button>
        ${{B.length>1?"<button class='btn btn-del' onclick='del("+(i)+")'>Remove</button>":""}}
      </div>
    </div>
    <div class="row">
      <div>
        <label>Name</label>
        <input value="${{esc(b.name)}}" onchange="upd(${{i}},'name',this.value)" placeholder="e.g. Local LLM">
      </div>
      <div>
        <label>Base URL (ends in /v1)</label>
        <input value="${{esc(b.url)}}" onchange="upd(${{i}},'url',this.value)" placeholder="http://127.0.0.1:1234/v1">
      </div>
    </div>
    <label>API Key (blank = pass through extension key)</label>
    <input type="password" value="${{esc(b.key)}}" onchange="upd(${{i}},'key',this.value)" placeholder="sk-...">
    <label>Models (comma-separated — blank = catch-all)</label>
    <input value="${{esc((b.models||[]).join(", "))}}"
      onchange="upd(${{i}},'models',this.value.split(',').map(s=>s.trim()).filter(Boolean))"
      placeholder="claude-opus-4-7, claude-sonnet-4-6">
    <div class="ts" id="ts${{i}}"></div>
  </div>`).join("");
}}
window.upd=function(i,k,v){{B[i][k]=v}};
window.del=function(i){{B.splice(i,1);render()}};
window.addBackend=function(){{
  B.push({{name:"",url:"http://127.0.0.1:1234/v1",key:"",models:[]}});
  render();
  setTimeout(()=>document.getElementById("b"+(B.length-1))?.scrollIntoView({{behavior:"smooth"}}),50);
}};
window.testBackend=async function(i){{
  const b=B[i],el=document.getElementById("ts"+i);
  el.textContent="Testing...";el.style.color="#6b6651";
  try{{
    const h=b.key?{{Authorization:"Bearer "+b.key}}:{{}};
    const r=await fetch(b.url.replace(/\\/v1\\/?$/,"")+"/v1/models",{{headers:h}});
    if(r.ok){{
      const d=await r.json();
      const names=(d.data||[]).map(m=>m.id).slice(0,4).join(", ")||"OK";
      el.textContent="\u2713 "+names;el.style.color="#2d6a4f";
    }}else{{el.textContent="\u2717 HTTP "+r.status;el.style.color="#b04a3d"}}
  }}catch(e){{el.textContent="\u2717 "+e.message;el.style.color="#b04a3d"}}
}};
window.save=async function(){{
  try{{
    const r=await fetch("/api/backends",{{
      method:"POST",headers:{{"Content-Type":"application/json"}},
      body:JSON.stringify({{backends:B}})}});
    const d=await r.json();
    if(d.ok)st("\u2713 Saved and applied");
    else st("Error: "+(d.error||"unknown"),true);
  }}catch(e){{st("Save failed: "+e.message,true)}}
}};
async function load(){{
  try{{
    const r=await fetch("/api/backends");
    const d=await r.json();
    B=d.backends||[];
    if(!B.length)B=[{{name:"Default",url:"http://127.0.0.1:1234/v1",key:"",models:[]}}];
    render();
  }}catch(e){{st("Cannot reach proxy: "+e.message,true)}}
}}
load();
</script></body></html>"""
class MultiC2Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f" [{time.strftime('%H:%M:%S')}] {args[0]}")
    def handle_one_request(self):
        try: super().handle_one_request()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError): pass
    def _json(self, data):
        b = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(b)))
        self.send_header("Connection","close")
        self._cors()
        self.end_headers()
        try: self.wfile.write(b)
        except OSError: pass
    def _html(self, html):
        b = html.encode()
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length",str(len(b)))
        self.send_header("Connection","close")
        self._cors()
        self.end_headers()
        try: self.wfile.write(b)
        except OSError: pass
    def _204(self):
        self.send_response(204)
        self.send_header("Connection","close")
        self._cors()
        self.end_headers()
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET, POST, PATCH, OPTIONS")
        self.send_header("Access-Control-Allow-Headers",
            "Content-Type, Cache-Control, anthropic-version, anthropic-beta, "
            "anthropic-client-platform, anthropic-client-version, "
            "Authorization, x-app, x-service-name")
        self.send_header("Access-Control-Allow-Private-Network","true")
    def _is_auth(self, p):
        if p.startswith("/https://") or p.startswith("/http://"): return True
        if p.startswith("/chrome-extension://"): return True
        return any(s in p for s in [
            "/oauth/","/bootstrap","/domain_info","/chat_conversations",
            "/organizations","/url_hash_check","/api/web/","/features/",
            "/spotlight","/usage","/entitlements","/flags","/mcp/v2/",
        ])
    def _is_v1(self, p):
        return "/v1/" in p and "/v1/oauth" not in p and (
            "api.anthropic.com" in p or
            p.startswith("/v1/") or
            p.startswith("/<https://api.anthropic.com/v1/>")
        )
    def _forward_v1(self, method, body):
        model = ""
        if body:
            try: model = json.loads(body).get("model", "")
            except: pass
        p = self.path
        if p.startswith("/https://") or p.startswith("/http://"):
            inner = p[1:]
            idx = inner.find("/v1/")
            suffix = inner[idx:] if idx != -1 else "/v1"
        else:
            suffix = p
        path_suffix = suffix[3:] if suffix.startswith("/v1") else suffix
        base_hdrs = {k: v for k, v in self.headers.items()
                     if k.lower() in ("content-type","accept","anthropic-version",
                                      "anthropic-beta","anthropic-client-platform",
                                      "anthropic-client-version")}
        ext_auth = self.headers.get("Authorization","")
        last_err = None
        for backend in _pick_backends(model):
            target = backend["url"].rstrip("/") + path_suffix
            hdrs = dict(base_hdrs)
            if backend.get("key"):
                hdrs["Authorization"] = f"Bearer {backend['key']}"
            elif ext_auth:
                hdrs["Authorization"] = ext_auth
            req = urllib.request.Request(
                target, data=body or None, headers=hdrs, method=method)
            try:
                with urllib.request.urlopen(req, timeout=300) as r:
                    data = r.read()
                    self.send_response(r.status)
                    for h in ("Content-Type","Content-Length","Transfer-Encoding"):
                        v = r.headers.get(h)
                        if v: self.send_header(h, v)
                    self.send_header("Connection","close")
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
                        e.headers.get("Content-Type","application/json"))
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Connection","close")
                    self._cors()
                    self.end_headers()
                    try: self.wfile.write(data)
                    except OSError: pass
                    return
                last_err = e
            except Exception as ex:
                last_err = ex
        err_msg = json.dumps({"error":{"type":"proxy_error",
                                        "message":str(last_err)}}).encode()
        self.send_response(502)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(err_msg)))
        self.send_header("Connection","close")
        self._cors()
        self.end_headers()
        try: self.wfile.write(err_msg)
        except OSError: pass
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Connection","close")
        self._cors()
        self.end_headers()
    def do_GET(self):
        p = self.path
        if self._is_v1(p): self._forward_v1("GET", b""); return
        if p.startswith("/api/options"):
            self._json({"mode":"","cfcBase":CFC_BASE,"anthropicBaseUrl":DEFAULT_BACKEND_URL,
                "apiBaseIncludes":["https://api.anthropic.com/v1/"],
                "proxyIncludes":[
                    "https://api.anthropic.com/v1/",
                    "cdn.segment.com","featureassets.org","assetsconfigcdn.org",
                    "featuregates.org","api.segment.io","prodregistryv2.org","beyondwickedmapping.org",
                    "api.honeycomb.io","statsigapi.net","events.statsigapi.net","api.statsigcdn.com",
                    "*ingest.us.sentry.io","https://api.anthropic.com/api/oauth/profile",
                    "https://api.anthropic.com/api/bootstrap","https://console.anthropic.com/v1/oauth/token",
                    "https://platform.claude.com/v1/oauth/token","https://api.anthropic.com/api/oauth/account",
                    "https://api.anthropic.com/api/oauth/organizations",
                    "https://api.anthropic.com/api/oauth/chat_conversations",
                    "/api/web/domain_info/browser_extension","/api/web/url_hash_check/browser_extension"],
                "discardIncludes":["cdn.segment.com","api.segment.io","events.statsigapi.net",
                    "api.honeycomb.io","prodregistryv2.org","*ingest.us.sentry.io",
                    "browser-intake-us5-datadoghq.com","fpjs.dev","openfpcdn.io",
                    "googletagmanager.com"],
                "modelAlias":{},"ui":{},"uiNodes":[]})
            return
        if p.startswith("/api/backends"):
            self._json({"backends": BACKENDS}); return
        if p.startswith("/api/arc-split-view"):
            self._json({"html":"<div>CFC Proxy</div>"}); return
        if p.startswith("/assets/backend_settings_ui.js"):
            f = OUTPUT_DIR / "assets" / "backend_settings_ui.js"
            if f.exists():
                b = f.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type","application/javascript; charset=utf-8")
                self.send_header("Content-Length",str(len(b)))
                self.send_header("Connection","close")
                self._cors()
                self.end_headers()
                try: self.wfile.write(b)
                except OSError: pass
            else: self._204()
            return
        if "/oauth/authorize" in p:
            qs = urlparse(p).query
            self.send_response(302)
            self.send_header("Location", f"{CFC_BASE}oauth/redirect?{qs}")
            self.send_header("Connection","close")
            self._cors()
            self.end_headers()
            return
        if p.startswith("/oauth/redirect"):
            self._html(_redirect_page_html()); return
        if p.startswith("/backend_settings"):
            self._html(_build_proxy_settings_html()); return
        if self._is_auth(p):
            self._json(get_local_auth(p)); return
        if p in ("/",) or p.startswith("/?"):
            self._html(f"""<!DOCTYPE html>
<html><head><title>CFC Proxy</title></head>
<body style="background:#f9f8f3;font-family:sans-serif;padding:40px;color:#3d3929">
<h1>CFC Multi-C2 Proxy — Port {CFC_PORT}</h1>
<p>Model-based routing to multiple backends • per-backend keys • failover • auth answered locally</p>
<p><a href="/backend_settings" style="color:#c45f3d">\u2699\ufe0f Backend Settings</a></p>
</body></html>"""); return
        self._204()
    def do_POST(self):
        cl = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl) if cl > 0 else b""
        p = self.path
        if p.startswith("/api/backends"):
            try:
                cfg = json.loads(body)
                bs = cfg.get("backends", [])
                if not isinstance(bs, list) or not bs:
                    self._json({"error": "backends must be a non-empty list"}); return
                BACKENDS.clear()
                BACKENDS.extend(bs)
                _save_backends()
                self._json({"ok": True})
            except Exception as ex:
                self._json({"error": str(ex)})
            return
        if self._is_v1(p): self._forward_v1("POST", body); return
        if self._is_auth(p): self._json(get_local_auth(p)); return
        self._204()
    def do_PATCH(self):
        cl = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl) if cl > 0 else b""
        p = self.path
        if self._is_v1(p): self._forward_v1("PATCH", body); return
        if self._is_auth(p): self._json(get_local_auth(p)); return
        self._204()
class MultiC2Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
def start_multi_c2():
    try:
        server = MultiC2Server(("127.0.0.1", CFC_PORT), MultiC2Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"\n[OK] Real multi-backend C2 proxy running on {CFC_BASE}")
        return server
    except OSError as e:
        print(f"[WARN] Cannot bind port {CFC_PORT}: {e}")
        return None
def print_report(m):
    print("\n" + "=" * 62)
    print(f" DONE — {OUTPUT_DIR}")
    print("=" * 62)
    print(f" {m.get('name')} v{m.get('version')}")
    print(f"\n Install:")
    print(f" 1. Disable cocodem in chrome://extensions/")
    print(f" 2. Enable Developer Mode")
    print(f" 3. Load unpacked → {OUTPUT_DIR.resolve()}")
    print(f"\n Backend Settings:")
    print(f" {BACKEND_SETTINGS_URL}")
    print(f"\n C2 proxy: {CFC_BASE}")
    print(f"\n Keep terminal open. Ctrl+C to stop.\n")
def main():
    print("=" * 62)
    print(f" Claude Extension Sanitizer — {TIMESTAMP}")
    print(f" Source: {COCODEM_SRC}")
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
    server = start_multi_c2()
    print_report(m)
    if server:
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            print("\n[CFC multi-C2 proxy] Shutting down...")
            server.shutdown()
    else:
        print("[WARN] C2 proxy did not start.")
if __name__ == "__main__":
    main()