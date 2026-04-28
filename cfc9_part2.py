
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

    const origCb = cb
    const safeArgs = [...args]
    if (typeof origCb === "function") {
      const cbIdx = safeArgs.lastIndexOf(origCb)
      safeArgs[cbIdx] = function(response) {
        if (chrome.runtime.lastError) {
          setTimeout(() => { try { origCb(undefined) } catch(e) {} }, 0)
          return
        }
        try { origCb(response) } catch(e) {}
      }
    }
    try {
      return __origSendMessage(...safeArgs)
    } catch(e) {
      setTimeout(() => {
        try { if (typeof origCb === "function") origCb(undefined) } catch(e2) {}
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

  if (location.pathname == "/sidepanel.html" && location.search.includes("code=")) {
    const params = new URLSearchParams(location.search)
    const code   = params.get("code")
    if (code) {
      chrome.storage.local.set({
        sidepanelToken:        "cfc-local-permanent",
        sidepanelTokenExpiry:  9999999999999,
      })
      const u = new URL(location.href)
      u.search = ""
      history.replaceState(null, "", u.href)
    }
  }

  if (location.pathname == "/sidepanel.html" && location.search == "") {
    let _spAttempts = 0
    function _trySidepanel() {
      chrome.storage.local.get({ sidepanelToken: "", sidepanelTokenExpiry: 0 })
        .then(({ sidepanelToken, sidepanelTokenExpiry }) => {
          const now = Date.now()
          if (!sidepanelToken || !sidepanelTokenExpiry || sidepanelTokenExpiry < now) {
            if (_spAttempts++ < 10) {
              setTimeout(_trySidepanel, 150)
              return
            }
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
        }).catch(() => {
          if (_spAttempts++ < 10) setTimeout(_trySidepanel, 150)
        })
    }
    _trySidepanel()
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
      link.innerHTML = "⚙️ Backend Settings"
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
      "ru-RU": "Русский",
      "zh-CN": "简体中文",
      "zh-TW": "繁體中文",
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
    print(f"[OK] assets/request.js -- cfcBase: {REMOTE_BASE!r} || {CFC_BASE!r}")

