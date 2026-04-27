// worker.js -- CFC Contract Cloudflare Worker
// Implements the complete cfc.aroic.workers.dev + openclaude.111724.xyz API contract.
//
// Deploy to your own Cloudflare Worker (free tier, no KV needed).
// This Worker handles config/auth/license only.
// API traffic NEVER passes through this Worker -- the extension routes /v1/*
// directly to the user's local server (http://localhost:LOCAL_PORT/v1) via the
// apiBaseUrl field returned in /api/options.  Zero credential exposure.
//
// Routes served:
//   /api/options          --> CFC options contract (identical response shape to live endpoint)
//   /api/arc-split-view   --> arc split-view HTML
//   /api/backends         --> empty backend list (writes go to local server)
//   /oauth/authorize      --> local OAuth redirect page
//   /oauth/redirect       --> same redirect page
//   /oauth/token, /bootstrap, /oauth/profile, /oauth/account, /oauth/organizations
//   /licenses/verify, /domain_info, /url_hash_check, /features/*, etc.
//   /https://*, /http://* --> proxied URL prefix -- extract and answer locally
//   /                     --> status dashboard
//   anything else         --> {"ok": true}

// ── identity constants (match local server defaults) ─────────────────────────

const _UUID_U = "ac507011-00b5-56c4-b3ec-ad820dbafbc1"
const _UUID_O = "1b61ee4a-d0ce-50b5-8b67-7eec034d3d08"
const _EMAIL  = "free@claudeagent.ai"
const EXT_ID  = "fcoeoabgfenejglbffodgkkbkcdhcgfn"

// ── CORS ─────────────────────────────────────────────────────────────────────

const CORS = {
  "Access-Control-Allow-Origin":          "*",
  "Access-Control-Allow-Methods":         "GET, POST, PATCH, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers":         "Content-Type, Cache-Control, Accept, anthropic-version, anthropic-beta, anthropic-client-platform, anthropic-client-version, Authorization, x-app, x-service-name, x-api-key",
  "Access-Control-Allow-Private-Network": "true",
  "Access-Control-Max-Age":               "86400",
}

// ── helpers ──────────────────────────────────────────────────────────────────

function _jwt(payload) {
  const enc = s => btoa(JSON.stringify(s)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")
  return enc({alg:"none",typ:"JWT"}) + "." + enc(payload) + ".local"
}

function _token() {
  const now = Math.floor(Date.now() / 1000)
  const tok  = _jwt({iss:"cfc", sub:_UUID_U, exp:now+315360000, iat:now})
  return {access_token:tok, token_type:"bearer", expires_in:315360000,
          refresh_token:tok, scope:"user:profile user:inference user:chat"}
}

function json(data, status=200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {...CORS, "Content-Type":"application/json"},
  })
}

function html(body, status=200) {
  return new Response(body, {
    status,
    headers: {...CORS, "Content-Type":"text/html; charset=utf-8"},
  })
}

function no_content() {
  return new Response(null, {status:204, headers:CORS})
}

// ── telemetry check ───────────────────────────────────────────────────────────

const TEL_DOMAINS = [
  "segment.com","statsig","honeycomb","sentry","datadoghq",
  "featureassets","assetsconfigcdn","featuregates","prodregistryv2",
  "beyondwickedmapping","fpjs.dev","openfpcdn.io","api.fpjs.io",
  "googletagmanager","googletag",
]

function isTel(path) { return TEL_DOMAINS.some(d => path.includes(d)) }

// ── local auth data ───────────────────────────────────────────────────────────

const LOCAL_ACCOUNT = {
  uuid:_UUID_U, id:_UUID_U, email_address:_EMAIL, email:_EMAIL,
  full_name:"Local User", name:"Local User", display_name:"Local User",
  has_password:true, has_completed_onboarding:true,
  preferred_language:"en-US", has_claude_pro:true,
  created_at:"2024-01-01T00:00:00Z", updated_at:"2024-01-01T00:00:00Z",
  settings:{theme:"system", language:"en-US"},
}

const LOCAL_ORG = {
  uuid:_UUID_O, id:_UUID_O, name:"Local", role:"admin",
  organization_type:"personal", billing_type:"self_serve",
  capabilities:["chat","claude_pro_plan","api","computer_use","claude_for_chrome"],
  rate_limit_tier:"default_claude_pro", settings:{},
  created_at:"2024-01-01T00:00:00Z",
}

const LOCAL_PROFILE = {
  ...LOCAL_ACCOUNT,
  account:LOCAL_ACCOUNT, organization:LOCAL_ORG,
  memberships:[{organization:LOCAL_ORG, role:"admin", joined_at:"2024-01-01T00:00:00Z"}],
  active_organization_uuid:_UUID_O,
}

const LOCAL_BOOTSTRAP = {
  ...LOCAL_ACCOUNT,
  account_uuid:_UUID_U, account:LOCAL_ACCOUNT,
  organization:LOCAL_ORG, organizations:[LOCAL_ORG],
  memberships:[{organization:LOCAL_ORG, role:"admin", joined_at:"2024-01-01T00:00:00Z"}],
  active_organization_uuid:_UUID_O,
  statsig:{
    user:{userID:_UUID_U, custom:{organization_uuid:_UUID_O}},
    values:{feature_gates:{}, dynamic_configs:{}, layer_configs:{}},
  },
  flags:{}, features:[], active_flags:{},
  active_subscription:{
    plan:"claude_pro", status:"active", type:"claude_pro", billing_period:"monthly",
    current_period_start:"2024-01-01T00:00:00Z",
    current_period_end:  "2099-12-31T23:59:59Z",
  },
  has_claude_pro:true, chat_enabled:true,
  capabilities:["chat","claude_pro_plan","api","computer_use","claude_for_chrome"],
  rate_limit_tier:"default_claude_pro",
  settings:{theme:"system", language:"en-US"},
}

function getLocalAuth(path) {
  if (path.includes("/licenses/verify"))        return {valid:true, license:"local", tier:"pro", expires:"2099-12-31"}
  if (path.includes("/mcp/v2/bootstrap"))       return {servers:[], tools:[], enabled:false}
  if (path.includes("/spotlight"))              return {items:[], total:0}
  if (path.includes("/features/"))             return {enabled:true, features:{}}
  if (path.includes("/oauth/account/settings")) return {settings:{theme:"system", language:"en-US"}}
  if (path.includes("/oauth/profile"))         return LOCAL_PROFILE
  if (path.includes("/oauth/account"))         return LOCAL_PROFILE
  if (path.includes("/oauth/token"))           return _token()
  if (path.includes("/bootstrap"))            return LOCAL_BOOTSTRAP
  if (path.includes("/oauth/organizations")) {
    const tail = path.split("/oauth/organizations/")[1] || ""
    if (tail.includes("/")) return {}
    if (tail) return LOCAL_ORG
    return [LOCAL_ORG]
  }
  if (path.includes("/chat_conversations"))   return {conversations:[], limit:0, has_more:false, cursor:null}
  if (path.includes("/domain_info"))          return {domain:"local", allowed:true}
  if (path.includes("/url_hash_check"))       return {allowed:true}
  if (path.includes("/usage"))               return {usage:{}, limit:null}
  if (path.includes("/entitlements"))         return {entitlements:[]}
  if (path.includes("/flags"))               return {}
  return {}
}

// ── /api/options -- CORE CFC CONTRACT ─────────────────────────────────────────
//
// CRITICAL DESIGN: apiBaseIncludes is set to ["https://api.anthropic.com/v1/"]
// so the extension's apiBase branch fires for ALL /v1/* calls.  The extension
// then resolves the actual backend URL from:
//   globalThis.__cfc_options.apiBaseUrl  (set by cfctest.py to localhost:PORT/v1)
//   OR localStorage.apiBaseUrl           (set by backend_settings_ui.js)
//   OR anthropicBaseUrl                  (empty -- NOT Anthropic's real servers)
//   OR u.origin                          (last resort, not reached in normal use)
//
// Result: /v1/* traffic goes DIRECTLY to the local CFC server, never to this
// Worker.  Only config/auth/license calls (via proxyIncludes + cfcBase) come
// here.  Zero API key or conversation data ever hits this Worker.

function buildOptions() {
  return {
    mode:             "",
    anthropicBaseUrl: "",
    apiBaseIncludes:  ["https://api.anthropic.com/v1/"],
    proxyIncludes: [
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
    discardIncludes: [
      "cdn.segment.com", "api.segment.io", "events.statsigapi.net",
      "api.honeycomb.io", "prodregistryv2.org", "*ingest.us.sentry.io",
      "browser-intake-us5-datadoghq.com",
    ],
    modelAlias: {},
    // ui={} and uiNodes=[] match the most-recent CFCBASE wrapper.  The Worker
    // must NOT inject replacement nodes -- the local server is the only place
    // where Backend Settings affordances are rendered, and even there the
    // server now serves them as a separate page rather than as JSX injection.
    ui:         {},
    uiNodes:    [],
  }
}

// ── OAuth redirect page ───────────────────────────────────────────────────────

function oauthRedirectPage(workerOrigin) {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Authenticating…</title></head>
<body style="background:#f9f8f3;font-family:-apple-system,sans-serif;display:flex;
             align-items:center;justify-content:center;height:100vh;margin:0">
<div style="background:white;border:1px solid #e5e2d9;border-radius:32px;padding:40px;
            max-width:400px;width:100%;text-align:center">
  <h2 style="margin:0 0 8px;font-size:22px;font-family:'Iowan Old Style',Georgia,serif;
             font-weight:400;color:#1d1b16">Signed in!</h2>
  <p id="msg" style="color:#8b856c;font-size:13px;font-weight:500;margin:8px 0">Working…</p>
</div>
<script>
(async () => {
  const msg  = document.getElementById("msg")
  const done = t => { msg.textContent = t; msg.style.color = "#2d6a4f";
    setTimeout(() => { try { window.close() } catch(e) {} }, 800) }
  try {
    const p   = new URLSearchParams(window.location.search)
    const r   = p.get("redirect_uri") || "", state = p.get("state") || ""
    let eid   = "${EXT_ID}"
    if (r.startsWith("chrome-extension://")) { try { eid = new URL(r).host } catch(e) {} }
    const arr = new Uint8Array(32); crypto.getRandomValues(arr)
    const code = "cfc-" + btoa(String.fromCharCode(...arr))
      .replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=/g,"")
    let final = r
    if (final) {
      try {
        const u = new URL(final)
        u.searchParams.set("code", code)
        if (state) u.searchParams.set("state", state)
        final = u.toString()
      } catch(e) {
        final = r + (r.includes("?") ? "&" : "?") + "code=" + code
      }
    }
    if (typeof chrome !== "undefined" && chrome.runtime && eid) {
      chrome.runtime.sendMessage(eid, {type:"oauth_redirect", redirect_uri:final}, rv => {
        if (chrome.runtime.lastError || !rv?.success) {
          chrome.runtime.sendMessage(eid, {type:"_set_storage_local", data:{
            accessToken: btoa(JSON.stringify({alg:"none",typ:"JWT"})) + "." +
              btoa(JSON.stringify({iss:"cfc",sub:"${_UUID_U}",exp:9999999999,
                iat:Math.floor(Date.now()/1000)})) + ".local",
            refreshToken: "local-refresh", tokenExpiry: Date.now() + 31536000000,
            accountUuid: "${_UUID_U}",
            sidepanelToken: "cfc-local", sidepanelTokenExpiry: Date.now() + 31536000000,
          }}, () => done("Done!"))
        } else done("Done!")
      })
    } else done("Auth complete.")
  } catch(e) { msg.textContent = "Error: " + e.message; msg.style.color = "#b04a3d" }
})()
</script></body></html>`
}

// ── root dashboard ────────────────────────────────────────────────────────────

function dashboardPage(workerUrl) {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CFC Worker</title>
<style>
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:#f9f8f3;color:#3d3929;margin:0;padding:0;min-height:100vh;
  display:flex;align-items:center;justify-content:center}
.card{background:white;border:1px solid #e5e2d9;border-radius:24px;padding:40px;
  max-width:520px;width:100%;margin:32px 20px;text-align:center;
  box-shadow:0 8px 32px rgba(0,0,0,.04)}
h1{font-size:28px;font-family:'Iowan Old Style',Georgia,serif;font-weight:400;
  color:#1d1b16;margin:0 0 12px;letter-spacing:-.02em}
p{color:#6b6651;font-size:14px;line-height:1.7;margin:0 0 20px}
.links{display:flex;flex-direction:column;gap:8px;text-align:left}
a{color:#c45f3d;font-weight:700;font-size:13px;text-decoration:none;
  background:#fcfbf9;border:1px solid #e5e2d9;border-radius:8px;
  padding:10px 14px;display:flex;justify-content:space-between;align-items:center}
a:hover{background:#f0f0ea}
.badge{font-size:10px;font-weight:900;color:#2d6a4f;text-transform:uppercase;
  letter-spacing:.1em;background:#e6f2eb;border-radius:4px;padding:2px 7px}
.url{font-size:11px;color:#8b856c;margin-top:16px;font-family:monospace;
  background:#f9f8f3;border:1px solid #e5e2d9;border-radius:8px;padding:10px}
</style></head>
<body><div class="card">
  <h1>CFC Worker</h1>
  <p>Cloudflare Worker implementing the CFC contract for the cocodem sanitizer.<br>
  Config &amp; auth only &mdash; zero API keys or conversation data ever reach this Worker.</p>
  <div class="links">
    <a href="/api/options">/api/options <span class="badge">CFC Contract</span></a>
    <a href="/licenses/verify">/licenses/verify <span class="badge">always valid</span></a>
    <a href="/oauth/authorize?redirect_uri=test&response_type=code&client_id=test&state=1">/oauth/authorize</a>
    <a href="/api/arc-split-view">/api/arc-split-view</a>
  </div>
  <div class="url">${workerUrl}</div>
</div></body></html>`
}

// ── request handler ───────────────────────────────────────────────────────────

addEventListener("fetch", event => {
  event.respondWith(handle(event.request))
})

async function handle(request) {
  const url    = new URL(request.url)
  const method = request.method
  const path   = url.pathname

  // OPTIONS preflight
  if (method === "OPTIONS") return no_content()

  // Telemetry -- always 204, before everything else
  if (isTel(path)) return no_content()

  // Proxied URL prefix: request.js sends cfcBase + "https://..." or "http://..."
  // e.g.  GET /https://api.anthropic.com/api/bootstrap
  //        GET /https://api.anthropic.com/api/oauth/profile
  // Strip the leading slash and route by the inner URL's path.
  if (path.startsWith("/https://") || path.startsWith("/http://") || path.startsWith("/chrome-extension://")) {
    const inner = path.slice(1)        // "https://api.anthropic.com/api/bootstrap"
    const auth  = getLocalAuth(inner)
    return json(auth)
  }

  // /api/options  -- the core CFC endpoint
  if (path.startsWith("/api/options")) return json(buildOptions())

  // /api/arc-split-view
  if (path.startsWith("/api/arc-split-view")) {
    return json({html: `<div style="display:flex;height:100vh;font-family:-apple-system,sans-serif"><div style="flex:1;border-right:1px solid #e5e2d9;padding:20px;background:white;"><p style="color:#8b856c;font-size:13px">Web Panel</p></div><div style="flex:1;padding:20px;background:#f9f8f3"><p style="color:#b4af9a;font-size:13px">Claude Panel</p></div></div>`})
  }

  // /api/backends  -- read-only; writes go to local server
  if (path.startsWith("/api/backends")) {
    return json({backends:[{name:"Default",url:"http://127.0.0.1:1234/v1",key:"",models:[],enabled:true}]})
  }

  // /oauth/authorize  -- open OAuth tab
  if (path.includes("/oauth/authorize")) {
    const qs    = url.search
    const base  = url.origin
    // Redirect to /oauth/redirect preserving query string so the page can read redirect_uri
    return Response.redirect(base + "/oauth/redirect" + qs, 302)
  }

  // /oauth/redirect  -- serve the auth page (messages extension with code)
  if (path.startsWith("/oauth/redirect")) {
    return html(oauthRedirectPage(url.origin))
  }

  // Auth / bootstrap / license endpoints
  const AUTH_PATHS = [
    "/oauth/", "/bootstrap", "/domain_info", "/chat_conversations",
    "/organizations", "/url_hash_check", "/api/web/", "/features/",
    "/spotlight", "/usage", "/entitlements", "/flags", "/mcp/v2/",
    "/licenses/",
  ]
  if (AUTH_PATHS.some(s => path.includes(s))) return json(getLocalAuth(path))

  // Root dashboard
  if (path === "/" || path === "") return html(dashboardPage(request.url.split("?")[0].replace(/\/$/, "")))

  // Fallback -- never 204 for unmatched routes
  return json({ok:true, path})
}
