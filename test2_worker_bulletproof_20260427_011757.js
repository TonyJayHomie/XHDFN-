// test2_worker_bulletproof_20260427_011757.js
//
// FULL test2 Cloudflare Worker — drop into the Worker editor & deploy.
//
// Fix vs previous deploy: Continue button is now a plain <a href="..."> link.
// No onclick, no inline JS, no JSON template-substitution that can break it.
// Click → browser navigates → done. CSP-proof, escape-proof, copy-paste proof.
//
// Routes:
//   GET  /                         status page (so preview pane shows something)
//   GET  /oauth/authorize          auth gate, "Continue" goes to /oauth/redirect
//   GET  /oauth/redirect           writes auth tokens to extension storage,
//                                  then navigates to redirect_uri with code+state
//   GET  /api/options              uiNodes:[], ui:{} contract
//   GET  /api/identity             local identity stub
//   GET  /api/backends             empty backends stub
//   *    /https://api.anthropic... cfcBase-rewritten paths → routeAuth() handles
//   *    everything else           307 → http://localhost:8520

const EXTENSION_ID  = "fcoeoabgfenejglbffodgkkbkcdhcgfn";
const LOCAL_BACKEND = "http://127.0.0.1:1234/v1";
const LOCAL_CFC     = "http://localhost:8520";
const USER_UUID     = "ac507011-00b5-56c4-b3ec-ad820dbafbc1";
const ORG_UUID      = "1b61ee4a-d0ce-50b5-8b67-7eec034d3d08";

const ACCOUNT = {
  uuid: USER_UUID, id: USER_UUID, account_uuid: USER_UUID,
  email_address: "user@local", email: "user@local",
  full_name: "Local User", name: "Local User", display_name: "Local User",
  has_password: true, has_completed_onboarding: true,
  preferred_language: "en-US", has_claude_pro: true,
  created_at: "2024-01-01T00:00:00Z", updated_at: "2024-01-01T00:00:00Z",
  settings: { theme: "system", language: "en-US" },
};

const ORG = {
  uuid: ORG_UUID, id: ORG_UUID, name: "Local CFC", role: "admin",
  organization_type: "personal", billing_type: "local",
  capabilities: ["chat","api","computer_use","claude_for_chrome"],
  rate_limit_tier: "local", settings: {},
  created_at: "2024-01-01T00:00:00Z",
};

const PROFILE = {
  ...ACCOUNT, account: ACCOUNT, organization: ORG,
  organizations: [ORG],
  memberships: [{organization: ORG, role: "admin", joined_at: "2024-01-01T00:00:00Z"}],
  active_organization_uuid: ORG_UUID,
};

const BOOTSTRAP = {
  ...PROFILE, account_uuid: USER_UUID,
  statsig: {
    user: {userID: USER_UUID, custom: {organization_uuid: ORG_UUID}},
    values: {feature_gates: {}, dynamic_configs: {}, layer_configs: {}},
  },
  flags: {}, features: [], active_flags: {},
  active_subscription: {
    plan: "local_cfc", status: "active", type: "local_cfc",
    billing_period: "none",
    current_period_start: "2024-01-01T00:00:00Z",
    current_period_end: "2099-12-31T23:59:59Z",
  },
  chat_enabled: true,
  capabilities: ["chat","api","computer_use","claude_for_chrome"],
  rate_limit_tier: "local",
  settings: {theme: "system", language: "en-US"},
};

// ── helpers ──────────────────────────────────────────────────────────────────

function b64url(obj) {
  const s = btoa(JSON.stringify(obj));
  return s.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function tokenResponse() {
  const tok = b64url({alg:"none", typ:"JWT"}) + "." +
              b64url({iss:"cfc", sub:USER_UUID,
                      exp: Math.floor(Date.now()/1000) + 315360000,
                      iat: 1700000000}) + ".local";
  return {
    access_token: tok, token_type: "bearer",
    expires_in: 315360000, refresh_token: "local-refresh",
    scope: "user:profile user:inference user:chat",
  };
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type,Authorization,Accept,x-api-key,anthropic-version,anthropic-beta,anthropic-client-platform,anthropic-client-version",
    },
  });
}

function html(body) {
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

function escAttr(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// ── /api/options payload (uiNodes:[], ui:{} contract) ────────────────────────

function optionsPayload(cfcBase) {
  return {
    mode: "",
    cfcBase: cfcBase,
    anthropicBaseUrl: "",
    apiBaseUrl: LOCAL_BACKEND,
    apiKey: "",
    authToken: "",
    apiBaseIncludes: ["https://api.anthropic.com/v1/"],
    proxyIncludes: [
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
      "cdn.segment.com","api.segment.io","events.statsigapi.net",
      "api.honeycomb.io","prodregistryv2.org","*ingest.us.sentry.io",
      "browser-intake-us5-datadoghq.com","fpjs.dev","openfpcdn.io",
      "api.fpjs.io","googletagmanager.com",
    ],
    backends: [{name:"Default", url:LOCAL_BACKEND, key:"", models:[], modelAlias:{}, enabled:true}],
    modelAlias: {},
    ui: {},
    uiNodes: [],
    blockAnalytics: true,
  };
}

// ── auth route handler (matches full URL string for cfcBase-rewritten paths) ─

function routeAuth(raw) {
  if (raw.includes("oauth/token"))        return json(tokenResponse());
  if (raw.includes("oauth/profile"))      return json(PROFILE);
  if (raw.includes("oauth/account"))      return json(PROFILE);
  if (raw.includes("bootstrap"))          return json(BOOTSTRAP);
  if (raw.includes("organizations"))      return json([ORG]);
  if (raw.includes("chat_conversations")) return json({conversations:[],limit:0,has_more:false,cursor:null});
  if (raw.includes("licenses/verify"))    return json({valid:true, license:"local", tier:"local", expires:"2099-12-31"});
  if (raw.includes("domain_info"))        return json({domain:"local", allowed:true});
  if (raw.includes("url_hash_check"))     return json({allowed:true});
  return null;
}

// ── pages ────────────────────────────────────────────────────────────────────

function statusPage(origin) {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>test2 CFCBASE</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f9f8f3;color:#1d1b16;margin:0;padding:48px 24px}
.box{max-width:720px;margin:0 auto;background:white;border:1px solid #e5e2d9;border-radius:18px;padding:28px}
h1{font-family:Georgia,serif;font-weight:400;margin:0 0 12px}
code{background:#f4f1ea;padding:2px 6px;border-radius:5px;font-size:13px}
ul{line-height:1.9}
.ok{color:#2d6a4f;font-weight:700}
</style></head>
<body><div class="box">
  <h1>test2 CFCBASE Worker</h1>
  <p class="ok">Online · ${new Date().toISOString()}</p>
  <p>Origin: <code>${escAttr(origin)}</code></p>
  <ul>
    <li><code>/oauth/authorize</code> — auth gate (Continue → redirect)</li>
    <li><code>/oauth/redirect</code> — writes tokens to extension storage</li>
    <li><code>/api/options</code> — uiNodes:[], ui:{}</li>
    <li>auth routes answered locally via <code>routeAuth(raw)</code></li>
    <li>everything else → 307 → <code>${LOCAL_CFC}</code></li>
  </ul>
</div></body></html>`;
}

// auth gate — Continue links DIRECTLY to the local proxy's /oauth/redirect.
//
// Why localhost (not the Worker)?
//   1. chrome.runtime.sendMessage() needs the page origin in the extension's
//      externally_connectable manifest list. mnmf restricts that to localhost.
//      The Worker origin (test2.mahnikka.workers.dev) is NOT allowed → message
//      fails → tokens never get written → sidepanel stays blank.
//   2. Chrome blocks navigation to chrome-extension:// URLs from a remote page
//      unless web_accessible_resources matches that origin. localhost is the
//      only origin guaranteed to be in WAR matches (and we add it in mnmf).
//
// So: Worker hosts the auth gate. Local proxy hosts the redirect handler.
function authGate(url) {
  const params = url.searchParams;
  const redirectUri = params.get("redirect_uri") || "";
  const state       = params.get("state") || "";

  const next = new URL(LOCAL_CFC + "/oauth/redirect");
  if (redirectUri) next.searchParams.set("redirect_uri", redirectUri);
  if (state)       next.searchParams.set("state", state);
  const nextHref = next.toString();

  return html(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Claude in Chrome</title>
<style>
*{box-sizing:border-box}
body{background:#f9f8f3;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;color:#1d1b16}
.box{background:white;border:1px solid #e5e2d9;border-radius:32px;padding:40px;max-width:420px;width:100%;text-align:center;box-shadow:0 12px 40px rgba(0,0,0,.04)}
.logo{width:72px;height:72px;border-radius:20px;border:1px solid #e5e2d9;margin:0 auto 20px;display:flex;align-items:center;justify-content:center;color:#d97757;font-size:38px}
h1{font-family:"Iowan Old Style",Georgia,serif;font-weight:400;margin:0 0 10px;font-size:28px}
p{color:#6b6651;font-size:14px;line-height:1.5;margin:0 0 24px}
a.btn{display:inline-flex;align-items:center;justify-content:center;height:48px;padding:0 32px;background:#c45f3d;color:white;text-decoration:none;border-radius:12px;font-size:16px;font-weight:800;cursor:pointer;border:0}
a.btn:hover{background:#b15535}
a.btn:active{background:#9c4a2e}
</style></head>
<body><div class="box">
  <div class="logo">&#10038;</div>
  <h1>Claude in Chrome</h1>
  <p>Local CFC. No Anthropic credentials required.</p>
  <a class="btn" id="continue" href="${escAttr(nextHref)}">Continue</a>
</div></body></html>`);
}

// redirect page — writes tokens via _set_storage_local, then navigates
function redirectPage(url) {
  const params       = url.searchParams;
  const redirectUri  = params.get("redirect_uri") || "";
  const state        = params.get("state") || "";
  const code         = params.get("code") || `cfc-local-${Date.now()}`;
  const tok          = tokenResponse();

  let finalUri = redirectUri;
  if (finalUri) {
    const sep = finalUri.includes("?") ? "&" : "?";
    finalUri += sep + "code=" + encodeURIComponent(code) +
                "&state=" + encodeURIComponent(state);
  }

  const storage = {
    accessToken: tok.access_token,
    refreshToken: tok.refresh_token,
    tokenExpiry: Date.now() + 31536000000,
    accountUuid: USER_UUID,
    sidepanelToken: code,
    sidepanelTokenExpiry: Date.now() + 31536000000,
    ANTHROPIC_BASE_URL: LOCAL_BACKEND,
    ANTHROPIC_API_KEY: "",
    ANTHROPIC_AUTH_TOKEN: "",
    email: "user@local",
    username: "local-user",
    licenseKey: "",
    hijackSettings: {
      backendUrl: LOCAL_BACKEND,
      modelAliases: {},
      blockAnalytics: true,
    },
  };

  // Inline JSON-stringified values for the inline script.
  const storageJson  = JSON.stringify(storage);
  const finalUriJson = JSON.stringify(finalUri);
  const extIdJson    = JSON.stringify(EXTENSION_ID);

  return html(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Signed In</title>
<style>
body{background:#f9f8f3;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;color:#1d1b16}
.box{background:white;border:1px solid #e5e2d9;border-radius:32px;padding:40px;max-width:520px;width:100%;text-align:center}
h1{font-family:Georgia,serif;font-weight:400;margin:0 0 10px;font-size:28px}
#msg{color:#6b6651;font-size:14px;line-height:1.5;margin:0 0 12px}
a.fallback{display:inline-block;margin-top:16px;color:#c45f3d;font-weight:700}
</style></head>
<body><div class="box">
  <h1>Signed in</h1>
  <p id="msg">Writing local state to extension...</p>
  <a class="fallback" id="fallback" href="${escAttr(finalUri)}" style="display:none">Continue manually</a>
</div>
<script>
(function(){
  var eid = ${extIdJson};
  var storage = ${storageJson};
  var finalUri = ${finalUriJson};
  var msg = document.getElementById("msg");
  var fb  = document.getElementById("fallback");
  function done(text, ok){
    msg.textContent = text;
    msg.style.color = ok ? "#2d6a4f" : "#b04a3d";
    if (ok && finalUri) {
      setTimeout(function(){ location.href = finalUri; }, 350);
    } else if (!ok && finalUri) {
      fb.style.display = "inline-block";
    }
  }
  try {
    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage(eid, {type: "_set_storage_local", data: storage}, function(resp){
        if (chrome.runtime.lastError) {
          done("Storage write failed: " + chrome.runtime.lastError.message, false);
          return;
        }
        done("Done — loading sidepanel...", true);
      });
    } else {
      done("Chrome extension messaging unavailable.", false);
    }
  } catch (e) {
    done("Error: " + e.message, false);
  }
})();
<\/script></body></html>`);
}

// ── main fetch handler ───────────────────────────────────────────────────────

export default {
  async fetch(request) {
    const url  = new URL(request.url);
    const path = url.pathname;
    const raw  = request.url.toLowerCase();

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 200,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type,Authorization,Accept,x-api-key,anthropic-version,anthropic-beta,anthropic-client-platform,anthropic-client-version",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    // Status page so the preview pane is not blank
    if (path === "/" || path === "/backend_settings") {
      return html(statusPage(url.origin));
    }

    // OAuth flow.
    // /oauth/authorize → Worker hosts the gate (Continue → localhost redirect).
    // /oauth/redirect  → 307 to localhost so the local proxy handles it
    //                    (where chrome.runtime.sendMessage actually works).
    if (path === "/oauth/authorize" || path.endsWith("/oauth/authorize")) {
      return authGate(url);
    }
    if (path === "/oauth/redirect" || path.endsWith("/oauth/redirect")) {
      return Response.redirect(LOCAL_CFC + path + url.search, 307);
    }

    // /api/options — uiNodes:[], ui:{}
    if (path === "/api/options") {
      return json(optionsPayload(url.origin + "/"));
    }
    if (path === "/api/identity") {
      return json({
        apiBaseUrl: LOCAL_BACKEND, apiKey: "", authToken: "",
        email: "user@local", username: "local-user", licenseKey: "",
        blockAnalytics: true, modelAliases: {}, mode: "",
      });
    }
    if (path === "/api/backends") {
      return json({backends: [{name:"Default", url:LOCAL_BACKEND, key:"", models:[], modelAlias:{}, enabled:true}]});
    }

    // cfcBase-rewritten paths land as /https://api.anthropic.com/...
    // routeAuth uses the full URL string, so it matches regardless of prefix
    const auth = routeAuth(raw);
    if (auth) return auth;

    // Catch-all → local proxy on 8520
    return Response.redirect(LOCAL_CFC + path + url.search, 307);
  },
};
