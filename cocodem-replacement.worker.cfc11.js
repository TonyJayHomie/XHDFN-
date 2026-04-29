// cocodem-replacement.worker.js -- CFC11
// Drop-in Cloudflare Worker that emulates cocodem's openclaude.111724.xyz
// + cfc.aroic.workers.dev contract. Returns the EXACT Statsig feature-gates
// shape the extension expects, plus profile / account-settings / token /
// license / bootstrap / org / domain_info endpoints. Zero phone-home.
//
// CFC11 changes vs the previous combo:
//   * Toggleable debug logging (`DEBUG = true`) -- visible in `wrangler tail`
//     or the Workers dashboard "Live Logs" tab. Logs incoming method/path,
//     auth header presence (REDACTED), branch matched, and response status.
//   * `/cfc-debug-ping` endpoint -- returns a small JSON envelope echoing the
//     request so you can curl-test from anywhere on the public internet.
//   * `cfcVersion: "CFC11"` and `severed: true` sentinel fields on /api/options
//     so the extension and your eyeball have an easy way to confirm the new
//     contract is live.
//   * proxyIncludes / discardIncludes match the CFC11 Python contract verbatim
//     (this is the part the m21-revert dropped).
//
// Deploy: paste into a new Cloudflare Worker, save & deploy. Take the
// resulting *.workers.dev URL and put it as REMOTE_BASE in CFC11.py.

const EXTENSION_ID = "fcoeoabgfenejglbffodgkkbkcdhcgfn";

// Static identity. Stable across requests so chrome.storage.onChanged never
// fires from a value flip (this is the React #185 trap CFC8 already solved
// locally -- the worker MUST also stay stable for the same reason).
const ACCOUNT_UUID  = "ac507011-00b5-56c4-b3ec-ad820dbafbc1";
const ORG_UUID      = "1b61ee4a-d0ce-50b5-8b67-7eec034d3d08";
const ANON_ID       = "anon-cfc-local-permanent";
const EMAIL         = "free@local";
const TOKEN_STATIC  = "cfc-local-permanent.cfc-local-permanent.cfc-local-permanent";
const TOKEN_EXPIRES = 9999999999;

// =========================== debug logging =================================
// Toggle DEBUG to false to silence. Logs land in `wrangler tail` and the
// Cloudflare Dashboard -> Workers -> <worker> -> Logs (Live).
const DEBUG = true;
function redact(v, keep = 8) {
  if (!v) return "<empty>";
  const s = String(v);
  return s.length > keep
    ? `<len=${s.length} tail=...${s.slice(-keep)}>`
    : `<len=${s.length} value=${s}>`;
}
function dbg(tag, ...args) {
  if (!DEBUG) return;
  try { console.log(`[CFC11/${tag}]`, ...args); } catch (e) {}
}

// =========================== CORS ===========================================
const CORS = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "GET,POST,PATCH,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers":
    "Authorization, Content-Type, anthropic-beta, anthropic-version, " +
    "anthropic-dangerous-direct-browser-access, x-app, x-service-name, " +
    "x-api-key, x-stainless-arch, x-stainless-lang, x-stainless-os, " +
    "x-stainless-package-version, x-stainless-runtime, " +
    "x-stainless-runtime-version, x-stainless-retry-count, " +
    "x-stainless-timeout, x-stainless-helper-method",
  "Access-Control-Max-Age": "86400",
};
const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...CORS, ...extra },
  });
const text = (s, status = 200, ct = "text/plain") =>
  new Response(s, { status, headers: { "Content-Type": ct, ...CORS } });
const noContent = () => new Response(null, { status: 204, headers: CORS });

// =========================== auth payloads ==================================
const ACCOUNT = {
  uuid:                    ACCOUNT_UUID,
  id:                      ACCOUNT_UUID,
  email_address:           EMAIL,
  email:                   EMAIL,
  full_name:               "Local User",
  name:                    "Local User",
  display_name:            "Local User",
  has_password:            true,
  has_completed_onboarding:true,
  preferred_language:      "en-US",
  has_claude_pro:          true,
  has_claude_max:          true,
  created_at:              "2024-01-01T00:00:00Z",
  updated_at:              "2024-01-01T00:00:00Z",
  settings: { theme: "system", language: "en-US" },
};

const ORGANIZATION = {
  uuid:               ORG_UUID,
  id:                 ORG_UUID,
  name:               "Local",
  role:               "admin",
  organization_type:  "personal",
  billing_type:       "self_serve",
  capabilities: [
    "chat", "claude_pro_plan", "claude_max_plan", "api",
    "computer_use", "claude_for_chrome", "raven", "mcp",
    "browser_extension", "tier_max_5x",
  ],
  rate_limit_tier:    "default_claude_max",
  settings:           {},
  created_at:         "2024-01-01T00:00:00Z",
  active_subscription: {
    plan:                  "claude_max",
    status:                "active",
    type:                  "claude_max",
    billing_period:        "monthly",
    current_period_start:  "2024-01-01T00:00:00Z",
    current_period_end:    "2099-12-31T23:59:59Z",
  },
};

const PROFILE = {
  ...ACCOUNT,
  account:                  ACCOUNT,
  organization:             ORGANIZATION,
  organizations:            [ORGANIZATION],
  memberships: [{
    organization: ORGANIZATION,
    role:         "admin",
    joined_at:    "2024-01-01T00:00:00Z",
  }],
  active_organization_uuid: ORG_UUID,
};

const ACCOUNT_SETTINGS = {
  uuid:                       ACCOUNT_UUID,
  enabled_mcp_tools:          {},
  preferred_model:            "claude-haiku-4-5-20251001",
  preferred_model_quick_mode: "claude-haiku-4-5-20251001",
  system_prompt:              "",
  selected_models: [
    "claude-opus-4-6",
    "claude-sonnet-4-5-20250929",
    "claude-haiku-4-5-20251001",
  ],
  settings: { theme: "system", language: "en-US" },
};

const TOKEN_PAYLOAD = {
  access_token:  TOKEN_STATIC,
  refresh_token: TOKEN_STATIC,
  token_type:    "bearer",
  expires_in:    315360000,
  expires_at:    TOKEN_EXPIRES * 1000,
  scope:         "user:profile user:inference user:chat",
  account:       { uuid: ACCOUNT_UUID },
};

// =========================== Statsig features ===============================
function buildFeatures() {
  const f = {};
  const set = (gate, value, idType = "userID", ruleId = "default") => {
    f[gate] = {
      name:    gate,
      value:   value,
      on:      typeof value === "boolean" ? value : true,
      rule_id: ruleId,
      group:   ruleId,
      id_type: idType,
      passed:  true,
      is_device_based: false,
    };
  };

  set("chrome_ext_eligibility",                true);
  set("chrome_ext_allow_api_key",              true);
  set("chrome_ext_edit_system_prompt",         true);
  set("chrome_ext_planning_mode_enabled",      true);
  set("chrome_ext_domain_transition_prompts",  true);
  set("chrome_ext_trace_headers",              true);
  set("chrome_ext_mcp_integration",            true);
  set("chrome_ext_show_model_selector",        true, "organizationUUID");
  set("chrome_ext_record_workflow",            true);
  set("chrome_ext_sessions_planning_mode",     true, "organizationUUID");
  set("chrome_ext_default_sessions",           true, "organizationUUID");
  set("chrome_ext_downloads",                  true);
  set("chrome_scheduled_tasks",                true, "anonymousID");
  set("crochet_browse_shortcuts",              true, "anonymousID");
  set("crochet_can_skip_permissions",          true, "anonymousID");
  set("crochet_default_debug_mode",            true, "anonymousID");
  set("cic_ext_silent_reauth",                 false);

  set("cascade_nebula",                        false, "organizationUUID");
  set("chrome_extension_show_user_email",      false);
  set("crochet_can_see_browser_indicator",     false, "anonymousID");
  set("crochet_can_submit_feedback",           false, "anonymousID");
  set("crochet_upsell_ant_build",              false, "anonymousID");

  set("chrome_ext_models", {
    default:                    "claude-haiku-4-5-20251001",
    default_model_override_id:  "launch-2025-11-24-1",
    small_fast_model:           "claude-haiku-4-5-20251001",
    options: [
      { model: "claude-opus-4-6",          name: "Opus 4.6",   description: "Most capable for complex work" },
      { model: "claude-sonnet-4-5-20250929", name: "Sonnet 4.5", description: "Smartest for everyday tasks" },
      { model: "claude-haiku-4-5-20251001",  name: "Haiku 4.5",  description: "Fastest for quick answers" },
    ],
    modelFallbacks: {
      "claude-opus-4-6":           { currentModelName: "Opus 4.6",   fallbackModelName: "claude-sonnet-4-20250514", fallbackDisplayName: "Sonnet 4", learnMoreUrl: "" },
      "claude-sonnet-4-5-20250929":{ currentModelName: "Sonnet 4.5", fallbackModelName: "claude-sonnet-4-20250514", fallbackDisplayName: "Sonnet 4", learnMoreUrl: "" },
      "claude-haiku-4-5-20251001": { currentModelName: "Haiku 4.5",  fallbackModelName: "claude-sonnet-4-20250514", fallbackDisplayName: "Sonnet 4", learnMoreUrl: "" },
    },
  });
  set("chrome_ext_version_info",        { latest_version: "1.0.66", min_supported_version: "1.0.11" });
  set("chrome_ext_announcement",        { id: "local-cfc", enabled: false, text: "" });
  set("chrome_ext_permission_modes",    { default: "ask", options: ["ask", "auto", "manual"] });
  set("extension_landing_page_url",     { relative_url: "/chrome/installed" });
  set("chrome_ext_system_prompt",       { systemPrompt: "You are Claude, an AI assistant created by Anthropic, operating as a browser automation assistant." });
  set("chrome_ext_skip_perms_system_prompt", { skipPermissionsSystemPrompt: "You are Claude, an AI assistant created by Anthropic, operating as a browser automation assistant." });
  set("chrome_ext_multiple_tabs_system_prompt", { multipleTabsSystemPrompt: "<browser_tabs_usage>You can work with multiple browser tabs simultaneously.</browser_tabs_usage>" });
  set("chrome_ext_explicit_permissions_prompt", { prompt: "<explicit-permission>Claude requires explicit user permission for irreversible actions.</explicit-permission>" }, "organizationUUID");
  set("chrome_ext_tool_usage_prompt",   { prompt: "<tool_usage>Maintain a todo list for multi-step tasks.</tool_usage>" }, "organizationUUID");
  set("chrome_ext_planning_mode_prompt",{ prompt: "Work with the user to create a plan, then execute it." });
  set("chrome_ext_custom_tool_prompts", { update_plan: { toolDescription: "Update the plan for user approval." }, TodoWrite: { toolDescription: "Create a structured task list." } }, "organizationUUID");
  set("crochet_chips",          {}, "anonymousID");
  set("crochet_domain_skills",  {}, "anonymousID");
  set("crochet_github",         { skill: "" }, "anonymousID");
  set("crochet_gmail",          { skill: "" }, "anonymousID");
  set("crochet_google_calendar",{ skill: "" }, "anonymousID");
  set("crochet_google_docs",    { skill: "" }, "anonymousID");
  set("crochet_linkedin",       { skill: "" }, "anonymousID");
  set("crochet_slack",          { skill: "" }, "anonymousID");
  set("crochet_bad_hostnames",  { hostnames: [] }, "organizationUUID");
  set("cic_ext_timeouts",       { oauthRefreshMs: 10000, debuggerAttachMs: 8000, cdpSendCommandMs: 30000 });
  set("cic_screencast_warmup",  false);

  return { features: f };
}
const FEATURES = buildFeatures();

// =========================== free-trial / status page ======================
const FREE_TRIAL_HTML = `<!doctype html><html><head>
<meta charset="utf-8"><title>Open Claude -- CFC11 Worker</title>
<style>body{font:16px system-ui;background:#0a0a0a;color:#eee;margin:0;padding:40px;text-align:center}
.card{max-width:560px;margin:60px auto;background:#1a1a1a;padding:32px;border-radius:14px;border:1px solid #333}
h1{margin:0 0 12px}p{color:#aaa}code{background:#000;padding:2px 6px;border-radius:4px;color:#7af}
.tag{display:inline-block;background:#2d6a4f;color:#fff;padding:4px 10px;border-radius:10px;font-size:12px;font-weight:700;margin-bottom:8px}
button{background:#d97757;color:#fff;border:0;padding:12px 24px;border-radius:8px;font-size:16px;cursor:pointer;margin-top:16px}
</style></head><body>
<div class="card">
<span class="tag">CFC11 -- SEVERED</span>
<h1>Open Claude</h1>
<p>Local CFC worker active. No remote phone-home.</p>
<p>Pin the extension and click its icon (or press <code>Ctrl+E</code> / <code>&#8984;+E</code>) to open the side panel.</p>
<p style="font-size:13px;margin-top:24px;color:#666">Worker URL: <code id="u"></code></p>
<script>document.getElementById('u').textContent=location.origin</script>
</div></body></html>`;

// =========================== route ==========================================
async function handle(request) {
  const url    = new URL(request.url);
  const path   = url.pathname;
  const method = request.method;

  // --- CFC11 debug envelope ---
  const inAuth = request.headers.get("Authorization") || "";
  const inXkey = request.headers.get("x-api-key")    || "";
  dbg("in", method, path, "auth=" + redact(inAuth), "xkey=" + redact(inXkey),
      "ua=" + (request.headers.get("User-Agent") || "").slice(0, 60));

  if (method === "OPTIONS") {
    dbg("preflight", path);
    return noContent();
  }

  // --- 1. cocodem's request.js proxy wrapping: when CFC proxies a URL it
  //        prepends cfcBase to the full target URL, so we receive paths like
  //        /https://api.anthropic.com/api/oauth/profile -- strip the prefix.
  let p = path;
  if (p.startsWith("/https://") || p.startsWith("/http://")) {
    try {
      const inner = new URL(p.slice(1) + url.search);
      p = inner.pathname + inner.search;
      dbg("unwrap", "->", p);
    } catch (_) {}
  }
  const bare = p.split("?")[0];

  // --- 2. CFC11 debug ping (curl-friendly) ---
  if (bare === "/cfc-debug-ping") {
    const echo = {
      cfcVersion: "CFC11",
      now:        new Date().toISOString(),
      method,
      path,
      bare,
      origin:     url.origin,
      headers: {
        Authorization: redact(inAuth),
        "x-api-key":   redact(inXkey),
        "user-agent":  (request.headers.get("User-Agent") || "").slice(0, 80),
      },
    };
    dbg("ping", JSON.stringify(echo));
    return json(echo);
  }

  // --- 3. Telemetry sinks -- always 204, before anything else ---
  const TELEMETRY = [
    "/cdn.segment.com", "/api.segment.io", "/events.statsigapi.net",
    "/api.honeycomb.io", "/prodregistryv2.org", "ingest.us.sentry.io",
    "browser-intake-us5-datadoghq.com", "fpjs.dev", "openfpcdn.io",
    "api.fpjs.io", "googletagmanager.com", "/featureassets.org",
    "/assetsconfigcdn.org", "/featuregates.org", "/api.statsigcdn.com",
    "/v1/log_event", "/event_logging",
  ];
  if (TELEMETRY.some(t => p.includes(t))) {
    dbg("tel.sink", p.slice(0, 120));
    return noContent();
  }

  // --- 4. Bootstrap features (THE blank-sidepanel fixer) ---
  if (bare === "/api/bootstrap/features/claude_in_chrome" ||
      bare.endsWith("/api/bootstrap/features/claude_in_chrome")) {
    dbg("bootstrap.features", "200 features=" + Object.keys(FEATURES.features).length);
    return json(FEATURES);
  }
  if (bare.startsWith("/api/bootstrap")) {
    dbg("bootstrap.full", bare);
    return json({ ...PROFILE, ...FEATURES, statsig: {
      user:   { userID: ACCOUNT_UUID, custom: { organization_uuid: ORG_UUID } },
      values: FEATURES,
    }});
  }

  // --- 5. OAuth: profile / account / settings / orgs / token / authorize ---
  if (bare.endsWith("/api/oauth/profile"))             { dbg("oauth.profile"); return json(PROFILE); }
  if (bare.endsWith("/api/oauth/account"))             { dbg("oauth.account"); return json(ACCOUNT); }
  if (bare.endsWith("/api/oauth/account/settings"))    { dbg("oauth.account.settings"); return json(ACCOUNT_SETTINGS); }
  if (bare.endsWith("/api/oauth/organizations"))       { dbg("oauth.orgs.list"); return json([ORGANIZATION]); }
  if (bare.match(/\/api\/oauth\/organizations\/[^/]+$/))                 { dbg("oauth.org.one"); return json(ORGANIZATION); }
  if (bare.match(/\/api\/oauth\/organizations\/[^/]+\/spotlight$/))      { dbg("oauth.spotlight"); return json({ items: [], total: 0 }); }
  if (bare.match(/\/api\/oauth\/organizations\/[^/]+\/mcp\/v2\/bootstrap$/)) {
    dbg("oauth.mcp.sse");
    const stream = new ReadableStream({
      start(controller) {
        const enc = new TextEncoder();
        controller.enqueue(enc.encode(`event: server_list\ndata: ${JSON.stringify({servers:[]})}\n\n`));
      },
    });
    return new Response(stream, { headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      ...CORS,
    }});
  }
  if (bare.endsWith("/api/oauth/chat_conversations")) {
    dbg("oauth.chat_conversations");
    return json({ conversations: [], limit: 0, has_more: false, cursor: null });
  }

  if (bare.endsWith("/v1/oauth/token") || bare.endsWith("/oauth/token")) {
    dbg("oauth.token", "-> static");
    return json(TOKEN_PAYLOAD);
  }

  if (bare.endsWith("/oauth/authorize")) {
    const sp = url.searchParams;
    const redir = sp.get("redirect_uri") || `chrome-extension://${EXTENSION_ID}/sidepanel.html`;
    const state = sp.get("state") || "cfc-local";
    const dest  = new URL(redir);
    dest.searchParams.set("code",  "cfc-local-permanent");
    dest.searchParams.set("state", state);
    dbg("oauth.authorize", "redirect ->", dest.toString());
    return Response.redirect(dest.toString(), 302);
  }
  if (bare.endsWith("/oauth/redirect")) {
    dbg("oauth.redirect.html");
    return text(`<script>
      try { window.opener?.postMessage({type:"oauth_redirect",redirect_uri:location.href},"*") } catch(e){}
      try { chrome.runtime.sendMessage("${EXTENSION_ID}",{type:"oauth_redirect",redirect_uri:location.href},()=>window.close()) } catch(e){}
      setTimeout(()=>window.close(), 500);
    </script>OK`, 200, "text/html");
  }

  // --- 6. License + domain checks ---
  if (bare.includes("/licenses/verify")) {
    dbg("license.verify");
    return json({ valid: true, license: "local", tier: "max",
                  expires_at: "2099-12-31T00:00:00Z" });
  }
  if (bare.endsWith("/api/web/domain_info/browser_extension")) {
    dbg("domain_info");
    return json({ domain: url.searchParams.get("domain") || "",
                  is_known: true, category: "general",
                  trust_score: 100, warnings: [], allowed: true });
  }
  if (bare.endsWith("/api/web/url_hash_check/browser_extension")) {
    dbg("url_hash_check");
    return json({ allowed: true });
  }

  // --- 7. /api/options + /api/identity (CFC11 contract) ---
  if (bare === "/api/options") {
    dbg("api.options");
    return json({
      cfcVersion: "CFC11",
      severed:    true,
      mode: "",
      cfcBase: url.origin + "/",
      anthropicBaseUrl: "",
      apiBaseUrl: "",
      apiBaseIncludes: [],
      proxyIncludes: [
        "https://api.anthropic.com/api/oauth/profile",
        "https://api.anthropic.com/api/oauth/account",
        "https://api.anthropic.com/api/oauth/organizations",
        "https://api.anthropic.com/api/oauth/chat_conversations",
        "https://api.anthropic.com/api/bootstrap",
        "https://api.anthropic.com/api/web/domain_info/browser_extension",
        "https://api.anthropic.com/api/web/url_hash_check/browser_extension",
        "https://console.anthropic.com/v1/oauth/token",
        "https://platform.claude.com/v1/oauth/token",
        "/api/web/domain_info/browser_extension",
        "/api/web/url_hash_check/browser_extension",
        "cfc.aroic.workers.dev",
      ],
      discardIncludes: [
        "cdn.segment.com","api.segment.io","events.statsigapi.net",
        "api.honeycomb.io","prodregistryv2.org","*ingest.us.sentry.io",
        "browser-intake-us5-datadoghq.com","fpjs.dev","openfpcdn.io",
        "api.fpjs.io","googletagmanager.com","featureassets.org",
        "assetsconfigcdn.org","featuregates.org","api.statsigcdn.com",
      ],
      modelAlias: {},
      ui: {},
      uiNodes: [],
      identity: { email: EMAIL, username: "Local User", licenseKey: "FREE-TRIAL-LOCAL" },
      apiKey: "", authToken: TOKEN_STATIC,
      blockAnalytics: true,
    });
  }
  if (bare === "/api/identity") {
    dbg("api.identity");
    return json({
      apiBaseUrl: "", apiKey: "", authToken: TOKEN_STATIC,
      email: EMAIL, username: "Local User",
      licenseKey: "FREE-TRIAL-LOCAL",
      blockAnalytics: true, modelAliases: {}, mode: "",
      cfcVersion: "CFC11", severed: true,
    });
  }

  // --- 8. Free Trial / root pages ---
  if (bare === "/" || bare === "/free-trial" || bare === "/chrome/installed") {
    dbg("page.free_trial", bare);
    return text(FREE_TRIAL_HTML, 200, "text/html");
  }

  // --- 9. Discard sink ---
  if (bare === "/discard") { dbg("discard"); return noContent(); }

  // --- 10. Catch-all: ANYTHING else returns {} 200 so no fetch throws.
  dbg("catchall.empty200", bare);
  return json({});
}

export default {
  fetch(request) {
    return handle(request).catch(e => {
      dbg("FATAL", String(e && e.stack || e));
      return json({ error: String(e && e.message || e) }, 500);
    });
  },
};
