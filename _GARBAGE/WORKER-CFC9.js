// cocodem-replacement.worker.js — CFC9 auto-generated. Zero phone-home.
// Deploy: paste into Cloudflare Workers dashboard → Save & Deploy.
// Take the *.workers.dev URL, set it as REMOTE_BASE in CFC9.py.

const EXTENSION_ID = "fcoeoabgfenejglbffodgkkbkcdhcgfn";
const LOCAL_CFC     = "http://localhost:8520"; // local Python proxy


const ACCOUNT_UUID  = "ac507011-00b5-56c4-b3ec-ad820dbafbc1";
const ORG_UUID      = "1b61ee4a-d0ce-50b5-8b67-7eec034d3d08";
const ANON_ID       = "anon-cfc-local-permanent";
const EMAIL         = "free@local";
const TOKEN_STATIC  = "cfc-local-permanent.cfc-local-permanent.cfc-local-permanent";
const TOKEN_EXPIRES = 9999999999;

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
// Both .value AND .on required: getFeatureValue() uses .value, isFeatureEnabled() uses .on
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
  // boolean gates that must be true for full UI
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
  // KEEP false: prevents launchWebAuthFlow infinite loop
  set("cic_ext_silent_reauth",                 false);
  // false gates (telemetry/fingerprint surfaces)
  set("cascade_nebula",                        false, "organizationUUID");
  set("chrome_extension_show_user_email",      false);
  set("crochet_can_see_browser_indicator",     false, "anonymousID");
  set("crochet_can_submit_feedback",           false, "anonymousID");
  set("crochet_upsell_ant_build",              false, "anonymousID");
  // object-valued gates
  set("chrome_ext_models", {
    default:                    "claude-haiku-4-5-20251001",
    default_model_override_id:  "launch-2025-11-24-1",
    small_fast_model:           "claude-haiku-4-5-20251001",
    options: [
      { model: "claude-opus-4-6",          name: "Opus 4.6",   description: "Most capable" },
      { model: "claude-sonnet-4-5-20250929", name: "Sonnet 4.5", description: "Smartest for everyday" },
      { model: "claude-haiku-4-5-20251001",  name: "Haiku 4.5",  description: "Fastest" },
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

// =========================== local settings page ============================
function settingsPage(workerOrigin) {
  return `<!doctype html><html><head>
<meta charset="utf-8"><title>CFC9 Worker</title>
<style>body{font:16px system-ui;background:#0a0a0a;color:#eee;margin:0;padding:40px;text-align:center}
.card{max-width:560px;margin:60px auto;background:#1a1a1a;padding:32px;border-radius:14px;border:1px solid #333}
h1{margin:0 0 12px}p{color:#aaa}code{background:#000;padding:2px 6px;border-radius:4px;color:#7af}
a.btn{display:inline-block;background:#d97757;color:#fff;border:0;padding:12px 24px;border-radius:8px;
  font-size:15px;font-weight:700;text-decoration:none;margin:16px 0 8px}
.ok{color:#4ade80;font-weight:700}.note{font-size:12px;color:#555;margin-top:18px}</style></head><body>
<div class="card">
<h1>Open Claude — CFC Worker</h1>
<p class="ok">Worker active. Zero phone-home to cocodem/Anthropic.</p>
<p>API calls route through local Python proxy at<br><code>${LOCAL_CFC}</code></p>
<a class="btn" href="${LOCAL_CFC}/backend_settings" target="_blank">Backend Settings</a>
<p class="note">Worker: <code>${workerOrigin}</code></p>
</div></body></html>`;
}

// =========================== route ==========================================
async function handle(request) {
  if (request.method === "OPTIONS") return noContent();

  const url  = new URL(request.url);
  const path = url.pathname;

  // Strip cfcBase proxy wrapping: /https://api.anthropic.com/... -> /api/...
  let p = path;
  if (p.startsWith("/https://") || p.startsWith("/http://")) {
    try {
      const inner = new URL(p.slice(1) + url.search);
      p = inner.pathname + inner.search;
    } catch {}
  }
  const bare = p.split("?")[0];

  // Telemetry sinks
  const TELEMETRY = [
    "/cdn.segment.com", "/api.segment.io", "/events.statsigapi.net",
    "/api.honeycomb.io", "/prodregistryv2.org", "ingest.us.sentry.io",
    "browser-intake-us5-datadoghq.com", "fpjs.dev", "openfpcdn.io",
    "api.fpjs.io", "googletagmanager.com", "/featureassets.org",
    "/assetsconfigcdn.org", "/featuregates.org", "/api.statsigcdn.com",
    "/v1/log_event", "/event_logging",
  ];
  if (TELEMETRY.some(t => p.includes(t))) return noContent();

  // Statsig bootstrap
  if (bare === "/api/bootstrap/features/claude_in_chrome" ||
      bare.endsWith("/api/bootstrap/features/claude_in_chrome"))
    return json(FEATURES);
  if (bare.startsWith("/api/bootstrap"))
    return json({ ...PROFILE, ...FEATURES, statsig: {
      user:   { userID: ACCOUNT_UUID, custom: { organization_uuid: ORG_UUID } },
      values: FEATURES,
    }});

  // OAuth
  if (bare.endsWith("/api/oauth/profile"))           return json(PROFILE);
  if (bare.endsWith("/api/oauth/account") &&
      !bare.endsWith("/api/oauth/account/settings")) return json(ACCOUNT);
  if (bare.endsWith("/api/oauth/account/settings"))  return json(ACCOUNT_SETTINGS);
  if (bare.endsWith("/api/oauth/organizations"))      return json([ORGANIZATION]);
  if (bare.match(/\/api\/oauth\/organizations\/[^/]+$/))                return json(ORGANIZATION);
  if (bare.match(/\/api\/oauth\/organizations\/[^/]+\/spotlight$/))    return json({ items: [], total: 0 });
  if (bare.match(/\/api\/oauth\/organizations\/[^/]+\/mcp\/v2\/bootstrap$/)) {
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(
          `event: server_list\ndata: ${JSON.stringify({servers:[]})}\n\n`));
      },
    });
    return new Response(stream, { headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive", ...CORS } });
  }
  if (bare.endsWith("/api/oauth/chat_conversations"))
    return json({ conversations: [], limit: 0, has_more: false, cursor: null });
  if (bare.endsWith("/v1/oauth/token") || bare.endsWith("/oauth/token"))
    return json(TOKEN_PAYLOAD);

  // OAuth authorize -> straight redirect to extension with permanent code
  if (bare.endsWith("/oauth/authorize")) {
    const sp    = url.searchParams;
    const redir = sp.get("redirect_uri") || `chrome-extension://${EXTENSION_ID}/sidepanel.html`;
    const state = sp.get("state") || "cfc-local";
    const dest  = new URL(redir);
    dest.searchParams.set("code",  "cfc-local-permanent");
    dest.searchParams.set("state", state);
    return Response.redirect(dest.toString(), 302);
  }
  if (bare.endsWith("/oauth/redirect")) {
    return text(`<script>
      try { window.opener?.postMessage({type:"oauth_redirect",redirect_uri:location.href},"*") } catch(e){}
      try { chrome.runtime.sendMessage("${EXTENSION_ID}",{type:"oauth_redirect",redirect_uri:location.href},()=>window.close()) } catch(e){}
      setTimeout(()=>window.close(), 500);
    </script>OK`, 200, "text/html");
  }

  // License + domain
  if (bare.includes("/licenses/verify"))
    return json({ valid: true, license: "local", tier: "max", expires_at: "2099-12-31T00:00:00Z" });
  if (bare.endsWith("/api/web/domain_info/browser_extension"))
    return json({ domain: url.searchParams.get("domain") || "", is_known: true,
                  category: "general", trust_score: 100, warnings: [], allowed: true });
  if (bare.endsWith("/api/web/url_hash_check/browser_extension"))
    return json({ allowed: true });

  // /api/options -- the critical config payload read.js reads at startup
  if (bare === "/api/options") {
    return json({
      mode: "",
      cfcBase:          url.origin + "/",         // Worker handles auth
      anthropicBaseUrl: LOCAL_CFC,                 // API calls -> local proxy -> LM Studio
      apiBaseUrl:       "",                        // user sets in backend settings (overrides above)
      apiBaseIncludes:  ["https://api.anthropic.com/v1/"], // intercept API calls
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
    return json({ apiBaseUrl: "", apiKey: "", authToken: TOKEN_STATIC,
                  email: EMAIL, username: "Local User",
                  licenseKey: "FREE-TRIAL-LOCAL", blockAnalytics: true,
                  modelAliases: {}, mode: "" });
  }

  // Backend settings -> redirect to local Python proxy
  if (bare === "/backend_settings" || bare.startsWith("/backend_settings/"))
    return Response.redirect(LOCAL_CFC + "/backend_settings", 302);

  // Root + landing pages
  if (bare === "/" || bare === "/free-trial" || bare === "/chrome/installed")
    return text(settingsPage(url.origin), 200, "text/html");

  // Discard
  if (bare === "/discard") return noContent();

  // Catch-all: {} so React Query never sees 4xx and infinite-loops
  return json({});
}

export default {
  fetch(request) {
    return handle(request).catch(e =>
      json({ error: String(e && e.message || e) }, 500));
  },
};

