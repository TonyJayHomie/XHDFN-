// CFC14 Cloudflare Worker (test2-derived, user-provided base)
// Deploy: paste into Cloudflare Workers -> Save & Deploy.
// Set BACKEND_URL env var (or use the configurable page at /#api).
// LOCAL_CFC fallback for /backend_settings: http://localhost:8520

// =============================================================================
// CONFIGURATION (set as Worker Variables in Cloudflare dashboard)
// =============================================================================
//   BACKEND_URL   - REQUIRED for /v1/* forwarding.
//   BACKEND_KEY   - Optional API key.
//   BACKEND_LABEL - Display name on the worker status page.
//   CONFIG_KV     - Optional KV namespace binding for persistent config.
//   CONFIG_TOKEN  - Optional shared secret for the config save form.
// =============================================================================

const EXTENSION_ID  = "fcoeoabgfenejglbffodgkkbkcdhcgfn";
const ACCOUNT_UUID  = "ac507011-00b5-56c4-b3ec-ad820dbafbc1";
const ORG_UUID      = "1b61ee4a-d0ce-50b5-8b67-7eec034d3d08";

// In-memory config fallback when no KV binding is present.
const _MEM_CONFIG = { BACKEND_URL: "", BACKEND_KEY: "", BACKEND_LABEL: "" };

// =============================================================================
// FAT profile (verbatim from live cocodem)
// =============================================================================
const PROFILE = {"account":{"uuid":ACCOUNT_UUID,"id":ACCOUNT_UUID,"email_address":"free@claudeagent.ai","email":"free@claudeagent.ai","full_name":"Local User","name":"Local User","display_name":"Local User","has_password":true,"has_completed_onboarding":true,"preferred_language":"en-US","has_claude_pro":true,"has_claude_max":true,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","settings":{"theme":"system","language":"en-US"}},"organization":{"uuid":ORG_UUID,"id":ORG_UUID,"name":"Local","role":"admin","organization_type":"personal","billing_type":"self_serve","capabilities":["chat","claude_pro_plan","claude_max_plan","api","computer_use","claude_for_chrome"],"rate_limit_tier":"default_claude_max","settings":{},"created_at":"2024-01-01T00:00:00Z"},"organizations":[{"uuid":ORG_UUID,"id":ORG_UUID,"name":"Local","role":"admin","organization_type":"personal","billing_type":"self_serve","capabilities":["chat","claude_pro_plan","api","computer_use","claude_for_chrome"],"rate_limit_tier":"default_claude_max","settings":{},"created_at":"2024-01-01T00:00:00Z"}],"memberships":[{"organization":{"uuid":ORG_UUID,"id":ORG_UUID,"name":"Local","role":"admin","organization_type":"personal","billing_type":"self_serve"},"role":"admin","joined_at":"2024-01-01T00:00:00Z"}],"active_organization_uuid":ORG_UUID};

// =============================================================================
// 42-feature Statsig payload
// =============================================================================
function buildFeatures() {
  const f = {};
  const set = (gate, value, idType, ruleId) => {
    if (!idType) idType = "userID";
    if (!ruleId) ruleId = "default";
    f[gate] = {
      name: gate, value: value, on: typeof value === "boolean" ? value : true,
      rule_id: ruleId, group: ruleId, id_type: idType,
      passed: true, is_device_based: false,
    };
  };
  set("chrome_ext_eligibility", true);
  set("chrome_ext_allow_api_key", true);
  set("chrome_ext_edit_system_prompt", true);
  set("chrome_ext_planning_mode_enabled", true);
  set("chrome_ext_domain_transition_prompts", true);
  set("chrome_ext_trace_headers", true);
  set("chrome_ext_mcp_integration", true);
  set("chrome_ext_show_model_selector", true, "organizationUUID");
  set("chrome_ext_record_workflow", true);
  set("chrome_ext_sessions_planning_mode", true, "organizationUUID");
  set("chrome_ext_default_sessions", true, "organizationUUID");
  set("chrome_ext_downloads", true);
  set("chrome_scheduled_tasks", true, "anonymousID");
  set("crochet_browse_shortcuts", true, "anonymousID");
  set("crochet_can_skip_permissions", true, "anonymousID");
  set("crochet_default_debug_mode", true, "anonymousID");
  set("cic_ext_silent_reauth", false);
  set("cascade_nebula", false, "organizationUUID");
  set("chrome_extension_show_user_email", false);
  set("crochet_can_see_browser_indicator", false, "anonymousID");
  set("crochet_can_submit_feedback", false, "anonymousID");
  set("crochet_upsell_ant_build", false, "anonymousID");
  set("chrome_ext_models", {
    default: "claude-haiku-4-5-20251001",
    default_model_override_id: "launch-2025-11-24-1",
    small_fast_model: "claude-haiku-4-5-20251001",
    options: [
      {model:"claude-opus-4-6", name:"Opus 4.6", description:"Most capable"},
      {model:"claude-sonnet-4-5-20250929", name:"Sonnet 4.5", description:"Smartest for everyday"},
      {model:"claude-haiku-4-5-20251001", name:"Haiku 4.5", description:"Fastest"},
    ],
    modelFallbacks: {
      "claude-opus-4-6":           {currentModelName:"Opus 4.6",   fallbackModelName:"claude-sonnet-4-20250514", fallbackDisplayName:"Sonnet 4", learnMoreUrl:""},
      "claude-sonnet-4-5-20250929":{currentModelName:"Sonnet 4.5", fallbackModelName:"claude-sonnet-4-20250514", fallbackDisplayName:"Sonnet 4", learnMoreUrl:""},
      "claude-haiku-4-5-20251001": {currentModelName:"Haiku 4.5",  fallbackModelName:"claude-sonnet-4-20250514", fallbackDisplayName:"Sonnet 4", learnMoreUrl:""},
    },
  });
  set("chrome_ext_version_info", {latest_version:"1.0.66", min_supported_version:"1.0.11"});
  set("chrome_ext_announcement", {id:"local-cfc", enabled:false, text:""});
  set("chrome_ext_permission_modes", {default:"ask", options:["ask","auto","manual"]});
  set("extension_landing_page_url", {relative_url:"/chrome/installed"});
  set("chrome_ext_system_prompt", {systemPrompt:"You are Claude, an AI assistant created by Anthropic, operating as a browser automation assistant."});
  set("chrome_ext_skip_perms_system_prompt", {skipPermissionsSystemPrompt:"You are Claude, an AI assistant created by Anthropic, operating as a browser automation assistant."});
  set("chrome_ext_multiple_tabs_system_prompt", {multipleTabsSystemPrompt:"<browser_tabs_usage>You can work with multiple browser tabs simultaneously.</browser_tabs_usage>"});
  set("chrome_ext_explicit_permissions_prompt", {prompt:"<explicit-permission>Claude requires explicit user permission for irreversible actions.</explicit-permission>"}, "organizationUUID");
  set("chrome_ext_tool_usage_prompt", {prompt:"<tool_usage>Maintain a todo list for multi-step tasks.</tool_usage>"}, "organizationUUID");
  set("chrome_ext_planning_mode_prompt", {prompt:"Work with the user to create a plan, then execute it."});
  set("chrome_ext_custom_tool_prompts", {update_plan:{toolDescription:"Update the plan for user approval."}, TodoWrite:{toolDescription:"Create a structured task list."}}, "organizationUUID");
  set("crochet_chips", {}, "anonymousID");
  set("crochet_domain_skills", {}, "anonymousID");
  set("crochet_github", {skill:""}, "anonymousID");
  set("crochet_gmail", {skill:""}, "anonymousID");
  set("crochet_google_calendar", {skill:""}, "anonymousID");
  set("crochet_google_docs", {skill:""}, "anonymousID");
  set("crochet_linkedin", {skill:""}, "anonymousID");
  set("crochet_slack", {skill:""}, "anonymousID");
  set("crochet_bad_hostnames", {hostnames:[]}, "organizationUUID");
  set("cic_ext_timeouts", {oauthRefreshMs:10000, debuggerAttachMs:8000, cdpSendCommandMs:30000});
  set("cic_screencast_warmup", false);
  return { features: f };
}
const FEATURES_FULL = buildFeatures();

// =============================================================================
// CORS + helpers
// =============================================================================
const CORS = {
  "Access-Control-Allow-Origin": "*",
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
const json = (obj, status, extra) => {
  if (!status) status = 200;
  if (!extra) extra = {};
  return new Response(JSON.stringify(obj),
    {status: status, headers: {"Content-Type":"application/json", ...CORS, ...extra}});
};
const text = (s, status, ct) => {
  if (!status) status = 200;
  if (!ct) ct = "text/plain";
  return new Response(s, {status: status, headers: {"Content-Type":ct, ...CORS}});
};
const noContent = () => new Response(null, {status:204, headers:CORS});

// =============================================================================
// Effective config: env -> KV -> in-memory fallback
// =============================================================================
async function loadConfig(env) {
  let url   = env.BACKEND_URL   || "";
  let key   = env.BACKEND_KEY   || "";
  let label = env.BACKEND_LABEL || "";
  if (env.CONFIG_KV) {
    try {
      if (!url)   url   = (await env.CONFIG_KV.get("BACKEND_URL"))   || "";
      if (!key)   key   = (await env.CONFIG_KV.get("BACKEND_KEY"))   || "";
      if (!label) label = (await env.CONFIG_KV.get("BACKEND_LABEL")) || "";
    } catch (e) {}
  }
  if (!url   && _MEM_CONFIG.BACKEND_URL)   url   = _MEM_CONFIG.BACKEND_URL;
  if (!key   && _MEM_CONFIG.BACKEND_KEY)   key   = _MEM_CONFIG.BACKEND_KEY;
  if (!label && _MEM_CONFIG.BACKEND_LABEL) label = _MEM_CONFIG.BACKEND_LABEL;
  return { BACKEND_URL: url, BACKEND_KEY: key, BACKEND_LABEL: label };
}

async function saveConfig(env, cfg) {
  if (env.CONFIG_KV) {
    try {
      if (cfg.BACKEND_URL   !== undefined) await env.CONFIG_KV.put("BACKEND_URL",   String(cfg.BACKEND_URL   || ""));
      if (cfg.BACKEND_KEY   !== undefined) await env.CONFIG_KV.put("BACKEND_KEY",   String(cfg.BACKEND_KEY   || ""));
      if (cfg.BACKEND_LABEL !== undefined) await env.CONFIG_KV.put("BACKEND_LABEL", String(cfg.BACKEND_LABEL || ""));
    } catch (e) {}
  }
  if (cfg.BACKEND_URL   !== undefined) _MEM_CONFIG.BACKEND_URL   = String(cfg.BACKEND_URL   || "");
  if (cfg.BACKEND_KEY   !== undefined) _MEM_CONFIG.BACKEND_KEY   = String(cfg.BACKEND_KEY   || "");
  if (cfg.BACKEND_LABEL !== undefined) _MEM_CONFIG.BACKEND_LABEL = String(cfg.BACKEND_LABEL || "");
}

// =============================================================================
// uiNodes -- links point to extension options page (chrome-extension://)
// =============================================================================
function buildUiNodes() {
  var extBase = "chrome-extension://" + EXTENSION_ID + "/options.html#api";
  return [
    {"selector":{"type":"div","props":{"className":null,"children":[{"type":"label","props":{"htmlFor":"apiKey"}}]}},"append":{"type":"p","props":{"className":"mt-2 font-bold text-text-300","children":[{"type":"a","props":{"href":extBase,"target":"_blank","className":"inline-link","style":{},"children":["Backend URL and Model Alias"]}}]}}},
    {"selector":{"type":"ul","props":{"className":"flex gap-1 md:flex-col mb-0","children":[{"type":"li","props":{}}]}},"append":{"type":"li","props":{"children":[{"type":"a","props":{"href":extBase,"target":"_blank","className":"block w-full text-left whitespace-nowrap transition-all ease-in-out active:scale-95 cursor-pointer font-base rounded-lg px-3 py-3 text-text-200 hover:bg-bg-200 hover:text-text-100","children":"Backend Settings"}}]}}}
  ];
}

// =============================================================================
// /api/options
// =============================================================================
function buildOptions(workerOrigin) {
  return {
    "mode": "",
    "anthropicBaseUrl": workerOrigin,
    "apiBaseIncludes": ["https://api.anthropic.com/v1/"],
    "proxyIncludes": [
      "featureassets.org","assetsconfigcdn.org","featuregates.org",
      "prodregistryv2.org","beyondwickedmapping.org","api.honeycomb.io",
      "statsigapi.net","events.statsigapi.net","api.statsigcdn.com",
      "*ingest.us.sentry.io",
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
      "cdn.segment.com","api.segment.io","events.statsigapi.net",
      "api.honeycomb.io","prodregistryv2.org","*ingest.us.sentry.io",
      "browser-intake-us5-datadoghq.com",
    ],
    "modelAlias": {},
    "uiNodes": buildUiNodes(),
  };
}

// =============================================================================
// /v1/* forwarder
// =============================================================================
async function forwardV1(request, url, cfg) {
  var backendUrl = (cfg.BACKEND_URL || "").replace(/\/+$/, "");
  if (!backendUrl) {
    return json({
      error: {
        type: "config_error",
        message: "Worker BACKEND_URL is not set. Configure it in the Cloudflare dashboard or at " + url.origin + "/#api"
      }
    }, 503);
  }
  var target = backendUrl + url.pathname + url.search;

  var allowed = new Set([
    "content-type","accept",
    "anthropic-version","anthropic-beta",
    "anthropic-client-platform","anthropic-client-version",
    "x-service-name","x-stainless-arch","x-stainless-lang","x-stainless-os",
    "x-stainless-package-version","x-stainless-runtime",
    "x-stainless-runtime-version","x-stainless-retry-count",
    "x-stainless-timeout","x-stainless-helper-method",
    "x-app",
  ]);
  var out = new Headers();
  for (var pair of request.headers.entries()) {
    if (allowed.has(pair[0].toLowerCase())) out.set(pair[0], pair[1]);
  }
  var isAnthropicTarget =
    /(^|\/\/)(api\.anthropic\.com|console\.anthropic\.com|platform\.claude\.com)/i
      .test(backendUrl);
  var inAuth = request.headers.get("Authorization") || "";
  var inXKey = request.headers.get("x-api-key") || "";

  if (cfg.BACKEND_KEY) {
    out.set("Authorization", "Bearer " + cfg.BACKEND_KEY);
    out.set("x-api-key", cfg.BACKEND_KEY);
  } else if (isAnthropicTarget && inAuth) {
    out.set("Authorization", inAuth);
    if (inXKey) out.set("x-api-key", inXKey);
  } else {
    out.delete("Authorization");
    out.delete("x-api-key");
    if (!isAnthropicTarget) {
      out.delete("anthropic-version");
      out.delete("anthropic-beta");
      out.delete("anthropic-client-platform");
      out.delete("anthropic-client-version");
    }
  }

  var init = { method: request.method, headers: out, redirect: "follow" };
  if (!["GET","HEAD"].includes(request.method)) init.body = await request.arrayBuffer();
  var resp;
  try { resp = await fetch(target, init); }
  catch (e) {
    return json({error:{type:"upstream_error",
      message:"fetch to BACKEND_URL failed: " + (e && e.message || e),
      target: target}}, 502);
  }
  var respHeaders = new Headers(resp.headers);
  for (var k in CORS) respHeaders.set(k, CORS[k]);
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers: respHeaders });
}

// =============================================================================
// Status / configurable backend page  (root + #api)
// =============================================================================
function statusPage(cfg, workerOrigin, kvBound, tokenRequired) {
  var backend = cfg.BACKEND_URL || "(unset)";
  var label   = cfg.BACKEND_LABEL || "configured backend";
  var keyOK   = cfg.BACKEND_KEY ? "set (" + String(cfg.BACKEND_KEY).length + " chars)" : "open (no key)";
  var persistMsg = kvBound
    ? "<span class='tag ok'>persistent (KV)</span>"
    : "<span class='tag warn'>in-memory (resets on cold start)</span>";
  var tokenMsg = tokenRequired
    ? "<span class='tag ok'>required</span> -- the form below sends X-CFC-Token"
    : "<span class='tag warn'>not set</span> -- anyone can change BACKEND_URL";
  var activeTag = cfg.BACKEND_URL
    ? "<span class=\"tag ok\">ACTIVE</span>"
    : "<span class=\"tag warn\">UNSET -- /v1/* will return 503</span>";
  return "<!doctype html><html><head><meta charset=\"utf-8\">\n"
    + "<title>CFC14 Worker</title>\n"
    + "<style>\n"
    + "*{box-sizing:border-box}\n"
    + "body{font:14px/1.5 -apple-system,system-ui,sans-serif;background:#f9f8f3;color:#3d3929;margin:0;padding:24px}\n"
    + ".wrap{max-width:920px;margin:0 auto}\n"
    + "h1{font:400 28px Georgia,serif;margin:0 0 6px}\n"
    + ".sub{color:#6b6651;margin:0 0 20px}\n"
    + ".card{background:#fff;border:1px solid #e5e2d9;border-radius:14px;padding:20px;margin-bottom:14px}\n"
    + ".card h2{font:700 11px system-ui;text-transform:uppercase;letter-spacing:.5px;color:#8b856c;margin:0 0 12px}\n"
    + "table{width:100%;border-collapse:collapse;font-size:13px}\n"
    + "td{padding:6px 10px;border-bottom:1px solid #f0eee6;vertical-align:top}\n"
    + "td:first-child{color:#6b6651;width:34%}\n"
    + "code{background:#f4f1ea;padding:2px 6px;border-radius:5px;font-size:12px;word-break:break-all}\n"
    + ".tag{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700}\n"
    + ".ok{background:#d8f3dc;color:#1b4332}\n"
    + ".warn{background:#ffd7d7;color:#7a1212}\n"
    + "input[type=text],input[type=password]{width:100%;padding:8px 10px;border:1px solid #e5e2d9;border-radius:6px;font-size:13px;font-family:inherit}\n"
    + "label{display:block;font-size:11px;font-weight:700;text-transform:uppercase;color:#8b856c;margin:14px 0 4px}\n"
    + "button{background:#d97757;color:#fff;border:0;padding:10px 18px;border-radius:8px;font-weight:700;cursor:pointer;margin-top:14px}\n"
    + "button.secondary{background:#e5e2d9;color:#3d3929}\n"
    + ".row{display:flex;gap:14px;flex-wrap:wrap}\n"
    + ".row > div{flex:1;min-width:240px}\n"
    + "pre{background:#fcfbf9;padding:12px;border-radius:8px;font-size:12px;overflow-x:auto;margin:0;white-space:pre-wrap;word-break:break-all}\n"
    + ".flash{padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:12px;display:none}\n"
    + ".flash.ok{background:#d8f3dc;color:#1b4332;display:block}\n"
    + ".flash.err{background:#ffd7d7;color:#7a1212;display:block}\n"
    + "</style></head><body><div class=\"wrap\">\n"
    + "<h1>CFC14 Worker</h1>\n"
    + "<p class=\"sub\">cocodem-replacement contract &middot; FAT profile &middot; configurable /v1/* forwarder</p>\n"
    + "<div id=\"flash\" class=\"flash\"></div>\n"
    + "<div class=\"card\" id=\"api\"><h2>Backend Settings (live)</h2>\n"
    + "<table>\n"
    + "<tr><td>BACKEND_URL</td><td><code id=\"cur_url\">" + backend + "</code></td></tr>\n"
    + "<tr><td>BACKEND_LABEL</td><td>" + label + "</td></tr>\n"
    + "<tr><td>BACKEND_KEY</td><td>" + keyOK + "</td></tr>\n"
    + "<tr><td>Status</td><td>" + activeTag + "</td></tr>\n"
    + "<tr><td>Persistence</td><td>" + persistMsg + "</td></tr>\n"
    + "<tr><td>CONFIG_TOKEN</td><td>" + tokenMsg + "</td></tr>\n"
    + "</table>\n"
    + "<form id=\"cfgform\" style=\"margin-top:18px\" autocomplete=\"off\">\n"
    + "  <div class=\"row\">\n"
    + "    <div>\n"
    + "      <label for=\"f_url\">BACKEND_URL</label>\n"
    + "      <input type=\"text\" id=\"f_url\" name=\"BACKEND_URL\" placeholder=\"http://YOUR_PUBLIC_IP:1234  or  https://openrouter.ai/api/v1\" value=\"" + (cfg.BACKEND_URL || "") + "\">\n"
    + "    </div>\n"
    + "    <div>\n"
    + "      <label for=\"f_label\">BACKEND_LABEL (optional)</label>\n"
    + "      <input type=\"text\" id=\"f_label\" name=\"BACKEND_LABEL\" placeholder=\"LM Studio @ home\" value=\"" + (cfg.BACKEND_LABEL || "") + "\">\n"
    + "    </div>\n"
    + "  </div>\n"
    + "  <div class=\"row\">\n"
    + "    <div>\n"
    + "      <label for=\"f_key\">BACKEND_KEY (optional)</label>\n"
    + "      <input type=\"password\" id=\"f_key\" name=\"BACKEND_KEY\" placeholder=\"sk-or-... (leave blank for open LM Studio)\" value=\"\">\n"
    + "    </div>\n"
    + "    <div>\n"
    + "      <label for=\"f_token\">CONFIG_TOKEN (only if Worker requires one)</label>\n"
    + "      <input type=\"password\" id=\"f_token\" name=\"CONFIG_TOKEN\" value=\"\">\n"
    + "    </div>\n"
    + "  </div>\n"
    + "  <button type=\"submit\">Save backend config</button>\n"
    + "  <button type=\"button\" class=\"secondary\" id=\"testbtn\">Test /v1/models</button>\n"
    + "  <button type=\"button\" class=\"secondary\" id=\"clearbtn\">Clear</button>\n"
    + "</form>\n"
    + "<p style=\"font-size:12px;color:#6b6651;margin-top:14px\">\n"
    + "Persistence: <b>" + (kvBound ? "KV (CONFIG_KV namespace)" : "in-memory (resets on Worker cold start)") + "</b>.\n"
    + "For permanent config, bind a KV namespace named <code>CONFIG_KV</code> in Cloudflare dashboard.\n"
    + "</p>\n"
    + "<h2 style=\"margin-top:24px\">Backend examples</h2>\n"
    + "<table>\n"
    + "<tr><td>LM Studio (public IP)</td><td><code>http://YOUR_PUBLIC_IP:1234</code></td></tr>\n"
    + "<tr><td>LM Studio via cloudflared tunnel</td><td><code>https://your-tunnel.trycloudflare.com</code></td></tr>\n"
    + "<tr><td>OpenRouter</td><td><code>https://openrouter.ai/api/v1</code> + BACKEND_KEY</td></tr>\n"
    + "<tr><td>CFC14 Python proxy via tunnel</td><td><code>https://your-tunnel.trycloudflare.com</code> (fronts localhost:8520)</td></tr>\n"
    + "<tr><td>Real Anthropic</td><td><code>https://api.anthropic.com</code></td></tr>\n"
    + "<tr><td>Ollama</td><td><code>http://YOUR_PUBLIC_IP:11434</code></td></tr>\n"
    + "</table></div>\n"
    + "<div class=\"card\"><h2>cocodem auth contract endpoints</h2>\n"
    + "<table>\n"
    + "<tr><td><code>/api/options</code></td><td>cocodem-shape, anthropicBaseUrl=this worker</td></tr>\n"
    + "<tr><td><code>/api/oauth/profile</code></td><td>FAT shape</td></tr>\n"
    + "<tr><td><code>/api/oauth/account</code></td><td>same as profile</td></tr>\n"
    + "<tr><td><code>/api/oauth/account/settings</code></td><td>{enabled_mcp_tools:{enabled_key_1:true}}</td></tr>\n"
    + "<tr><td><code>/api/oauth/chat_conversations</code></td><td>[]</td></tr>\n"
    + "<tr><td><code>/api/oauth/organizations</code></td><td>404 (matches live cocodem)</td></tr>\n"
    + "<tr><td><code>/api/bootstrap/features/claude_in_chrome</code></td><td>42 features</td></tr>\n"
    + "<tr><td><code>/api/web/domain_info/browser_extension</code></td><td>{category:\"unknown\"}</td></tr>\n"
    + "<tr><td><code>/v1/oauth/token</code></td><td>static cfc-local-permanent token</td></tr>\n"
    + "<tr><td><code>/oauth/redirect</code></td><td>HTML -> chrome.runtime.sendMessage</td></tr>\n"
    + "<tr><td><code>/v1/*</code></td><td>forwarded to BACKEND_URL with auth policy</td></tr>\n"
    + "<tr><td><code>/api/worker-config</code></td><td>GET/POST: programmatic backend config</td></tr>\n"
    + "</table></div>\n"
    + "<div class=\"card\"><h2>Diagnostic curl</h2>\n"
    + "<pre>curl " + workerOrigin + "/api/options | jq .\n"
    + "curl " + workerOrigin + "/api/oauth/profile | jq .\n"
    + "curl -X POST " + workerOrigin + "/v1/messages \\\n"
    + "  -H \"content-type: application/json\" \\\n"
    + "  -d '{\"model\":\"claude-haiku-4-5\",\"max_tokens\":256,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}'</pre>\n"
    + "</div>\n"
    + "</div>\n"
    + "<script>\n"
    + "(function(){\n"
    + "  var flash = document.getElementById(\"flash\");\n"
    + "  function show(msg, ok) {\n"
    + "    flash.className = \"flash \" + (ok ? \"ok\" : \"err\");\n"
    + "    flash.textContent = msg;\n"
    + "  }\n"
    + "  document.getElementById(\"cfgform\").addEventListener(\"submit\", function(e) {\n"
    + "    e.preventDefault();\n"
    + "    var fd = new FormData(e.target);\n"
    + "    var body = {\n"
    + "      BACKEND_URL:   fd.get(\"BACKEND_URL\")   || \"\",\n"
    + "      BACKEND_KEY:   fd.get(\"BACKEND_KEY\")   || \"\",\n"
    + "      BACKEND_LABEL: fd.get(\"BACKEND_LABEL\") || \"\",\n"
    + "    };\n"
    + "    var headers = {\"content-type\":\"application/json\"};\n"
    + "    var tok = fd.get(\"CONFIG_TOKEN\");\n"
    + "    if (tok) headers[\"x-cfc-token\"] = tok;\n"
    + "    fetch(\"/api/worker-config\", {method:\"POST\", headers:headers, body:JSON.stringify(body)})\n"
    + "      .then(function(r){ return r.json().then(function(j){ return {r:r,j:j}; }); })\n"
    + "      .then(function(o){\n"
    + "        if (o.r.ok) {\n"
    + "          show(\"Saved. BACKEND_URL = \" + (o.j.BACKEND_URL || \"(empty)\"), true);\n"
    + "          document.getElementById(\"cur_url\").textContent = o.j.BACKEND_URL || \"(unset)\";\n"
    + "        } else show(\"Save failed: \" + (o.j.error && o.j.error.message || o.r.status), false);\n"
    + "      }).catch(function(err){ show(\"Save failed: \" + err, false); });\n"
    + "  });\n"
    + "  document.getElementById(\"clearbtn\").addEventListener(\"click\", function() {\n"
    + "    var headers = {\"content-type\":\"application/json\"};\n"
    + "    var tok = document.getElementById(\"f_token\").value;\n"
    + "    if (tok) headers[\"x-cfc-token\"] = tok;\n"
    + "    fetch(\"/api/worker-config\", {method:\"POST\", headers:headers, body:JSON.stringify({BACKEND_URL:\"\",BACKEND_KEY:\"\",BACKEND_LABEL:\"\"})})\n"
    + "      .then(function(r){ return r.json(); })\n"
    + "      .then(function(j){\n"
    + "        show(\"Cleared.\", true);\n"
    + "        document.getElementById(\"cur_url\").textContent = \"(unset)\";\n"
    + "        document.getElementById(\"f_url\").value = \"\";\n"
    + "        document.getElementById(\"f_label\").value = \"\";\n"
    + "        document.getElementById(\"f_key\").value = \"\";\n"
    + "      }).catch(function(err){ show(\"Clear failed: \" + err, false); });\n"
    + "  });\n"
    + "  document.getElementById(\"testbtn\").addEventListener(\"click\", function() {\n"
    + "    show(\"Testing /v1/models...\", true);\n"
    + "    fetch(\"/v1/models\")\n"
    + "      .then(function(r){ return r.text().then(function(t){ return {r:r,t:t}; }); })\n"
    + "      .then(function(o){ show(\"HTTP \" + o.r.status + \" from /v1/models -- \" + o.t.slice(0,200), o.r.ok); })\n"
    + "      .catch(function(err){ show(\"Test failed: \" + err, false); });\n"
    + "  });\n"
    + "})();\n"
    + "</script>\n"
    + "</body></html>";
}

// =============================================================================
// /oauth/redirect HTML
// =============================================================================
function oauthRedirectHtml(code, state) {
  var codeJson  = JSON.stringify(code);
  var stateJson = JSON.stringify(state);
  return "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sign-in complete</title>\n"
    + "<style>body{font:15px system-ui;background:#f9f8f3;color:#3d3929;margin:0;padding:48px 24px;text-align:center}\n"
    + ".c{max-width:420px;margin:0 auto;background:white;border:1px solid #e5e2d9;border-radius:24px;padding:32px}\n"
    + "button{background:#d97757;color:#fff;border:0;padding:12px 24px;border-radius:10px;font-weight:700;cursor:pointer}\n"
    + "code{background:#f4f1ea;padding:2px 6px;border-radius:5px;font-size:11px}</style></head><body><div class=\"c\">\n"
    + "<h1 style=\"font:400 22px Georgia,serif;margin:0 0 10px\">Sign-in complete</h1>\n"
    + "<p>If the side panel did not open, click below.</p>\n"
    + "<button id=\"go\">Open side panel</button>\n"
    + "<p style=\"margin-top:18px;font-size:11px;color:#999\">code=<code>" + code + "</code></p>\n"
    + "</div>\n"
    + "<script>\n"
    + "(function(){\n"
    + "  var code  = " + codeJson + ";\n"
    + "  var state = " + stateJson + ";\n"
    + "  var EXT   = \"" + EXTENSION_ID + "\";\n"
    + "  function notify() {\n"
    + "    try { window.opener && window.opener.postMessage({type:\"oauth_redirect\", code:code, state:state, redirect_uri:location.href}, \"*\"); } catch(e){}\n"
    + "    try { chrome.runtime.sendMessage(EXT, {type:\"oauth_redirect\", code:code, state:state, redirect_uri:location.href}, function(){}); } catch(e){}\n"
    + "  }\n"
    + "  document.getElementById(\"go\").addEventListener(\"click\", function() { notify(); setTimeout(function(){ try { window.close(); } catch(e){} }, 200); });\n"
    + "  notify();\n"
    + "  setTimeout(function(){ if (window.opener) try { window.close(); } catch(e){} }, 4000);\n"
    + "})();\n"
    + "</script></body></html>";
}

// =============================================================================
// MAIN ROUTER
// =============================================================================
async function handle(request, env) {
  var url    = new URL(request.url);
  var method = request.method;
  if (method === "OPTIONS") return noContent();

  // Strip cfcBase wrapping: /https://api.anthropic.com/path -> /path
  var p = url.pathname;
  if (p.startsWith("/https://") || p.startsWith("/http://")) {
    try {
      var inner = new URL(p.slice(1) + url.search);
      p = inner.pathname + inner.search;
    } catch (e) {}
  }
  var bare = p.split("?")[0];
  var workerOrigin = url.origin;

  // Telemetry sinks (always 204)
  var TELEMETRY = [
    "/cdn.segment.com","/api.segment.io","/events.statsigapi.net",
    "/api.honeycomb.io","/prodregistryv2.org","ingest.us.sentry.io",
    "browser-intake-us5-datadoghq.com","fpjs.dev","openfpcdn.io",
    "api.fpjs.io","googletagmanager.com","/featureassets.org",
    "/assetsconfigcdn.org","/featuregates.org","/api.statsigcdn.com",
    "/v1/log_event","/event_logging",
  ];
  if (TELEMETRY.some(function(t){ return p.includes(t); })) return noContent();

  // /api/worker-config (runtime backend configuration)
  if (bare === "/api/worker-config") {
    var cfgR = await loadConfig(env);
    if (method === "GET") {
      return json({
        BACKEND_URL:   cfgR.BACKEND_URL,
        BACKEND_LABEL: cfgR.BACKEND_LABEL,
        BACKEND_KEY_set: !!cfgR.BACKEND_KEY,
        kv_bound: !!env.CONFIG_KV,
        token_required: !!env.CONFIG_TOKEN,
      });
    }
    if (method === "POST") {
      if (env.CONFIG_TOKEN) {
        var provided = request.headers.get("x-cfc-token") || "";
        if (provided !== env.CONFIG_TOKEN)
          return json({error:{type:"forbidden",message:"x-cfc-token mismatch"}}, 403);
      }
      var body = {};
      try { body = await request.json(); } catch (e) {}
      await saveConfig(env, {
        BACKEND_URL:   body.BACKEND_URL,
        BACKEND_KEY:   body.BACKEND_KEY,
        BACKEND_LABEL: body.BACKEND_LABEL,
      });
      var cur = await loadConfig(env);
      return json({
        ok: true,
        BACKEND_URL:   cur.BACKEND_URL,
        BACKEND_LABEL: cur.BACKEND_LABEL,
        BACKEND_KEY_set: !!cur.BACKEND_KEY,
      });
    }
    return json({error:{message:"method not allowed"}}, 405);
  }

  // /v1/* forwarder (must run BEFORE the token route below)
  if (bare.startsWith("/v1/") && !bare.endsWith("/v1/oauth/token")) {
    var cfgV = await loadConfig(env);
    return forwardV1(request, url, cfgV);
  }

  // cocodem auth/contract endpoints
  if (bare === "/api/options" || bare.endsWith("/api/options"))
    return json(buildOptions(workerOrigin));
  if (bare === "/api/oauth/profile" || bare.endsWith("/api/oauth/profile"))
    return json(PROFILE);
  if (bare === "/api/oauth/account" || bare.endsWith("/api/oauth/account"))
    return json(PROFILE);
  if (bare === "/api/oauth/account/settings" || bare.endsWith("/api/oauth/account/settings"))
    return json({"enabled_mcp_tools":{"enabled_key_1":true}});
  if (bare === "/api/oauth/chat_conversations" || bare.endsWith("/api/oauth/chat_conversations"))
    return json([]);
  if (bare === "/api/web/domain_info/browser_extension" || bare.endsWith("/api/web/domain_info/browser_extension"))
    return json({"category":"unknown"});
  if (bare === "/api/web/url_hash_check/browser_extension" || bare.endsWith("/api/web/url_hash_check/browser_extension"))
    return json({"allowed":true});
  if (bare === "/api/bootstrap/features/claude_in_chrome" || bare.endsWith("/api/bootstrap/features/claude_in_chrome"))
    return json(FEATURES_FULL);
  if (bare.startsWith("/api/bootstrap"))
    return json(Object.assign({}, PROFILE, FEATURES_FULL));
  if (bare.endsWith("/v1/oauth/token") || bare.endsWith("/oauth/token")) {
    return json({
      "access_token":  "cfc-local-permanent.cfc-local-permanent.cfc-local-permanent",
      "refresh_token": "cfc-local-permanent.cfc-local-permanent.cfc-local-permanent",
      "token_type":    "bearer",
      "expires_in":    315360000,
      "expires_at":    9999999999000,
      "scope":         "user:profile user:inference user:chat",
      "account":       {"uuid": ACCOUNT_UUID},
    });
  }
  if (bare.endsWith("/oauth/authorize")) {
    var sp    = url.searchParams;
    var code  = "cfc-local-permanent";
    var state = sp.get("state") || "cfc-local";
    var dest  = new URL(workerOrigin + "/oauth/redirect");
    dest.searchParams.set("code", code);
    dest.searchParams.set("state", state);
    return Response.redirect(dest.toString(), 302);
  }
  if (bare.endsWith("/oauth/redirect")) {
    var rCode  = url.searchParams.get("code")  || "cfc-local-permanent";
    var rState = url.searchParams.get("state") || "cfc-local";
    return text(oauthRedirectHtml(rCode, rState), 200, "text/html");
  }
  if (bare.startsWith("/api/oauth/organizations") || bare.includes("/api/oauth/organizations"))
    return text("404 Not Found", 404);
  if (bare.includes("/licenses/")) return text("404 Not Found", 404);
  if (bare.includes("/mcp/v2/"))   return text("404 Not Found", 404);

  // root + #api status/config page
  if (bare === "/" || bare === "" || bare === "/index.html") {
    var cfgS = await loadConfig(env);
    return text(statusPage(cfgS, workerOrigin, !!env.CONFIG_KV, !!env.CONFIG_TOKEN), 200, "text/html");
  }

  // Default: empty 200 (cocodem behavior for unknown routes)
  return json({});
}

export default {
  async fetch(request, env, ctx) {
    try { return await handle(request, env || {}); }
    catch (e) { return json({error:{type:"worker_error",message:String(e && e.message || e)}}, 500); }
  },
};
