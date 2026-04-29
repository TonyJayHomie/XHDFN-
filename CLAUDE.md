# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## FILE MANAGEMENT RULES (MANDATORY, NO EXCEPTIONS)

- **NEVER edit, overwrite, or delete any pre-existing file.**
- **ALWAYS create a new timestamped copy** before producing any output file. Name format: `CFC16-YYYYMMDD-HHMMSS.py`, `worker-YYYYMMDD-HHMMSS.js`, etc.
- **NEVER delete anything.** If something must be discarded, move it to `GARBAGE/` (create the folder if absent).
- Every new file you write must have the creation timestamp in its filename.

---

## What this project is

A defensive sanitizer that replaces the phone-home C2 infrastructure of **cocodem** (a trojanized Chrome extension that hijacks Anthropic's official extension ID `fcoeoabgfenejglbffodgkkbkcdhcgfn`) with the user's own locally-controlled server. Nothing phones home to any third party. All traffic loops back to the user's own Cloudflare Worker + localhost proxy.

Two output artifacts per version:
1. **Python script (`CFC*.py`)** — patches the extension folder and runs the local proxy server.
2. **Cloudflare Worker script (`CFC* WORKER CODE.js`)** — deployed by the user to their own Cloudflare account.

---

## How to run

```bash
# Place cocodem's extracted extension folder at: COCODEMS ORIGINAL ZIP/
python CFC15.py
# Load unpacked from the timestamped output folder in chrome://extensions
```

Source folder must be named exactly `COCODEMS ORIGINAL ZIP` (with spaces). Output is `claude-sanitized-YYYYMMDD-HHMMSS/`.

Port defaults: local proxy = **8520**, default backend = `http://127.0.0.1:1234/v1`.

---

## Architecture

### Python sanitizer (`CFC*.py`)

| Section | Purpose |
|---|---|
| Constants (top) | `CFC_PORT`, `CFC_BASE`, `REMOTE_BASE`, `EXTENSION_ID`, path constants |
| Backend manager | `_load_backends()`, `_save_backends()`, `_pick_backends()` — JSON file `cfc_backends.json` |
| Identity | `_load_identity()`, `_save_identity()` — JSON file `cfc_identity.json` |
| OpenAI↔Anthropic translation | `_anthropic_to_openai_body()`, `_openai_to_anthropic_response()` — bridges LM Studio/Ollama to Anthropic-shaped requests |
| Local auth responses | `get_local_auth(path)` — returns exact cocodem-shaped JSON for every `/api/oauth/*`, `/api/bootstrap/*` endpoint |
| Worker script builder | `_build_worker_script()` — inline JS string that becomes `CFC* WORKER CODE.js` |
| Extension patcher | `copy_source()`, `patch_manifest()`, `write_sanitized_request_js()`, `inject_index_module()`, `write_backend_settings_ui()` |
| HTTP server | `MultiC2Handler(BaseHTTPRequestHandler)` + `MultiC2Server` — serves all cocodem contract endpoints locally |

### Cloudflare Worker (`CFC* WORKER CODE.js`)

- `buildOptions(env, workerOrigin)` — `/api/options` response; sets `anthropicBaseUrl = workerOrigin` so extension rewrites all `/v1/*` through the worker
- `buildUiNodes(workerOrigin)` — JSX patch nodes injected into the extension's options page sidebar nav
- `forwardV1(request, url, env)` — forwards `/v1/*` to `env.BACKEND_URL` (set in Cloudflare dashboard); strips auth for open backends, passes through for Anthropic-shaped backends
- `PROFILE` / `FEATURES_FULL` — exact cocodem response shapes for `/api/oauth/profile` and `/api/bootstrap/features/claude_in_chrome`
- `oauthRedirectHtml()` — static HTML page that calls `chrome.runtime.sendMessage` back to the extension to complete the OAuth flow without any real Anthropic round-trip
- Router: telemetry → 204; `/v1/*` → `forwardV1`; auth endpoints → static JSON; `/oauth/authorize` → own `/oauth/redirect`

### request.js (written into the sanitized extension)

- `cfcBase` = `REMOTE_BASE || CFC_BASE || ""` — worker is primary, localhost is fallback
- Monkey-patches global `fetch` and `XMLHttpRequest.prototype.open`
- `proxyIncludes` list: routes selected Anthropic OAuth/bootstrap URLs through cfcBase
- `discardIncludes` list: silently drops telemetry (Segment, Statsig, Sentry, etc.)
- `apiBaseIncludes`: rewrites `/v1/*` Anthropic calls to `anthropicBaseUrl` (the worker)
- Intercepts `chrome.tabs.create` to redirect `claude.ai/oauth/authorize` → `cfcBase/oauth/authorize`
- Sidepanel dropdown injector: clones the "Settings" menu item, retitles it "Backend Settings", routes click to `chrome.runtime.getURL("options.html#api")`

### Key data files (runtime, in working directory)

- `cfc_backends.json` — list of configured backends `[{url, key, label, models:[]}]`
- `cfc_identity.json` — `{apiKey, authToken, email, username, licenseKey, modelAliases, ...}`
- `cocodem_features.json` — 42-flag Statsig payload captured from cocodem; embedded verbatim as `FEATURES_FULL`

### Extension contract (what the sidepanel boot sequence requires)

The sidepanel's root component makes these requests on every boot — all must return valid JSON or the panel renders blank:

| Endpoint | Consumer | Required shape |
|---|---|---|
| `GET /api/options` | `request.js getOptions()` | `{anthropicBaseUrl, apiBaseIncludes, proxyIncludes, discardIncludes, uiNodes, modelAlias, ...}` |
| `GET /api/oauth/profile` | `ot()` hook (root component) | `{account:{uuid,...}, organization:{uuid, capabilities:[...],...}}` |
| `GET /api/oauth/account/settings` | `us()` hook | `{enabled_mcp_tools:{}}` |
| `GET /api/bootstrap/features/claude_in_chrome` | feature gates | 42-flag Statsig object (full `cocodem_features.json`) |
| `GET /api/web/domain_info/browser_extension` | domain check | `{category:"unknown"}` |

### uiNodes / setJsx

Cocodem's worker returns a `uiNodes` array in `/api/options`. The extension's JSX runtime (`index-BVS4T5_D.js`) has a `setJsx` hook; `inject_index_module()` patches that file to call `setJsx` with the nodes. The nodes patch two locations in the options page: a link next to the `apiKey` label, and a nav `<li>` in the sidebar. **The href in both must point to `chrome-extension://fcoeoabgfenejglbffodgkkbkcdhcgfn/options.html#api`, NOT to the remote worker URL** — pointing to the worker URL causes Cloudflare 403/1003.

### Version lineage

`CFC8` → `CFC9` (exact cocodem auth shapes) → `CFC10` → `CFC11` (OpenAI↔Anthropic translation, permanent-state dashboard) → `CFC12` (sidepanel dropdown injector) → `CFC13FAT` (FAT profile, full features payload) → `CFC14` (uiNodes via worker, no options.html DOM injection) → `CFC15` (current). Each `.py` carries a surgical-changes header listing exactly what changed from the prior version.
