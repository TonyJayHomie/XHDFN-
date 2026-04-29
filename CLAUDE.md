# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## MANDATORY FILE HANDLING RULES — NO EXCEPTIONS

1. **NEVER overwrite or edit any existing file directly.** Not even a blank file. Not even by one character.
2. **Before touching any file, make TWO backups first** — copy to `GARBAGE_BIN/` with unique timestamped names (e.g. `FILENAME_YYYYMMDD_HHMMSS_backup1.ext` and `FILENAME_YYYYMMDD_HHMMSS_backup2.ext`).
3. **All output goes to a NEW file with a unique timestamped name.** Format: `BASENAME_YYYYMMDD_HHMMSS.ext`. Never reuse a name.
4. **Nothing is ever deleted.** Move to `GARBAGE_BIN/` instead. `GARBAGE_BIN/` itself is never cleared.
5. **Read files completely and verbatim — no truncation, summarization, compaction, or keyword-only scanning.** Read every byte sequentially. Do not use grep/search as a substitute for reading.

---

## Project Overview

This is **CFC (Claude For Chrome)** — a sanitizer + replacement infrastructure for the cocodem trojanized Claude Chrome extension. The goal is a 1:1 copy of cocodem's architecture with only the remote URLs ("phone numbers") swapped to the user's own infrastructure:
- Remote Cloudflare Worker: `test2.mahnikka.workers.dev`
- Local Python proxy: `localhost:8520`

The Chrome extension ID is `fcoeoabgfenejglbffodgkkbkcdhcgfn`.

---

## Key Files

| File | Purpose |
|------|---------|
| `USE THIS AS THE WORKER BASE` | **Canonical correct Cloudflare Worker base** (666 lines, 35KB). This is the authoritative source. Never modify it — always copy to a new timestamped file before working. |
| `CFC15.py` | Main sanitizer script (~4600+ lines). Reads the extension zip, patches `request.js`, generates the worker JS, options pages, backend settings UI, and writes the sanitized output zip. |
| `CFC15 WORKER CODE.js` | Original uploaded worker code (191KB). Do not touch — reference only. |
| `CFC13-FAT.worker.js` | Earlier FAT-profile worker reference (191KB). |
| `cocodem-replacement.worker.cfc11.js` / `cfc12.js` | Older worker versions for reference. |
| `cocodem_features.json` | Raw Statsig 42-gate feature payload captured from live cocodem. |
| `GARBAGE_BIN/` | Trash folder. All displaced files go here with timestamped names. Never delete from here. |
| `CFC8.py` … `CFC13FAT.py` | Earlier sanitizer versions. Reference only — do not modify. |
| `READ`, `R3AD` | Large reference/data files. Read verbatim when needed. |

---

## Architecture

### Python Sanitizer (`CFC15.py`)

Runs as a standalone script. Key phases:

1. **Unzips** the target Chrome extension (`claude_1.0.66 (4).zip`)
2. **Patches `request.js`** — injects `cfcBase` (remote-first with localhost fallback), `getOptions()`, and the fetch-intercept logic
3. **Writes the worker JS** — embeds `_CFC14_WORKER_EMBEDDED` (the inline fallback) or loads from `CFC14.worker.js` on disk
4. **Generates options/backend pages** — `backend_settings_ui.js`, `backend_settings.html`, `options.html`
5. **Runs a local HTTP server** on port 8520 (`CfcProxyHandler`) that serves auth endpoints, proxies `/v1/*` to configured backends

Critical constants (top of `CFC15.py`):
```
REMOTE_BASE   = "https://test2.mahnikka.workers.dev/"   # worker, always first
CFC_BASE      = "http://localhost:8520/"                 # local fallback only
EXTENSION_ID  = "fcoeoabgfenejglbffodgkkbkcdhcgfn"
```

`cfcBase` in the generated `request.js` is always: `REMOTE_BASE || CFC_BASE || ""`  — remote-first, localhost is a dev backdoor, never primary.

### Cloudflare Worker (`USE THIS AS THE WORKER BASE`)

Single-file ES module worker. Key components:

- `_MEM_CONFIG` — in-memory fallback when no KV binding
- `loadConfig(env)` / `saveConfig(env, cfg)` — reads config from env vars → KV → `_MEM_CONFIG` in priority order
- `buildFeatures(systemPrompt)` — constructs the 42-gate Statsig payload dynamically; `chrome_ext_system_prompt` is configurable
- `buildUiNodes()` — returns JSX-patch shapes pointing to `chrome-extension://EXTENSION_ID/options.html#api` (NOT the worker URL)
- `buildOptions(workerOrigin, systemPrompt)` — serves `/api/options` in cocodem contract shape
- `forwardV1(request, url, cfg)` — proxies `/v1/*` to `BACKEND_URL` with auth policy
- `statusPage(cfg, ...)` — the `/#api` live config form (BACKEND_URL, BACKEND_KEY, BACKEND_LABEL, SYSTEM_PROMPT)
- `/api/worker-config` POST — saves config to KV; protected by `CONFIG_TOKEN`

Worker env vars: `BACKEND_URL`, `BACKEND_KEY`, `BACKEND_LABEL`, `SYSTEM_PROMPT`, `CONFIG_KV` (KV namespace), `CONFIG_TOKEN`.

### uiNodes Mechanism

The worker serves `/api/options` with a `uiNodes` array. `request.js` in the extension reads this via `getOptions()` and calls `setJsx`/`remixJsx` to inject:
- A "Backend URL and Model Alias" link below the API key label on the options page
- A "Backend Settings" link in the sidepanel left-rail nav

Both hrefs point to `chrome-extension://EXTENSION_ID/options.html#api`.

### Auth Flow (cocodem contract)

The worker must serve these endpoints exactly:
- `/api/options` → cocodem options shape with `anthropicBaseUrl = workerOrigin`
- `/api/oauth/profile` and `/api/oauth/account` → FAT profile JSON
- `/api/bootstrap/features/claude_in_chrome` → 42-feature Statsig payload
- `/v1/oauth/token` and `/oauth/token` → static `cfc-local-permanent` token
- `/oauth/redirect` → HTML that calls `chrome.runtime.sendMessage` to the extension
- `/api/oauth/organizations` → 404 (matches live cocodem)

`apiBaseIncludes: ["https://api.anthropic.com/v1/"]` causes `request.js` to rewrite all Anthropic API calls through the worker's `/v1/*` forwarder.

---

## Development Branch

All work goes on branch: `claude/fix-token-limit-issues-Bb8eZ`

Never push to main/master.
