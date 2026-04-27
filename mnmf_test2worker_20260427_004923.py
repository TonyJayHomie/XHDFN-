#!/usr/bin/env python3
"""
mnmf_test2worker_20260427_004923.py

Wrapper around mnmf.py that patches cfcBase in the generated request.js
to point at https://test2.mahnikka.workers.dev/ instead of http://localhost:8520/

Rules:
  - Does NOT edit mnmf.py or any other existing file
  - Creates the same timestamped output folder mnmf.py would, with one change:
      const cfcBase = "https://test2.mahnikka.workers.dev/"
    instead of:
      const cfcBase = "http://localhost:8520/"
  - Everything else (manifest patch, backend_settings_ui.js, server on :8520) is
    identical to mnmf.py
"""

import importlib.util
from pathlib import Path

# ── load mnmf.py without running its main() ───────────────────────────────────
_spec = importlib.util.spec_from_file_location(
    "mnmf", Path(__file__).resolve().parent / "mnmf.py"
)
mnmf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mnmf)

# ── patch: replace localhost cfcBase with test2 Worker URL ────────────────────
TEST2_URL = "https://test2.mahnikka.workers.dev/"
_original_write = mnmf.write_sanitized_request_js


def _patched_write_sanitized_request_js():
    _original_write()
    # request.js was just written — open it and swap cfcBase
    req_js = mnmf.OUTPUT_DIR / "assets" / "request.js"
    if req_js.exists():
        src = req_js.read_text(encoding="utf-8")
        patched = src.replace(
            'const cfcBase = "http://localhost:8520/"',
            f'const cfcBase = "{TEST2_URL}"',
        )
        if patched == src:
            print(f"[WARN] cfcBase line not found verbatim in request.js — check manually")
        else:
            req_js.write_text(patched, encoding="utf-8")
            print(f"[OK] request.js cfcBase → {TEST2_URL}")


mnmf.write_sanitized_request_js = _patched_write_sanitized_request_js

# ── run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    mnmf.main()
