

def write_backend_settings_ui():
    ui = r"""(async () => {
  const container = document.getElementById("__cfc_settings_container");
  if (!container) return;
  const ICON = chrome?.runtime?.getURL ? chrome.runtime.getURL("icon-128.png") : "/icon-128.png";
  const K = {
    link:  '<svg width="11" height="11" viewBox="0 0 512 512" fill="currentColor"><path d="M320 0c-17.7 0-32 14.3-32 32s14.3 32 32 32l82.7 0L201.4 265.4c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0L448 109.3 448 192c0 17.7 14.3 32 32 32s32-14.3 32-32l0-160c0-17.7-14.3-32-32-32L320 0zM80 32C35.8 32 0 67.8 0 112L0 432c0 44.2 35.8 80 80 80l320 0c44.2 0 80-35.8 80-80l0-112c0-17.7-14.3-32-32-32s-32 14.3-32 32l0 112c0 8.8-7.2 16-16 16L80 448c-8.8 0-16-7.2-16-16l0-320c0-8.8 7.2-16 16-16l112 0c17.7 0 32-14.3 32-32s-14.3-32-32-32L80 32z"/></svg>',
    key:   '<svg width="11" height="11" viewBox="0 0 512 512" fill="currentColor"><path d="M336 352c97.2 0 176-78.8 176-176S433.2 0 336 0S160 78.8 160 176c0 18.7 2.9 36.8 8.3 53.7L7 391c-4.5 4.5-7 10.6-7 17l0 80c0 13.3 10.7 24 24 24l80 0c13.3 0 24-10.7 24-24l0-40 40 0c13.3 0 24-10.7 24-24l0-40 40 0c6.4 0 12.5-2.5 17-7l33.3-33.3c16.9 5.4 35 8.3 53.7 8.3zM376 96a40 40 0 1 1 0 80 40 40 0 1 1 0-80z"/></svg>',
    mail:  '<svg width="11" height="11" viewBox="0 0 512 512" fill="currentColor"><path d="M48 64C21.5 64 0 85.5 0 112c0 15.1 7.1 29.3 19.2 38.4L236.8 313.6c11.4 8.5 27 8.5 38.4 0L492.8 150.4c12.1-9.1 19.2-23.3 19.2-38.4c0-26.5-21.5-48-48-48L48 64zM0 176L0 384c0 35.3 28.7 64 64 64l384 0c35.3 0 64-28.7 64-64l0-208L294.4 339.2c-22.8 17.1-54 17.1-76.8 0L0 176z"/></svg>',
    user:  '<svg width="11" height="11" viewBox="0 0 448 512" fill="currentColor"><path d="M224 256A128 128 0 1 0 224 0a128 128 0 1 0 0 256zm-45.7 48C79.8 304 0 383.8 0 482.3C0 498.7 13.3 512 29.7 512l388.6 0c16.4 0 29.7-13.3 29.7-29.7C448 383.8 368.2 304 269.7 304l-91.4 0z"/></svg>',
    cog:   '<svg width="10" height="10" viewBox="0 0 512 512" fill="currentColor"><path d="M495.9 166.6c3.2 8.7 .5 18.4-6.4 24.6l-43.3 39.4c1.1 8.3 1.7 16.8 1.7 25.4s-.6 17.1-1.7 25.4l43.3 39.4c6.9 6.2 9.6 15.9 6.4 24.6c-4.4 11.9-9.7 23.3-15.8 34.3l-4.7 8.1c-6.6 11-14 21.4-22.1 31.2c-5.9 7.2-15.7 9.6-24.5 6.8l-55.7-17.7c-13.4 10.3-28.2 18.9-44 25.4l-12.5 57.1c-2 9.1-9 16.3-18.2 17.8c-13.8 2.3-28 3.5-42.5 3.5s-28.7-1.2-42.5-3.5c-9.2-1.5-16.2-8.7-18.2-17.8l-12.5-57.1c-15.8-6.5-30.6-15.1-44-25.4L83.1 425.9c-8.8 2.8-18.6 .3-24.5-6.8c-8.1-9.8-15.5-20.2-22.1-31.2l-4.7-8.1c-6.1-11-11.4-22.4-15.8-34.3c-3.2-8.7-.5-18.4 6.4-24.6l43.3-39.4C64.6 273.1 64 264.6 64 256s.6-17.1 1.7-25.4L22.4 191.2c-6.9-6.2-9.6-15.9-6.4-24.6c4.4-11.9 9.7-23.3 15.8-34.3l4.7-8.1c6.6-11 14-21.4 22.1-31.2c5.9-7.2 15.7-9.6 24.5-6.8l55.7 17.7c13.4-10.3 28.2-18.9 44-25.4l12.5-57.1c2-9.1 9-16.3 18.2-17.8C227.3 1.2 241.5 0 256 0s28.7 1.2 42.5 3.5c9.2 1.5 16.2 8.7 18.2 17.8l12.5 57.1c15.8 6.5 30.6 15.1 44 25.4l55.7-17.7c8.8-2.8 18.6-.3 24.5 6.8c8.1 9.8 15.5 20.2 22.1 31.2l4.7 8.1c6.1 11 11.4 22.4 15.8 34.3zM256 336a80 80 0 1 0 0-160 80 80 0 1 0 0 160z"/></svg>',
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
            <span style="color:#2d6a4f;font-weight:700">\u2714 No calls to cocodem servers.</span>
          </p>
        </div>
        <div id="bs_st" style="padding:11px 16px;border-radius:10px;margin-bottom:18px;
             display:none;font-size:13px;font-weight:600"></div>
        <div style="font-size:9px;font-weight:900;color:#8B856C;text-transform:uppercase;
                    letter-spacing:.15em;margin-bottom:14px">\u25b8 API Configuration</div>
        ${F("bs_base","API Base URL","text","http://127.0.0.1:1234/v1",K.link,"")}
        ${F("bs_key","API Key","password","sk-ant-\u2026 or any string",K.key,"")}
        ${F("bs_auth","Auth Token","password","optional",K.key,"")}
        <div style="font-size:9px;font-weight:900;color:#8B856C;text-transform:uppercase;
                    letter-spacing:.15em;margin:22px 0 8px">\u25b8 Model Aliases
          <span style="color:#b4af9a;font-weight:600;text-transform:none;letter-spacing:0;margin-left:6px">(JSON, optional)</span>
        </div>
        <textarea id="bs_aliases" placeholder='{"claude-opus-4-7": "local-model-name"}'
          style="width:100%;min-height:76px;padding:11px 14px;margin-bottom:4px;
                 border:1px solid #e5e2d9;background:#fcfbf9;color:#1d1b16;
                 border-radius:12px;font-size:13px;font-family:monospace;
                 box-sizing:border-box;outline:none;resize:vertical"></textarea>
        <div style="font-size:9px;font-weight:900;color:#8B856C;text-transform:uppercase;
                    letter-spacing:.15em;margin:22px 0 14px">\u25b8 Identity
          <span style="color:#2d6a4f;font-weight:700;text-transform:none;letter-spacing:0;margin-left:6px">\u2714 local \u2014 no license server</span>
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
            Proxy is source of truth. Falls back to
            <code style="background:#fcfbf9;padding:2px 5px;border-radius:4px;
            color:#c45f3d;font-family:monospace">chrome.storage.local</code> if proxy is down.
          </p>
        </div>
      </div>
    </div>`;
  document.querySelectorAll("input,textarea").forEach(el => {
    el.addEventListener("focus", () => { el.style.borderColor="#c45f3d"; el.style.boxShadow="0 0 0 3px rgba(196,95,61,.06)"; });
    el.addEventListener("blur",  () => { el.style.borderColor="#e5e2d9"; el.style.boxShadow="none"; });
  });
  const $ = id => document.getElementById(id);
  function st(m, k) {
    const el=$("bs_st"), s=k==="e"?{bg:"#fbe7e1",c:"#b04a3d",b:"1px solid #f3c5b8"}
      :k==="w"?{bg:"#fdf4e0",c:"#8b6914",b:"1px solid #f0d9a3"}
      :{bg:"#e6f2eb",c:"#2d6a4f",b:"1px solid #c5e0d0"};
    el.textContent=m; el.style.display="block";
    Object.assign(el.style,{background:s.bg,color:s.c,border:s.b});
    clearTimeout(el.__t); el.__t=setTimeout(()=>{el.style.display="none";},5000);
  }
  const KEYS=["ANTHROPIC_BASE_URL","ANTHROPIC_API_KEY","ANTHROPIC_AUTH_TOKEN",
              "email","username","licenseKey","hijackSettings"];
  const CFC_PROXY_BASE = "http://localhost:8520/";
  let proxyIdentity = null;
  try {
    const r = await fetch(CFC_PROXY_BASE + "api/identity", {cache:"no-store"});
    if (r.ok) proxyIdentity = await r.json();
  } catch(e) { /* proxy down -- fall back to chrome.storage.local */ }
  const saved=await chrome.storage.local.get(KEYS);
  const hs=saved.hijackSettings||{};
  const pickStr = (proxyKey, ...locals) => {
    if (proxyIdentity && typeof proxyIdentity[proxyKey] === "string" && proxyIdentity[proxyKey] !== "") return proxyIdentity[proxyKey];
    for (const v of locals) { if (v) return v; }
    return "";
  };
  const pickAny = (proxyKey, fallback) => {
    if (proxyIdentity && proxyIdentity[proxyKey] !== undefined) return proxyIdentity[proxyKey];
    return fallback;
  };
  $("bs_base").value  = pickStr("apiBaseUrl", saved.ANTHROPIC_BASE_URL, hs.backendUrl, "http://127.0.0.1:1234/v1");
  $("bs_key").value   = pickStr("apiKey",     saved.ANTHROPIC_API_KEY);
  $("bs_auth").value  = pickStr("authToken",  saved.ANTHROPIC_AUTH_TOKEN);
  $("bs_email").value = pickStr("email",      saved.email,    "user@local");
  $("bs_user").value  = pickStr("username",   saved.username, "local-user");
  $("bs_lic").value   = pickStr("licenseKey", saved.licenseKey);
  $("bs_block").checked = pickAny("blockAnalytics", hs.blockAnalytics !== false);
  const aliasSrc = (proxyIdentity && proxyIdentity.modelAliases) || hs.modelAliases || {};
  $("bs_aliases").value = aliasSrc && Object.keys(aliasSrc).length
    ? JSON.stringify(aliasSrc, null, 2) : "";
  if (proxyIdentity) {
    st("\u2714 Loaded from proxy at " + CFC_PROXY_BASE);
  }
  $("bs_save").onclick = async () => {
    const base=($("bs_base").value.trim()||"http://127.0.0.1:1234/v1");
    let ma={};
    const raw=$("bs_aliases").value.trim();
    if(raw){try{ma=JSON.parse(raw);}catch{st("Invalid JSON in Model Aliases","e");return;}}
    const payload = {
      apiBaseUrl:     base,
      apiKey:         $("bs_key").value.trim(),
      authToken:      $("bs_auth").value.trim(),
      email:          $("bs_email").value.trim()||"user@local",
      username:       $("bs_user").value.trim()||"local-user",
      licenseKey:     $("bs_lic").value.trim(),
      blockAnalytics: $("bs_block").checked,
      modelAliases:   ma,
    };
    let proxyOk = false;
    try {
      const r = await fetch(CFC_PROXY_BASE + "api/identity", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify(payload),
      });
      const d = await r.json();
      proxyOk = !!d.ok;
      if (!proxyOk) { st("Proxy save error: "+(d.error||"unknown"),"e"); }
    } catch(e) {
      st("\u2717 Proxy unreachable -- saved to chrome.storage only: "+e.message,"w");
    }
    await chrome.storage.local.set({
      ANTHROPIC_BASE_URL:   base,
      ANTHROPIC_API_KEY:    $("bs_key").value.trim(),
      ANTHROPIC_AUTH_TOKEN: $("bs_auth").value.trim(),
      email:      $("bs_email").value.trim()||"user@local",
      username:   $("bs_user").value.trim()||"local-user",
      licenseKey: $("bs_lic").value.trim(),
      hijackSettings:{backendUrl:base,modelAliases:ma,blockAnalytics:$("bs_block").checked},
    });
    try{localStorage.setItem("apiBaseUrl",base);}catch(e){}
    try {
      if (chrome?.runtime?.sendMessage) {
        chrome.runtime.sendMessage({type:"_update_options"}, ()=>{});
      }
    } catch(e) {}
    if (proxyOk) {
      st("\u2714 Saved to proxy + mirror. Backend: "+base);
    } else {
      st("\u26a0 Saved locally only (proxy unreachable). Backend: "+base, "w");
    }
  };
  $("bs_test").onclick = async () => {
    const url=$("bs_base").value.trim()||"http://127.0.0.1:1234/v1";
    st("Testing "+url+"\u2026","w");
    try{
      const r=await fetch(url.replace(/\/v1\/?$/,"")+"/v1/models");
      if(r.ok){const d=await r.json();st("\u2714 Models: "+(d.data?.map(m=>m.id).join(", ")||"OK"));}
      else st("HTTP "+r.status,"e");
    }catch(e){st("\u2717 Cannot reach "+url,"e");}
  };
  $("bs_adv").onclick=()=>{const p=$("bs_ap");p.style.display=p.style.display==="none"?"block":"none";};
  $("bs_clear").onclick=async()=>{
    if(!confirm("Clear all saved Backend Settings (proxy + chrome.storage)?"))return;
    try {
      await fetch(CFC_PROXY_BASE + "api/identity", {
        method:  "POST",
        headers: {"Content-Type":"application/json"},
        body:    JSON.stringify({
          apiBaseUrl:     "http://127.0.0.1:1234/v1",
          apiKey:         "",
          authToken:      "",
          email:          "user@local",
          username:       "local-user",
          licenseKey:     "",
          blockAnalytics: true,
          modelAliases:   {},
        }),
      });
    } catch(e) {}
    await chrome.storage.local.remove(KEYS);
    try{localStorage.removeItem("apiBaseUrl");}catch(e){}
    st("\u2714 Cleared (proxy + mirror)");setTimeout(()=>location.reload(),600);
  };
  $("bs_dump").onclick=async()=>{
    const all=await chrome.storage.local.get(null);
    const MASK=/^(ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|licenseKey|accessToken|refreshToken|sidepanelToken)$/;
    const pre=$("bs_pre");
    pre.textContent=JSON.stringify(all,(k,v)=>MASK.test(k)&&typeof v==="string"&&v.length>8?v.slice(0,4)+"\u2026"+v.slice(-4):v,2);
    pre.style.display="block";
    console.log("[cfc] storage.local dump:",all);
    st("\u2714 Dumped to console");
  };
})();
"""
    (OUTPUT_DIR / "assets" / "backend_settings_ui.js").write_text(ui, encoding="utf-8")
    print(f"[OK] assets/backend_settings_ui.js ({len(ui)} bytes)")


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
        content  = html_file.read_text(encoding="utf-8")
        orig_len = len(content)
        lines, new_lines, skip = content.split("\n"), [], False
        for line in lines:
            if "<script" in line:
                if 'src=' in line or 'type="module"' in line or "type='module'" in line:
                    new_lines.append(line); skip = False
                else:
                    skip = True
            elif "</script>" in line and skip:
                skip = False
            elif not skip:
                new_lines.append(line)
        content = "\n".join(new_lines)
        content = re.sub(r"<script>\s*</script>", "", content, flags=re.DOTALL)
        html_file.write_text(content, encoding="utf-8")
        print(f"[OK] {html_file.name} -- stripped {orig_len - len(content)} bytes inline scripts")

    stub = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="0;url=/options.html#backendsettings">
<title>Backend Settings</title></head>
<body><p>Redirecting to <a href="/options.html#backendsettings">Backend Settings</a>...</p></body>
</html>"""
    bs = OUTPUT_DIR / "backend_settings.html"
    og = OUTPUT_DIR / "backend_settingsOG.html"
    if bs.exists() and not og.exists():
        shutil.copy2(bs, og)
        print("[OK] backend_settings.html --> backend_settingsOG.html (preserved)")
    bs.write_text(stub, encoding="utf-8")
    if not og.exists():
        og.write_text(stub, encoding="utf-8")
    print("[OK] backend_settings.html (meta-refresh stub)")


def inject_index_module():
    assets = OUTPUT_DIR / "assets"
    target = None
    known  = assets / "index-BVS4T5_D.js"
    if known.exists():
        target = known
        print(f"  jsx-runtime: {target.relative_to(OUTPUT_DIR)} (known)")
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
                        print(f"  jsx-runtime: {target.relative_to(OUTPUT_DIR)} (modulepreload)")
                        break
    if not target:
        for f in sorted(assets.glob("index-*.js")):
            if f.stat().st_size < 30000:
                t = f.read_text(encoding="utf-8")
                if "jsx" in t and "jsxs" in t and "Fragment" in t:
                    target = f
                    print(f"  jsx-runtime: {target.relative_to(OUTPUT_DIR)} (scan)")
                    break
    if not target:
        print("[WARN] jsx-runtime not found -- setJsx not injected")
        return
    content = target.read_text(encoding="utf-8")
    if "setJsx" in content:
        print(f"[OK] setJsx already in {target.relative_to(OUTPUT_DIR)} -- skip")
        return
    m        = re.search(r",(\w)=\{\}[,;]", content) or re.search(r"(\w)=\{\}", content)
    var_name = m.group(1) if m else "l"
    print(f"  jsx var: {var_name}")
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
    print(f"[OK] Injected setJsx({var_name}) --> {target.relative_to(OUTPUT_DIR)}")

# ─── local auth responses ─────────────────────────────────────────────────────

def _jwt(payload: dict) -> str:
    h = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    b = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    return f"{h}.{b}.local"

# Cached at startup -- every /oauth/token call returns the SAME token.
# If iat changes on each call, useStorageState sees a new value in storage
# every time the sidepanel refreshes the token, which fires the onChanged
# listener and can feed the setState loop.
_LOCAL_TOKEN_CACHE: dict = {}

def build_local_token() -> dict:
    global _LOCAL_TOKEN_CACHE
    if _LOCAL_TOKEN_CACHE:
        return _LOCAL_TOKEN_CACHE
    now = int(time.time())
    p   = {"iss": "cfc", "sub": "ac507011-00b5-56c4-b3ec-ad820dbafbc1",
           "exp": now + 315360000, "iat": now}
    tok = _jwt(p)
    _LOCAL_TOKEN_CACHE = {"access_token": tok, "token_type": "bearer",
                          "expires_in": 315360000, "refresh_token": tok,
                          "scope": "user:profile user:inference user:chat"}
    return _LOCAL_TOKEN_CACHE


LOCAL_ACCOUNT = {
    "uuid": _UUID_U, "id": _UUID_U,
    "email_address": _EMAIL, "email": _EMAIL,
    "full_name": "Local User", "name": "Local User", "display_name": "Local User",
    "has_password": True, "has_completed_onboarding": True,
    "preferred_language": "en-US", "has_claude_pro": True,
    "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z",
    "settings": {"theme": "system", "language": "en-US"},
}
LOCAL_ORG = {
    "uuid": _UUID_O, "id": _UUID_O, "name": "Local", "role": "admin",
    "organization_type": "personal", "billing_type": "self_serve",
    "capabilities": ["chat", "claude_pro_plan", "api", "computer_use", "claude_for_chrome"],
    "rate_limit_tier": "default_claude_pro", "settings": {},
    "created_at": "2024-01-01T00:00:00Z",
}

# CFC9: LOCAL_BOOTSTRAP uses FEATURES_PAYLOAD for Statsig feature gates
LOCAL_BOOTSTRAP = {
    **THIN_PROFILE,
    "account_uuid": _UUID_U,
    "account": THIN_PROFILE["account"],
    "organization": THIN_PROFILE["organization"],
    "organizations": [THIN_PROFILE["organization"]],
    "memberships": [{"organization": THIN_PROFILE["organization"], "role": "admin",
                     "joined_at": "2024-01-01T00:00:00Z"}],
    "active_organization_uuid": _UUID_O,
    "statsig": {
        "user": {"userID": _UUID_U, "custom": {"organization_uuid": _UUID_O}},
        "values": {
            "feature_gates": {
                k: {"value": v["value"], "rule_id": v.get("rule_id", "default"),
                    "secondary_exposures": []}
                for k, v in FEATURES_PAYLOAD["features"].items()
                if isinstance(v.get("value"), bool)
            },
            "dynamic_configs": {
                k: {"value": v["value"], "rule_id": v.get("rule_id", "default"),
                    "secondary_exposures": []}
                for k, v in FEATURES_PAYLOAD["features"].items()
                if isinstance(v.get("value"), dict)
            },
            "layer_configs": {},
        },
    },
    "flags": {},
    "features": FEATURES_PAYLOAD["features"],
    "active_flags": {},
    "has_claude_pro": True,
    "chat_enabled": True,
    "capabilities": ["chat", "claude_pro_plan", "api", "computer_use", "claude_for_chrome"],
    "rate_limit_tier": "default_claude_pro",
    "settings": {"theme": "system", "language": "en-US"},
}

def get_local_auth(path: str):
    # Verbatim-verified shapes from live cfc.aroic.workers.dev 2026-04-27
    if "/licenses/verify"        in path: return {"valid": True, "license": "local", "tier": "pro", "expires": "2099-12-31"}
    if "/mcp/v2/bootstrap"       in path: return {"servers": [], "tools": [], "enabled": False}
    if "/features/"              in path: return FEATURES_PAYLOAD
    if "/oauth/token"            in path: return build_local_token()
    if "/oauth/account/settings" in path: return {"enabled_mcp_tools": {}}
    if "/oauth/profile"          in path: return THIN_PROFILE
    if "/oauth/account"          in path: return THIN_PROFILE
    if "/bootstrap"              in path: return LOCAL_BOOTSTRAP
    if "/oauth/organizations"    in path:
        tail = path.split("/oauth/organizations/", 1)[1] if "/oauth/organizations/" in path else ""
        if "/" in tail:  return {}
        if tail:         return THIN_PROFILE["organization"]
        return [THIN_PROFILE["organization"]]
    if "/chat_conversations"     in path: return []
    if "/api/web/domain_info"    in path: return {"category": "unknown"}
    if "/url_hash_check"         in path: return {"allowed": True}
    # Routes cocodem 404s -- return None so handler sends 404
    return None



def _redirect_page_html() -> str:
    eid = EXTENSION_ID
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Authenticating\u2026</title></head>
<body style="background:#f9f8f3;font-family:-apple-system,sans-serif;display:flex;
             align-items:center;justify-content:center;height:100vh;margin:0">
<div style="background:white;border:1px solid #e5e2d9;border-radius:32px;padding:40px;
            max-width:400px;width:100%;text-align:center">
  <h2 style="margin:0 0 8px;font-size:22px;font-family:'Iowan Old Style',Georgia,serif;
             font-weight:400;color:#1d1b16">Signed in!</h2>
  <p id="msg" style="color:#8b856c;font-size:13px;font-weight:500;margin:8px 0">Working\u2026</p>
</div>
<script>
(async()=>{{
  const msg=document.getElementById("msg");
  const done=t=>{{msg.textContent=t;msg.style.color="#2d6a4f";
    setTimeout(()=>{{try{{window.close()}}catch(e){{}}}},800)}};
  try{{
    const p=new URLSearchParams(window.location.search);
    const r=p.get("redirect_uri")||"",state=p.get("state")||"";
    let eid="{eid}";
    if(r.startsWith("chrome-extension://")){{try{{eid=new URL(r).host}}catch(e){{}}}}
    // FIX: static token values throughout. Dynamic Date.now()+31536000000 for
    // tokenExpiry/sidepanelTokenExpiry caused Chrome to always detect a changed
    // value vs what the SW bootstrap wrote, firing onChanged on EVERY auth flow,
    // triggering useStorageState Gb->Array.map->Gb recursion -> React #185.
    // Static 9999999999999 matches the SW bootstrap exactly -> Chrome sees no
    // diff -> fires zero onChanged -> zero #185.
    // sidepanelToken "cfc-local-permanent" matches SW bootstrap exactly for
    // the same reason (was "cfc-local", which is a different string -> diff ->
    // onChanged -> #185).
    const STATIC_EXPIRY = 9999999999999;
    const STATIC_TOKEN = btoa(JSON.stringify({{alg:"none",typ:"JWT"}}))+"."+
      btoa(JSON.stringify({{iss:"cfc",sub:"{_UUID_U}",exp:9999999999,
        iat:1700000000}}))+".local";
    if(typeof chrome!=="undefined"&&chrome.runtime&&eid){{
      chrome.runtime.sendMessage(eid,{{type:"_set_storage_local",data:{{
        accessToken:     STATIC_TOKEN,
        refreshToken:    "local-refresh",
        tokenExpiry:     STATIC_EXPIRY,
        accountUuid:     "{_UUID_U}",
        sidepanelToken:  "cfc-local-permanent",
        sidepanelTokenExpiry: STATIC_EXPIRY,
      }}}},rv=>{{
        if(chrome.runtime.lastError||!rv?.success){{
          chrome.runtime.sendMessage(eid,{{type:"_set_storage_local",data:{{
            accessToken:     STATIC_TOKEN,
            refreshToken:    "local-refresh",
            tokenExpiry:     STATIC_EXPIRY,
            accountUuid:     "{_UUID_U}",
            sidepanelToken:  "cfc-local-permanent",
            sidepanelTokenExpiry: STATIC_EXPIRY,
          }}}},()=>done("Done!"));
        }}else done("Done!");
      }});
    }}else done("Auth complete.");
  }}catch(e){{msg.textContent="Error: "+e.message;msg.style.color="#b04a3d"}}
}})();
</script></body></html>"""


def _build_proxy_settings_html() -> str:
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
.backend{{border:1px solid #e5e2d9;border-radius:12px;padding:18px;margin-bottom:12px;background:#fcfbf9}}
.bhead{{display:flex;align-items:center;gap:8px;margin-bottom:14px}}
.bname{{font-weight:700;font-size:14px;flex:1;color:#1d1b16}}
.badge{{font-size:10px;background:#e5e2d9;color:#6b6651;padding:2px 7px;border-radius:4px;font-weight:700}}
.row{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
label{{display:block;font-size:9px;font-weight:900;color:#8B856C;text-transform:uppercase;letter-spacing:.15em;margin:10px 0 4px 2px}}
input{{width:100%;height:38px;padding:0 12px;border:1px solid #e5e2d9;background:white;color:#1d1b16;border-radius:8px;font-size:13px;font-family:monospace;outline:none;transition:border-color .15s}}
input:focus{{border-color:#c45f3d;box-shadow:0 0 0 3px rgba(196,95,61,.08)}}
.actions{{display:flex;gap:6px}}
.btn{{height:34px;border:none;border-radius:7px;font-size:12px;font-weight:700;cursor:pointer;padding:0 14px;transition:all .15s}}
.btn-del{{background:#fbe7e1;color:#b04a3d}}
.btn-tst{{background:#f0f0ea;color:#3d3929}}
.btn-add{{background:#e6f2eb;color:#2d6a4f;width:100%;height:40px;font-size:13px;margin-top:4px}}
.btn-save{{background:#c45f3d;color:white;width:100%;height:46px;font-size:15px;margin-top:16px;border-radius:12px}}
.ts{{font-size:11px;margin-top:6px;min-height:16px;font-weight:600}}
.st{{padding:11px 16px;border-radius:10px;margin-bottom:16px;font-size:13px;font-weight:600;display:none}}
.ok{{display:block;background:#e6f2eb;color:#2d6a4f}}
.er{{display:block;background:#fbe7e1;color:#b04a3d}}
</style></head>
<body><div class="w">
  <h1>CFC Backend Settings</h1>
  <p class="sub">Remote: <code>{REMOTE_BASE}</code> &nbsp;\u00b7&nbsp; Local: <code>{CFC_BASE}</code><br>
    First backend whose models list matches the request model wins.<br>
    Empty models list = catch-all. Changes apply on save.</p>
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
  document.getElementById("list").innerHTML=B.map((b,i)=>
  `<div class="backend" id="b${{i}}">
    <div class="bhead">
      <span class="bname">${{esc(b.name)||"Backend "+(i+1)}}</span>
      ${{!b.models?.length?"<span class='badge'>catch-all</span>":""}}
      <div class="actions">
        <button class="btn btn-tst" onclick="testBackend(${{i}})">Test</button>
        ${{B.length>1?`<button class='btn btn-del' onclick='del(${{i}})'>Remove</button>`:""}}
      </div>
    </div>
    <div class="row">
      <div><label>Name</label>
        <input value="${{esc(b.name)}}" onchange="upd(${{i}},'name',this.value)" placeholder="e.g. LM Studio"></div>
      <div><label>Base URL (/v1)</label>
        <input value="${{esc(b.url)}}" onchange="upd(${{i}},'url',this.value)" placeholder="http://127.0.0.1:1234/v1"></div>
    </div>
    <label>API Key (blank = pass through extension key)</label>
    <input type="password" value="${{esc(b.key)}}" onchange="upd(${{i}},'key',this.value)" placeholder="sk-...">
    <label>Models (comma-separated -- blank = catch-all)</label>
    <input value="${{esc((b.models||[]).join(", "))}}"
      onchange="upd(${{i}},'models',this.value.split(',').map(s=>s.trim()).filter(Boolean))"
      placeholder="claude-opus-4-7, claude-sonnet-4-6">
    <div class="ts" id="ts${{i}}"></div>
  </div>`).join("");
}}
window.upd=function(i,k,v){{B[i][k]=v}};
window.del=function(i){{B.splice(i,1);render()}};
window.addBackend=function(){{
  B.push({{name:"",url:"http://127.0.0.1:1234/v1",key:"",models:[],enabled:true}});
  render();
  setTimeout(()=>document.getElementById("b"+(B.length-1))?.scrollIntoView({{behavior:"smooth"}}),50);
}};
window.testBackend=async function(i){{
  const b=B[i],el=document.getElementById("ts"+i);
  el.textContent="Testing...";el.style.color="#6b6651";
  try{{
    const h=b.key?{{Authorization:"Bearer "+b.key}}:{{}};
    const r=await fetch(b.url.replace(/\/v1\/?$/,"")+"/v1/models",{{headers:h}});
    if(r.ok){{const d=await r.json();el.textContent="\u2713 "+(d.data||[]).map(m=>m.id).slice(0,4).join(", ");el.style.color="#2d6a4f";}}
    else{{el.textContent="\u2717 HTTP "+r.status;el.style.color="#b04a3d"}}
  }}catch(e){{el.textContent="\u2717 "+e.message;el.style.color="#b04a3d"}}
}};
window.save=async function(){{
  try{{
    const r=await fetch("/api/backends",{{method:"POST",
      headers:{{"Content-Type":"application/json"}},body:JSON.stringify({{backends:B}})}});
    const d=await r.json();
    if(d.ok)st("\u2713 Saved");else st("Error: "+(d.error||"unknown"),true);
  }}catch(e){{st("Save failed: "+e.message,true)}}
}};
(async()=>{{
  try{{
    const r=await fetch("/api/backends");
    const d=await r.json();
    B=d.backends||[];
    if(!B.length)B=[{{name:"Default",url:"http://127.0.0.1:1234/v1",key:"",models:[],enabled:true}}];
    render();
  }}catch(e){{st("Cannot reach proxy: "+e.message,true)}}
}})();
</script></body></html>"""


def _build_arc_split_view_html() -> str:
    """Real arc split-view HTML -- two-panel layout for the arc page."""
    return """<div style="display:flex;height:100vh;width:100vw;overflow:hidden;font-family:-apple-system,sans-serif">
  <div id="web-panel" style="flex:1;border-right:1px solid #e5e2d9;display:flex;flex-direction:column;min-width:0">
    <div style="height:44px;border-bottom:1px solid #e5e2d9;display:flex;align-items:center;padding:0 12px;background:#f9f8f3;gap:8px">
      <div style="flex:1;height:32px;background:white;border:1px solid #e5e2d9;border-radius:8px;display:flex;align-items:center;padding:0 10px;font-size:13px;color:#8b856c">Web Panel</div>
    </div>
    <div style="flex:1;background:white;overflow:auto;padding:20px;color:#3d3929">
      <p style="color:#8b856c;font-size:13px">Select a tab or enter a URL to browse alongside Claude.</p>
    </div>
  </div>
  <div id="claude-panel" style="flex:1;display:flex;flex-direction:column;min-width:0">
    <div style="height:44px;border-bottom:1px solid #e5e2d9;display:flex;align-items:center;padding:0 12px;background:#f9f8f3;gap:8px">
      <div style="flex:1;height:32px;background:white;border:1px solid #e5e2d9;border-radius:8px;display:flex;align-items:center;padding:0 10px;font-size:13px;color:#8b856c">Claude Panel</div>
    </div>
    <div style="flex:1;background:#f9f8f3;overflow:auto;display:flex;align-items:center;justify-content:center">
      <p style="color:#b4af9a;font-size:13px">Claude conversation will appear here.</p>
    </div>
  </div>
</div>"""


def _build_root_page_html() -> str:
    """Real dashboard website served at / -- identical to cocodem's landing page."""
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CFC Multi-Backend Server</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f9f8f3;color:#3d3929;margin:0;padding:0;min-height:100vh}}
.nav{{background:white;border-bottom:1px solid #e5e2d9;padding:0 24px;height:56px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}}
.nav-left{{display:flex;align-items:center;gap:12px}}
.nav-logo{{font-size:18px;font-family:'Iowan Old Style',Georgia,serif;font-weight:400;color:#1d1b16;letter-spacing:-.02em}}
.nav-links{{display:flex;gap:4px}}
.nav-links a{{color:#6b6651;text-decoration:none;font-size:13px;font-weight:600;padding:6px 12px;border-radius:6px;transition:all .15s}}
.nav-links a:hover{{background:#f0f0ea;color:#1d1b16}}
.hero{{padding:64px 24px 48px;text-align:center;max-width:720px;margin:0 auto}}
.hero h1{{font-size:36px;font-family:'Iowan Old Style',Georgia,serif;font-weight:400;color:#1d1b16;margin:0 0 16px;letter-spacing:-.03em;line-height:1.2}}
.hero p{{font-size:15px;color:#6b6651;margin:0 0 32px;line-height:1.7}}
.btn-primary{{display:inline-flex;align-items:center;gap:8px;height:44px;padding:0 24px;background:#c45f3d;color:white;border:none;border-radius:12px;font-size:15px;font-weight:700;cursor:pointer;text-decoration:none;transition:all .15s;box-shadow:0 4px 14px rgba(196,95,61,.12)}}
.btn-primary:hover{{transform:translateY(-1px);box-shadow:0 6px 20px rgba(196,95,61,.18)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px;max-width:900px;margin:0 auto;padding:0 24px 48px}}
.card{{background:white;border:1px solid #e5e2d9;border-radius:20px;padding:28px;transition:all .15s}}
.card:hover{{box-shadow:0 8px 32px rgba(0,0,0,.06);transform:translateY(-2px)}}
.card-icon{{width:40px;height:40px;border-radius:12px;background:#fcfbf9;border:1px solid #e5e2d9;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:16px}}
.card h3{{font-size:15px;font-weight:700;color:#1d1b16;margin:0 0 8px}}
.card p{{font-size:13px;color:#6b6651;margin:0;line-height:1.6}}
.status{{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:700;margin-top:12px}}
.status-dot{{width:8px;height:8px;border-radius:50%;background:#2d6a4f;animation:pulse 2s infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.5}}}}
.footer{{text-align:center;padding:32px 24px;border-top:1px solid #e5e2d9;margin-top:auto}}
.footer p{{font-size:12px;color:#b4af9a;margin:0}}
</style></head>
<body>
<div class="nav">
  <div class="nav-left">
    <span class="nav-logo">CFC Server</span>
  </div>
  <div class="nav-links">
    <a href="/backend_settings">Backends</a>
    <a href="/oauth/authorize">OAuth</a>
    <a href="/api/options">Config</a>
    <a href="/api/identity">Identity</a>
  </div>
</div>
<div class="hero">
  <h1>Multi-Backend C2 Server</h1>
  <p>Local remote server identical to cocodem's infrastructure. Model-based routing, per-backend API keys, SSE streaming, failover -- all running on port {CFC_PORT}.<br>
  Remote Worker: <code style="font-size:13px">{REMOTE_BASE}</code></p>
  <a href="/backend_settings" class="btn-primary">\u2699\ufe0f Backend Settings</a>
</div>
<div class="grid">
  <div class="card">
    <div class="card-icon">\u2197\ufe0f</div>
    <h3>API Proxy</h3>
    <p>All /v1/* requests are routed to configured backends based on model matching, with automatic failover.</p>
    <div class="status"><span class="status-dot"></span>Active</div>
  </div>
  <div class="card">
    <div class="card-icon">\ud83d\udd10</div>
    <h3>Local Auth</h3>
    <p>OAuth, bootstrap, profile, and account endpoints are answered locally. No Anthropic account needed.</p>
    <div class="status"><span class="status-dot"></span>Active</div>
  </div>
  <div class="card">
    <div class="card-icon">\ud83d\udee1\ufe0f</div>
    <h3>License Gate</h3>
    <p>License verification always returns valid. No calls to external license servers.</p>
    <div class="status"><span class="status-dot"></span>Active</div>
  </div>
  <div class="card">
    <div class="card-icon">\ud83d\udeab</div>
    <h3>Telemetry Block</h3>
    <p>Segment, Statsig, Sentry, Datadog, FingerprintJS -- all dropped with 204 No Content.</p>
    <div class="status"><span class="status-dot"></span>Active</div>
  </div>
  <div class="card">
    <div class="card-icon">\u2699\ufe0f</div>
    <h3>Backend Management</h3>
    <p>Add multiple backends with per-backend API keys and model aliases. Test connectivity live.</p>
    <div class="status"><span class="status-dot"></span>{len(BACKENDS)} backend(s)</div>
  </div>
  <div class="card">
    <div class="card-icon">\ud83d\udce1</div>
    <h3>Dynamic Serving</h3>
    <p>Every URL returns a real response. No sinkhole -- no 204 for unknown routes. Full C2 replication.</p>
    <div class="status"><span class="status-dot"></span>Active</div>
  </div>
</div>
<div class="footer">
  <p>CFC Multi-Backend Server -- Port {CFC_PORT} -- Remote: {REMOTE_BASE}</p>
</div>
</body></html>"""


def _build_fallback_html(path: str) -> str:
    """Sensible fallback HTML for any route that doesn't match a specific handler."""
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CFC Server -- {path}</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:-apple-system,sans-serif;background:#f9f8f3;color:#3d3929;margin:0;padding:40px 20px;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.w{{background:white;border:1px solid #e5e2d9;border-radius:24px;padding:40px;max-width:480px;width:100%;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.04)}}
h1{{font-size:20px;font-family:'Iowan Old Style',Georgia,serif;font-weight:400;color:#1d1b16;margin:0 0 8px}}
p{{color:#6b6651;font-size:13px;margin:0 0 20px;line-height:1.6}}
a{{color:#c45f3d;text-decoration:none;font-weight:700;font-size:13px}}
a:hover{{text-decoration:underline}}
.code{{background:#fcfbf9;border:1px solid #e5e2d9;border-radius:8px;padding:12px;font-family:monospace;font-size:12px;color:#8b856c;text-align:left;margin-top:16px;overflow-wrap:break-word}}
</style></head>
<body>
<div class="w">
  <h1>CFC Server</h1>
  <p>This route is served dynamically by the local C2 server.</p>
  <a href="/">Back to Dashboard</a>
  <div class="code">{path}</div>
</div>
</body></html>"""

# ─── proxy server ─────────────────────────────────────────────────────────────

class MultiC2Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"  [{time.strftime('%H:%M:%S')}] {args[0]}")

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
            pass

    # ── response helpers ──────────────────────────────────────────────────────

    def _json(self, data, status=200):
        b = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Connection",     "close")
        self._cors()
        self.end_headers()
        try: self.wfile.write(b)
        except OSError: pass

    def _html(self, html):
        b = html.encode()
        self.send_response(200)
        self.send_header("Content-Type",   "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Connection",     "close")
        self._cors()
        self.end_headers()
        try: self.wfile.write(b)
        except OSError: pass

    def _204(self):
        self.send_response(204)
        self.send_header("Connection", "close")
        self._cors()
        self.end_headers()

    def _redirect(self, location, status=302):
        self.send_response(status)
        self.send_header("Location",   location)
        self.send_header("Connection", "close")
        self._cors()
        self.end_headers()

    def _serve_file(self, file_path: Path, content_type: str):
        """Serve a static file from disk."""
        if not file_path.exists():
            self._html(_build_fallback_html(self.path))
            return
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type",   content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection",     "close")
        self._cors()
        self.end_headers()
        try: self.wfile.write(data)
        except OSError: pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin",          "*")
        self.send_header("Access-Control-Allow-Methods",
                         "GET, POST, PATCH, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers",
                         "Content-Type, Cache-Control, Accept, "
                         "anthropic-version, anthropic-beta, "
                         "anthropic-client-platform, anthropic-client-version, "
                         "Authorization, x-app, x-service-name, x-api-key")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age",               "86400")

    # ── route matchers ────────────────────────────────────────────────────────

    def _is_tel(self, p: str) -> bool:
        return any(d in p for d in TELEMETRY_DOMAINS)

    def _is_v1(self, p: str) -> bool:
        if "/v1/oauth" in p:
            return False
        if p.startswith("/v1/"):
            return True
        if "/v1/" in p and (
            "api.anthropic.com" in p or
            p.startswith("/https://api.anthropic.com/") or
            "cfc.aroic.workers.dev" in p
        ):
            return True
        return False

    def _is_auth(self, p: str) -> bool:
        if p.startswith("/https://") or p.startswith("/http://"):
            return True
        if p.startswith("/chrome-extension://"):
            return True
        return any(s in p for s in [
            "/oauth/", "/bootstrap", "/domain_info", "/chat_conversations",
            "/organizations", "/url_hash_check", "/api/web/", "/features/",
            "/spotlight", "/usage", "/entitlements", "/flags", "/mcp/v2/",
            "/licenses/",
        ])

    def _try_static_asset(self, p: str) -> bool:
        """Try to serve a static file from OUTPUT_DIR. Returns True if served."""
        if not p.startswith("/"):
            return False
        rel_path  = p.lstrip("/").split("?")[0]
        file_path = OUTPUT_DIR / rel_path
        if not file_path.exists() or not file_path.is_file():
            return False
        ct, _ = mimetypes.guess_type(str(file_path))
        if not ct:
            ext = file_path.suffix.lower()
            ct = {
                ".js":    "application/javascript; charset=utf-8",
                ".css":   "text/css; charset=utf-8",
                ".html":  "text/html; charset=utf-8",
                ".json":  "application/json",
                ".png":   "image/png",
                ".jpg":   "image/jpeg",
                ".jpeg":  "image/jpeg",
                ".svg":   "image/svg+xml",
                ".ico":   "image/x-icon",
                ".woff2": "font/woff2",
                ".woff":  "font/woff",
            }.get(ext, "application/octet-stream")
        self._serve_file(file_path, ct)
        return True

    # ── /v1/* forwarding ──────────────────────────────────────────────────────

    def _v1_path_suffix(self, p: str) -> str:
        """Extract bare suffix after /v1 from any path variant."""
        if p.startswith("/v1/"):
            return p[3:]
        idx = p.find("/v1/")
        if idx != -1:
            return p[idx + 3:]
        return p

    def _stream_sse(self, resp):
        """Write SSE (text/event-stream) response using HTTP chunked encoding."""
        ct = resp.headers.get("Content-Type", "text/event-stream")
        self.send_header("Content-Type",      ct)
        self.send_header("Cache-Control",     "no-cache")
        self.send_header("Connection",        "keep-alive")
        self.send_header("Transfer-Encoding", "chunked")
        self._cors()
        self.end_headers()
        try:
            while True:
                chunk = resp.read(4096)
                if not chunk:
                    break
                self.wfile.write(f"{len(chunk):x}\r\n".encode())
                self.wfile.write(chunk)
                self.wfile.write(b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (OSError, BrokenPipeError):
            pass
        finally:
            resp.close()

    def _forward_v1(self, method: str, body: bytes):
        """Forward /v1/* to the best available backend with failover."""
        model = ""
        if body:
            try: model = json.loads(body).get("model", "")
            except Exception: pass

        suffix = self._v1_path_suffix(self.path)

        ALLOW_HDRS = {
            "content-type", "accept", "authorization",
            "anthropic-version", "anthropic-beta",
            "anthropic-client-platform", "anthropic-client-version",
            "x-api-key", "x-service-name",
        }
        base_hdrs = {k: v for k, v in self.headers.items()
                     if k.lower() in ALLOW_HDRS}
        ext_auth  = self.headers.get("Authorization", "")

        last_err = None

        for backend in _pick_backends(model):
            target = backend["url"].rstrip("/") + suffix
            hdrs   = dict(base_hdrs)

            if backend.get("key"):
                hdrs["Authorization"] = f"Bearer {backend['key']}"
            elif ext_auth:
                hdrs["Authorization"] = ext_auth

            send_body = body
            if send_body and method in ("POST", "PUT", "PATCH"):
                try:
                    parsed = json.loads(send_body)
                    aliases = {**(_merged_model_alias()), **(backend.get("modelAlias") or {})}
                    if parsed.get("model") and aliases.get(parsed["model"]):
                        parsed["model"] = aliases[parsed["model"]]
                        send_body = json.dumps(parsed).encode()
                except Exception:
                    pass

            req = urllib.request.Request(
                target,
                data=send_body or None,
                headers=hdrs,
                method=method,
            )
            print(f"  [FWD\u2192{backend.get('name','?')}] {method} {target}"
                  + (f" [{model}]" if model else ""))

            try:
                resp = urllib.request.urlopen(req, timeout=300)
                ct   = resp.headers.get("Content-Type", "")
                self.send_response(resp.status)
                if "text/event-stream" in ct:
                    self._stream_sse(resp)
                else:
                    data = resp.read()
                    resp.close()
                    self.send_header("Content-Type",   ct or "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Connection",     "close")
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
                                     e.headers.get("Content-Type", "application/json"))
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Connection",     "close")
                    self._cors()
                    self.end_headers()
                    try: self.wfile.write(data)
                    except OSError: pass
                    return
                last_err = e
                print(f"  [FAIL\u2192{backend.get('name','?')}] HTTP {e.code} -- trying next")

            except Exception as ex:
                last_err = ex
                print(f"  [FAIL\u2192{backend.get('name','?')}] {ex} -- trying next")

        err = json.dumps({"error": {
            "type":    "proxy_error",
            "message": f"All backends failed. Last: {last_err}",
        }}).encode()
        self.send_response(502)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(err)))
        self.send_header("Connection",     "close")
        self._cors()
        self.end_headers()
        try: self.wfile.write(err)
        except OSError: pass

    # ── HTTP verbs ────────────────────────────────────────────────────────────

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Connection", "close")
        self._cors()
        self.end_headers()

    def do_GET(self):
        p = self.path

        # 1. Telemetry -- always 204 first, before everything
        if self._is_tel(p): self._204(); return

        # 2. Static assets from OUTPUT_DIR (JS, CSS, images, fonts, etc.)
        if self._try_static_asset(p): return

        # 3. /v1/* API proxy
        if self._is_v1(p): self._forward_v1("GET", b""); return

        # 4. Live options response built from IDENTITY + BACKENDS
        if p.startswith("/api/options"):
            self._json(_build_options_response()); return

        # 5. Identity GET -- server-side source of truth
        if p.startswith("/api/identity"):
            self._json({
                "apiBaseUrl":     IDENTITY.get("apiBaseUrl") or DEFAULT_BACKEND_URL,
                "apiKey":         IDENTITY.get("apiKey", ""),
                "authToken":      IDENTITY.get("authToken", ""),
                "email":          IDENTITY.get("email", "user@local"),
                "username":       IDENTITY.get("username", "local-user"),
                "licenseKey":     IDENTITY.get("licenseKey", ""),
                "blockAnalytics": bool(IDENTITY.get("blockAnalytics", True)),
                "modelAliases":   IDENTITY.get("modelAliases") or {},
                "mode":           IDENTITY.get("mode", "") or "",
            }); return

        # 6. Backend management
        if p.startswith("/api/backends"):
            self._json({"backends": BACKENDS}); return

        # 7. Arc split view -- real two-panel HTML
        if p.startswith("/api/arc-split-view"):
            self._json({"html": _build_arc_split_view_html()}); return

        # 8. Discard endpoint
        if p.startswith("/discard"):
            self._204(); return

        # 9. OAuth authorize -- redirect to local redirect page
        if "/oauth/authorize" in p:
            qs = urlparse(p).query
            self._redirect(f"{CFC_BASE}oauth/redirect?{qs}")
            return

        # 10. OAuth redirect page
        if p.startswith("/oauth/redirect"):
            self._html(_redirect_page_html()); return

        # 11. Backend settings page
        if p.startswith("/backend_settings"):
            self._html(_build_proxy_settings_html()); return

        # 12. Auth/bootstrap endpoints (including license verification)
        if self._is_auth(p):
            _resp = get_local_auth(p)
            if _resp is None: self.send_error(404); return
            self._json(_resp); return

        # 13. Root / -- real dashboard website
        if p in ("/",) or p.startswith("/?"):
            self._html(_build_root_page_html()); return

        # 14. Fallback -- real HTML, NEVER 204
        self._html(_build_fallback_html(p))

    def do_POST(self):
        cl   = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl) if cl > 0 else b""
        p    = self.path

        if self._is_tel(p): self._204(); return

        # Backend management
        if p.startswith("/api/backends"):
            try:
                cfg = json.loads(body)
                bs  = cfg.get("backends", [])
                if not isinstance(bs, list) or not bs:
                    self._json({"error": "backends must be a non-empty list"}); return
                for b in bs:
                    if not isinstance(b, dict):
                        self._json({"error": "each backend must be an object"}); return
                    b.setdefault("name",       "")
                    b.setdefault("url",        DEFAULT_BACKEND_URL)
                    b.setdefault("key",        "")
                    b.setdefault("models",     [])
                    b.setdefault("modelAlias", {})
                    b.setdefault("enabled",    True)
                BACKENDS.clear()
                BACKENDS.extend(bs)
                _save_backends()
                self._json({"ok": True, "backends": BACKENDS})
            except Exception as ex:
                self._json({"error": str(ex)})
            return

        # Identity update -- proxy is source of truth
        if p.startswith("/api/identity"):
            try:
                cfg = json.loads(body)
                ALLOWED = {"apiBaseUrl", "apiKey", "authToken",
                           "email", "username", "licenseKey",
                           "blockAnalytics", "modelAliases", "mode"}
                for k, v in cfg.items():
                    if k in ALLOWED:
                        IDENTITY[k] = v
                if not isinstance(IDENTITY.get("modelAliases"), dict):
                    IDENTITY["modelAliases"] = {}
                IDENTITY["blockAnalytics"] = bool(IDENTITY.get("blockAnalytics", True))
                _save_identity()
                self._json({"ok": True, "identity": {
                    "apiBaseUrl":     IDENTITY.get("apiBaseUrl") or DEFAULT_BACKEND_URL,
                    "apiKey":         IDENTITY.get("apiKey", ""),
                    "authToken":      IDENTITY.get("authToken", ""),
                    "email":          IDENTITY.get("email", "user@local"),
                    "username":       IDENTITY.get("username", "local-user"),
                    "licenseKey":     IDENTITY.get("licenseKey", ""),
                    "blockAnalytics": bool(IDENTITY.get("blockAnalytics", True)),
                    "modelAliases":   IDENTITY.get("modelAliases") or {},
                    "mode":           IDENTITY.get("mode", "") or "",
                }})
            except Exception as ex:
                self._json({"error": str(ex)})
            return

        if self._is_v1(p):   self._forward_v1("POST", body); return
        if self._is_auth(p):
            _resp = get_local_auth(p)
            if _resp is None: self.send_error(404); return
            self._json(_resp); return

        self._json({"ok": True})

    def do_PATCH(self):
        cl   = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl) if cl > 0 else b""
        p    = self.path
        if self._is_tel(p):  self._204(); return
        if self._is_v1(p):   self._forward_v1("PATCH", body); return
        if self._is_auth(p):
            _resp = get_local_auth(p)
            if _resp is None: self.send_error(404); return
            self._json(_resp); return
        self._json({"ok": True})

    def do_PUT(self):
        cl   = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl) if cl > 0 else b""
        p    = self.path
        if self._is_tel(p):  self._204(); return
        if self._is_v1(p):   self._forward_v1("PUT", body); return
        if self._is_auth(p):
            _resp = get_local_auth(p)
            if _resp is None: self.send_error(404); return
            self._json(_resp); return
        self._json({"ok": True})

    def do_DELETE(self):
        cl   = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl) if cl > 0 else b""
        p    = self.path
        if self._is_tel(p):  self._204(); return
        if self._is_v1(p):   self._forward_v1("DELETE", body); return
        if self._is_auth(p):
            _resp = get_local_auth(p)
            if _resp is None: self.send_error(404); return
            self._json(_resp); return
        self._json({"ok": True})



class MultiC2Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads      = True


def start_proxy():
    try:
        server = MultiC2Server(("127.0.0.1", CFC_PORT), MultiC2Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"\n[OK] Remote multi-C2 server running on {CFC_BASE}")
        print(f"     Remote Worker (primary cfcBase): {REMOTE_BASE}")
        print(f"     Replaces: openclaude.111724.xyz + cfc.aroic.workers.dev")
        print(f"     Backends: {len(BACKENDS)}")
        for b in BACKENDS:
            models = ", ".join(b.get("models") or ["(catch-all)"])
            print(f"       \u2022 {b.get('name','?')}: {b['url']} [{models}]")
        print(f"     Identity: {IDENTITY.get('email','?')} / {IDENTITY.get('username','?')}")
        print(f"     License verification: local (always valid)")
        print(f"     Telemetry: blocked (Segment, Statsig, Sentry, Datadog, FingerprintJS)")
        print(f"     /api/identity: GET/POST (proxy is source of truth)")
        print(f"     /api/options:  live from IDENTITY + BACKENDS")
        print(f"     Static assets: served from {OUTPUT_DIR}")
        print(f"     Fallback: real HTML for all unknown routes (NO sinkhole / 204)")
        print(f"\n     Worker JS: call _build_worker_script() and paste into CF dashboard")
        return server
    except OSError as e:
        print(f"[WARN] Cannot bind port {CFC_PORT}: {e}")
        return None


# ─── report ───────────────────────────────────────────────────────────────────

def print_report(m):
    print("\n" + "=" * 62)
    print(f"  DONE -- {OUTPUT_DIR}")
    print("=" * 62)
    print(f"  {m.get('name')} v{m.get('version')}")
    print(f"\n  Install:")
    print(f"  1. Disable cocodem in chrome://extensions/")
    print(f"  2. Enable Developer Mode")
    print(f"  3. Load unpacked --> {OUTPUT_DIR.resolve()}")
    print(f"\n  Backend Settings:")
    print(f"  {BACKEND_SETTINGS_URL}")
    print(f"\n  Local Server:")
    print(f"  {CFC_BASE}")
    print(f"\n  Remote Worker (primary cfcBase in request.js):")
    print(f"  {REMOTE_BASE}")
    print(f"  Replaces: openclaude.111724.xyz + cfc.aroic.workers.dev")
    print(f"\n  Keep terminal open. Ctrl+C to stop.\n")


# ─── main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 62)
    print(f"  Claude Extension Sanitizer -- {TIMESTAMP}")
    print(f"  Source: {COCODEM_SRC}")
    print(f"  Remote: {REMOTE_BASE}")
    print(f"  Local:  {CFC_BASE}")
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
    server = start_proxy()
    print_report(m)
    if server:
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            print("\n[Server] Shutting down...")
            server.shutdown()
    else:
        print("[WARN] Server did not start.")

if __name__ == "__main__":
    main()
