"use strict";

const { requireName } = require("../../scripts/patches/shared.js");

// A SEPARATE in-app update button for the *wrapper* (this repo's own Linux
// features/fixes), distinct from the upstream Codex DMG "Sparkle" button. It
// reads the wrapper-update fields that `codex-update-manager` records in
// state.json and is invisible unless a wrapper update is pending. Clicking it
// writes a `wrapper-update-pending` marker and quits; the launcher applies the
// update on the next start.

const HANDLER_NAME = "codex-linux-wrapper-updater";
const RUNTIME_VERSION = "codex-wrapper-updater-v1";

function warn(message, patchName) {
  console.warn(`WARN: ${message} - skipping ${patchName}`);
}

// ---------------------------------------------------------------------------
// Main bundle: register a handler at vscode://codex/codex-linux-wrapper-updater
// that the renderer-side button calls. Mirrors the DMG codex-updater handler
// but reads the wrapper-axis state fields and writes a distinct marker.
// ---------------------------------------------------------------------------

function applyMainBundlePatch(source) {
  if (source.includes(`"${HANDLER_NAME}":async`)) {
    return source;
  }

  const fsVar = requireName(source, "node:fs");
  const pathVar = requireName(source, "node:path");
  const osVar = requireName(source, "node:os") ?? requireName(source, "os");
  const childProcessVar =
    requireName(source, "node:child_process") ?? requireName(source, "child_process");
  if (fsVar == null || pathVar == null || osVar == null || childProcessVar == null) {
    warn(
      "Could not find node:fs/node:path/node:os/node:child_process deps",
      "codex wrapper updater main-bundle patch",
    );
    return source;
  }

  const helper = [
    `function codexLinuxWrapHome(){return process.env.HOME||${osVar}.homedir?.()||\`\`}`,
    `function codexLinuxWrapStatePath(){let h=codexLinuxWrapHome();let d=process.env.XDG_STATE_HOME||(h&&${pathVar}.join(h,\`.local\`,\`state\`));return d?${pathVar}.join(d,\`codex-update-manager\`,\`state.json\`):null}`,
    `function codexLinuxWrapMarkerPath(){let h=codexLinuxWrapHome();let d=process.env.XDG_STATE_HOME||(h&&${pathVar}.join(h,\`.local\`,\`state\`));return d?${pathVar}.join(d,\`codex-desktop\`,\`wrapper-update-pending\`):null}`,
    `function codexLinuxWrapReadStatus(){try{let p=codexLinuxWrapStatePath();if(!p||!${fsVar}.existsSync(p))return null;return JSON.parse(${fsVar}.readFileSync(p,\`utf8\`))}catch{return null}}`,
    `function codexLinuxWrapShouldShow(s){if(!s||typeof s!==\`object\`)return!1;if(s.wrapper_status===\`applying\`)return!0;return typeof s.candidate_wrapper_commit===\`string\`&&s.candidate_wrapper_commit.length>0}`,
    `function codexLinuxWrapStatusPayload(){let s=codexLinuxWrapReadStatus();return{ok:!0,show:codexLinuxWrapShouldShow(s),working:s&&s.wrapper_status===\`applying\`,changelog:s?s.wrapper_changelog||\`\`:\`\`,commit:s?s.candidate_wrapper_commit||\`\`:\`\`}}`,
    `function codexLinuxWrapManagerPath(){let e=process.env.CODEX_UPDATE_MANAGER_PATH;return typeof e===\`string\`&&e.trim().length>0?e:\`codex-update-manager\`}`,
    `function codexLinuxWrapSpawnCheck(){try{let c=${childProcessVar}.spawn(codexLinuxWrapManagerPath(),[\`check-wrapper\`],{stdio:\`ignore\`,detached:!0,env:process.env});c.on(\`error\`,()=>{});c.unref()}catch{}}`,
    `function codexLinuxWrapWriteMarker(){let p=codexLinuxWrapMarkerPath();if(!p)return{ok:!1,reason:\`no-marker-path\`};try{${fsVar}.mkdirSync(${pathVar}.dirname(p),{recursive:!0});${fsVar}.writeFileSync(p,new Date().toISOString());return{ok:!0,path:p}}catch(e){return{ok:!1,error:String(e?.message||e)}}}`,
    `function codexLinuxWrapInstallNow(){let m=codexLinuxWrapWriteMarker();if(!m.ok)return m;try{let a=require(\`electron\`).app;setTimeout(()=>a.exit(0),200);return{ok:!0}}catch(e){return{ok:!1,error:String(e?.message||e)}}}`,
    `function codexLinuxWrapHandle(e={}){let action=e&&e.action;if(action===\`status\`)return codexLinuxWrapStatusPayload();if(action===\`check\`){codexLinuxWrapSpawnCheck();return{ok:!0}}if(action===\`install\`)return codexLinuxWrapInstallNow();return{ok:!1,reason:\`unknown-action\`}}`,
    // Refresh wrapper state once at module load (primary instance only).
    `(()=>{if(process.env.CODEX_LINUX_MULTI_LAUNCH!==\`1\`)codexLinuxWrapSpawnCheck()})();`,
  ].join("");

  const handler = `"${HANDLER_NAME}":async(e)=>codexLinuxWrapHandle(e),`;
  const needle = `"native-desktop-apps":`;
  const handlerIndex = source.indexOf(needle);
  if (handlerIndex === -1) {
    warn(`Could not find ${needle} handler map needle`, "codex wrapper updater main-bundle patch");
    return source;
  }

  const withHandler = source.slice(0, handlerIndex) + handler + source.slice(handlerIndex);
  const useStrictDouble = `"use strict";`;
  const useStrictSingle = `'use strict';`;
  const helperInsertAt = withHandler.startsWith(useStrictDouble)
    ? useStrictDouble.length
    : withHandler.startsWith(useStrictSingle)
      ? useStrictSingle.length
      : 0;
  return withHandler.slice(0, helperInsertAt) + helper + withHandler.slice(helperInsertAt);
}

// ---------------------------------------------------------------------------
// Webview runtime: a fixed-position "Update" button, positioned left of the
// DMG update button so the two never overlap. Visible only when a wrapper
// update is pending.
// ---------------------------------------------------------------------------

function wrapperRuntimeSource() {
  return [
    `;(()=>{`,
    `const VERSION=${JSON.stringify(RUNTIME_VERSION)};`,
    `if(globalThis.codexLinuxWrapperUpdaterVersion===VERSION)return;`,
    `globalThis.codexLinuxWrapperUpdaterVersion=VERSION;`,
    `const METHOD=${JSON.stringify(HANDLER_NAME)};`,
    `let seq=0,pending=new Map,button=null,busy=false;`,
    `function onMessage(e){let t=e?.data;if(!t||typeof t!=="object"||t.type!=="fetch-response")return;let n=pending.get(t.requestId);if(!n)return;pending.delete(t.requestId);if(t.responseType==="success"){let v=null;try{v=t.bodyJsonString?JSON.parse(t.bodyJsonString):null}catch{}n.resolve({status:t.status,body:v})}else n.reject(Error(t.error||"fetch failed"))}`,
    `window.addEventListener("message",onMessage);`,
    `function dispatch(payload){let bridge=window.electronBridge,ev=new CustomEvent("codex-message-from-view",{detail:payload});if(bridge?.sendMessageFromView){ev.__codexForwardedViaBridge=!0;bridge.sendMessageFromView(payload).catch(()=>{})}window.dispatchEvent(ev)}`,
    `function post(params,timeoutMs=4000){let requestId="codex-linux-wrapper-updater-"+ ++seq;let payload={type:"fetch",hostId:"local",requestId,method:"POST",url:"vscode://codex/"+METHOD,body:JSON.stringify(params??{})};return new Promise((resolve,reject)=>{pending.set(requestId,{resolve,reject});setTimeout(()=>{pending.delete(requestId);reject(Error("timeout"))},timeoutMs);dispatch(payload)})}`,
    `function installStyle(){if(document.getElementById("codex-linux-wrapper-update-style"))return;let s=document.createElement("style");s.id="codex-linux-wrapper-update-style";s.textContent=".codex-linux-wrapper-update-btn{height:22px;padding:0 10px;margin:0 8px;display:none;align-items:center;font:500 12px/1 -apple-system,BlinkMacSystemFont,\\"Segoe UI\\",Roboto,sans-serif;color:#fff;background:#3a7d44;border:1px solid #4a9d54;border-radius:4px;cursor:pointer;pointer-events:auto;-webkit-app-region:no-drag;box-shadow:0 1px 2px rgba(0,0,0,0.18);transition:background-color 120ms ease;vertical-align:middle;line-height:1}.codex-linux-wrapper-update-btn[data-state=\\"available\\"],.codex-linux-wrapper-update-btn[data-state=\\"working\\"]{display:inline-flex}.codex-linux-wrapper-update-btn.codex-linux-wrapper-update-floating{position:fixed;top:6px;right:210px;z-index:2147483000}.codex-linux-wrapper-update-btn:hover{background:#4a9d54}.codex-linux-wrapper-update-btn:disabled{opacity:.7;cursor:default}";document.head.appendChild(s)}`,
    `function findHeaderTarget(){const candidates=["header","[role=\\"banner\\"]","nav[aria-label]"];for(const sel of candidates){const el=document.querySelector(sel);if(el&&el.getBoundingClientRect().top<120&&el.offsetHeight>0)return el}return null}`,
    `function attachButton(b){if(b.parentElement)return;let host=findHeaderTarget();if(host){b.classList.remove("codex-linux-wrapper-update-floating");host.appendChild(b)}else{b.classList.add("codex-linux-wrapper-update-floating");(document.body||document.documentElement).appendChild(b)}}`,
    `function ensureButton(){if(button&&document.contains(button))return button;installStyle();let b=document.createElement("button");b.type="button";b.className="codex-linux-wrapper-update-btn";b.setAttribute("aria-label","Update Codex Desktop Linux");b.title="A newer Codex Desktop Linux build is available";b.textContent="Update";b.addEventListener("click",onClick);button=b;attachButton(b);return b}`,
    `let observer=null;function watchForHeader(){if(observer)return;observer=new MutationObserver(()=>{if(!button)return;if(button.classList.contains("codex-linux-wrapper-update-floating")){let host=findHeaderTarget();if(host){button.classList.remove("codex-linux-wrapper-update-floating");host.appendChild(button)}}else if(!button.parentElement||!document.contains(button.parentElement)){attachButton(button)}});observer.observe(document.body||document.documentElement,{childList:!0,subtree:!0})}`,
    `function setState(payload){let b=ensureButton();if(payload&&payload.working){b.dataset.state="working";b.textContent="Updating…";b.title="Rebuilding Codex Desktop Linux";b.disabled=true;return}if(payload&&payload.show){b.dataset.state="available";b.textContent="Update";b.disabled=false;let cl=(payload.changelog||"").trim();b.title=cl?("What's new:\\n"+cl.split("\\n").slice(0,12).join("\\n")):"A newer Codex Desktop Linux build is available";return}b.dataset.state="hidden"}`,
    `async function onClick(){if(busy)return;busy=true;let b=ensureButton();b.disabled=true;try{let r=await post({action:"install"});if(r&&r.body&&r.body.ok===false){b.title=r.body.error||r.body.reason||"Update failed";setTimeout(()=>{b.title="A newer Codex Desktop Linux build is available"},2400)}}catch{}finally{busy=false;b.disabled=false}}`,
    `async function refresh(){try{let r=await post({action:"status"},2500);setState(r?.body||null)}catch{}}`,
    // Trigger a detection check from the renderer on startup (the spawn reliably
    // runs here), then poll status a few times early so the button appears within
    // seconds of the git check completing instead of waiting a full 30s interval.
    `function start(){if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",start,{once:!0});return}ensureButton();watchForHeader();post({action:"check"}).catch(()=>{});refresh();[2000,5000,9000,15000,22000].forEach(t=>setTimeout(refresh,t));setInterval(()=>{post({action:"check"}).catch(()=>{});setTimeout(refresh,4000)},30000)}`,
    `start();`,
    `})();`,
  ].join("");
}

function applyWebviewRuntimePatch(source) {
  if (source.includes(`codexLinuxWrapperUpdaterVersion=`)) {
    return source;
  }
  return source + wrapperRuntimeSource();
}

module.exports = {
  HANDLER_NAME,
  RUNTIME_VERSION,
  applyMainBundlePatch,
  applyWebviewRuntimePatch,
  descriptors: [
    {
      id: "codex-wrapper-updater-main-handler",
      phase: "main-bundle",
      order: 20_920,
      ciPolicy: "optional",
      apply: applyMainBundlePatch,
    },
    {
      id: "codex-wrapper-updater-webview-runtime",
      phase: "webview-asset",
      order: 20_921,
      ciPolicy: "optional",
      pattern: /^index-.*\.js$/,
      missingDescription: "webview index bundle",
      skipDescription: "codex wrapper updater webview runtime patch",
      apply: applyWebviewRuntimePatch,
    },
  ],
};
