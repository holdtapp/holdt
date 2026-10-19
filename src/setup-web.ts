// No-terminal setup (launch gate G9). Your Grok Bot installs Holdt on your Cloudflare account from your own computer
// (docs/agent-setup.md), then opens https://<worker>/setup#<token> in your browser. That page takes the Apple
// app-specific password, checks it live with iCloud, and seals it inside this Worker. Face ID setup follows at once.
//
// Owner proof: the setup token. 32 random bytes made on the owner's computer, single use, 30 minutes. Only its SHA-256
// is a Worker secret (SETUP_TOKEN_HASH), and the token rides in the URL fragment, so no server log, Referer or link
// preview ever sees it. Opening the link claims it at once for this browser: a signed, HttpOnly, SameSite=Strict
// session cookie that lasts 30 minutes and can save exactly once.
//
// Sealing: the password, the Apple Account email and the keys made here are encrypted with a fresh AES-256-GCM data
// key, wrapped by SEAL_KEY (AES-KW), a 32-byte Worker secret that Cloudflare stores and never shows again. The sealed
// record lives in the owner's Durable Object (KV only as a fallback). Nothing readable is ever stored or returned.
import type { Env } from "./worker.js";
import { guardFor } from "./guard.js";
import { importKek, seal, open, type Sealed } from "./vault.js";
import { safeEq, sameOriginJson, readJson, json, loadPasskeys } from "./passkey.js";
import { sha256Hex, page, subkey } from "./authorize.js";
import { screen, ICON, esc } from "./ui.js";
import { CalDavClient, CalDavError } from "./caldav.js";
import { registerSecret, log } from "./redact.js";
import { normalizeAppPassword, normalizeEmail } from "../setup/validate.js";

export const SETUP_TTL_MS = 30 * 60_000;
export const SESSION_COOKIE = "__Host-holdt-setup";
export const MAX_SETUP_TRIES = 8;
const SEAL_AAD = "holdt-owner-setup";
const SEALED_KEY = "sealed:setup";
const enc = new TextEncoder();
const b64u = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const rand = (n: number) => b64u(crypto.getRandomValues(new Uint8Array(n)));

/** What setup seals. Every field is a secret or a choice the owner made on the page. */
export interface SetupRecord { email: string; password: string; timezone: string; writes: boolean; confirm: string; epoch: string; enrollHash: string; enrollIssued: number; at: number }
type Stored = Sealed & { at: number };

// ---------- storage: the owner's Durable Object, KV only when the binding is missing ----------
function store(env: Pick<Env, "GUARD" | "OAUTH_KV">) {
  const g: any = guardFor(env);
  if (g && typeof g.sealedGet === "function") return { get: (k: string) => g.sealedGet(k) as Promise<any>, put: (k: string, v: unknown) => g.sealedPut(k, v) as Promise<void> };
  return { get: async (k: string) => { const t = await env.OAUTH_KV.get(k); return t ? JSON.parse(t) : undefined; }, put: (k: string, v: unknown) => env.OAUTH_KV.put(k, JSON.stringify(v)) };
}
async function kek(env: Pick<Env, "SEAL_KEY">) {
  const raw = unb64u(String(env.SEAL_KEY ?? ""));
  if (raw.length !== 32) throw new Error("SEAL_KEY must be 32 bytes, base64url");
  return importKek(raw);
}
export async function sealRecord(env: Env, r: SetupRecord): Promise<void> {
  const s = await seal(await kek(env), "seal-v1", SEAL_AAD, JSON.stringify(r));
  await store(env).put(SEALED_KEY, { ...s, at: r.at } satisfies Stored);
  cache = undefined;
}
let cache: { ct: string; rec: SetupRecord } | undefined;
/** The sealed setup, opened, or undefined when this Worker was set up the terminal way (or not yet at all). */
export async function openRecord(env: Env): Promise<SetupRecord | undefined> {
  if (!env.SEAL_KEY) return undefined;
  const s = (await store(env).get(SEALED_KEY)) as Stored | undefined;
  if (!s?.ct) return undefined;
  if (cache?.ct === s.ct) return cache.rec;
  try { const rec = JSON.parse(await open(await kek(env), SEAL_AAD, s)) as SetupRecord; cache = { ct: s.ct, rec }; return rec; }
  catch { log.warn("sealed setup can't be opened (SEAL_KEY changed?)"); return undefined; }
}
/** Every request runs with the sealed values in place of the terminal-made secrets. An env GRANT_EPOCH (from
 * `--revoke-all`) is folded in, so either way of cutting connections still works. The newer enroll link wins. */
export async function withSealed(env: Env): Promise<Env> {
  const r = await openRecord(env); if (!r) return env;
  registerSecret(r.password); registerSecret(r.email); registerSecret(r.confirm); registerSecret(r.epoch);
  const envEnrollNewer = env.ENROLL_TOKEN_HASH && Number(env.ENROLL_TOKEN_ISSUED ?? 0) > r.enrollIssued;
  return { ...env, ICLOUD_EMAIL: r.email, ICLOUD_APP_PASSWORD: r.password, CONFIRM_SECRET: r.confirm, GRANT_EPOCH: env.GRANT_EPOCH ? `${r.epoch}.${env.GRANT_EPOCH}` : r.epoch,
    TIMEZONE: r.timezone, WRITES_ENABLED: r.writes ? "true" : "false",
    ENROLL_TOKEN_HASH: envEnrollNewer ? env.ENROLL_TOKEN_HASH : r.enrollHash, ENROLL_TOKEN_ISSUED: envEnrollNewer ? env.ENROLL_TOKEN_ISSUED : String(r.enrollIssued) };
}
const configured = async (env: Env) => !!(await openRecord(env)) || !!(env.ICLOUD_EMAIL && env.ICLOUD_APP_PASSWORD);

// ---------- the session: claimed from the link, signed, one save ----------
async function sessionMac(env: Env, data: string) {
  const k = await crypto.subtle.importKey("raw", await subkey(String(env.SEAL_KEY), "holdt-setup-session-v1"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", k, enc.encode(data)));
}
type Session = { id: string; exp: number; th: string; tries: number; done?: boolean };
async function readSession(req: Request, env: Env, now = Date.now()): Promise<Session | undefined> {
  const raw = (req.headers.get("cookie") ?? "").split(/;\s*/).find((c) => c.startsWith(SESSION_COOKIE + "="))?.slice(SESSION_COOKIE.length + 1);
  if (!raw) return undefined;
  const [id, mac] = raw.split(".");
  if (!id || !mac || !safeEq(mac, await sessionMac(env, id))) return undefined;
  const s = (await store(env).get(`setup-session:${id}`)) as Session | undefined;
  if (!s || s.exp <= now || s.done) return undefined;
  if (s.th !== env.SETUP_TOKEN_HASH) return undefined; // a newer setup link ends older sessions
  return s;
}

/** Why a setup link can't be used, in the owner's words, or undefined when it's live. */
export function setupState(env: Env, now = Date.now()): "off" | "none" | "expired" | "live" {
  if (!env.SEAL_KEY) return "off";
  if (!env.SETUP_TOKEN_HASH || !env.SETUP_TOKEN_ISSUED) return "none";
  if (now - Number(env.SETUP_TOKEN_ISSUED) > SETUP_TTL_MS) return "expired";
  return "live";
}

export async function setupRoute(req: Request, env: Env, url: URL, fetchImpl?: typeof fetch): Promise<Response> {
  if (url.pathname === "/setup" && req.method === "GET") return setupPage(env, await noLinkView(req, env));
  if (url.pathname === "/setup/claim") return claim(req, env, url);
  if (url.pathname === "/setup/save") return save(req, env, url, fetchImpl);
  return json({ error: "not found" }, 404);
}

async function claim(req: Request, env: Env, url: URL, now = Date.now()): Promise<Response> {
  const bad = sameOriginJson(req, url); if (bad) return bad;
  let b: any; try { b = await readJson(req); } catch { return json({ ok: false }, 400); }
  const st = setupState(env, now);
  if (st !== "live") { log.warn(`setup link refused: ${st}`); return json({ ok: false, ended: true, reason: st === "off" ? "off" : "ended" }, 400); }
  const token = String(b?.token ?? "");
  if (!/^[A-Za-z0-9_-]{40,64}$/.test(token) || !safeEq(await sha256Hex(token), String(env.SETUP_TOKEN_HASH))) { log.warn("setup link refused: wrong"); return json({ ok: false, ended: true, reason: "ended" }, 400); }
  const g: any = guardFor(env), th = String(env.SETUP_TOKEN_HASH), exp = Number(env.SETUP_TOKEN_ISSUED) + SETUP_TTL_MS;
  // Single use: the first browser to open the link owns it. A second open, or a replay, is refused.
  if (g) { if (!(await g.spend(`setup:${th}`, exp))) { log.warn("setup link refused: used"); return json({ ok: false, ended: true, reason: "ended" }, 400); } }
  else { if (await env.OAUTH_KV.get(`setup-used:${th}`)) { log.warn("setup link refused: used"); return json({ ok: false, ended: true, reason: "ended" }, 400); } await env.OAUTH_KV.put(`setup-used:${th}`, "1", { expirationTtl: 3600 }); }
  const id = rand(24), s: Session = { id, exp: Math.min(exp, now + SETUP_TTL_MS), th, tries: 0 };
  await store(env).put(`setup-session:${id}`, s);
  log.info("setup link opened in a browser");
  const r = json({ ok: true, existing: await configured(env) });
  r.headers.append("Set-Cookie", `${SESSION_COOKIE}=${id}.${await sessionMac(env, id)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${Math.max(0, Math.floor((s.exp - now) / 1000))}`);
  return r;
}

const validZone = (z: unknown) => { if (typeof z !== "string" || z.length > 64) return undefined; try { new Intl.DateTimeFormat("en-US", { timeZone: z }); return z; } catch { return undefined; } };
const appleSays = (code: string) => {
  switch (code) {
    case "authentication": return "Apple didn’t accept these. Check the email, or make a new app-specific password.";
    case "rate_limited": case "unavailable": return "iCloud is busy right now. Wait a minute and try again.";
    case "forbidden": return "iCloud blocked the connection. Work and school Apple Accounts may not allow app-specific passwords.";
    default: return "Holdt couldn’t reach iCloud. Try again in a moment.";
  }
};

async function save(req: Request, env: Env, url: URL, fetchImpl?: typeof fetch, now = Date.now()): Promise<Response> {
  const bad = sameOriginJson(req, url); if (bad) return bad;
  const s = await readSession(req, env, now);
  if (!s) return json({ ok: false, ended: true }, 403);
  if (s.tries >= MAX_SETUP_TRIES) return json({ ok: false, ended: true }, 429);
  let b: any; try { b = await readJson(req); } catch { return json({ ok: false }, 400); }
  const e = normalizeEmail(b?.email); if (!e.ok) return json({ ok: false, field: "email", message: e.message });
  const p = normalizeAppPassword(b?.password); if (!p.ok) return json({ ok: false, field: "password", message: p.message.replace("Copy it again from Apple's page.", "Check it on Apple’s page.") });
  registerSecret(p.value); registerSecret(e.value);
  // Charged before Apple is asked. The Durable Object counts in one step, so parallel posts can't all read the same count.
  const g: any = guardFor(env);
  if (g) { if (!(await g.setupTry(s.id, MAX_SETUP_TRIES))) return json({ ok: false, ended: true }, 429); }
  else await store(env).put(`setup-session:${s.id}`, { ...s, tries: s.tries + 1 });
  let count = 0;
  try {
    const cols = await new CalDavClient({ baseUrl: env.CALDAV_URL ?? "https://caldav.icloud.com/", username: e.value, password: p.value, maxRetries: 2, fetch: (fetchImpl ?? ((u: any, i: any) => fetch(u, i))) as any }).listCollections();
    count = cols.filter((c) => c.components.includes("VEVENT")).length;
  } catch (err) {
    const code = err instanceof CalDavError ? err.code : "unknown";
    log.warn(`setup live check failed: ${code}`);
    return json({ ok: false, field: code === "authentication" ? "account" : undefined, message: appleSays(code) });
  }
  if (!count) return json({ ok: false, message: "Apple accepted the password, but this account has no calendars Holdt can read." });
  // One save per link. Spent before sealing, so a second request riding the same cookie can't race it.
  if (g &&!(await g.spend(`setup-save:${s.id}`, s.exp))) return json({ ok: false, ended: true }, 403);
  await store(env).put(`setup-session:${s.id}`, { ...s, tries: s.tries + 1, done: true });
  const enroll = rand(32);
  const rec: SetupRecord = { email: e.value, password: p.value, timezone: validZone(b?.timezone) ?? "UTC", writes: b?.writes === true, confirm: rand(32), epoch: rand(24),
    enrollHash: await sha256Hex(enroll), enrollIssued: now, at: now };
  await sealRecord(env, rec);
  log.info(`setup saved: ${count} calendars, ${rec.writes ? "changes with a yes" : "read-only"}, connections reset`);
  // The Face ID link goes back to this page only, which opens it in the same tab. Its token stays in the fragment.
  return json({ ok: true, calendars: count, next: `/enroll?from=setup#${enroll}` });
}

// ---------- the page ----------
const SETUP_CSS = `<style>
.grp{margin:.75rem 0 0;text-align:left}.grp>.gh{margin:0 1rem .4rem;font-size:.765rem;font-weight:400;color:var(--ink2);letter-spacing:-.005em;line-height:1.3;text-wrap:balance}
.grp:first-child{margin-top:1.1rem}
.gf{margin:.45rem 1rem 0;font-size:.765rem;color:var(--ink2);text-wrap:pretty}
.rows{background:var(--surface);border-radius:.62rem;overflow:hidden;corner-shape:squircle}
.row{display:flex;align-items:center;gap:.75rem;min-height:2.75rem;padding:0 1rem;position:relative}
.row+.row::before{content:"";position:absolute;top:0;left:1rem;right:0;border-top:.5px solid var(--line)}
.row{flex-wrap:wrap;column-gap:.75rem;row-gap:0}.row .rl{flex:0 0 6.9rem;font-weight:400;padding:.6rem 0}
.row input[type=email],.row input[type=password]{flex:1 1 10rem;min-width:10rem;min-height:2.75rem;border:0;background:transparent;color:var(--ink);font:inherit;letter-spacing:-.01em;padding:0;outline:none}
.row input::placeholder{color:var(--ink2);opacity:1}
.rows:focus-within{box-shadow:0 0 0 2px var(--green-ink)}
.rows[data-bad=account]{box-shadow:0 0 0 2px var(--err)}.rows[data-bad=email] .row:first-child,.rows[data-bad=password] .row:last-child{box-shadow:inset 0 0 0 2px var(--err);border-radius:.62rem}
a.row{color:var(--green-ink);text-decoration:none;font-weight:400}a.row svg{width:1.1rem;height:1.1rem;flex:none}a.row:focus-visible{outline:none;box-shadow:inset 0 0 0 2px var(--green-ink);border-radius:.62rem}
.slot .status{font-size:.765rem;justify-content:center;text-align:center}.slot .status .st{max-width:19rem;text-align:left}.status.err{font-weight:500}.status.err svg{color:var(--err)}
.status.ok svg{color:var(--green-ink)}
.addr{margin-top:1.25rem}.addr .row{font:inherit;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.88rem;word-break:break-all;padding:.7rem 1rem;margin:0;user-select:all}
#t-dead,#t-nolink,#t-unfinished,#t-off{font-size:1.65rem;line-height:1.21;letter-spacing:.013em}
.slot{min-height:2.2rem;display:flex;align-items:flex-end;justify-content:center;margin:.5rem 0 .5rem}.slot .status{margin:0}
@media (pointer:fine){html{font-size:17px}}
.gf.lock{color:var(--ink)}.gf.lock span{display:block}
.modes{border:0;margin:0;padding:0;min-width:0}.modes legend{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
label.row{cursor:pointer;padding:.55rem 1rem}label.row .rt{flex:1;min-width:0}label.row .rt strong{display:block;font-weight:400;letter-spacing:-.01em}label.row .rt span{display:block;color:var(--ink2);font-size:.88rem;text-wrap:pretty}
label.row input{position:absolute;opacity:0;width:1px;height:1px}label.row .ck{flex:none;width:1.1rem;height:1.1rem;color:var(--green-ink);visibility:hidden}
label.row:has(input:checked) .ck{visibility:visible}label.row:has(input:focus-visible){box-shadow:inset 0 0 0 2px var(--green-ink);border-radius:.62rem}
</style>`;

type NoLink = "set" | "unfinished" | "nolink" | "resume" | "resume-existing";
// Opened without a link: a tab that already claimed one (a reload) picks up where it was, for the rest of its 30 minutes.
async function noLinkView(req: Request, env: Env): Promise<NoLink> {
  const s = setupState(env) === "live" ? await readSession(req, env) : undefined;
  if (s && !s.done && s.tries < MAX_SETUP_TRIES) return (await configured(env)) ? "resume-existing" : "resume";
  if (!(await configured(env))) return "nolink";
  try { return (await loadPasskeys(env)).length ? "set" : "unfinished"; } catch { return "unfinished"; }
}
function setupPage(env: Env, nolink: NoLink): Response {
  const st = setupState(env);
  const close = `<p class="foot">You can close this page.</p>`;
  if (st === "off") return page("Holdt: Not fully installed", SETUP_CSS + screen({ title: "Holdt isn’t fully installed", titleId: "t-off", lede: "Ask your Grok\u00a0Bot to finish installing it.", markState: "muted", centered: true, actions: close }), 404, undefined, "", "history.replaceState(null,'',location.pathname);");
  const v = (id: string, o: Parameters<typeof screen>[0]) => `<div id="${id}" hidden>${screen(o)}</div>`;
  const check = `<svg class="ck" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  const form = `<div id="form"><section class="grp" aria-labelledby="g1"><h2 class="gh" id="g1">1. Make an app-specific password named Holdt</h2><div class="rows"><a class="row" href="https://account.apple.com/account/manage/section/security" target="_blank" rel="noopener noreferrer" id="apple">${ICON.globe}<span>Open Apple Account<span class="sr"> (opens in a new tab)</span></span></a></div></section>
<section class="grp" aria-labelledby="g2"><h2 class="gh" id="g2">2. Choose what it may do</h2><fieldset class="modes" aria-labelledby="g2"><div class="rows">
<label class="row"><input type="radio" name="mode" value="read" checked><span class="rt"><strong>Read only</strong><span>Grok\u00a0Bot only sees your calendar.</span></span>${check}</label>
<label class="row"><input type="radio" name="mode" value="write"><span class="rt"><strong>Changes, with your yes</strong><span>Grok\u00a0Bot suggests, you approve each one.</span></span>${check}</label></div></fieldset>
<p class="gf lock">Never deletes your events. <span>It can only take back its own, on your\u00a0yes.</span></p></section>
<section class="grp" aria-labelledby="g3"><h2 class="gh" id="g3">3. Paste it here, not your Apple Account password</h2><div class="rows" id="acct">
<div class="row"><label class="rl" for="email">Email</label><input id="email" type="email" autocomplete="email" autocapitalize="off" spellcheck="false" placeholder="Apple Account email" aria-describedby="acct-err"></div>
<div class="row"><label class="rl" for="pw">App password</label><input id="pw" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="xxxx-xxxx-xxxx-xxxx" aria-describedby="acct-err"></div></div>
</section></div>`;
  return page("Holdt: Set up", `${SETUP_CSS}
<div id="open">${screen({ title: "Opening setup", markState: "muted", centered: true, markId: "mk0", actions: `<p class="status">${ICON.spinner}<span class="st">One moment.</span></p>` })}</div>
${v("ask", { title: "Set up Holdt", titleId: "t-ask", markId: "mk", lede: `<span id="lede">Connect your iCloud Calendar to Grok\u00a0Bot.</span>`,
    body: form,
    actions: `<div class="slot"><p class="status err" id="acct-err" hidden>${ICON.alert}<span class="st"></span></p><p class="status" id="msg" aria-hidden="true" hidden>${ICON.alert}<span class="st"></span></p><p class="status ok" id="okmsg" aria-hidden="true" hidden>${ICON.checkCircle}<span class="st"></span></p></div><p class="sr" id="live" role="status" aria-live="polite"></p><button type="button" class="btn primary" id="go">${ICON.spinner}<span>Continue</span></button><p class="foot">Your app-specific password is sealed in your own Cloudflare account. Holdt sends it only to Apple.</p><noscript><p class="foot">Turn on JavaScript to finish setup.</p></noscript>` })}
${v("done", { title: "Holdt is set up", titleId: "t-done", markId: "mk2", markState: "closed", lede: "Last step: in Grok\u00a0Bot, open Connect Apps and add this address.", body: `<div class="rows addr"><p class="row" id="addr"></p></div>`, actions: `<button type="button" class="btn primary" id="copy">${ICON.copy}<span>Copy address</span></button><p class="foot">You can close this page after you copy it.</p>` })}
${v("dead", { title: "This link has ended", titleId: "t-dead", lede: "Setup links work once, for 30\u00a0minutes. Ask your Grok\u00a0Bot for a new one.", markState: "muted", centered: true, actions: close })}
${v("retry", { title: "Setup didn’t open", titleId: "t-retry", lede: "Your server didn’t answer clearly.", markState: "muted", actions: `<button type="button" class="btn primary" id="again-btn">Try again</button><p class="foot">If it keeps happening, ask your Grok\u00a0Bot to check the server.</p>` })}
${v("nolink", { title: "Ask Grok\u00a0Bot for a setup link", titleId: "t-nolink", lede: "Setup only opens from a one-time link.", markState: "muted", centered: true, actions: close })}
${v("unfinished", { title: "Setup isn’t finished", titleId: "t-unfinished", lede: "Your app-specific password is saved. Ask your Grok\u00a0Bot for a passkey link to finish.", markState: "muted", centered: true, actions: close })}
${v("set", { title: "Holdt is set up", titleId: "t-set", lede: "To change what Grok\u00a0Bot may do, ask it for a new setup link.", markState: "closed", centered: true, actions: close })}`, 200, undefined, "", `const NOTOKEN=${JSON.stringify(nolink)};` + SETUP_SCRIPT);
}

const SETUP_SCRIPT = `const $=id=>document.getElementById(id),VIEWS=["open","ask","done","dead","retry","nolink","unfinished","set"],show=id=>{VIEWS.forEach(x=>{$(x).hidden=x!==id;});const h=$(id).querySelector('h1');if(id!=='open'){h.setAttribute('tabindex','-1');h.focus();}setTimeout(()=>{document.title='Holdt: '+h.textContent.trim();},0);};
const KEY='holdt-setup-link',frag=location.hash.slice(1).split('&'),token=frag[0]||sessionStorage.getItem(KEY)||'',hint=(frag.find(x=>x.startsWith('e='))||'').slice(2);if(location.hash){sessionStorage.setItem(KEY,token);history.replaceState(null,'',location.pathname);}
const NET='Holdt couldn’t reach your server. Check your connection and try again.',SRV='Your Holdt server hit an error. Try again in a moment.';
const post=(p,b)=>fetch(p,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(r=>r.json().catch(()=>({ok:false,net:true,message:SRV})),()=>({ok:false,net:true,message:NET}));
const AGAIN='Continuing disconnects Grok\\u00a0Bot.',existing=()=>{$('lede').textContent=AGAIN;$('t-ask').textContent='Set up Holdt again';};
const claim=async()=>{show('open');const d=await post('/setup/claim',{token});if(d.ok||d.ended)sessionStorage.removeItem(KEY);if(d.ok){if(d.existing)existing();ready();return;}show(d.ended?'dead':'retry');};
$('again-btn').addEventListener('click',claim);
function ready(){show('ask');let e='';try{e=decodeURIComponent(hint);}catch{}if(/^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$/.test(e)&&!$('email').value)$('email').value=e;($('email').value?$('pw'):$('email')).focus();}
if(token)claim();else if(NOTOKEN.startsWith('resume')){if(NOTOKEN==='resume-existing')existing();ready();}else show(NOTOKEN);
const btn=$('go'),lab=btn.lastElementChild,msg=$('msg'),ok=$('okmsg'),live=$('live'),form=$('form'),acct=$('acct'),err=$('acct-err');
const fe=(f,t)=>{['email','pw'].forEach(x=>$(x).removeAttribute('aria-invalid'));delete acct.dataset.bad;err.hidden=!t;if(!t)return;err.lastElementChild.textContent=t;live.textContent='';acct.dataset.bad=f;(f==='account'?['email','pw']:[f==='email'?'email':'pw']).forEach(x=>$(x).setAttribute('aria-invalid','true'));const el=$(f==='email'?'email':'pw');el.focus();if(el.id==='pw')el.select();};
const say=t=>{msg.lastElementChild.textContent=t||'';msg.hidden=!t;live.textContent=t||'';};
let busy=false;const lock=on=>{busy=on;form.inert=on;btn.setAttribute('aria-disabled',String(on));};
const idle=()=>{live.textContent='';btn.removeAttribute('aria-busy');lab.textContent='Continue';lock(false);};
const b64=x=>Uint8Array.from(atob(x.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)),u64=a=>btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
let enroll='',opts=null,next='',saved=false;
const getOpts=async()=>{const r=await post('/enroll/options',{token:enroll});opts=r.ok?r:null;return opts;};
const check=async()=>{if(busy||saved)return;fe();say('');btn.setAttribute('aria-busy','true');lab.textContent='Checking with Apple';live.textContent='Checking with Apple.';lock(true);
const d=await post('/setup/save',{email:$('email').value,password:$('pw').value,writes:document.querySelector('input[name=mode]:checked').value==='write',timezone:Intl.DateTimeFormat().resolvedOptions().timeZone});
if(d.ok){saved=true;next=d.next;enroll=String(d.next).split('#')[1]||'';$('pw').value='';const n=d.calendars+(d.calendars===1?' calendar':' calendars');await getOpts();
btn.removeAttribute('aria-busy');busy=false;btn.setAttribute('aria-disabled','false');form.inert=true;lab.textContent=opts?'Save passkey':'Continue to passkey';ok.lastElementChild.textContent='Found '+n+'. Save a passkey to finish.';ok.hidden=false;live.textContent='Found '+n+'. Save a passkey to finish.';btn.focus();if(opts)passkey(true);return;}
idle();if(d.ended){show('dead');return;}if(d.field){fe(d.field,d.message);return;}say(d.message||'That didn’t work. Try again.');};
const passkey=async(auto)=>{if(busy)return;if(!opts){location.replace(next);return;}busy=true;say('');
try{const p=JSON.parse(JSON.stringify(opts.publicKey));p.challenge=b64(p.challenge);p.user.id=b64(p.user.id);p.excludeCredentials=(p.excludeCredentials||[]).map(x=>({type:x.type,id:b64(x.id)}));
const c=await navigator.credentials.create({publicKey:p});btn.setAttribute('aria-busy','true');lab.textContent='Saving';$('mk').classList.add('drop');
const r=await post('/enroll/finish',{token:enroll,challenge_token:opts.challenge_token,clientDataJSON:u64(c.response.clientDataJSON),attestationObject:u64(c.response.attestationObject),label:navigator.platform||''});
if(r.ok){$('addr').textContent=location.origin+'/mcp';show('done');return;}
btn.removeAttribute('aria-busy');$('mk').classList.remove('drop');lab.textContent='Save passkey';say(r.message||'The passkey wasn’t saved. Try again.');await getOpts();}
catch(e){btn.removeAttribute('aria-busy');lab.textContent='Save passkey';if(!auto)say('The passkey wasn’t saved. Try again.');}busy=false;};
btn.addEventListener('click',()=>{saved?passkey(false):check();});
const looksDone=()=>$('pw').value.replace(/[^a-z]/gi,'').length===16&&/^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$/.test($('email').value.trim());
$('pw').addEventListener('input',()=>{if(looksDone())check();});
window.addEventListener('focus',()=>{if(!saved&&!$('ask').hidden&&$('email').value&&!$('pw').value)$('pw').focus();});
$('copy').addEventListener('click',async()=>{try{await navigator.clipboard.writeText($('addr').textContent);$('copy').lastElementChild.textContent='Copied';}catch{const r=document.createRange();r.selectNodeContents($('addr'));const s=getSelection();s.removeAllRanges();s.addRange(r);}});
['email','pw'].forEach(f=>{$(f).addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();btn.focus();btn.click();}});$(f).addEventListener('input',()=>{if(!err.hidden)fe();});});`;
