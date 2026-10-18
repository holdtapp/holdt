// Passkey one-tap connect (docs/SECURITY.md, "Passkeys"). Behind PASSKEYS = "on". The approval code stays as the fallback.
//   Enroll: `npm run setup -- --add-device` prints https://<worker>/enroll#<token>. The token is single use, 15 minutes,
//           only its SHA-256 is a Worker secret, and it rides in the fragment so it never reaches a log or a Referer.
//   Connect: the consent page offers "Allow with Face ID". The challenge is an HMAC-signed, 5-minute, single-use token
//            bound to this consent handle, so an assertion can't be replayed or moved to another app's request.
//   Reset:   `npm run setup -- --reset-passkeys` rotates PASSKEY_EPOCH, which orphans every stored passkey at once.
import type { Env } from "./worker.js";
import { issue, verify, UsedStore, NO_SPEND } from "./confirm.js";
import { guardFor } from "./guard.js";
import { verifyRegistration, verifyAssertion, StoredCredential, WebAuthnError, b64u } from "./webauthn.js";
import { log } from "./redact.js";
import { checkCode } from "./authorize.js";

const enc = new TextEncoder();
export const ENROLL_TTL_MS = 15 * 60_000, CHALLENGE_TTL_MS = 5 * 60_000, MAX_PASSKEYS = 10;
const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const sha = async (s: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const safeEq = (a: string, b: string) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };

export const passkeysOn = (env: Partial<Env>) => env.PASSKEYS === "on";
/** One record per credential, keyed by the SHA-256 of its id, under the current PASSKEY_EPOCH.
 * With the Durable Object bound (production) it holds them: adds respect the cap atomically, and each sign-in's counter
 * is compared and stored in one step, so two logins can't overwrite each other. KV per-key records are the fallback. */
const ns = (env: Partial<Env>) => `v1:${env.PASSKEY_EPOCH || "0"}`;
const kvPrefix = (env: Partial<Env>) => `passkey:${ns(env)}:`;
const credKey = async (id: string) => hex(await crypto.subtle.digest("SHA-256", enc.encode(id)));
export async function loadPasskeys(env: Env): Promise<StoredCredential[]> {
  const g = guardFor(env);
  if (g) return (await g.pkList(ns(env))) as StoredCredential[];
  const out: StoredCredential[] = []; let cursor: string | undefined;
  do {
    const page: any = await env.OAUTH_KV.list({ prefix: kvPrefix(env), cursor });
    for (const k of page.keys) { try { const v = await env.OAUTH_KV.get(k.name); if (v) out.push(JSON.parse(v)); } catch { /* skip a damaged record */ } }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor && out.length <= MAX_PASSKEYS);
  return out;
}
export async function addPasskey(env: Env, cred: StoredCredential): Promise<"ok" | "dup" | "full"> {
  const key = await credKey(cred.id), g = guardFor(env);
  if (g) return g.pkAdd(ns(env), key, cred, MAX_PASSKEYS);
  const all = await loadPasskeys(env);
  if (all.some((c) => c.id === cred.id)) return "dup";
  if (all.length >= MAX_PASSKEYS) return "full";
  await env.OAUTH_KV.put(kvPrefix(env) + key, JSON.stringify(cred)); return "ok";
}
export async function bumpPasskey(env: Env, cred: StoredCredential, count: number): Promise<boolean> {
  const key = await credKey(cred.id), g = guardFor(env);
  if (g) return g.pkBump(ns(env), key, count);
  const v = await env.OAUTH_KV.get(kvPrefix(env) + key); if (!v) return false;
  const c = JSON.parse(v) as StoredCredential;
  if ((count !== 0 || c.signCount !== 0) && count <= c.signCount) return false;
  if (count !== c.signCount) await env.OAUTH_KV.put(kvPrefix(env) + key, JSON.stringify({ ...c, signCount: count }));
  return true;
}

/** A separate key for WebAuthn challenges, derived from CONFIRM_SECRET and the grant epoch, so a calendar confirm token never verifies here. */
async function challengeKey(env: Env) {
  const k = await crypto.subtle.importKey("raw", enc.encode(`${env.CONFIRM_SECRET}\n${env.GRANT_EPOCH}`), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", k, enc.encode("holdt/webauthn-challenge/v1")));
}
/** Single use across isolates when the Durable Object is bound, else KV plus the in-isolate reserve in confirm.ts. */
function usedStore(env: Env): UsedStore {
  const g = guardFor(env);
  if (g) return { has: () => false, add: () => undefined, spend: (n, exp) => g.spend(`webauthn:${n}`, exp) };
  return { has: async (n) => !!(await env.OAUTH_KV.get(`webauthn-used:${n}`)), add: (n) => env.OAUTH_KV.put(`webauthn-used:${n}`, "1", { expirationTtl: 900 }) };
}
async function newChallenge(env: Env, purpose: "login" | "enroll" | "enroll_code" | "enroll_auth", bind: string, now = Date.now()) {
  const token = await issue(await challengeKey(env), `webauthn_${purpose}`, { bind }, CHALLENGE_TTL_MS, now);
  return { token, challenge: b64u(await sha(token)) };
}
/** Checks the signed challenge token and spends it. Returns the challenge bytes the browser must have signed. */
async function takeChallenge(env: Env, purpose: "login" | "enroll" | "enroll_code" | "enroll_auth", bind: string, token: string, now = Date.now()) {
  const key = await challengeKey(env), expired = "The Face ID request expired. Reload the page and try again.";
  // Check the binding before spending, so a challenge pasted into another request can't burn the real one.
  const peek = await verify<{ bind: string }>(key, String(token ?? ""), `webauthn_${purpose}`, NO_SPEND, now, expired);
  if (peek.ok && !safeEq(String(peek.payload.bind), bind)) throw new WebAuthnError("challenge belongs to another request");
  const v = await verify<{ bind: string }>(key, String(token ?? ""), `webauthn_${purpose}`, usedStore(env), now, expired);
  if (!v.ok) throw new WebAuthnError(/already/.test(v.reason) ? "That Face ID approval was already used. Reload the page and try again." : v.reason);
  return sha(token);
}
const rp = (url: URL) => ({ rpId: url.hostname, origin: url.origin });
/** A passkey works only on the host it was made for. After a move (say workers.dev to connect.holdt.app) the old ones
 * can't sign in here, so they're left out instead of offered to a sheet that would find nothing. Records from before
 * rpId was stored count as this host's, which is true for every server that never moved. */
export const usableHere = (creds: StoredCredential[], url: URL) => creds.filter((c) => !c.rpId || c.rpId === url.hostname);

// ---------- connect (consent page) ----------
/** Options for the consent page's "Allow with Face ID" button, or undefined when one-tap is off or nothing is enrolled. */
export async function loginOptions(env: Env, url: URL, handle: string) {
  if (!passkeysOn(env) || !env.CONFIRM_SECRET) return undefined;
  const all = await loadPasskeys(env);
  if (all.length > MAX_PASSKEYS) { log.warn("passkeys over the cap: one-tap off until --reset-passkeys"); return undefined; }
  const creds = usableHere(all, url); if (!creds.length) return undefined;
  const c = await newChallenge(env, "login", await bindHandle(handle));
  return { token: c.token, challenge: c.challenge, rpId: url.hostname, ids: creds.map((x) => x.id) };
}
const bindHandle = async (handle: string) => b64u(await sha(`consent:${handle}`));
export type PasskeyVerdict = { ok: true } | { ok: false; reason: string; message: string };
export async function checkPasskeyLogin(env: Env, url: URL, handle: string, f: { token: string; id: string; clientDataJSON: string; authenticatorData: string; signature: string }, now = Date.now()): Promise<PasskeyVerdict> {
  const no = (reason: string, message = "Face ID didn't confirm it's you. Try again, or use an approval code instead.") => ({ ok: false as const, reason, message });
  if (!passkeysOn(env)) return no("off", "Face ID sign-in is turned off. Use an approval code instead.");
  try {
    const creds = await loadPasskeys(env);
    // Fail closed if the store somehow holds more than the cap: something wrote around enrollment.
    if (creds.length > MAX_PASSKEYS) return no("over cap", "Face ID sign-in is paused on this server. Use an approval code instead. The person who set up Holdt can reset Face ID from their computer.");
    const cred = usableHere(creds, url).find((c) => safeEq(c.id, String(f.id ?? "")));
    if (!cred) return no("unknown passkey", "This device isn't set up for Face ID with Holdt. Use an approval code instead.");
    const challenge = await takeChallenge(env, "login", await bindHandle(handle), f.token, now);
    const { signCount } = await verifyAssertion(f, cred, { ...rp(url), challenge });
    if (!(await bumpPasskey(env, cred, signCount))) throw new WebAuthnError("signature counter went backwards");
    return { ok: true };
  } catch (e) {
    if (e instanceof WebAuthnError) { log.warn(`passkey refused: ${e.message.slice(0, 80)}`); return no(e.message, /expired|already used/.test(e.message) ? e.message : undefined); }
    throw e;
  }
}

// ---------- enrollment ----------
async function enrollTokenProblem(env: Env, token: string, now: number): Promise<string | undefined> {
  if (!passkeysOn(env)) return "Face ID sign-in is turned off on this server.";
  if (!env.ENROLL_TOKEN_HASH || !env.ENROLL_TOKEN_ISSUED) return "This link isn't active. Make a new one on the computer where you set up Holdt.";
  if (!safeEq(hex(await crypto.subtle.digest("SHA-256", enc.encode(String(token ?? "")))), env.ENROLL_TOKEN_HASH)) return "This link isn't valid. Open the newest link from your computer.";
  if (now - Number(env.ENROLL_TOKEN_ISSUED) > ENROLL_TTL_MS) return "This link expired. Links last 15 minutes. Make a new one on your computer.";
  if (await env.OAUTH_KV.get(`enroll-used:${env.ENROLL_TOKEN_HASH}`)) return "This link was already used. Make a new one on your computer to add another device.";
  return undefined;
}
async function spendEnrollToken(env: Env, now: number) {
  const g = guardFor(env), h = env.ENROLL_TOKEN_HASH!;
  if (g && !(await g.spend(`enroll:${h}`, Number(env.ENROLL_TOKEN_ISSUED) + ENROLL_TTL_MS))) return false;
  if (await env.OAUTH_KV.get(`enroll-used:${h}`)) return false;
  await env.OAUTH_KV.put(`enroll-used:${h}`, String(now), { expirationTtl: 86400 });
  return true;
}
/** The consent page's note about a device added in the last 7 days, in plain words with the one thing to do. */
export const NOTICE_DAYS = 7;
/** What the passkey sheet shows. iOS reads "Sign in to <host> with your passkey for <user>". */
export const PASSKEY_NAMES = { rp: "Holdt", user: "iCloud Calendar" } as const;
/** navigator.platform, as a person would say it. */
export function deviceName(label?: string) {
  const l = String(label ?? "");
  if (/iphone/i.test(l)) return "an iPhone"; if (/ipad/i.test(l)) return "an iPad"; if (/mac/i.test(l)) return "a Mac";
  if (/win/i.test(l)) return "a Windows PC"; if (/android|arm/i.test(l)) return "an Android device"; if (/linux/i.test(l)) return "a Linux computer";
  return "a new device";
}
export function deviceNotice(creds: StoredCredential[], tz: string, now = Date.now()): string | undefined {
  const recent = creds.filter((c) => now - c.createdAt < NOTICE_DAYS * 86400_000).sort((a, b) => b.createdAt - a.createdAt);
  if (!recent.length) return undefined;
  let z = tz; try { new Intl.DateTimeFormat("en-US", { timeZone: z }); } catch { z = "UTC"; }
  const day = (ms: number) => new Intl.DateTimeFormat("en-CA", { timeZone: z, year: "numeric", month: "2-digit", day: "2-digit" }).format(ms);
  const when = (ms: number) => {
    const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: z, month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).formatToParts(ms).map((x) => [x.type, x.value]));
    const d = day(ms) === day(now) ? "today" : day(ms) === day(now - 86400_000) ? "yesterday" : `on ${p.month} ${p.day}`;
    return `${d} at ${p.hour}:${p.minute}\u00a0${p.dayPeriod}`;
  };
  const list = recent.slice(0, 3).map((c) => `${deviceName(c.label)} ${when(c.createdAt)}`);
  const joined = list.length === 1 ? list[0] : `${list.slice(0, -1).join(", ")} and ${list.at(-1)}`;
  return `Face ID was turned on for ${joined}. Not you? Tap\u00a0Don't\u00a0allow.`;
}
const json = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" } });

export async function enrollApi(req: Request, env: Env, now = Date.now()): Promise<Response> {
  const url = new URL(req.url);
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);
  // Same-origin only: the enroll page is ours, and nothing else has a reason to call this.
  const origin = req.headers.get("origin"); if (origin && origin !== url.origin) return json({ error: "origin not allowed" }, 403);
  let b: any; try { const t = await req.text(); if (t.length > 20000) return json({ error: "too large" }, 413); b = JSON.parse(t); } catch { return json({ ok: false, message: "Bad request." }, 400); }
  const problem = await enrollTokenProblem(env, b?.token, now);
  if (problem) return json({ ok: false, message: problem }, 400);
  const bind = env.ENROLL_TOKEN_HASH!;
  const creds = await loadPasskeys(env);
  if (url.pathname === "/enroll/options") {
    if (creds.length >= MAX_PASSKEYS) return json({ ok: false, message: `Holdt already has ${MAX_PASSKEYS} Face ID devices, the most it allows. Reset Face ID from your computer to start over.` }, 400);
    // Adding a device needs proof it's the owner: the current approval code, or a sign-in with a passkey already here.
    // The code is checked here, before the browser creates anything, so a typo never leaves an orphan passkey in iCloud Keychain.
    // A good code earns an "enroll_code" challenge, which /enroll/finish accepts as that proof.
    const given = String(b.code ?? "").replace(/\D/g, "");
    if (given) {
      const v = await checkCode(env, given, now);
      if (!v.ok) { log.warn(`enroll refused: approval code ${v.reason}`); return json({ ok: false, field: "code", message: v.message }, 400); }
    }
    const c = await newChallenge(env, given ? "enroll_code" : "enroll", bind, now);
    const here = usableHere(creds, url), auth = !given && here.length ? await newChallenge(env, "enroll_auth", bind, now) : undefined;
    return json({ ok: true, challenge_token: c.token, auth: auth ? { challenge_token: auth.token, challenge: auth.challenge, rpId: url.hostname, ids: here.map((x) => x.id) } : undefined, publicKey: {
      rp: { id: url.hostname, name: PASSKEY_NAMES.rp }, user: { id: b64u(await sha(`holdt-owner:${url.hostname}`)), name: PASSKEY_NAMES.user, displayName: PASSKEY_NAMES.user },
      challenge: c.challenge, pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }], timeout: 120000, attestation: "none",
      authenticatorSelection: { residentKey: "preferred", userVerification: "required" }, excludeCredentials: creds.map((x) => ({ type: "public-key", id: x.id })) } });
  }
  if (url.pathname === "/enroll/finish") {
    try {
      const byPasskey = !!(b.auth && typeof b.auth === "object");
      // Code path: the challenge itself proves the code passed in /enroll/options. Passkey path: proven below.
      if (!byPasskey && (await verify(await challengeKey(env), String(b.challenge_token ?? ""), "webauthn_enroll", NO_SPEND, now, "")).ok)
        return json({ ok: false, field: "code", message: "Enter the approval code first." }, 400); // no code and no passkey proof
      const challenge = await takeChallenge(env, byPasskey ? "enroll" : "enroll_code", bind, b.challenge_token, now);
      const cred = await verifyRegistration({ clientDataJSON: b.clientDataJSON, attestationObject: b.attestationObject }, { ...rp(url), challenge }, now);
      if (creds.some((c) => c.id === cred.id)) return json({ ok: false, message: "This device already uses Face ID with Holdt." }, 400);
      if (creds.length >= MAX_PASSKEYS) return json({ ok: false, message: `Holdt already has ${MAX_PASSKEYS} Face ID devices, the most it allows. Reset Face ID from your computer to start over.` }, 400);
      // The link alone is never enough: whoever opens a leaked link still needs the owner's code or passkey.
      let via: "approval code" | "existing passkey";
      if (byPasskey) {
        const old = usableHere(creds, url).find((c) => safeEq(c.id, String(b.auth.id ?? "")));
        if (!old) return json({ ok: false, message: "This device isn't set up for Face ID with Holdt. Enter the approval code instead." }, 400);
        const ac = await takeChallenge(env, "enroll_auth", bind, b.auth.challenge_token, now);
        const { signCount } = await verifyAssertion(b.auth, old, { ...rp(url), challenge: ac });
        if (!(await bumpPasskey(env, old, signCount))) throw new WebAuthnError("signature counter went backwards");
        via = "existing passkey";
      } else via = "approval code";
      cred.via = via; cred.rpId = url.hostname;
      if (!(await spendEnrollToken(env, now))) return json({ ok: false, message: "This link was already used. Make a new one on your computer to add another device." }, 400);
      cred.label = typeof b.label === "string" ? b.label.replace(/[^\w .'-]/g, "").slice(0, 40) : undefined;
      const added = await addPasskey(env, cred);
      if (added !== "ok") return json({ ok: false, message: added === "dup" ? "This device already uses Face ID with Holdt." : `Holdt already has ${MAX_PASSKEYS} Face ID devices, the most it allows. Reset Face ID from your computer to start over.` }, 400);
      // Visible in `npm run tail`, on the next consent pages and in connection_status (deviceNotice).
      log.info(`passkey enrolled: device "${cred.label || "unnamed"}" via ${via}, ${creds.length + 1} on this server`);
      return json({ ok: true, count: creds.length + 1 });
    } catch (e) {
      if (e instanceof WebAuthnError) { log.warn(`enroll refused: ${e.message.slice(0, 80)}`); return json({ ok: false, message: "Face ID wasn't saved. Reload this page and try again." }, 400); }
      throw e;
    }
  }
  return json({ error: "not found" }, 404);
}

// ---------- browser scripts (served with a per-response nonce, no other script may run) ----------
const CODEC = `const b=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));const u=a=>btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');`;
// Touch ID on a Mac, Face ID elsewhere. The lift mark's piece drops home the moment a passkey answers (src/ui.ts).
const TOUCH = `const touch=/Macintosh/.test(navigator.userAgent)&&!('ontouchend' in document),bio=touch?'Touch ID':'Face ID';`;
export const LOGIN_SCRIPT = `${CODEC}${TOUCH}
const btn=document.getElementById('pk'),f=btn.form,o=JSON.parse(btn.dataset.o),msg=document.getElementById('pkmsg').lastElementChild,mode=document.getElementById('mode'),live=document.getElementById('live'),wrap=document.getElementById('altwrap'),lab=document.getElementById('pklabel'),mk=document.getElementById('mk');
if(touch)lab.textContent='Allow with Touch ID';
const setMode=(on,say)=>{f.classList.toggle('code',on);if(!on){msg.parentNode.classList.remove('keep');msg.textContent='';}mode.setAttribute('aria-expanded',on?'true':'false');if(say){live.textContent=on?'Approval code shown':bio+' shown';(on?document.getElementById('code'):btn).focus();}};
f.classList.add('js');btn.hidden=false;mode.hidden=false;mode.addEventListener('click',()=>setMode(!f.classList.contains('code'),true));
if(touch)document.getElementById('modeface').textContent='Use Touch ID instead';
if(!window.PublicKeyCredential){btn.hidden=true;mode.hidden=true;setMode(true);msg.parentNode.classList.add('keep');msg.textContent=bio+' isn’t available in this window. Use an approval code instead.';}
const cf=document.getElementById('code');cf.addEventListener('input',()=>{const d=cf.value.replace(/\\D/g,'').slice(0,8),v=d.length>4?d.slice(0,4)+' '+d.slice(4):d;if(v!==cf.value)cf.value=v;});
let busy=false,fails=0;btn.addEventListener('click',async()=>{if(busy)return;busy=true;btn.setAttribute('aria-disabled','true');msg.textContent='';try{
const c=await navigator.credentials.get({publicKey:{challenge:b(o.challenge),rpId:o.rpId,allowCredentials:o.ids.map(id=>({type:'public-key',id:b(id)})),userVerification:'required',timeout:120000}});
f.pk_id.value=c.id;f.pk_cdj.value=u(c.response.clientDataJSON);f.pk_ad.value=u(c.response.authenticatorData);f.pk_sig.value=u(c.response.signature);
btn.setAttribute('aria-busy','true');lab.textContent='Approving';mk.classList.add('drop');wrap.inert=true;f.classList.add('busy');live.textContent='Approving. One moment.';f.submit();
}catch(e){busy=false;btn.removeAttribute('aria-disabled');fails++;msg.textContent=fails>1?bio+' didn’t finish.\\nEnter your approval code below.':bio+' didn’t finish.\\nTry again or use a\u00a0code.';if(fails>1){setMode(true);msg.parentNode.classList.add('keep');document.getElementById('code').focus();live.textContent=msg.textContent+' Approval code shown.';}else live.textContent=msg.textContent;}});`;
export const ENROLL_SCRIPT = `${CODEC}${TOUCH}
const t=location.hash.slice(1);history.replaceState(null,'',location.pathname);
const $=id=>document.getElementById(id),btn=$('go'),msg=$('msg').lastElementChild,code=$('code'),err=$('err');
if(touch){btn.lastElementChild.textContent='Turn on Touch ID';$('title').textContent='Turn on Touch ID';$('face1').textContent='Your fingerprint stays on your Mac. Holdt never sees it.';$('skip').querySelector('h1').textContent='Touch ID not turned on';$('skip').querySelector('.lede').textContent='Your approval code still works. You can turn on Touch ID anytime.';}
const post=(p,o)=>fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(o)}).then(r=>r.json()).catch(()=>({ok:false,message:'Holdt couldn’t reach your server. Check your connection and try again.'}));
const live=$('live'),say=m=>{msg.textContent=m;live.textContent=m;};
const clearErr=()=>{err.hidden=true;code.removeAttribute('aria-invalid');code.setAttribute('aria-describedby','codehint');};
const typo=m=>String(m).replace(/(\\w)'(\\w)/g,'$1’$2');
const fieldErr=m=>{err.lastElementChild.textContent=typo(m);err.hidden=false;code.setAttribute('aria-invalid','true');code.setAttribute('aria-describedby','err codehint');code.value='';code.focus();};
const dead=m=>{$('setup').hidden=true;const d=$('dead');d.hidden=false;const k=/expired/.test(m)?0:/already used/.test(m)?1:2;d.querySelector('h1').textContent=['This link expired','This link was already used','This link doesn’t work'][k];d.querySelector('.lede').textContent=['Links last 15 minutes. ','Each link adds one device. ','This link isn’t complete or isn’t current. '][k]+'Make a new one on the computer where you set up Holdt.';d.querySelector('h1').setAttribute('tabindex','-1');d.querySelector('h1').focus();};
$('enrollf').addEventListener('submit',e=>{e.preventDefault();if(!btn.disabled)btn.click();});
$('later').addEventListener('click',()=>{$('setup').hidden=true;const k=$('skip');k.hidden=false;const h=k.querySelector('h1');h.setAttribute('tabindex','-1');h.focus();});
code.addEventListener('input',()=>{clearErr();const d=code.value.replace(/\\D/g,'').slice(0,8);const v=d.length>4?d.slice(0,4)+' '+d.slice(4):d;if(v!==code.value)code.value=v;});
if(!t){btn.disabled=true;say('This link is missing its last part. Open the full link from your computer.');}
else if(!window.PublicKeyCredential){btn.disabled=true;say('This browser can’t save '+bio+' for Holdt. Open the link in Safari.');}
let kept=null;const blab=btn.lastElementChild,idle=()=>{blab.textContent=touch?'Turn on Touch ID':'Turn on Face ID';},busyAs=(l,m)=>{blab.textContent=l;live.textContent=m;};
btn.addEventListener('click',async()=>{btn.disabled=true;btn.setAttribute('aria-busy','true');say('');clearErr();busyAs('Checking code','Checking your code.');try{
const cv=code.value.replace(/\\D/g,'');let auth;
// A checked code is spent, so keep its challenge for a retry after a cancelled sheet (good for 5 minutes, same code only).
let r=kept&&kept.cv===cv&&Date.now()-kept.at<270000?kept.r:null;
if(!r&&cv&&kept&&kept.cv===cv){const e=new Error('That code already started Face ID and has now timed out. Get a new one on the computer where you set up Holdt.');e.field=1;throw e;}
if(!r){r=await post('/enroll/options',{token:t,code:cv});if(!r.ok){btn.removeAttribute('aria-busy');live.textContent='';if(r.field){const e=new Error(r.message);e.field=1;throw e;}return dead(r.message);}if(cv)kept={cv,r,at:Date.now()};}
if(!cv){if(!r.auth){const e=new Error('Enter the approval code first.');e.field=1;throw e;}
const a=await navigator.credentials.get({publicKey:{challenge:b(r.auth.challenge),rpId:r.auth.rpId,allowCredentials:r.auth.ids.map(id=>({type:'public-key',id:b(id)})),userVerification:'required',timeout:120000}});
auth={challenge_token:r.auth.challenge_token,id:a.id,clientDataJSON:u(a.response.clientDataJSON),authenticatorData:u(a.response.authenticatorData),signature:u(a.response.signature)};}
const p=JSON.parse(JSON.stringify(r.publicKey));p.challenge=b(p.challenge);p.user.id=b(p.user.id);p.excludeCredentials=p.excludeCredentials.map(x=>({type:x.type,id:b(x.id)}));
idle();const c=await navigator.credentials.create({publicKey:p});busyAs('Turning on','Turning on '+bio+'. One moment.');
const d=await post('/enroll/finish',{token:t,auth,challenge_token:r.challenge_token,clientDataJSON:u(c.response.clientDataJSON),attestationObject:u(c.response.attestationObject),label:navigator.platform||''});
kept=null;if(!d.ok){const e=new Error(d.message);e.field=d.field==='code';throw e;}
$('setup').hidden=true;const done=$('done');done.hidden=false;const h=done.querySelector('h1');
h.textContent=bio+' is on';if(touch)done.querySelector('.lede').textContent='Next time, click Allow with Touch ID. Your other Apple devices with iCloud Keychain can use it too.';
h.setAttribute('tabindex','-1');h.focus();requestAnimationFrame(()=>$('mkdone').classList.add('drop'));
}catch(e){btn.disabled=false;btn.removeAttribute('aria-busy');idle();live.textContent='';const m=(e&&e.message)||'That didn’t work. Try again.';
if(e&&e.name==='NotAllowedError')say(bio+' didn’t finish.\\nTry again, or tap Not\u00a0now.');else if(e&&e.name==='InvalidStateError')say('This device already uses '+bio+' with Holdt.');else if(e&&e.field)fieldErr(m);else say(typo(m));}});`;
