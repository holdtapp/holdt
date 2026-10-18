// Passkey one-tap connect (docs/SECURITY.md, "Passkeys", and docs/no-typed-codes.md). Nobody types a code in the normal flow.
//   Enroll: `npm run setup` and `npm run add-device` print https://<worker>/enroll#<token> and a QR code. The token is single use,
//           10 minutes, only its SHA-256 is a Worker secret, and it rides in the fragment so it never reaches a log, a Referer or
//           a link-preview fetch. Owner proof is control of the Worker's secrets (only the owner's wrangler login can set them).
//           It is spent by POST /enroll/finish, never by opening the page.
//   Pair:   a new device can also be approved from a device that already has a passkey (src/away.ts).
//   Connect: the consent page offers "Allow with Face ID". The challenge is an HMAC-signed, 5-minute, single-use token
//            bound to this consent handle, so an assertion can't be replayed or moved to another app's request.
//   Reset:   `npm run setup -- --reset-passkeys` rotates PASSKEY_EPOCH, which orphans every stored passkey at once.
import type { Env } from "./worker.js";
import { issue, verify, UsedStore, NO_SPEND } from "./confirm.js";
import { guardFor } from "./guard.js";
import { verifyRegistration, verifyAssertion, StoredCredential, WebAuthnError, b64u } from "./webauthn.js";
import { log } from "./redact.js";
import { pairForEnroll, spendPair } from "./away.js";

const enc = new TextEncoder();
export const ENROLL_TTL_MS = 10 * 60_000, CHALLENGE_TTL_MS = 5 * 60_000, MAX_PASSKEYS = 10;
const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const sha = async (s: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));
export const safeEq = (a: string, b: string) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };

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
export async function challengeKey(env: Env) {
  const k = await crypto.subtle.importKey("raw", enc.encode(`${env.CONFIRM_SECRET}\n${env.GRANT_EPOCH}`), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", k, enc.encode("holdt/webauthn-challenge/v1")));
}
/** Single use across isolates when the Durable Object is bound, else KV plus the in-isolate reserve in confirm.ts. */
function usedStore(env: Env): UsedStore {
  const g = guardFor(env);
  if (g) return { has: () => false, add: () => undefined, spend: (n, exp) => g.spend(`webauthn:${n}`, exp) };
  return { has: async (n) => !!(await env.OAUTH_KV.get(`webauthn-used:${n}`)), add: (n) => env.OAUTH_KV.put(`webauthn-used:${n}`, "1", { expirationTtl: 900 }) };
}
export type Purpose = "login" | "enroll" | "enroll_pair" | "away";
export async function newChallenge(env: Env, purpose: Purpose, bind: string, now = Date.now()) {
  const token = await issue(await challengeKey(env), `webauthn_${purpose}`, { bind }, CHALLENGE_TTL_MS, now);
  return { token, challenge: b64u(await sha(token)) };
}
/** Checks the signed challenge token and spends it. Returns the challenge bytes the browser must have signed. */
export async function takeChallenge(env: Env, purpose: Purpose, bind: string, token: string, now = Date.now()) {
  const key = await challengeKey(env), expired = "The Face ID request expired. Reload the page and try again.";
  // Check the binding before spending, so a challenge pasted into another request can't burn the real one.
  const peek = await verify<{ bind: string }>(key, String(token ?? ""), `webauthn_${purpose}`, NO_SPEND, now, expired);
  if (peek.ok && !safeEq(String(peek.payload.bind), bind)) throw new WebAuthnError("challenge belongs to another request");
  const v = await verify<{ bind: string }>(key, String(token ?? ""), `webauthn_${purpose}`, usedStore(env), now, expired);
  if (!v.ok) throw new WebAuthnError(/already/.test(v.reason) ? "That Face ID approval was already used. Reload the page and try again." : v.reason);
  return sha(token);
}
export const rp = (url: URL) => ({ rpId: url.hostname, origin: url.origin });
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
export const bindHandle = async (handle: string) => b64u(await sha(`consent:${handle}`));
export type PasskeyVerdict = { ok: true } | { ok: false; reason: string; message: string };
export async function checkPasskeyLogin(env: Env, url: URL, handle: string, f: { token: string; id: string; clientDataJSON: string; authenticatorData: string; signature: string }, now = Date.now()): Promise<PasskeyVerdict> {
  const no = (reason: string, message = "Face ID didn't confirm it's you.\nTry again, or approve on your iPhone.") => ({ ok: false as const, reason, message });
  if (!passkeysOn(env)) return no("off", "Face ID sign-in is turned off on this server.");
  try {
    const creds = await loadPasskeys(env);
    // Fail closed if the store somehow holds more than the cap: something wrote around enrollment.
    if (creds.length > MAX_PASSKEYS) return no("over cap", "Face ID sign-in is paused on this server. The person who set up Holdt can reset Face ID from their computer.");
    const cred = usableHere(creds, url).find((c) => safeEq(c.id, String(f.id ?? "")));
    if (!cred) return no("unknown passkey", "This device isn't set up for Face ID with Holdt.\nApprove on your iPhone instead.");
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
  if (now - Number(env.ENROLL_TOKEN_ISSUED) > ENROLL_TTL_MS) return "This link expired. Links last 10 minutes. Make a new one on your computer.";
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
export const json = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" } });

/** Registration options for this host. Shared by the setup link and by pairing. */
export async function createOptions(env: Env, url: URL, creds: StoredCredential[], purpose: "enroll" | "enroll_pair", bind: string, now: number) {
  const c = await newChallenge(env, purpose, bind, now);
  return { challenge_token: c.token, publicKey: {
    rp: { id: url.hostname, name: PASSKEY_NAMES.rp }, user: { id: b64u(await sha(`holdt-owner:${url.hostname}`)), name: PASSKEY_NAMES.user, displayName: PASSKEY_NAMES.user },
    challenge: c.challenge, pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }], timeout: 120000, attestation: "none",
    authenticatorSelection: { residentKey: "preferred", userVerification: "required" }, excludeCredentials: creds.map((x) => ({ type: "public-key", id: x.id })) } };
}
const FULL = `Holdt already has ${MAX_PASSKEYS} Face ID devices, the most it allows. Reset Face ID from your computer to start over.`;
/** Same-origin JSON only. A form on another site can't send application/json without a preflight we never answer,
 * and a missing or foreign Origin is refused, so no page elsewhere can drive these endpoints (CSRF). */
export function sameOriginJson(req: Request, url: URL): Response | undefined {
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);
  if (req.headers.get("origin") !== url.origin) return json({ error: "origin not allowed" }, 403);
  if (!/^application\/json\b/i.test(req.headers.get("content-type") ?? "")) return json({ error: "content type not allowed" }, 415);
  return undefined;
}
export async function readJson(req: Request): Promise<any> { const t = await req.text(); if (t.length > 20000) throw new Error("too large"); return JSON.parse(t); }

export async function enrollApi(req: Request, env: Env, now = Date.now()): Promise<Response> {
  const url = new URL(req.url);
  const bad = sameOriginJson(req, url); if (bad) return bad;
  let b: any; try { b = await readJson(req); } catch { return json({ ok: false, message: "Bad request." }, 400); }
  if (!passkeysOn(env)) return json({ ok: false, message: "Face ID sign-in is turned off on this server." }, 400);
  // Two ways in: the setup link from the owner's computer (token), or a pairing an enrolled device approved (pair).
  const viaPair = typeof b?.pair === "string" && !b?.token;
  const pair = viaPair ? await pairForEnroll(env, b.pair, now) : undefined;
  if (viaPair && !pair!.ok) return json({ ok: false, message: pair!.message }, 400);
  if (!viaPair) { const problem = await enrollTokenProblem(env, b?.token, now); if (problem) return json({ ok: false, message: problem }, 400); }
  const pairId = pair && pair.ok ? pair.id : "";
  const bind = viaPair ? `pair:${pairId}` : env.ENROLL_TOKEN_HASH!;
  const creds = await loadPasskeys(env);
  if (url.pathname === "/enroll/options") {
    if (creds.length >= MAX_PASSKEYS) return json({ ok: false, message: FULL }, 400);
    return json({ ok: true, ...(await createOptions(env, url, creds, viaPair ? "enroll_pair" : "enroll", bind, now)) });
  }
  if (url.pathname === "/enroll/finish") {
    try {
      const challenge = await takeChallenge(env, viaPair ? "enroll_pair" : "enroll", bind, b.challenge_token, now);
      const cred = await verifyRegistration({ clientDataJSON: b.clientDataJSON, attestationObject: b.attestationObject }, { ...rp(url), challenge }, now);
      if (creds.some((c) => c.id === cred.id)) return json({ ok: false, message: "This device already uses Face ID with Holdt." }, 400);
      if (creds.length >= MAX_PASSKEYS) return json({ ok: false, message: FULL }, 400);
      const via = viaPair ? "approved on another device" : "setup link";
      cred.via = via; cred.rpId = url.hostname;
      // Spent here, after Face ID made a real passkey, never on opening the page (a link preview can't burn it).
      if (viaPair ? !(await spendPair(env, pairId, now)) : !(await spendEnrollToken(env, now)))
        return json({ ok: false, message: viaPair ? "This approval was already used. Start again on this device." : "This link was already used. Make a new one on your computer to add another device." }, 400);
      cred.label = typeof b.label === "string" ? b.label.replace(/[^\w .'-]/g, "").slice(0, 40) : undefined;
      const added = await addPasskey(env, cred);
      if (added !== "ok") return json({ ok: false, message: added === "dup" ? "This device already uses Face ID with Holdt." : FULL }, 400);
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
const TOUCH = `const touch=/Macintosh/.test(navigator.userAgent)&&!('ontouchend' in document),bio=touch?'Touch ID':'Face ID';if(touch)document.documentElement.classList.add('touch');`;
/** Pages with no other script: on a Mac, say Touch ID inside [data-bio] and show the fingerprint glyph. */
export const BIO_SWAP = `(()=>{if(!(/Macintosh/.test(navigator.userAgent)&&!('ontouchend' in document)))return;document.documentElement.classList.add('touch');document.querySelectorAll('[data-bio]').forEach(e=>{const w=document.createTreeWalker(e,4);let n;while((n=w.nextNode()))n.nodeValue=n.nodeValue.replace(/Face(\\u00a0| )ID/g,'Touch$1ID');});document.title=document.title.replace('Face ID','Touch ID');})();`;
export const LOGIN_SCRIPT = `${CODEC}${TOUCH}
const btn=document.getElementById('pk'),f=btn.form,o=JSON.parse(btn.dataset.o),msg=document.getElementById('pkmsg').lastElementChild,mode=document.getElementById('mode'),live=document.getElementById('live'),wrap=document.getElementById('altwrap'),lab=document.getElementById('pklabel'),mk=document.getElementById('mk');
if(touch)lab.textContent='Allow with Touch ID';
const setMode=(on,say)=>{f.classList.toggle('code',on);if(!on){msg.parentNode.classList.remove('keep');msg.textContent='';live.textContent='';}mode.setAttribute('aria-expanded',on?'true':'false');if(say){live.textContent=on?'Approval code shown':bio+' shown';(on?document.getElementById('code'):btn).focus();}};
f.classList.add('js');btn.hidden=false;mode.hidden=false;mode.addEventListener('click',()=>setMode(!f.classList.contains('code'),true));
if(touch)document.getElementById('modeface').textContent='Use Touch ID instead';
if(!window.PublicKeyCredential){btn.hidden=true;mode.hidden=true;setMode(true);msg.parentNode.classList.add('keep');msg.textContent=bio+' isn’t available in this window. Use an approval code instead.';live.textContent=msg.textContent;}
const cf=document.getElementById('code');cf.addEventListener('input',()=>{const d=cf.value.replace(/\\D/g,'').slice(0,8),v=d.length>4?d.slice(0,4)+' '+d.slice(4):d;if(v!==cf.value)cf.value=v;});
let busy=false,fails=0;btn.addEventListener('click',async()=>{if(busy)return;busy=true;btn.setAttribute('aria-disabled','true');msg.textContent='';try{
const c=await navigator.credentials.get({publicKey:{challenge:b(o.challenge),rpId:o.rpId,allowCredentials:o.ids.map(id=>({type:'public-key',id:b(id),transports:['internal','hybrid']})),userVerification:'required',timeout:120000}});
f.pk_id.value=c.id;f.pk_cdj.value=u(c.response.clientDataJSON);f.pk_ad.value=u(c.response.authenticatorData);f.pk_sig.value=u(c.response.signature);
btn.setAttribute('aria-busy','true');lab.textContent='Approving';mk.classList.add('drop');wrap.inert=true;f.classList.add('busy');live.textContent='Approving. One moment.';f.submit();
}catch(e){busy=false;btn.removeAttribute('aria-disabled');fails++;msg.textContent=fails>1?bio+' didn’t finish.\\nEnter your approval code below.':bio+' didn’t finish.\\nTry again or use a\u00a0code.';if(fails>1){setMode(true);msg.parentNode.classList.add('keep');document.getElementById('code').focus();live.textContent=msg.textContent+' Approval code shown.';}else live.textContent=msg.textContent;}});`;
// Shared by the pages below: same-origin JSON POST, the views, and making a passkey.
const POST = `const post=(p,o)=>fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(o)}).then(r=>r.json()).catch(()=>({ok:false,net:1,message:'Holdt couldn’t reach your server. Check your connection and try again.'}));`;
const VIEWS = (ids: string[]) => `const $=id=>document.getElementById(id),VIEWS=${JSON.stringify(ids)},show=id=>{VIEWS.forEach(x=>{const e=$(x);if(e)e.hidden=x!==id;});const h=$(id)&&$(id).querySelector('h1');if(h){h.setAttribute('tabindex','-1');h.focus();}};`;
const REGISTER = `const register=async(r,extra,onBusy)=>{const p=JSON.parse(JSON.stringify(r.publicKey));p.challenge=b(p.challenge);p.user.id=b(p.user.id);p.excludeCredentials=p.excludeCredentials.map(x=>({type:x.type,id:b(x.id)}));
const c=await navigator.credentials.create({publicKey:p});onBusy();
return post('/enroll/finish',Object.assign({challenge_token:r.challenge_token,clientDataJSON:u(c.response.clientDataJSON),attestationObject:u(c.response.attestationObject),label:navigator.platform||''},extra));};
const typo=m=>String(m).replace(/(\\w)'(\\w)/g,'$1’$2');`;
/** The setup link. Tap Turn on Face ID, look at the phone, done. The token leaves the address bar at once. */
export const ENROLL_SCRIPT = `${CODEC}${TOUCH}${POST}${VIEWS(["setup", "done", "skip", "dead"])}${REGISTER}
const t=location.hash.slice(1),fromSetup=/[?&]from=setup\\b/.test(location.search);history.replaceState(null,'',location.pathname);
const btn=$('go'),msg=$('msg').lastElementChild,live=$('live'),blab=btn.lastElementChild;
if(touch){blab.textContent='Turn on Touch ID';$('title').textContent='Turn on Touch ID';$('face1').textContent='Your fingerprint stays on your Mac. Holdt never sees it.';$('skip').querySelector('h1').textContent='Touch ID not turned on';$('skip').querySelector('.lede').textContent='Holdt needs Touch ID to approve connections on this Mac. Turn it on whenever you’re ready.';}
const say=m=>{msg.textContent=m;live.textContent=m;};
const dead=m=>{const d=$('dead'),k=/expired/.test(m)?0:/already used/.test(m)?1:2;d.querySelector('h1').textContent=['This link expired','This link was already used','This link doesn’t work'][k];d.querySelector('.lede').textContent=['Links last 10 minutes. ','Each link adds one device. ','This link isn’t complete or isn’t current. '][k]+'Make a new one on the computer where you set up Holdt.';show('dead');};
$('later').addEventListener('click',()=>show('skip'));
// The options are fetched as the page opens (a POST from this script, which spends nothing), so the one click goes
// straight to the passkey sheet with the browser's user gesture intact. Only /enroll/finish, after that click and
// Touch ID or Face ID, spends the link.
let pre=null,preAt=0;const fetchOpts=()=>{preAt=Date.now();pre=post('/enroll/options',{token:t});return pre;};
if(!t){btn.disabled=true;say('This link is missing its last part. Open the newest link from your computer.');}
else if(!window.PublicKeyCredential){btn.disabled=true;say('This browser can’t save '+bio+' for Holdt. Open the link in Safari.');}
else fetchOpts().then(r=>{if(!r.ok&&!r.net&&!/most it allows/.test(r.message||''))dead(r.message);});
const idle=()=>{blab.textContent='Turn on '+bio;};
btn.addEventListener('click',async()=>{btn.disabled=true;say('');try{
let r=await(Date.now()-preAt<240000&&pre?pre:fetchOpts());if(!r.ok&&r.net)r=await fetchOpts();
if(!r.ok){if(r.net||/most it allows/.test(r.message||''))throw new Error(r.message);return dead(r.message);}
const d=await register(r,{token:t},()=>{btn.setAttribute('aria-busy','true');blab.textContent='Turning on';live.textContent='Turning on '+bio+'. One moment.';});
if(!d.ok){if(/already used|expired/.test(d.message||''))return dead(d.message);throw new Error(d.message);}
const h=$('done').querySelector('h1');h.textContent=bio+' is on';
const lede=$('done').querySelector('.lede');lede.textContent=fromSetup?(touch?'Holdt is ready. With iCloud Keychain on, your iPhone can use it too.':'Holdt is ready on this device. With iCloud Keychain on, your other Apple devices can use it too.'):touch?'Next time, click Allow with Touch ID. With iCloud Keychain on, your other Apple devices can use it too.':lede.textContent;if(touch)$('done').querySelector('h1').textContent='Touch ID is on';
if(fromSetup){$('next').hidden=false;$('closeline').hidden=true;const cl=$('copy').lastElementChild;$('copy').addEventListener('click',async()=>{try{await navigator.clipboard.writeText($('say').textContent);cl.textContent='Copied';$('copylive').textContent='Copied. Paste it in Grok Bot.';setTimeout(()=>{cl.textContent='Copy';},2000);}catch(e){const r=document.createRange();r.selectNodeContents($('say'));const s=getSelection();s.removeAllRanges();s.addRange(r);cl.textContent='Copy';$('copylive').textContent='Couldn’t copy. The text is selected, so copy it yourself.';}});}
show('done');requestAnimationFrame(()=>$('mkdone').classList.add('drop'));
}catch(e){btn.disabled=false;btn.removeAttribute('aria-busy');idle();live.textContent='';fetchOpts();
if(e&&e.name==='NotAllowedError')say(bio+' didn’t finish.\\nTry again when you’re\u00a0ready.');else if(e&&e.name==='InvalidStateError')say('This device already uses '+bio+' with Holdt.');else say(typo((e&&e.message)||'That didn’t work. Try again.'));btn.focus();}});`;

/** The consent page: Face ID here (the sheet can also offer a nearby phone), or scan the QR code and approve on the iPhone.
 * The page polls for the iPhone's answer and finishes by itself. Without script, the QR code shows with a Continue button. */
export const CONSENT_SCRIPT = `${CODEC}${TOUCH}${POST}
const $=id=>document.getElementById(id),btn=$('pk'),f=btn.form,o=JSON.parse(btn.dataset.o),msg=$('pkmsg').lastElementChild,mode=$('mode'),live=$('live'),wrap=$('altwrap'),lab=$('pklabel'),mk=$('mk'),panel=$('awaypanel'),am=$('awaymsg'),other=panel.dataset.other||'your iPhone',Other=other;
if(touch){lab.textContent='Allow with Touch ID';$('modeface').textContent='Use Touch ID on this Mac';}
let timer=0,done=false,fails=0,busy=false;
const say=m=>{msg.textContent=m;live.textContent=m;};
const refresh=async()=>{const r=await post('/authorize/away/new',{handle:f.handle.value,ctx:f.ctx.value});if(r&&r.ok&&r.qr){const w=$('qrwrap');w.innerHTML=r.qr;w.dataset.link=r.link;}};
const finish=(away)=>{done=true;clearInterval(timer);if(away){$('awayok').hidden=false;window.scrollTo(0,0);live.textContent='Approved on '+Other+'. Finishing up.';f.away.value='1';}
mk.classList.add('drop');wrap.inert=true;f.classList.add('busy');setTimeout(()=>f.submit(),away?500:0);};
const poll=async()=>{if(done||document.hidden)return;const r=await post('/authorize/away',{handle:f.handle.value});if(done||!r||!r.ok)return;
if(r.status==='approved')finish(true);
else if(r.status==='denied'){done=true;clearInterval(timer);const i=document.createElement('input');i.type='hidden';i.name='decision';i.value='deny';f.appendChild(i);live.textContent='Not allowed on '+Other+'.';f.submit();}
else if(r.status==='gone')refresh();};
const setMode=(on,speak)=>{f.classList.toggle('away',on);if(!on){msg.parentNode.classList.remove('keep');msg.textContent='';live.textContent='';}mode.setAttribute('aria-expanded',on?'true':'false');
if(on&&!timer)timer=setInterval(poll,2000);if(speak){live.textContent=on?(other==='your iPhone'?'QR code shown. Scan it with your iPhone’s camera.':'QR code shown. Scan it with another device’s camera.'):bio+' shown';if(on){panel.focus({preventScroll:true});const d=f.querySelector('[value=deny]')||panel,fc=document.querySelector('.facts')||panel,y=e=>e.getBoundingClientRect().top+scrollY,need=d.getBoundingClientRect().bottom+scrollY+24-innerHeight;if(need>scrollY)scrollTo(0,y(fc)-12>=need?y(fc)-12:y(panel)-16);}else btn.focus();}};
f.classList.add('js');btn.hidden=false;mode.hidden=false;mode.addEventListener('click',()=>setMode(!f.classList.contains('away'),true));
if(f.classList.contains('away'))setMode(true);
if(!window.PublicKeyCredential){btn.hidden=true;mode.hidden=true;setMode(true);}
btn.addEventListener('click',async()=>{if(busy||done)return;busy=true;btn.setAttribute('aria-disabled','true');msg.textContent='';try{
const c=await navigator.credentials.get({publicKey:{challenge:b(o.challenge),rpId:o.rpId,allowCredentials:o.ids.map(id=>({type:'public-key',id:b(id),transports:['internal','hybrid']})),userVerification:'required',timeout:120000}});
if(done)return;f.pk_id.value=c.id;f.pk_cdj.value=u(c.response.clientDataJSON);f.pk_ad.value=u(c.response.authenticatorData);f.pk_sig.value=u(c.response.signature);
btn.setAttribute('aria-busy','true');lab.textContent='Approving';live.textContent='Approving. One moment.';finish(false);
}catch(e){busy=false;btn.removeAttribute('aria-disabled');if(done)return;fails++;
if(fails>1){setMode(true);msg.parentNode.classList.add('keep');say(bio+' didn’t finish.\\nScan the QR code with '+(other==='your iPhone'?'your iPhone':'another device')+' instead.');}else say(bio+' didn’t finish.\\nTry again, or approve on '+other.replace(/ (\\S+)$/,'\u00a0$1')+'.');}});`;

/** Consent page before any device has Face ID: wait, and carry on by itself once one does. */
export const READY_SCRIPT = `${POST}
const m=document.getElementById('readymsg');if(m){m.hidden=false;setTimeout(()=>{document.getElementById('readylive').textContent=m.textContent.replace(/\\s+/g,' ').trim();},600);}
const t=setInterval(async()=>{if(document.hidden)return;const r=await post('/authorize/ready',{});if(r&&r.ready){clearInterval(t);location.reload();}},3000);`;

/** The approving iPhone. The secret leaves the address bar at once. Reading the request is a POST, so a link preview
 * that fetches the page learns and changes nothing. Approving needs a tap and Face ID. */
export const OK_SCRIPT = `${CODEC}${TOUCH}${POST}${VIEWS(["load", "ask", "ok", "no", "dead", "nopk"])}
const s=location.hash.slice(1);history.replaceState(null,'',location.pathname);
const gone=r=>{if(r.gone==='nopk')return show('nopk');const d=$('dead');
if(r.gone==='decided'){d.querySelector('h1').textContent='Already answered';d.querySelector('.lede').textContent='This request already has an answer. There’s nothing more to do here.';}
else if(r.gone==='invalid'||r.net){d.querySelector('h1').textContent=r.net?'Holdt couldn’t reach your server':'This link doesn’t work';d.querySelector('.lede').textContent=r.net?'Check your connection, then scan the code again.':'Scan the newest code on your computer.';}
show('dead');};
(async()=>{if(!s)return gone({gone:'invalid'});let o=await post('/ok/view',{s});if(!o.ok)return gone(o);
$('ask').innerHTML=o.html;show('ask');$('ask').querySelector('h1').removeAttribute('tabindex');
if(o.kind==='pair'){$('ok').querySelector('h1').textContent='Device approved';$('ok').querySelector('.lede').textContent='Go back to the new device to finish.';$('no').querySelector('h1').textContent='Device not added';$('no').querySelector('.lede').textContent='Nothing changed.';}else if(o.device&&o.device!=='device')$('ok').querySelector('.lede').textContent='Your '+o.device+' finishes on its own. There’s nothing more to do here.';
const yes=$('yes'),lab=$('yeslabel'),msg=$('askmsg').lastElementChild,live=$('live'),idle=()=>{lab.textContent='Allow with '+bio;};idle();
const say=m=>{msg.textContent=m;live.textContent=m;};
if(!window.PublicKeyCredential){yes.disabled=true;say(bio+' isn’t available in this browser. Open the link in Safari.');}
let busy=false;
yes.addEventListener('click',async()=>{if(busy)return;busy=true;yes.setAttribute('aria-disabled','true');say('');try{
const c=await navigator.credentials.get({publicKey:{challenge:b(o.challenge),rpId:o.rpId,allowCredentials:o.ids.map(id=>({type:'public-key',id:b(id),transports:['internal','hybrid']})),userVerification:'required',timeout:120000}});
yes.setAttribute('aria-busy','true');lab.textContent='Approving';live.textContent='Approving. One moment.';
const d=await post('/ok/approve',{s,challenge_token:o.challenge_token,id:c.id,clientDataJSON:u(c.response.clientDataJSON),authenticatorData:u(c.response.authenticatorData),signature:u(c.response.signature)});
if(d.ok){show('ok');requestAnimationFrame(()=>$('mkok').classList.add('drop'));return;}
if(d.gone)return gone(d);
const n=await post('/ok/view',{s});if(n.ok)o=n;else return gone(n);throw new Error(d.message);
}catch(e){busy=false;yes.removeAttribute('aria-disabled');yes.removeAttribute('aria-busy');idle();
say(e&&e.name==='NotAllowedError'?bio+' didn’t finish.\\nTry again, or tap Don’t\u00a0allow.':String((e&&e.message)||'That didn’t work. Try again.'));yes.focus();}});
$('nope').addEventListener('click',async()=>{const d=await post('/ok/deny',{s});if(d.ok)show('no');else gone(d);});
})();`;

/** A new device: show a QR code, wait for the iPhone's yes, then make this device's own passkey on a tap.
 * The claim secret stays in this page's memory. It is never in the QR code, so whoever sees the code can't enroll. */
export const PAIR_SCRIPT = `${CODEC}${TOUCH}${POST}${VIEWS(["ask", "ready", "done", "no", "skip", "dead", "nopk"])}${REGISTER}
let claim='',opts=null,timer=0;const live=$('live');
if(touch){$('ready').querySelector('h1').textContent='Turn on Touch ID';$('go').lastElementChild.textContent='Turn on Touch ID';$('done').querySelector('h1').textContent='Touch ID is on';$('done').querySelector('.lede').textContent='Next time, click Allow with Touch ID on this Mac.';}
const stop=()=>{clearInterval(timer);timer=0;};
const poll=async()=>{if(document.hidden||!claim)return;const r=await post('/pair/status',{claim});if(!r||!r.ok||!timer)return;
if(r.status==='approved'&&r.publicKey){stop();opts=r;show('ready');}else if(r.status==='denied'){stop();show('no');}else if(r.status==='gone'){stop();show('dead');}};
(async()=>{const r=await post('/pair/new',{});if(!r.ok)return show(/yet/.test(r.message||'')?'nopk':'dead');claim=r.claim;const w=$('qrwrap');w.innerHTML=r.qr;w.classList.remove('qrwait');live.textContent='QR code shown. Scan it with your iPhone’s camera.';timer=setInterval(poll,2000);})();
$('later').addEventListener('click',()=>{stop();show('skip');});$('later2').addEventListener('click',()=>show('skip'));
const btn=$('go'),msg=$('msg').lastElementChild,live2=$('live2'),blab=btn.lastElementChild,idle=()=>{blab.textContent='Turn on '+bio;};
const say=m=>{msg.textContent=m;live2.textContent=m;};
btn.addEventListener('click',async()=>{btn.disabled=true;btn.setAttribute('aria-busy','true');say('');try{
const d=await register(opts,{pair:claim},()=>{blab.textContent='Turning on';live2.textContent='Turning on '+bio+'. One moment.';});
if(!d.ok){if(/expired|already used/.test(d.message||'')){show('dead');return;}throw new Error(d.message);}
show('done');requestAnimationFrame(()=>$('mkdone').classList.add('drop'));
}catch(e){btn.disabled=false;btn.removeAttribute('aria-busy');idle();
if(e&&e.name==='NotAllowedError')say(bio+' didn’t finish.\\nTry again when you’re\u00a0ready.');else if(e&&e.name==='InvalidStateError')say('This device already uses '+bio+' with Holdt.');else say(typo((e&&e.message)||'That didn’t work. Try again.'));btn.focus();}});`;
