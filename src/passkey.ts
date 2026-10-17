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

const enc = new TextEncoder();
export const ENROLL_TTL_MS = 15 * 60_000, CHALLENGE_TTL_MS = 5 * 60_000, MAX_PASSKEYS = 10;
const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const sha = async (s: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const safeEq = (a: string, b: string) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };

export const passkeysOn = (env: Partial<Env>) => env.PASSKEYS === "on";
const credsKey = (env: Partial<Env>) => `passkeys:v1:${env.PASSKEY_EPOCH || "0"}`;
export async function loadPasskeys(env: Env): Promise<StoredCredential[]> {
  try { const v = await env.OAUTH_KV.get(credsKey(env)); const a = v ? JSON.parse(v) : []; return Array.isArray(a) ? a : []; } catch { return []; }
}
const savePasskeys = (env: Env, a: StoredCredential[]) => env.OAUTH_KV.put(credsKey(env), JSON.stringify(a));

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
async function newChallenge(env: Env, purpose: "login" | "enroll", bind: string, now = Date.now()) {
  const token = await issue(await challengeKey(env), `webauthn_${purpose}`, { bind }, CHALLENGE_TTL_MS, now);
  return { token, challenge: b64u(await sha(token)) };
}
/** Checks the signed challenge token and spends it. Returns the challenge bytes the browser must have signed. */
async function takeChallenge(env: Env, purpose: "login" | "enroll", bind: string, token: string, now = Date.now()) {
  const key = await challengeKey(env), expired = "The Face ID request expired (5 minutes). Reload the page and try again.";
  // Check the binding before spending, so a challenge pasted into another request can't burn the real one.
  const peek = await verify<{ bind: string }>(key, String(token ?? ""), `webauthn_${purpose}`, NO_SPEND, now, expired);
  if (peek.ok && !safeEq(String(peek.payload.bind), bind)) throw new WebAuthnError("challenge belongs to another request");
  const v = await verify<{ bind: string }>(key, String(token ?? ""), `webauthn_${purpose}`, usedStore(env), now, expired);
  if (!v.ok) throw new WebAuthnError(/already/.test(v.reason) ? "That Face ID approval was already used. Reload the page and try again." : v.reason);
  return sha(token);
}
const rp = (url: URL) => ({ rpId: url.hostname, origin: url.origin });

// ---------- connect (consent page) ----------
/** Options for the consent page's "Allow with Face ID" button, or undefined when one-tap is off or nothing is enrolled. */
export async function loginOptions(env: Env, url: URL, handle: string) {
  if (!passkeysOn(env) || !env.CONFIRM_SECRET) return undefined;
  const creds = await loadPasskeys(env); if (!creds.length) return undefined;
  const c = await newChallenge(env, "login", await bindHandle(handle));
  return { token: c.token, challenge: c.challenge, rpId: url.hostname, ids: creds.map((x) => x.id) };
}
const bindHandle = async (handle: string) => b64u(await sha(`consent:${handle}`));
export type PasskeyVerdict = { ok: true } | { ok: false; reason: string; message: string };
export async function checkPasskeyLogin(env: Env, url: URL, handle: string, f: { token: string; id: string; clientDataJSON: string; authenticatorData: string; signature: string }, now = Date.now()): Promise<PasskeyVerdict> {
  const no = (reason: string, message = "Face ID didn't confirm it's you. Try again, or use an approval code.") => ({ ok: false as const, reason, message });
  if (!passkeysOn(env)) return no("off", "One-tap connect is turned off. Use an approval code.");
  try {
    const creds = await loadPasskeys(env);
    const cred = creds.find((c) => safeEq(c.id, String(f.id ?? "")));
    if (!cred) return no("unknown passkey", "That passkey isn't enrolled here. Use an approval code, or run npm run setup -- --add-device.");
    const challenge = await takeChallenge(env, "login", await bindHandle(handle), f.token, now);
    const { signCount } = await verifyAssertion(f, cred, { ...rp(url), challenge });
    if (signCount !== cred.signCount) { cred.signCount = signCount; await savePasskeys(env, creds); }
    return { ok: true };
  } catch (e) {
    if (e instanceof WebAuthnError) { log.warn(`passkey refused: ${e.message.slice(0, 80)}`); return no(e.message, /expired|already used/.test(e.message) ? e.message : undefined); }
    throw e;
  }
}

// ---------- enrollment ----------
async function enrollTokenProblem(env: Env, token: string, now: number): Promise<string | undefined> {
  if (!passkeysOn(env)) return "One-tap connect is turned off on this server.";
  if (!env.ENROLL_TOKEN_HASH || !env.ENROLL_TOKEN_ISSUED) return "No enroll link is active. On your computer, run npm run setup -- --add-device.";
  if (!safeEq(hex(await crypto.subtle.digest("SHA-256", enc.encode(String(token ?? "")))), env.ENROLL_TOKEN_HASH)) return "This enroll link isn't valid. Use the newest link from npm run setup -- --add-device.";
  if (now - Number(env.ENROLL_TOKEN_ISSUED) > ENROLL_TTL_MS) return "This enroll link expired (15 minutes). Run npm run setup -- --add-device for a fresh one.";
  if (await env.OAUTH_KV.get(`enroll-used:${env.ENROLL_TOKEN_HASH}`)) return "This enroll link was already used. Run npm run setup -- --add-device to add another device.";
  return undefined;
}
async function spendEnrollToken(env: Env, now: number) {
  const g = guardFor(env), h = env.ENROLL_TOKEN_HASH!;
  if (g && !(await g.spend(`enroll:${h}`, Number(env.ENROLL_TOKEN_ISSUED) + ENROLL_TTL_MS))) return false;
  if (await env.OAUTH_KV.get(`enroll-used:${h}`)) return false;
  await env.OAUTH_KV.put(`enroll-used:${h}`, String(now), { expirationTtl: 86400 });
  return true;
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
    if (creds.length >= MAX_PASSKEYS) return json({ ok: false, message: `This server already has ${MAX_PASSKEYS} passkeys. Run npm run setup -- --reset-passkeys to start over.` }, 400);
    const c = await newChallenge(env, "enroll", bind, now);
    return json({ ok: true, challenge_token: c.token, publicKey: {
      rp: { id: url.hostname, name: "Holdt" }, user: { id: b64u(await sha(`holdt-owner:${url.hostname}`)), name: "Holdt owner", displayName: "Holdt (iCloud Calendar)" },
      challenge: c.challenge, pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }], timeout: 120000, attestation: "none",
      authenticatorSelection: { residentKey: "preferred", userVerification: "required" }, excludeCredentials: creds.map((x) => ({ type: "public-key", id: x.id })) } });
  }
  if (url.pathname === "/enroll/finish") {
    try {
      const challenge = await takeChallenge(env, "enroll", bind, b.challenge_token, now);
      const cred = await verifyRegistration({ clientDataJSON: b.clientDataJSON, attestationObject: b.attestationObject }, { ...rp(url), challenge }, now);
      if (creds.some((c) => c.id === cred.id)) return json({ ok: false, message: "This device is already enrolled." }, 400);
      if (!(await spendEnrollToken(env, now))) return json({ ok: false, message: "This enroll link was already used. Run npm run setup -- --add-device to add another device." }, 400);
      cred.label = typeof b.label === "string" ? b.label.replace(/[^\w .'-]/g, "").slice(0, 40) : undefined;
      await savePasskeys(env, [...creds, cred]);
      log.info("passkey enrolled");
      return json({ ok: true, count: creds.length + 1 });
    } catch (e) {
      if (e instanceof WebAuthnError) { log.warn(`enroll refused: ${e.message.slice(0, 80)}`); return json({ ok: false, message: "Couldn't save the passkey. Reload this page and try again." }, 400); }
      throw e;
    }
  }
  return json({ error: "not found" }, 404);
}

// ---------- browser scripts (served with a per-response nonce, no other script may run) ----------
const CODEC = `const b=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));const u=a=>btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');`;
export const LOGIN_SCRIPT = `${CODEC}
const btn=document.getElementById('pk'),f=btn.form,o=JSON.parse(btn.dataset.o),msg=document.getElementById('pkmsg'),alt=document.getElementById('codealt');
if(!window.PublicKeyCredential){btn.hidden=true;alt.open=true;msg.textContent="Face ID isn't available in this window. Use an approval code.";}
btn.addEventListener('click',async()=>{btn.disabled=true;msg.textContent='';try{
const c=await navigator.credentials.get({publicKey:{challenge:b(o.challenge),rpId:o.rpId,allowCredentials:o.ids.map(id=>({type:'public-key',id:b(id)})),userVerification:'required',timeout:120000}});
f.pk_id.value=c.id;f.pk_cdj.value=u(c.response.clientDataJSON);f.pk_ad.value=u(c.response.authenticatorData);f.pk_sig.value=u(c.response.signature);f.submit();
}catch(e){btn.disabled=false;alt.open=true;msg.textContent="Face ID didn't finish. Try again, or use an approval code.";}});`;
export const ENROLL_SCRIPT = `${CODEC}
const t=location.hash.slice(1);history.replaceState(null,'',location.pathname);
const btn=document.getElementById('go'),msg=document.getElementById('msg');
const post=(p,o)=>fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(o)}).then(r=>r.json());
if(!t){btn.hidden=true;msg.textContent='Open the full link from npm run setup -- --add-device.';}
else if(!window.PublicKeyCredential){btn.hidden=true;msg.textContent="This browser can't save passkeys. Open the link in Safari or Chrome.";}
btn.addEventListener('click',async()=>{btn.disabled=true;msg.textContent='';try{
const r=await post('/enroll/options',{token:t});if(!r.ok)throw new Error(r.message);
const p=r.publicKey;p.challenge=b(p.challenge);p.user.id=b(p.user.id);p.excludeCredentials=p.excludeCredentials.map(x=>({type:x.type,id:b(x.id)}));
const c=await navigator.credentials.create({publicKey:p});
const d=await post('/enroll/finish',{token:t,challenge_token:r.challenge_token,clientDataJSON:u(c.response.clientDataJSON),attestationObject:u(c.response.attestationObject),label:navigator.platform||''});
if(!d.ok)throw new Error(d.message);document.getElementById('card').innerHTML='<h1>One-tap connect is on</h1><p class="muted">Next time you connect, tap Allow with Face ID. Your other Apple devices get this passkey through iCloud Keychain.</p>';
}catch(e){btn.disabled=false;msg.textContent=e&&e.name==='NotAllowedError'?'Cancelled. Tap the button to try again.':(e&&e.message)||'That didn\\'t work. Try again.';}});`;
