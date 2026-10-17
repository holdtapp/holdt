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
async function newChallenge(env: Env, purpose: "login" | "enroll" | "enroll_auth", bind: string, now = Date.now()) {
  const token = await issue(await challengeKey(env), `webauthn_${purpose}`, { bind }, CHALLENGE_TTL_MS, now);
  return { token, challenge: b64u(await sha(token)) };
}
/** Checks the signed challenge token and spends it. Returns the challenge bytes the browser must have signed. */
async function takeChallenge(env: Env, purpose: "login" | "enroll" | "enroll_auth", bind: string, token: string, now = Date.now()) {
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
  if (creds.length > MAX_PASSKEYS) { log.warn("passkeys over the cap: one-tap off until --reset-passkeys"); return undefined; }
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
    // Fail closed if the store somehow holds more than the cap: something wrote around enrollment.
    if (creds.length > MAX_PASSKEYS) return no("over cap", "One-tap connect is paused on this server. Use an approval code, then run npm run setup -- --reset-passkeys.");
    const cred = creds.find((c) => safeEq(c.id, String(f.id ?? "")));
    if (!cred) return no("unknown passkey", "That passkey isn't enrolled here. Use an approval code, or run npm run setup -- --add-device.");
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
/** "New device added <date>" for the consent page and connection_status, for passkeys added in the last 7 days. */
export const NOTICE_DAYS = 7;
export function deviceNotice(creds: StoredCredential[], tz: string, now = Date.now()): string | undefined {
  const recent = creds.filter((c) => now - c.createdAt < NOTICE_DAYS * 86400_000).sort((a, b) => b.createdAt - a.createdAt);
  if (!recent.length) return undefined;
  const fmt = (ms: number) => { let z = tz; try { new Intl.DateTimeFormat("en-US", { timeZone: z }); } catch { z = "UTC"; } return new Intl.DateTimeFormat("en-US", { timeZone: z, month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit", timeZoneName: "short" }).format(ms); };
  return recent.map((c) => `New device added ${fmt(c.createdAt)}${c.label ? ` (${c.label})` : ""}`).join(". ") + ". Not you? Run npm run setup -- --reset-passkeys.";
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
    // Adding a device needs proof it's the owner: the current approval code, or a sign-in with a passkey already here.
    const auth = creds.length ? await newChallenge(env, "enroll_auth", bind, now) : undefined;
    return json({ ok: true, challenge_token: c.token, auth: auth ? { challenge_token: auth.token, challenge: auth.challenge, rpId: url.hostname, ids: creds.map((x) => x.id) } : undefined, publicKey: {
      rp: { id: url.hostname, name: "Holdt" }, user: { id: b64u(await sha(`holdt-owner:${url.hostname}`)), name: "Holdt owner", displayName: "Holdt (iCloud Calendar)" },
      challenge: c.challenge, pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }], timeout: 120000, attestation: "none",
      authenticatorSelection: { residentKey: "preferred", userVerification: "required" }, excludeCredentials: creds.map((x) => ({ type: "public-key", id: x.id })) } });
  }
  if (url.pathname === "/enroll/finish") {
    try {
      const challenge = await takeChallenge(env, "enroll", bind, b.challenge_token, now);
      const cred = await verifyRegistration({ clientDataJSON: b.clientDataJSON, attestationObject: b.attestationObject }, { ...rp(url), challenge }, now);
      if (creds.some((c) => c.id === cred.id)) return json({ ok: false, message: "This device is already enrolled." }, 400);
      if (creds.length >= MAX_PASSKEYS) return json({ ok: false, message: `This server already has ${MAX_PASSKEYS} passkeys. Run npm run setup -- --reset-passkeys to start over.` }, 400);
      // The link alone is never enough: whoever opens a leaked link still needs the owner's code or passkey.
      let via: "approval code" | "existing passkey";
      if (b.auth && typeof b.auth === "object") {
        const old = creds.find((c) => safeEq(c.id, String(b.auth.id ?? "")));
        if (!old) return json({ ok: false, message: "That passkey isn't enrolled here. Enter the approval code instead." }, 400);
        const ac = await takeChallenge(env, "enroll_auth", bind, b.auth.challenge_token, now);
        const { signCount } = await verifyAssertion(b.auth, old, { ...rp(url), challenge: ac });
        if (!(await bumpPasskey(env, old, signCount))) throw new WebAuthnError("signature counter went backwards");
        via = "existing passkey";
      } else {
        const v = await checkCode(env, String(b.code ?? ""), now);
        if (!v.ok) { log.warn(`enroll refused: approval code ${v.reason}`); return json({ ok: false, field: "code", message: v.message }, 400); }
        via = "approval code";
      }
      cred.via = via;
      if (!(await spendEnrollToken(env, now))) return json({ ok: false, message: "This enroll link was already used. Run npm run setup -- --add-device to add another device." }, 400);
      cred.label = typeof b.label === "string" ? b.label.replace(/[^\w .'-]/g, "").slice(0, 40) : undefined;
      const added = await addPasskey(env, cred);
      if (added !== "ok") return json({ ok: false, message: added === "dup" ? "This device is already enrolled." : `This server already has ${MAX_PASSKEYS} passkeys. Run npm run setup -- --reset-passkeys to start over.` }, 400);
      // Visible in `npm run tail`, on the next consent pages and in connection_status (deviceNotice).
      log.info(`passkey enrolled: device "${cred.label || "unnamed"}" via ${via}, ${creds.length + 1} on this server`);
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
const code=document.getElementById('code').value;let auth;
if(!code.replace(/\D/g,'')){if(!r.auth)throw new Error('Enter the approval code from your setup screen.');
const a=await navigator.credentials.get({publicKey:{challenge:b(r.auth.challenge),rpId:r.auth.rpId,allowCredentials:r.auth.ids.map(id=>({type:'public-key',id:b(id)})),userVerification:'required',timeout:120000}});
auth={challenge_token:r.auth.challenge_token,id:a.id,clientDataJSON:u(a.response.clientDataJSON),authenticatorData:u(a.response.authenticatorData),signature:u(a.response.signature)};}
const p=r.publicKey;p.challenge=b(p.challenge);p.user.id=b(p.user.id);p.excludeCredentials=p.excludeCredentials.map(x=>({type:x.type,id:b(x.id)}));
const c=await navigator.credentials.create({publicKey:p});
const d=await post('/enroll/finish',{token:t,code,auth,challenge_token:r.challenge_token,clientDataJSON:u(c.response.clientDataJSON),attestationObject:u(c.response.attestationObject),label:navigator.platform||''});
if(!d.ok)throw new Error(d.message);document.getElementById('card').innerHTML='<h1>One-tap connect is on</h1><p class="muted">Next time you connect, tap Allow with Face ID. Your other Apple devices get this passkey through iCloud Keychain.</p>';
}catch(e){btn.disabled=false;msg.textContent=e&&e.name==='NotAllowedError'?'Cancelled. Tap the button to try again.':(e&&e.message)||'That didn\\'t work. Try again.';}});`;
