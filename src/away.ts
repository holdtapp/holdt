// Approve from another device, with nothing to type (docs/no-typed-codes.md).
//   consent: the consent page shows a QR code for /ok#<secret>. The owner scans it with an iPhone that has Holdt's passkey,
//            sees who is asking and from where, and approves with Face ID. The consent page notices and finishes.
//   pair:    a new device's /pair page shows a QR code for /ok#<secret>. An enrolled device approves with Face ID.
//            The new device then makes its own passkey, which only the page holding the claim secret can do.
// Threat model, one line each (each has an ATTACK test and a prove row):
//   leakage   the secret lives only in the fragment and in page memory. KV keeps its SHA-256. 5 minutes, then gone.
//   prefetch  every GET is a static page. Only a POST from our own page, after a tap and Face ID, changes anything.
//   CSRF      POSTs need our exact Origin and application/json.
//   replay    the Face ID challenge is single use and bound to this request. A request is decided once and used once.
//   race      approving needs an enrolled passkey. A pairing approval can only be claimed with the secret that never
//             leaves the new device's page, so someone who sees the QR code can't enroll in its place.
//   phishing  the approve page names the app, where access goes, the place the request came from, and the device type it claims.
import type { Env } from "./worker.js";
import { guardFor } from "./guard.js";
import { verifyAssertion, WebAuthnError, b64u } from "./webauthn.js";
import { log } from "./redact.js";
import { loadPasskeys, usableHere, bumpPasskey, newChallenge, takeChallenge, rp, bindHandle, json, sameOriginJson, readJson, safeEq, passkeysOn, MAX_PASSKEYS, createOptions } from "./passkey.js";

export const AWAY_TTL_MS = 5 * 60_000;
type Kind = "consent" | "pair";
type Status = "pending" | "approved" | "denied";
export type AwayRec = { kind: Kind; bind: string; created: number; from: string; status: Status; app?: Record<string, unknown>; writes?: string };
const enc = new TextEncoder();
const hex = async (s: string) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)))].map((x) => x.toString(16).padStart(2, "0")).join("");
const idOf = (secret: string) => hex(`away:${String(secret ?? "")}`);
const claimBind = async (claim: string) => `claim:${await hex(`claim:${String(claim ?? "")}`)}`;
const random = () => b64u(crypto.getRandomValues(new Uint8Array(32)));
const KV_TTL = 600;

/** Who asked, as a person would say it: "a device that says it’s a Mac near Denver, CO". The place is Cloudflare's own geo
 * fields. The device type comes from the User-Agent, which the client sets, so the page says it is only what the device says. */
export function whereFrom(req: Request): string {
  const ua = req.headers.get("user-agent") ?? "";
  const kind = /iPhone/.test(ua) ? "an iPhone" : /iPad/.test(ua) ? "an iPad" : /Android/.test(ua) ? "an Android device" : /Macintosh|Mac OS X/.test(ua) ? "a Mac" : /Windows/.test(ua) ? "a Windows PC" : /CrOS/.test(ua) ? "a Chromebook" : /Linux/.test(ua) ? "a Linux computer" : "";
  const device = kind ? `a device that says it’s ${kind}` : "a device";
  const cf = (req as any).cf ?? {};
  const city = typeof cf.city === "string" ? cf.city.replace(/[^\p{L}\p{M} .'-]/gu, "").slice(0, 40) : "";
  const region = typeof cf.regionCode === "string" && /^[A-Z0-9]{1,3}$/.test(cf.regionCode) ? cf.regionCode : typeof cf.country === "string" && /^[A-Z]{2}$/.test(cf.country) ? cf.country : "";
  return city ? `${device} near ${city}${region ? `, ${region}` : ""}` : device;
}
export const ago = (ms: number) => ms < 60_000 ? "just now" : ms < 120_000 ? "1 minute ago" : `${Math.floor(ms / 60_000)} minutes ago`;

async function load(env: Env, id: string, now: number): Promise<AwayRec | undefined> {
  const v = await env.OAUTH_KV.get(`away:${id}`); if (!v) return undefined;
  try { const r = JSON.parse(v) as AwayRec; return now - r.created > AWAY_TTL_MS ? undefined : r; } catch { return undefined; }
}
const save = (env: Env, id: string, r: AwayRec) => env.OAUTH_KV.put(`away:${id}`, JSON.stringify(r), { expirationTtl: KV_TTL });
/** First caller wins, across isolates when the Durable Object is bound. */
async function once(env: Env, key: string, exp: number) {
  const g = guardFor(env);
  if (g && !(await g.spend(key, exp))) return false;
  if (await env.OAUTH_KV.get(`once:${key}`)) return false;
  await env.OAUTH_KV.put(`once:${key}`, "1", { expirationTtl: KV_TTL });
  return true;
}
async function create(env: Env, kind: Kind, bind: string, from: string, now: number, extra: Partial<AwayRec> = {}) {
  const secret = random(), id = await idOf(secret);
  await save(env, id, { kind, bind, created: now, from, status: "pending", ...extra });
  await env.OAUTH_KV.put(`away-for:${bind}`, id, { expirationTtl: KV_TTL });
  return { secret, id };
}
async function byBind(env: Env, bind: string, now: number) {
  const id = await env.OAUTH_KV.get(`away-for:${bind}`); if (!id) return undefined;
  const rec = await load(env, id, now); return rec && safeEq(rec.bind, bind) ? { id, rec } : undefined;
}

// ---------- consent ----------
export async function createConsentAway(env: Env, handle: string, from: string, app: Record<string, unknown>, writes: string, now = Date.now()) {
  return create(env, "consent", await bindHandle(handle), from, now, { app, writes });
}
export async function consentAwayStatus(env: Env, handle: string, now = Date.now()): Promise<Status | "gone"> {
  const r = await byBind(env, await bindHandle(handle), now); return r ? r.rec.status : "gone";
}
/** For POST /authorize: an approval from the owner's iPhone, for this exact consent, used once. */
export async function takeConsentAway(env: Env, handle: string, now = Date.now()): Promise<{ ok: true } | { ok: false; reason: string; message: string }> {
  const r = await byBind(env, await bindHandle(handle), now);
  if (!r) return { ok: false, reason: "gone", message: "That approval expired. Try again." };
  if (r.rec.kind !== "consent" || r.rec.status !== "approved") return { ok: false, reason: r.rec.status, message: r.rec.status === "denied" ? "Your iPhone said no." : "Approve on your iPhone first." };
  if (!(await once(env, `away-use:${r.id}`, r.rec.created + AWAY_TTL_MS))) return { ok: false, reason: "used", message: "That approval was already used." };
  return { ok: true };
}

// ---------- pairing ----------
export async function createPair(env: Env, from: string, now = Date.now()) {
  const claim = random();
  const { secret } = await create(env, "pair", await claimBind(claim), from, now);
  return { claim, secret };
}
export async function pairStatus(env: Env, claim: string, now = Date.now()): Promise<Status | "gone"> {
  const r = await byBind(env, await claimBind(claim), now); return r ? r.rec.status : "gone";
}
export async function pairForEnroll(env: Env, claim: string, now = Date.now()): Promise<{ ok: true; id: string } | { ok: false; message: string }> {
  const r = await byBind(env, await claimBind(claim), now);
  if (!r || r.rec.kind !== "pair") return { ok: false, message: "This request expired. Start again on this device." };
  if (r.rec.status !== "approved") return { ok: false, message: r.rec.status === "denied" ? "Your other device said no." : "Approve this device from your other device first." };
  if (await env.OAUTH_KV.get(`once:away-use:${r.id}`)) return { ok: false, message: "This approval was already used. Start again on this device." };
  return { ok: true, id: r.id };
}
export const spendPair = (env: Env, id: string, now = Date.now()) => once(env, `away-use:${id}`, now + AWAY_TTL_MS);

// ---------- the approving device: /ok/view, /ok/approve, /ok/deny ----------
const GONE = { expired: "This request expired. Requests last 5 minutes.", decided: "This request was already answered.", invalid: "This link isn’t complete or isn’t current." };
export async function awayApi(req: Request, env: Env, now = Date.now()): Promise<Response> {
  const url = new URL(req.url);
  const bad = sameOriginJson(req, url); if (bad) return bad;
  let b: any; try { b = await readJson(req); } catch { return json({ ok: false, message: "Bad request." }, 400); }
  if (!passkeysOn(env)) return json({ ok: false, gone: "invalid", message: GONE.invalid }, 400);
  const p = url.pathname;
  // The consent page and the new device: create, refresh and poll.
  if (p === "/authorize/away") {
    const handle = String(b?.handle ?? ""); if (!handle) return json({ ok: false }, 400);
    return json({ ok: true, status: await consentAwayStatus(env, handle, now) });
  }
  if (p === "/pair/new") {
    const all = await loadPasskeys(env);
    if (!usableHere(all, url).length) return json({ ok: false, message: "No device has Face ID for Holdt yet. Set it up from your computer first." }, 400);
    if (all.length >= MAX_PASSKEYS) return json({ ok: false, message: `Holdt already has ${MAX_PASSKEYS} passkeys, the most it allows.` }, 400);
    const { claim, secret } = await createPair(env, whereFrom(req), now);
    const { qrSvg } = await import("./qr.js");
    const link = `${url.origin}/ok#${secret}`;
    return json({ ok: true, claim, link, qr: qrSvg(link, "QR code. Scan it with that iPhone’s camera to approve this device.") });
  }
  if (p === "/pair/status") {
    const claim = String(b?.claim ?? ""); const status = await pairStatus(env, claim, now);
    if (status !== "approved") return json({ ok: true, status });
    const pr = await pairForEnroll(env, claim, now); if (!pr.ok) return json({ ok: true, status: "gone" });
    return json({ ok: true, status, ...(await createOptions(env, url, await loadPasskeys(env), "enroll_pair", `pair:${pr.id}`, now)) });
  }
  // The approving device.
  const secret = String(b?.s ?? ""); if (!/^[A-Za-z0-9_-]{40,60}$/.test(secret)) return json({ ok: false, gone: "invalid", message: GONE.invalid }, 400);
  const id = await idOf(secret), rec = await load(env, id, now);
  if (!rec) return json({ ok: false, gone: "expired", message: GONE.expired }, 400);
  if (rec.status !== "pending") return json({ ok: false, gone: "decided", status: rec.status, message: GONE.decided }, 400);
  if (p === "/ok/view") {
    const creds = usableHere(await loadPasskeys(env), url);
    if (!creds.length) return json({ ok: false, gone: "nopk", message: "No device has Face ID for Holdt yet." }, 400);
    const c = await newChallenge(env, "away", `away:${id}`, now);
    const { askHtml } = await import("./authorize.js");
    return json({ ok: true, kind: rec.kind, device: String(rec.from ?? "").split(" near ")[0].replace(/^a device that says it’s /, "").replace(/^an? /, "").slice(0, 40), html: askHtml(rec.kind, rec.from, ago(now - rec.created), rec.app, rec.writes ?? ""), challenge_token: c.token, challenge: c.challenge, rpId: url.hostname, ids: creds.map((x) => x.id) });
  }
  if (p === "/ok/deny") {
    if (!(await once(env, `away-decide:${id}`, rec.created + AWAY_TTL_MS))) return json({ ok: false, gone: "decided", message: GONE.decided }, 400);
    await save(env, id, { ...rec, status: "denied" }); log.info(`${rec.kind === "pair" ? "new device" : "connection"} declined on another device`);
    return json({ ok: true, status: "denied" });
  }
  if (p === "/ok/approve") {
    try {
      const creds = await loadPasskeys(env);
      if (creds.length > MAX_PASSKEYS) return json({ ok: false, message: "Face ID sign-in is paused on this server." }, 400);
      const cred = usableHere(creds, url).find((c) => safeEq(c.id, String(b.id ?? "")));
      if (!cred) return json({ ok: false, field: "pk", message: "This device isn’t set up for Face ID with Holdt." }, 400);
      const challenge = await takeChallenge(env, "away", `away:${id}`, b.challenge_token, now);
      const { signCount } = await verifyAssertion({ clientDataJSON: b.clientDataJSON, authenticatorData: b.authenticatorData, signature: b.signature }, cred, { ...rp(url), challenge });
      if (!(await bumpPasskey(env, cred, signCount))) throw new WebAuthnError("signature counter went backwards");
      if (!(await once(env, `away-decide:${id}`, rec.created + AWAY_TTL_MS))) return json({ ok: false, gone: "decided", message: GONE.decided }, 400);
      await save(env, id, { ...rec, status: "approved" });
      log.info(rec.kind === "pair" ? "new device approved on another device" : "connection approved on another device");
      return json({ ok: true, status: "approved", kind: rec.kind });
    } catch (e) {
      if (e instanceof WebAuthnError) { log.warn(`away approval refused: ${e.message.slice(0, 80)}`); return json({ ok: false, message: /expired|already used/.test(e.message) ? e.message : "Face ID didn’t confirm it’s you. Try again." }, 400); }
      throw e;
    }
  }
  return json({ error: "not found" }, 404);
}
