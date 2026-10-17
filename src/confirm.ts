// Two-step writes: prepare_* returns a preview + a short-lived HMAC token bound to the exact
// change. commit_* re-verifies the token, so the bot cannot alter the change after the user saw it.
const enc = new TextEncoder();
const b64u = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

async function key(secret: string) { return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]); }
export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().filter((k) => (v as any)[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonical((v as any)[k])}`).join(",")}}`;
  return JSON.stringify(v);
}
export async function issue(secret: string, action: string, payload: unknown, ttlMs = 10 * 60_000, now = Date.now()): Promise<string> {
  const body = b64u(enc.encode(JSON.stringify({ a: action, h: await digest(canonical(payload)), e: now + ttlMs, n: crypto.randomUUID(), p: payload })));
  const sig = b64u(await crypto.subtle.sign("HMAC", await key(secret), enc.encode(body)));
  return `${body}.${sig}`;
}
/** Remembers which confirm tokens were already spent. A Set works in one process. The Worker passes a KV-backed store. */
export interface UsedStore { has(nonce: string): boolean | Promise<boolean>; add(nonce: string): unknown }
/** For tokens that may be shown more than once (a revert token is checked at prepare and again at commit). Never use it for a commit. */
export const NO_SPEND: UsedStore = { has: () => false, add: () => undefined };
export async function verify<T = unknown>(secret: string, token: string, action: string, used: UsedStore, now = Date.now(), expiredMsg = "That preview expired (10 minutes). Ask for a fresh one."): Promise<{ ok: true; payload: T } | { ok: false; reason: string }> {
  const [body, sig] = (typeof token === "string" ? token : "").split(".");
  if (!body || !sig) return { ok: false, reason: "That confirmation code is missing or damaged. Ask for a fresh preview." };
  let valid = false;
  try { valid = await crypto.subtle.verify("HMAC", await key(secret), fromB64u(sig), enc.encode(body)); } catch { valid = false; }
  if (!valid) return { ok: false, reason: "That confirmation code isn't valid. Ask for a fresh preview." };
  let t: any; try { t = JSON.parse(new TextDecoder().decode(fromB64u(body))); } catch { return { ok: false, reason: "That confirmation code is damaged. Ask for a fresh preview." }; }
  if (t.a !== action) return { ok: false, reason: "That confirmation was for a different kind of change." };
  if (t.e < now) return { ok: false, reason: expiredMsg };
  if (t.h !== (await digest(canonical(t.p)))) return { ok: false, reason: "The change doesn't match what you approved. Ask for a fresh preview." };
  // Reserve the nonce synchronously first, so two commits racing in one isolate can't both pass the KV check.
  // (Across isolates, KV can't do compare-and-set: see REDTEAM-REPORT.md, Durable Object hardening item.)
  if (used !== NO_SPEND && !reserve(t.n, t.e)) return { ok: false, reason: "That change was already made. Nothing was done twice." };
  if (await used.has(t.n)) return { ok: false, reason: "That change was already made. Nothing was done twice." };
  await used.add(t.n);
  return { ok: true, payload: t.p as T };
}
const RESERVED = new Map<string, number>();
function reserve(n: string, exp: number, now = Date.now()) {
  if (RESERVED.size > 5000) for (const [k, e] of RESERVED) if (e < now) RESERVED.delete(k);
  if (RESERVED.has(n)) return false; RESERVED.set(n, exp); return true;
}
async function digest(s: string) { return b64u(await crypto.subtle.digest("SHA-256", enc.encode(s))); }
