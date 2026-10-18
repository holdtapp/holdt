// Reviewer test path (docs/reviewer-testing.md). Marketplace reviewers connect to a separate demo Worker on the test
// Apple Account with one shared reviewer code. Unlike the owner's approval code it is multi-use, lasts 14 days and can be
// revoked at any time. Three locks keep it to the demo Worker:
//   1. REVIEWER_MODE = "on" must be set in that Worker's [vars]. The production wrangler.toml never sets it.
//   2. The stored hash is bound to the Worker's iCloud account, so a code minted for the test account matches nowhere else.
//   3. Every reviewer connection carries the code's id and the account binding. Revoking, expiring or changing the
//      account cuts those connections on their next call, while the owner's own connections keep working.
// The code is 80 random bits, so guessing is hopeless even without a lockout. There is deliberately no lockout: one
// stranger typing wrong codes must not be able to switch the reviewer path off for every reviewer. Per-IP rate limits
// on POST /authorize (RL_APPROVE) still apply.

export const REVIEWER_TTL_MS = 14 * 86_400_000;
export const REVIEWER_PREFIX = "RVW";
export const REVIEWER_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32: no I, L, O or U
export const REVIEWER_CHARS = 16; // 16 x 5 bits = 80 bits
const CLOCK_SKEW_MS = 5 * 60_000;

export interface ReviewerEnv {
  REVIEWER_MODE?: string; REVIEWER_CODE_HASH?: string; REVIEWER_CODE_ISSUED?: string; ICLOUD_EMAIL?: string; OAUTH_KV?: any;
}
export type ReviewerState =
  | { active: true; id: string; acct: string; expiresAt: number }
  | { active: false; reason: "off" | "none" | "revoked" | "expired" | "invalid" };
export interface ReviewerProps { via: "reviewer"; rc: string; acct: string }

async function sha256Hex(s: string) { return [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))].map((b) => b.toString(16).padStart(2, "0")).join(""); }
const safeEq = (a: string, b: string) => { let d = a.length ^ b.length; for (let i = 0; i < Math.min(a.length, b.length); i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };

/** Binds a code to one iCloud account without storing the address. Same value in setup (node) and the Worker. */
export function accountTag(email: string) { return sha256Hex(`holdt-reviewer/v1\n${String(email ?? "").trim().toLowerCase()}`); }
/** What PBKDF2 actually hashes: the account binding plus the normalized code. */
export const reviewerSecretInput = (tag: string, code: string) => `${tag}:${code}`;

/** "rvw-7k2m 9qxd-..." -> "RVW7K2M9QXD..." Crockford rules: O reads as 0, I and L read as 1. undefined if it isn't one. */
export function normalizeReviewerCode(raw: string): string | undefined {
  const s = String(raw ?? "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (!s.startsWith(REVIEWER_PREFIX)) return undefined;
  const body = s.slice(REVIEWER_PREFIX.length).replace(/O/g, "0").replace(/[IL]/g, "1");
  if (body.length !== REVIEWER_CHARS || [...body].some((c) => !REVIEWER_ALPHABET.includes(c))) return undefined;
  return REVIEWER_PREFIX + body;
}
/** True when the typed text is meant as a reviewer code (owner approval codes are digits only). */
export const looksLikeReviewerCode = (raw: string) => /^\s*r\s*v\s*w/i.test(String(raw ?? ""));

const HASH_RE = /^pbkdf2\$(\d{4,6})\$([A-Za-z0-9_-]{16,64})\$([0-9a-f]{64})$/;
async function pbkdf2Matches(stored: string, input: string) {
  const m = stored.match(HASH_RE); if (!m) return false;
  const it = Math.min(Number(m[1]), 100_000);
  const salt = Uint8Array.from(atob(m[2]!.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(input), "PBKDF2", false, ["deriveBits"]);
  const got = [...new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: it }, k, 256))].map((b) => b.toString(16).padStart(2, "0")).join("");
  return safeEq(got, m[3]!);
}

/** Is the reviewer path open right now? Cheap: no PBKDF2, at most one KV read. */
export async function reviewerState(env: ReviewerEnv, now = Date.now()): Promise<ReviewerState> {
  if (env.REVIEWER_MODE !== "on") return { active: false, reason: "off" };
  const hash = env.REVIEWER_CODE_HASH;
  if (!hash) return { active: false, reason: "none" };
  if (hash === "revoked") return { active: false, reason: "revoked" };
  if (!HASH_RE.test(hash) || !env.ICLOUD_EMAIL) return { active: false, reason: "invalid" };
  const issued = Number(env.REVIEWER_CODE_ISSUED);
  if (!Number.isFinite(issued) || issued <= 0 || issued > now + CLOCK_SKEW_MS) return { active: false, reason: "invalid" };
  if (now - issued > REVIEWER_TTL_MS) return { active: false, reason: "expired" };
  const id = (await sha256Hex(`holdt-reviewer-id/v1\n${hash}`)).slice(0, 24);
  try { if (env.OAUTH_KV && (await env.OAUTH_KV.get(`reviewer-revoked:${id}`))) return { active: false, reason: "revoked" }; } catch { /* KV down: the hash and expiry checks still hold */ }
  return { active: true, id, acct: (await accountTag(env.ICLOUD_EMAIL)).slice(0, 24), expiresAt: issued + REVIEWER_TTL_MS };
}

export type ReviewerVerdict = { ok: true; props: ReviewerProps } | { ok: false; reason: string; message: string };
const ENDED = "This reviewer code has ended. Ask the developer for a new one.";
/** Checks a typed reviewer code. Multi-use: a match spends nothing. */
export async function checkReviewerCode(env: ReviewerEnv, raw: string, now = Date.now()): Promise<ReviewerVerdict> {
  const st = await reviewerState(env, now);
  if (!st.active) return { ok: false, reason: `reviewer ${st.reason}`, message: st.reason === "off" || st.reason === "none" ? "Reviewer codes aren't accepted on this server." : ENDED };
  const code = normalizeReviewerCode(raw);
  if (!code) return { ok: false, reason: "reviewer malformed", message: "That reviewer code isn't complete. It starts with RVW and has 16 more letters and digits." };
  const tag = await accountTag(env.ICLOUD_EMAIL!);
  if (!(await pbkdf2Matches(env.REVIEWER_CODE_HASH!, reviewerSecretInput(tag, code)))) return { ok: false, reason: "reviewer wrong", message: "That reviewer code doesn't match. Check the testing instructions and try again." };
  return { ok: true, props: { via: "reviewer", rc: st.id, acct: st.acct } };
}

/** On every /mcp call from a reviewer connection: still the same live code, on the same account? */
export async function reviewerGrantValid(env: ReviewerEnv, props: Partial<ReviewerProps>, now = Date.now()) {
  const st = await reviewerState(env, now);
  return st.active && typeof props.rc === "string" && typeof props.acct === "string" && safeEq(props.rc, st.id) && safeEq(props.acct, st.acct);
}
