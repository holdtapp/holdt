// Cloudflare Worker entry (self-host). OAuth 2.1 via @cloudflare/workers-oauth-provider:
// Grok Bot registers itself (DCR), the owner approves on /authorize with a one-time setup code,
// and /mcp only ever sees requests carrying a valid access token. No key is ever pasted into chat.
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { CalDavClient } from "./caldav.js";
import { Tools } from "./tools.js";
import { handleRpc, statusOf, SUPPORTED } from "./mcp.js";
import { registerSecret, log } from "./redact.js";
import { authorizeHandler } from "./authorize.js";
import { guardFor } from "./guard.js";
export { Guard } from "./guard.js";

export interface Env {
  ICLOUD_EMAIL: string; ICLOUD_APP_PASSWORD: string; CONFIRM_SECRET: string; GRANT_EPOCH: string;
  /** Optional comma-separated browser origins allowed to call /mcp. Requests without an Origin header (server-side clients) always pass. */ ALLOWED_ORIGINS?: string; /** "report" logs Origin headers without refusing (for the rollout check). Default: enforce. */ ORIGIN_CHECK?: string;
  APPROVAL_CODE_HASH?: string; APPROVAL_CODE_ISSUED?: string; /** Set only during a key rotation (see docs/key-rotation.md). */ CONFIRM_SECRET_PREVIOUS?: string;
  TIMEZONE?: string; WRITES_ENABLED?: string; CALENDAR_ALLOWLIST?: string; CALDAV_URL?: string;
  /** Off in v1: Apple's upgraded Reminders aren't reachable over CalDAV. */ REMINDERS_EXPERIMENTAL?: string;
  /** Comma-separated exact OAuth callback URIs allowed to receive a code. Unset: any https or loopback callback. */ REDIRECT_ALLOWLIST?: string;
  /** Workers Rate Limiting bindings (wrangler.toml). Absent: no limit. */ RL_REGISTER?: RateLimiter; RL_APPROVE?: RateLimiter; RL_MCP?: RateLimiter;
  OAUTH_KV: any;
  /** Durable Object for atomic single use (confirm tokens, approval code). Optional: without it, KV plus in-isolate locks are used. */ GUARD?: any;
}
export interface GrantProps { epoch: string }

export const SEC_HEADERS = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" };
const json = (o: unknown, status = 200, h: Record<string, string> = {}) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json", ...SEC_HEADERS, ...h } });

export function registerEnvSecrets(env: Partial<Env>) { for (const s of [env.ICLOUD_APP_PASSWORD, env.CONFIRM_SECRET, env.CONFIRM_SECRET_PREVIOUS, env.ICLOUD_EMAIL, env.GRANT_EPOCH, env.APPROVAL_CODE_HASH]) registerSecret(s); }

/** The MCP endpoint. Called only after the OAuth library has verified the access token. */
export async function mcpEndpoint(req: Request, env: Env, props: GrantProps | undefined, fetchImpl?: typeof fetch): Promise<Response> {
  registerEnvSecrets(env);
  if (!env.ICLOUD_EMAIL || !env.ICLOUD_APP_PASSWORD || !env.CONFIRM_SECRET || !env.GRANT_EPOCH) return json({ error: "This connector isn't set up yet. Run `npm run setup`." }, 503);
  // Rerunning setup (or `npm run setup -- --revoke-all`) rotates GRANT_EPOCH, which cuts off every earlier grant at once.
  if (!props || props.epoch !== env.GRANT_EPOCH) {
    // Point the client back at our metadata (RFC 9728 §5.1) so it can re-authorize on its own.
    const rm = `${new URL(req.url).origin}/.well-known/oauth-protected-resource/mcp`;
    return json({ error: "invalid_token", error_description: "This connection was revoked. Reconnect it in Grok Bot." }, 401, { "WWW-Authenticate": `Bearer error="invalid_token", error_description="connection revoked", resource_metadata="${rm}"` });
  }
  if (req.method === "GET" || req.method === "DELETE") return new Response(null, { status: 405, headers: { Allow: "POST", ...SEC_HEADERS } });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);
  // MCP Streamable HTTP: servers MUST validate Origin (DNS rebinding). A browser on any other site is refused.
  const origin = req.headers.get("origin");
  // Rollout: ORIGIN_CHECK = "report" only logs what clients send (watch `npm run tail`), anything else enforces.
  if (env.ORIGIN_CHECK === "report") { if (origin) log.info(`origin seen: ${originLabel(origin, req, env)}`); }
  else if (origin && origin !== new URL(req.url).origin && !(env.ALLOWED_ORIGINS ?? "").split(",").map((s) => s.trim()).filter(Boolean).includes(origin)) { log.warn(`origin refused: ${originLabel(origin, req, env)}`); return json({ error: "origin not allowed" }, 403); }
  const len = Number(req.headers.get("content-length") ?? 0); if (len > MAX_BODY) return json({ error: "request too large" }, 413);
  const headerVersion = req.headers.get("mcp-protocol-version");
  if (headerVersion && !SUPPORTED.includes(headerVersion)) return json({ jsonrpc: "2.0", id: null, error: { code: -32022, message: "Unsupported protocol version", data: { supported: SUPPORTED, requested: headerVersion.slice(0, 40) } } }, 400);
  const raw = await readCapped(req, MAX_BODY); if (raw === undefined) return json({ error: "request too large" }, 413);
  let body: any; try { body = JSON.parse(raw); } catch { return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400); }
  const reminders = env.REMINDERS_EXPERIMENTAL === "true";
  const makeTools = () => new Tools(new CalDavClient({ baseUrl: env.CALDAV_URL ?? "https://caldav.icloud.com/", username: env.ICLOUD_EMAIL, password: env.ICLOUD_APP_PASSWORD, fetch: (fetchImpl ?? ((u: any, i: any) => fetch(u, i))) as any }), {
    timezone: env.TIMEZONE || "UTC", writesEnabled: env.WRITES_ENABLED === "true", confirmSecret: confirmKey(env), previousSecrets: env.CONFIRM_SECRET_PREVIOUS ? [confirmKey({ CONFIRM_SECRET: env.CONFIRM_SECRET_PREVIOUS, GRANT_EPOCH: env.GRANT_EPOCH })] : undefined, remindersExperimental: reminders, usedStore: guardUsedStore(env) ?? kvUsedStore(env.OAUTH_KV), journal: env.OAUTH_KV, owner: env.ICLOUD_EMAIL,
    calendarAllowlist: env.CALENDAR_ALLOWLIST ? env.CALENDAR_ALLOWLIST.split(",").map((s) => s.trim()).filter(Boolean) : undefined });
  const msgs = Array.isArray(body) ? body : [body];
  if (msgs.length > 20) return json({ error: "batch too large" }, 413);
  const t0 = Date.now();
  const out = (await Promise.all(msgs.map((m) => handleRpc(m, makeTools, { remindersExperimental: reminders, headerVersion })))).filter(Boolean) as object[];
  if (!out.length) return new Response(null, { status: 202, headers: SEC_HEADERS });
  // One line per request: method/tool names, outcome and latency only. Never arguments or results.
  const outcome = out.map((o: any) => (o.error ? `err${o.error.code}` : o.result?.isError ? "toolError" : "ok")).join(",");
  log.info(`mcp ${msgs.map((m) => (m?.method === "tools/call" ? `tools/call:${String(m.params?.name).slice(0, 40)}` : String(m?.method).slice(0, 40))).join(",")} ${outcome} ${Date.now() - t0}ms`);
  return json(Array.isArray(body) ? out : out[0], Array.isArray(body) ? 200 : statusOf(out[0]));
}

const MAX_BODY = 256_000;
/** Reads the body but stops at `max` bytes, whatever Content-Length claims (chunked bodies have none). */
async function readCapped(req: Request, max: number): Promise<string | undefined> {
  if (!req.body) return "";
  const r = req.body.getReader(); const parts: Uint8Array[] = []; let n = 0;
  for (;;) { const { done, value } = await r.read(); if (done) break; n += value.byteLength; if (n > max) { await r.cancel().catch(() => {}); return undefined; } parts.push(value); }
  const all = new Uint8Array(n); let o = 0; for (const p of parts) { all.set(p, o); o += p.byteLength; }
  return new TextDecoder().decode(all);
}
/** Confirm tokens are bound to the grant epoch, so `--revoke-all` also voids every preview still in flight. */
export const confirmKey = (env: Pick<Env, "CONFIRM_SECRET" | "GRANT_EPOCH">) => `${env.CONFIRM_SECRET}\n${env.GRANT_EPOCH}`;
/** Spent confirm-token nonces live in KV for 15 minutes (tokens last 10), so a replay is refused across requests and isolates. */
function originLabel(origin: string, req: Request, env: Env) {
  if (origin === new URL(req.url).origin) return "same-origin";
  if ((env.ALLOWED_ORIGINS ?? "").split(",").map((s) => s.trim()).includes(origin)) return `allowed ${origin.slice(0, 80)}`;
  return `foreign ${origin.replace(/[^\w.:/-]/g, "").slice(0, 80)}`;
}
/** Spent tokens in the owner's Durable Object: truly single use across every isolate and region. */
export function guardUsedStore(env: Pick<Env, "GUARD">) {
  const g = guardFor(env); if (!g) return undefined;
  return { has: () => false, add: () => undefined, spend: (n: string, exp: number) => g.spend(`confirm:${n}`, exp) };
}
export function kvUsedStore(kv: any) {
  if (!kv) return undefined;
  return { has: async (n: string) => !!(await kv.get(`confirm-used:${n}`)), add: (n: string) => kv.put(`confirm-used:${n}`, "1", { expirationTtl: 900 }) };
}

const providers = new Map<string, OAuthProvider<Env>>();
export function providerFor(origin: string, fetchImpl?: typeof fetch): OAuthProvider<Env> {
  const key = origin + (fetchImpl ? ":test" : "");
  let p = providers.get(key);
  if (!p) {
    p = new OAuthProvider<Env>({
      apiRoute: "/mcp",
      apiHandler: { fetch: (req: Request, env: Env, ctx: any) => mcpEndpoint(req, env, ctx.props as GrantProps, fetchImpl) } as any,
      defaultHandler: { fetch: (req: Request, env: Env) => authorizeHandler(req, env) } as any,
      authorizeEndpoint: "/authorize",
      tokenEndpoint: "/oauth/token",
      clientRegistrationEndpoint: "/oauth/register",
      scopesSupported: ["calendar"],
      requiredScopes: ["calendar"],
      // Grok Bot registers cursor://anysphere.cursor-mcp/oauth/callback; authorize.ts limits private-use schemes to cursor: only.
      allowPrivateUseRedirectUris: true,
      // MCP 2026-07-28 prefers Client ID Metadata Documents over DCR. Active only with the global_fetch_strictly_public flag (wrangler.toml).
      clientIdMetadataDocumentEnabled: true,
      accessTokenTTL: 3600,
      // 90-day sliding window: a connection used at least once every 90 days never needs reconnecting. GRANT_EPOCH still cuts all off at once.
      refreshTokenTTL: 90 * 86400,
      refreshTokenIdleTTL: 90 * 86400,
      resourceMetadata: { resource: `${origin}/mcp`, authorization_servers: [origin] },
    } as any);
    providers.set(key, p);
  }
  return p;
}

export interface RateLimiter { limit(o: { key: string }): Promise<{ success: boolean }> }
/** Per-IP limits on sign-up (DCR) and approval-code submits, per-connection on /mcp. A limiter error fails open,
 * because every route behind it has its own hard checks; the limits are there to stop floods and lockout griefing. */
export async function rateLimited(req: Request, env: Env, path: string): Promise<boolean> {
  const ip = req.headers.get("cf-connecting-ip") ?? "unknown";
  let rl: RateLimiter | undefined, key = "";
  if (path === "/oauth/register") { rl = env.RL_REGISTER; key = `reg:${ip}`; }
  else if (path === "/authorize" && req.method === "POST") { rl = env.RL_APPROVE; key = `approve:${ip}`; }
  else if (path === "/mcp") { rl = env.RL_MCP; const auth = req.headers.get("authorization") ?? ""; key = `mcp:${auth ? (await sha256Short(auth)) : ip}`; }
  if (!rl) return false;
  try { return !(await rl.limit({ key })).success; } catch (e) { log.warn(`rate limiter unavailable: ${(e as any)?.name ?? "error"}`); return false; }
}
async function sha256Short(s: string) { return [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))].slice(0, 12).map((b) => b.toString(16).padStart(2, "0")).join(""); }

export default {
  async fetch(req: Request, env: Env, ctx: any) {
    const url = new URL(req.url);
    if (url.pathname === "/" || url.pathname === "/health") return json({ ok: true, name: "holdt", mcp: "/mcp" });
    if (await rateLimited(req, env, url.pathname)) { log.warn(`rate limited ${url.pathname.slice(0, 40)}`); return json({ error: "rate_limited", error_description: "Too many requests. Wait a minute and try again." }, 429, { "Retry-After": "60" }); }
    return providerFor(url.origin).fetch(req, env, ctx);
  },
};
