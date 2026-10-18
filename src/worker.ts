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
import { loadPasskeys } from "./passkey.js";
import { reviewerGrantValid } from "./reviewer.js";
import { setupRoute, withSealed } from "./setup-web.js";
export { Guard } from "./guard.js";

export interface Env {
  ICLOUD_EMAIL: string; ICLOUD_APP_PASSWORD: string; CONFIRM_SECRET: string; GRANT_EPOCH: string;
  /** Optional comma-separated browser origins allowed to call /mcp. Requests without an Origin header (server-side clients) always pass. */ ALLOWED_ORIGINS?: string; /** "report" logs Origin headers without refusing (for the rollout check). Default: enforce. */ ORIGIN_CHECK?: string;
  APPROVAL_CODE_HASH?: string; APPROVAL_CODE_ISSUED?: string; /** Set only during a key rotation (see docs/key-rotation.md). */ CONFIRM_SECRET_PREVIOUS?: string;
  TIMEZONE?: string; WRITES_ENABLED?: string; CALENDAR_ALLOWLIST?: string; CALDAV_URL?: string;
  /** Off in v1: Apple's upgraded Reminders aren't reachable over CalDAV. */ REMINDERS_EXPERIMENTAL?: string;
  /** Comma-separated exact OAuth callback URIs allowed to receive a code. Unset: any https or loopback callback. */ REDIRECT_ALLOWLIST?: string;
  /** Comma-separated exact OAuth client_ids allowed to connect. Unset: any registered client. */ CLIENT_ALLOWLIST?: string;
  /** Workers Rate Limiting bindings (wrangler.toml). Absent: no limit. */ RL_REGISTER?: RateLimiter; RL_APPROVE?: RateLimiter; RL_MCP?: RateLimiter;
  /** "on" lets clients identify with a Client ID Metadata Document URL. Off by default (see providerFor). */ CIMD?: string;
  /** "on" turns on passkey one-tap connect (src/passkey.ts). The approval code always stays as the fallback. */ PASSKEYS?: string;
  /** SHA-256 of the one-time enroll token from `npm run setup -- --add-device`, and when it was issued. */ ENROLL_TOKEN_HASH?: string; ENROLL_TOKEN_ISSUED?: string;
  /** Rotated by `--reset-passkeys`: passkeys enrolled under an older value stop working. */ PASSKEY_EPOCH?: string;
  /** Reviewer test path (src/reviewer.ts, docs/reviewer-testing.md). Only a demo Worker on the test account sets REVIEWER_MODE = "on". */
  REVIEWER_MODE?: string; REVIEWER_CODE_HASH?: string; REVIEWER_CODE_ISSUED?: string;
  /** No-terminal setup (src/setup-web.ts, docs/agent-setup.md): the 32-byte key that seals the setup, and the one-time setup link's SHA-256 and issue time. */
  SEAL_KEY?: string; SETUP_TOKEN_HASH?: string; SETUP_TOKEN_ISSUED?: string;
  OAUTH_KV: any;
  /** Durable Object for atomic single use (confirm tokens, approval code). Optional: without it, KV plus in-isolate locks are used. */ GUARD?: any;
}
export interface GrantProps { epoch: string; via?: "reviewer"; rc?: string; acct?: string }

export const SEC_HEADERS = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" };
const json = (o: unknown, status = 200, h: Record<string, string> = {}) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json", ...SEC_HEADERS, ...h } });

export function registerEnvSecrets(env: Partial<Env>) { for (const s of [env.ICLOUD_APP_PASSWORD, env.CONFIRM_SECRET, env.CONFIRM_SECRET_PREVIOUS, env.ICLOUD_EMAIL, env.GRANT_EPOCH, env.APPROVAL_CODE_HASH, env.ENROLL_TOKEN_HASH, env.REVIEWER_CODE_HASH, env.SEAL_KEY, env.SETUP_TOKEN_HASH]) registerSecret(s); }

/** The MCP endpoint. Called only after the OAuth library has verified the access token. */
export async function mcpEndpoint(req: Request, env: Env, props: GrantProps | undefined, fetchImpl?: typeof fetch): Promise<Response> {
  registerEnvSecrets(env);
  if (!env.ICLOUD_EMAIL || !env.ICLOUD_APP_PASSWORD || !env.CONFIRM_SECRET || !env.GRANT_EPOCH) return json({ error: "This connector isn't set up yet. Run `npm run setup`." }, 503);
  // Rerunning setup (or `npm run setup -- --revoke-all`) rotates GRANT_EPOCH, which cuts off every earlier grant at once.
  // A reviewer connection lives only as long as its reviewer code: revoked, expired or a different iCloud account cuts it.
  if (!props || props.epoch !== env.GRANT_EPOCH || (props.via === "reviewer" && !(await reviewerGrantValid(env, props)))) {
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
    timezone: env.TIMEZONE || "UTC", writesEnabled: env.WRITES_ENABLED === "true", confirmSecret: confirmKey(env), previousSecrets: env.CONFIRM_SECRET_PREVIOUS ? [confirmKey({ CONFIRM_SECRET: env.CONFIRM_SECRET_PREVIOUS, GRANT_EPOCH: env.GRANT_EPOCH })] : undefined, remindersExperimental: reminders, usedStore: guardUsedStore(env) ?? kvUsedStore(env.OAUTH_KV), journal: env.OAUTH_KV, owner: env.ICLOUD_EMAIL, devices: env.PASSKEYS === "on" ? () => loadPasskeys(env) : undefined,
    calendarAllowlist: env.CALENDAR_ALLOWLIST ? env.CALENDAR_ALLOWLIST.split(",").map((s) => s.trim()).filter(Boolean) : undefined });
  const msgs = Array.isArray(body) ? body : [body];
  if (msgs.length > 20) return json({ error: "batch too large" }, 413);
  // A batch rides on one rate-limit hit, so cap the calls that can reach iCloud: 120 requests/min stays near 120 tool calls/min, not 2,400.
  if (msgs.filter((m) => m?.method === "tools/call").length > MAX_TOOL_CALLS) return json({ error: `too many tool calls in one request (max ${MAX_TOOL_CALLS})` }, 413);
  const t0 = Date.now();
  const out = (await Promise.all(msgs.map((m) => handleRpc(m, makeTools, { remindersExperimental: reminders, headerVersion })))).filter(Boolean) as object[];
  if (!out.length) return new Response(null, { status: 202, headers: SEC_HEADERS });
  // One line per request: method/tool names, outcome and latency only. Never arguments or results.
  const outcome = out.map((o: any) => (o.error ? `err${o.error.code}` : o.result?.isError ? "toolError" : "ok")).join(",");
  // Protocol version and tool count help diagnose client caching. Both are fixed strings or numbers, never user data.
  const ver = (v: unknown) => (typeof v === "string" && /^\d{4}-\d\d-\d\d$/.test(v) ? v : "?");
  const label = (m: any, i: number) => {
    if (m?.method === "tools/call") return `tools/call:${String(m.params?.name).slice(0, 40)}`;
    if (m?.method === "initialize") return `initialize(v=${ver(m.params?.protocolVersion)})`;
    if (m?.method === "tools/list") { const r: any = (out as any[]).find((o: any) => o?.id === m.id); return `tools/list(n=${Array.isArray(r?.result?.tools) ? r.result.tools.length : "?"}${headerVersion ? `,v=${ver(headerVersion)}` : ""})`; }
    return String(m?.method).slice(0, 40);
  };
  log.info(`mcp ${msgs.map(label).join(",")} ${outcome} ${Date.now() - t0}ms`);
  return json(Array.isArray(body) ? out : out[0], Array.isArray(body) ? 200 : statusOf(out[0]));
}

const MAX_BODY = 256_000;
export const MAX_TOOL_CALLS = 4;
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
export function providerFor(origin: string, fetchImpl?: typeof fetch, opts: { cimd?: boolean } = {}): OAuthProvider<Env> {
  const key = origin + (fetchImpl ? ":test" : "") + (opts.cimd ? ":cimd" : "");
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
      // Client ID Metadata Documents (MCP 2026-07-28) are OFF unless CIMD = "on". Grok Bot connects with DCR today (the
      // live grant's client was DCR-registered), and CIMD makes this Worker fetch a URL the caller picks, before anyone
      // has approved anything. Turn it on only when a client needs it. global_fetch_strictly_public (wrangler.toml)
      // still keeps those fetches off private hosts.
      clientIdMetadataDocumentEnabled: opts.cimd === true,
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
  const ip = ipKey(req.headers.get("cf-connecting-ip") ?? "unknown");
  const hit = async (rl: RateLimiter | undefined, key: string) => { if (!rl) return false; try { return !(await rl.limit({ key })).success; } catch (e) { log.warn(`rate limiter unavailable: ${(e as any)?.name ?? "error"}`); return false; } };
  if (path === "/oauth/register") return hit(env.RL_REGISTER, `reg:${ip}`);
  // Status polls from the consent page and a new device share a roomier per-IP bucket. Every other POST that can
  // approve, create or decide something is in the tight one.
  if ((path === "/authorize/away" || path === "/pair/status") && req.method === "POST") return hit(env.RL_MCP, `poll:${ip}`);
  if ((path === "/authorize" || path.startsWith("/authorize/") || path.startsWith("/enroll/") || path.startsWith("/ok/") || path.startsWith("/pair/") || path.startsWith("/review/") || path.startsWith("/setup/")) && req.method === "POST") return hit(env.RL_APPROVE, `approve:${ip}`);
  // The OAuth library routes /mcp and every /mcp/... path to the MCP handler, so limit them all. Per caller IP first
  // (a made-up bearer token must not buy a fresh bucket), then per connection.
  if (path === "/mcp" || path.startsWith("/mcp/")) {
    if (await hit(env.RL_MCP, `mcpip:${ip}`)) return true;
    const auth = req.headers.get("authorization") ?? "";
    return auth ? hit(env.RL_MCP, `mcp:${await sha256Short(auth)}`) : false;
  }
  return false;
}
/** IPv6 callers usually own a whole /64, so key them by that prefix. IPv4 stays exact. */
export function ipKey(ip: string) {
  if (!ip.includes(":")) return ip;
  let [head, tail] = ip.toLowerCase().split("::") as [string, string | undefined];
  const h = head ? head.split(":") : [], t = tail ? tail.split(":") : [];
  const groups = tail === undefined ? h : [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill("0"), ...t];
  if (groups.length < 4 || groups.slice(0, 4).some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return ip.slice(0, 64);
  return groups.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, "")).join(":") + "::/64";
}
async function sha256Short(s: string) { return [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))].slice(0, 12).map((b) => b.toString(16).padStart(2, "0")).join(""); }

/** Every request. A Worker set up from the web page (src/setup-web.ts) runs with its sealed values in place. */
export async function handleRequest(req: Request, env: Env, ctx: any, fetchImpl?: typeof fetch): Promise<Response> {
  const url = new URL(req.url);
  if (url.pathname === "/" || url.pathname === "/health") return json({ ok: true, name: "holdt", mcp: "/mcp" });
  if (await rateLimited(req, env, url.pathname)) { log.warn(`rate limited ${url.pathname.slice(0, 40)}`); return json({ error: "rate_limited", error_description: "Too many requests. Wait a minute and try again." }, 429, { "Retry-After": "60" }); }
  registerEnvSecrets(env);
  if (url.pathname === "/setup" || url.pathname.startsWith("/setup/")) return setupRoute(req, env, url, fetchImpl);
  return providerFor(url.origin, fetchImpl, { cimd: env.CIMD === "on" }).fetch(req, await withSealed(env), ctx);
}

export default {
  fetch(req: Request, env: Env, ctx: any) { return handleRequest(req, env, ctx); },
};
