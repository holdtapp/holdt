// Cloudflare Worker entry (self-host). OAuth 2.1 via @cloudflare/workers-oauth-provider:
// Grok Bot registers itself (DCR), the owner approves on /authorize with a one-time setup code,
// and /mcp only ever sees requests carrying a valid access token. No key is ever pasted into chat.
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { CalDavClient } from "./caldav.js";
import { Tools } from "./tools.js";
import { handleRpc, statusOf, SUPPORTED } from "./mcp.js";
import { registerSecret, log } from "./redact.js";
import { authorizeHandler } from "./authorize.js";

export interface Env {
  ICLOUD_EMAIL: string; ICLOUD_APP_PASSWORD: string; CONFIRM_SECRET: string; GRANT_EPOCH: string;
  APPROVAL_CODE_HASH?: string; APPROVAL_CODE_ISSUED?: string;
  TIMEZONE?: string; WRITES_ENABLED?: string; CALENDAR_ALLOWLIST?: string; CALDAV_URL?: string;
  /** Off in v1: Apple's upgraded Reminders aren't reachable over CalDAV. */ REMINDERS_EXPERIMENTAL?: string;
  OAUTH_KV: any;
}
export interface GrantProps { epoch: string }

export const SEC_HEADERS = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" };
const json = (o: unknown, status = 200, h: Record<string, string> = {}) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json", ...SEC_HEADERS, ...h } });

export function registerEnvSecrets(env: Partial<Env>) { for (const s of [env.ICLOUD_APP_PASSWORD, env.CONFIRM_SECRET, env.ICLOUD_EMAIL, env.GRANT_EPOCH, env.APPROVAL_CODE_HASH]) registerSecret(s); }

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
  const len = Number(req.headers.get("content-length") ?? 0); if (len > 256_000) return json({ error: "request too large" }, 413);
  const headerVersion = req.headers.get("mcp-protocol-version");
  if (headerVersion && !SUPPORTED.includes(headerVersion)) return json({ jsonrpc: "2.0", id: null, error: { code: -32022, message: "Unsupported protocol version", data: { supported: SUPPORTED, requested: headerVersion.slice(0, 40) } } }, 400);
  let body: any; try { body = await req.json(); } catch { return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400); }
  const reminders = env.REMINDERS_EXPERIMENTAL === "true";
  const makeTools = () => new Tools(new CalDavClient({ baseUrl: env.CALDAV_URL ?? "https://caldav.icloud.com/", username: env.ICLOUD_EMAIL, password: env.ICLOUD_APP_PASSWORD, fetch: (fetchImpl ?? ((u: any, i: any) => fetch(u, i))) as any }), {
    timezone: env.TIMEZONE || "UTC", writesEnabled: env.WRITES_ENABLED === "true", confirmSecret: env.CONFIRM_SECRET, remindersExperimental: reminders, usedStore: kvUsedStore(env.OAUTH_KV),
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

/** Spent confirm-token nonces live in KV for 15 minutes (tokens last 10), so a replay is refused across requests and isolates. */
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
      refreshTokenTTL: 30 * 86400,
      resourceMetadata: { resource: `${origin}/mcp`, authorization_servers: [origin] },
    } as any);
    providers.set(key, p);
  }
  return p;
}

export default {
  fetch(req: Request, env: Env, ctx: any) {
    const url = new URL(req.url);
    if (url.pathname === "/" || url.pathname === "/health") return json({ ok: true, name: "holdt", mcp: "/mcp" });
    return providerFor(url.origin).fetch(req, env, ctx);
  },
};
