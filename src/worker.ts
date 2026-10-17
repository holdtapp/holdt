// Cloudflare Worker entry (self-host). OAuth 2.1 via @cloudflare/workers-oauth-provider:
// Grok Bot registers itself (DCR), the owner approves on /authorize with a one-time setup code,
// and /mcp only ever sees requests carrying a valid access token. No key is ever pasted into chat.
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { CalDavClient } from "./caldav.js";
import { Tools } from "./tools.js";
import { handleRpc } from "./mcp.js";
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
  if (!props || props.epoch !== env.GRANT_EPOCH) return json({ error: "invalid_token", error_description: "This connection was revoked. Reconnect it in Grok Bot." }, 401, { "WWW-Authenticate": 'Bearer error="invalid_token"' });
  if (req.method === "GET" || req.method === "DELETE") return new Response(null, { status: 405, headers: { Allow: "POST", ...SEC_HEADERS } });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);
  const len = Number(req.headers.get("content-length") ?? 0); if (len > 256_000) return json({ error: "request too large" }, 413);
  let body: any; try { body = await req.json(); } catch { return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400); }
  const reminders = env.REMINDERS_EXPERIMENTAL === "true";
  const makeTools = () => new Tools(new CalDavClient({ baseUrl: env.CALDAV_URL ?? "https://caldav.icloud.com/", username: env.ICLOUD_EMAIL, password: env.ICLOUD_APP_PASSWORD, fetch: (fetchImpl ?? ((u: any, i: any) => fetch(u, i))) as any }), {
    timezone: env.TIMEZONE || "UTC", writesEnabled: env.WRITES_ENABLED === "true", confirmSecret: env.CONFIRM_SECRET, remindersExperimental: reminders,
    calendarAllowlist: env.CALENDAR_ALLOWLIST ? env.CALENDAR_ALLOWLIST.split(",").map((s) => s.trim()).filter(Boolean) : undefined });
  const msgs = Array.isArray(body) ? body : [body];
  if (msgs.length > 20) return json({ error: "batch too large" }, 413);
  const out = (await Promise.all(msgs.map((m) => handleRpc(m, makeTools, { remindersExperimental: reminders })))).filter(Boolean);
  if (!out.length) return new Response(null, { status: 202, headers: SEC_HEADERS });
  log.info(`mcp ${msgs.map((m) => (m?.method === "tools/call" ? `tools/call:${m.params?.name}` : m?.method)).join(",")}`);
  return json(Array.isArray(body) ? out : out[0]);
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
