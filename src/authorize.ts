// The owner's approval page. Grok Bot opens it during sign-in. The owner proves it's them with the
// one-time code that `npm run setup` showed on their own computer: single use, 15 minutes, 5 tries.
import { AuthorizationError } from "@cloudflare/workers-oauth-provider";
import type { Env } from "./worker.js";
import { registerEnvSecrets, SEC_HEADERS } from "./worker.js";
import { log } from "./redact.js";
import { guardFor } from "./guard.js";

const CODE_TTL_MS = 15 * 60_000, MAX_TRIES = 5;
const esc = (v: string) => String(v).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
export async function sha256Hex(s: string) { return [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))].map((b) => b.toString(16).padStart(2, "0")).join(""); }
export const normalizeCode = (s: string) => String(s ?? "").replace(/\D/g, "");

/** Only https, loopback http, or the cursor: scheme Grok Bot uses may receive a code. Never userinfo (grok@evil) or a fragment. */
export function redirectAllowed(uri: string) {
  try { const u = new URL(uri); if (u.username || u.password || u.hash) return false; return u.protocol === "https:" || u.protocol === "cursor:" || (u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname)); } catch { return false; }
}

const STYLE = `:root{--bg:#f6f7f9;--card:#fff;--ink:#111827;--muted:#5b6472;--line:#e5e7eb;--blue:#0a66ff;--red:#c62828;--amber:#8a5a00;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--ink:#e6edf3;--muted:#9aa4b2;--line:#2a313c;--blue:#4c8dff;--red:#ff6b6b;--amber:#e3b341}}
*{box-sizing:border-box}body{margin:0;font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--ink)}
main{max-width:480px;margin:8vh auto;padding:0 16px}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:26px;box-shadow:0 8px 24px rgba(0,0,0,.05)}
h1{font-size:21px;margin:0 0 8px}p{margin:0 0 14px}.muted{color:var(--muted);font-size:14px}.warn{color:var(--amber);font-size:14px}
label{display:block;font-weight:600;font-size:14px;margin:6px 0}input{width:100%;font:22px ui-monospace,Menlo,monospace;letter-spacing:.12em;text-align:center;padding:12px;border-radius:10px;border:1px solid var(--line);background:transparent;color:inherit}
input[aria-invalid=true]{border-color:var(--red)}.err{color:var(--red);font-size:14px;margin-top:6px}
.row{display:flex;gap:10px;margin-top:16px}button{flex:1;border:0;border-radius:10px;padding:12px;font:inherit;font-weight:600;cursor:pointer}
.allow{background:var(--blue);color:#fff}.deny{background:transparent;color:var(--ink);border:1px solid var(--line)}button:focus-visible,input:focus-visible{outline:3px solid color-mix(in srgb,var(--blue) 45%,transparent);outline-offset:2px}`;

export function formActionFor(uri: string) {
  try { const u = new URL(uri); if (u.username || u.password || u.hash) return false; return u.protocol === "https:" || u.protocol === "http:" ? u.origin : u.protocol; } catch { return ""; }
}
function page(title: string, body: string, status = 200, headers?: Headers, redirectUri = "") {
  const h = headers ?? new Headers();
  h.set("Content-Type", "text/html; charset=utf-8"); for (const [k, v] of Object.entries(SEC_HEADERS)) h.set(k, v);
  h.set("Content-Security-Policy", `default-src 'none'; style-src 'unsafe-inline'; form-action 'self'${redirectUri && formActionFor(redirectUri) ? " " + formActionFor(redirectUri) : ""}; frame-ancestors 'none'; base-uri 'none'`);
  h.set("X-Frame-Options", "DENY");
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>${STYLE}</style><main><div class="card">${body}</div></main></html>`, { status, headers: h });
}
function consentBody(d: any, handle: string, writes: string, error?: string) {
  const local = d.redirectIsLoopback ? `<p class="warn">This sends access to an app on this computer. Continue only if you just started connecting from it.</p>` : "";
  return `<h1>Connect ${esc(d.clientName || "an app")} to your iCloud Calendar?</h1>
<p class="muted">${d.clientDomain ? `Published by <strong>${esc(d.clientDomain)}</strong>.` : "This app registered itself, so its name isn't verified."} Access goes to <strong>${esc(d.redirectHost || "the app")}</strong>.</p>${local}
<p class="muted">It can read your calendars. Changes are ${esc(writes)}. It can never delete events or send invitations.</p>
<form method="post" autocomplete="off">
<input type="hidden" name="handle" value="${esc(handle)}"><input type="hidden" name="ctx" value="${esc(d.__ctx ?? "")}">
<label for="code">Approval code from your setup screen</label>
<input id="code" name="code" inputmode="numeric" placeholder="1234-5678" maxlength="12" autofocus ${error ? 'aria-invalid="true" aria-describedby="err"' : ""}>
${error ? `<div class="err" id="err" role="alert">${esc(error)}</div>` : ""}
<div class="row"><button class="deny" name="decision" value="deny">Don't allow</button><button class="allow" name="decision" value="approve">Allow</button></div>
</form>
<p class="muted" style="margin-top:14px">No code, or it expired? On your computer, run <code>npm run setup -- --new-code</code>.</p>`;
}

export async function authorizeHandler(req: Request, env: Env): Promise<Response> {
  registerEnvSecrets(env);
  const url = new URL(req.url);
  if (url.pathname !== "/authorize") return new Response("Not found", { status: 404, headers: SEC_HEADERS });
  const oauth = (env as any).OAUTH_PROVIDER;
  const writes = env.WRITES_ENABLED === "true" ? "allowed, and each one waits for your yes" : "turned off (read-only)";
  try {
    if (req.method === "GET") {
      const request = await oauth.parseAuthRequest(req);
      if (!redirectAllowed(request.redirectUri)) return page("Not allowed", `<h1>This app can't connect</h1><p class="muted">It asked to send access somewhere this connector doesn't allow.</p>`, 400);
      const details = await oauth.describeConsent(request);
      const consent = await oauth.beginConsent(request);
      (details as any).__ctx = await signCtx(env, { clientName: details.clientName, clientDomain: details.clientDomain, redirectHost: details.redirectHost, redirectIsLoopback: details.redirectIsLoopback, redirectUri: request.redirectUri });
      return page("Holdt: Connect iCloud Calendar", consentBody(details, consent.handle, writes), 200, consent.headers, request.redirectUri);
    }
    if (req.method !== "POST") return new Response(null, { status: 405, headers: SEC_HEADERS });
    const form = await req.formData();
    const handle = String(form.get("handle") ?? "");
    if (form.get("decision") !== "approve") {
      const denied = await oauth.denyConsent(req, handle);
      return new Response(null, { status: 302, headers: denied.headers });
    }
    const verdict = await checkCode(env, String(form.get("code") ?? ""));
    if (!verdict.ok) {
      log.warn(`approval code rejected: ${verdict.reason}`);
      const ctxRaw = String(form.get("ctx") ?? "");
      const details: any = (await readCtx(env, ctxRaw)) ?? { clientName: "the app", redirectHost: "" };
      details.__ctx = ctxRaw;
      if (verdict.reason === "used") return page("Already approved", `<h1>You're already approved</h1><p class="muted">This code already connected Holdt. Go back to Grok Bot and check the connection. If it still asks to connect, run <code>npm run setup -- --new-code</code> and try once more.</p>`, 400);
      return page("Holdt: Connect iCloud Calendar", consentBody(details, handle, writes, verdict.message), 400, undefined, details.redirectUri ?? "");
    }
    const approved = await oauth.approveConsent(req, handle, { scope: ["calendar"] });
    if (!redirectAllowed(approved.request.redirectUri)) return page("Not allowed", `<h1>This app can't connect</h1>`, 400);
    const { redirectTo } = await oauth.completeAuthorization({ request: approved.request, userId: "owner", metadata: { label: "Grok Bot" }, scope: approved.request.scope, props: { epoch: env.GRANT_EPOCH } });
    log.info("connection approved");
    approved.headers.set("Location", redirectTo);
    return new Response(null, { status: 302, headers: approved.headers });
  } catch (e) {
    if (e instanceof AuthorizationError && (e as any).redirectTo && redirectAllowed((e as any).redirectTo)) return Response.redirect((e as any).redirectTo, 302);
    if (e instanceof AuthorizationError) return page("Couldn't connect", `<h1>That didn't work</h1><p class="muted">${esc((e as any).description ?? "This approval page expired or was already used.")} Start connecting again from Grok Bot.</p>`, 400);
    log.error("authorize failed", e);
    return page("Couldn't connect", `<h1>Something went wrong</h1><p class="muted">Start connecting again from Grok Bot.</p>`, 500);
  }
}

type Verdict = { ok: true; hash: string } | { ok: false; reason: string; message: string };
// Code checks run one at a time per isolate, and each try is charged and the code is spent inside that turn,
// so simultaneous guesses can't read a stale counter and one code can't approve two connections.
let codeQueue: Promise<unknown> = Promise.resolve();
export function checkCode(env: Env, raw: string, now = Date.now()): Promise<Verdict> {
  const run = codeQueue.then(() => checkCodeOnce(env, raw, now));
  codeQueue = run.catch(() => undefined);
  return run;
}
export const CODE_SALT = "icloud-mcp-approval:";
async function checkCodeOnce(env: Env, raw: string, now: number): Promise<Verdict> {
  const g = guardFor(env);
  if (g && env.APPROVAL_CODE_HASH && env.APPROVAL_CODE_ISSUED) {
    // Atomic across isolates: the Durable Object decides used / locked / spent / charged in one step.
    const hash = env.APPROVAL_CODE_HASH;
    if (now - Number(env.APPROVAL_CODE_ISSUED) > CODE_TTL_MS) return { ok: false, reason: "expired", message: "That code expired (codes last 15 minutes). On your computer, run npm run setup -- --new-code." };
    const code = normalizeCode(raw); const given = await sha256Hex(`${CODE_SALT}${code}`);
    let diff = given.length ^ hash.length; for (let i = 0; i < Math.min(given.length, hash.length); i++) diff |= given.charCodeAt(i) ^ hash.charCodeAt(i);
    const v = await g.codeTry(hash, code.length === 8 && diff === 0, MAX_TRIES);
    if (v.ok) { await env.OAUTH_KV.put(`approval-used:${hash}`, "1", { expirationTtl: 86400 }); return { ok: true, hash }; }
    if (v.reason === "locked") return { ok: false, reason: "locked", message: "Too many wrong tries, so this code is now blocked. On your computer, run npm run setup -- --new-code." };
    if (v.reason === "used") return { ok: false, reason: "used", message: "That code was already used. On your computer, run npm run setup -- --new-code for a fresh one." };
    return { ok: false, reason: "wrong", message: v.left > 0 ? `That code doesn't match. Check your setup screen and try again (${v.left} ${v.left === 1 ? "try" : "tries"} left).` : "That code doesn't match, and this code is now blocked. On your computer, run npm run setup -- --new-code." };
  }
  if (!env.APPROVAL_CODE_HASH || !env.APPROVAL_CODE_ISSUED) return { ok: false, reason: "none", message: "No approval code is set. On your computer, run npm run setup -- --new-code." };
  const hash = env.APPROVAL_CODE_HASH;
  const failKey = `approval-fail:${hash}`;
  const fails = Number((await env.OAUTH_KV.get(failKey)) ?? 0);
  if (fails >= MAX_TRIES) return { ok: false, reason: "locked", message: "Too many wrong tries, so this code is now blocked. On your computer, run npm run setup -- --new-code." };
  if (await env.OAUTH_KV.get(`approval-used:${hash}`)) return { ok: false, reason: "used", message: "That code was already used. On your computer, run npm run setup -- --new-code for a fresh one." };
  if (now - Number(env.APPROVAL_CODE_ISSUED) > CODE_TTL_MS) return { ok: false, reason: "expired", message: "That code expired (codes last 15 minutes). On your computer, run npm run setup -- --new-code." };
  const code = normalizeCode(raw);
  const given = await sha256Hex(`icloud-mcp-approval:${code}`);
  let diff = given.length ^ hash.length; for (let i = 0; i < Math.min(given.length, hash.length); i++) diff |= given.charCodeAt(i) ^ hash.charCodeAt(i);
  if (code.length === 8 && diff === 0) { await env.OAUTH_KV.put(`approval-used:${hash}`, "1", { expirationTtl: 86400 }); return { ok: true, hash }; }
  {
    await env.OAUTH_KV.put(failKey, String(fails + 1), { expirationTtl: 86400 });
    const left = MAX_TRIES - fails - 1;
    return { ok: false, reason: "wrong", message: left > 0 ? `That code doesn't match. Check your setup screen and try again (${left} ${left === 1 ? "try" : "tries"} left).` : "That code doesn't match, and this code is now blocked. On your computer, run npm run setup -- --new-code." };
  }
}

// The re-shown page (after a wrong code) needs the client's name. Carry it in an HMAC-signed field
// so a forged form can't make the page lie about who is asking.
async function mac(env: Env, data: string) {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(`consent-ctx:${env.CONFIRM_SECRET}`), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return [...new Uint8Array(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(data)))].map((b) => b.toString(16).padStart(2, "0")).join("");
}
const safeEq = (a: string, b: string) => { let d = a.length ^ b.length; for (let i = 0; i < Math.min(a.length, b.length); i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
async function signCtx(env: Env, o: object) { const d = btoa(unescape(encodeURIComponent(JSON.stringify(o)))); return `${d}.${await mac(env, d)}`; }
async function readCtx(env: Env, s: string) { const [d, m] = s.split("."); if (!d || !m || !safeEq(m, await mac(env, d))) return undefined; try { return JSON.parse(decodeURIComponent(escape(atob(d)))); } catch { return undefined; } }
