import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { MockCalDav } from "./mock-caldav.js";
import { MockKV } from "./kv-mock.js";
import { providerFor } from "../src/worker.js";
import { sha256Hex, redirectAllowed } from "../src/authorize.js";
import { setLogSink } from "../src/redact.js";
import { TOOLS, REMINDER_TOOLS } from "../src/tools.js";

const USER = "owner@example.com", PASS = "wxyz-abcd-efgh-ijkl", CODE = "48291376";
const ORIGIN = "http://localhost:8787", CB = "cursor://anysphere.cursor-mcp/oauth/callback";
const logs: string[] = []; setLogSink((l) => logs.push(l));
const cal = new MockCalDav({ user: USER, pass: PASS });
let kv: MockKV; let env: any;
before(async () => { await cal.start(); });
after(async () => { await cal.stop(); });

async function freshEnv(over: Record<string, unknown> = {}) {
  kv = new MockKV();
  env = { ICLOUD_EMAIL: USER, ICLOUD_APP_PASSWORD: PASS, CONFIRM_SECRET: "k".repeat(43), GRANT_EPOCH: "epoch-1-" + "e".repeat(30), TIMEZONE: "America/Denver", WRITES_ENABLED: "false", CALDAV_URL: cal.base, OAUTH_KV: kv, PASSKEYS: "on",
    APPROVAL_CODE_HASH: await sha256Hex(`icloud-mcp-approval:${CODE}`), APPROVAL_CODE_ISSUED: String(Date.now()), ...over };
}
const ctx = () => ({ waitUntil(_p: Promise<unknown>) {}, passThroughOnException() {}, props: undefined });
const call = (path: string, init: RequestInit = {}) => providerFor(ORIGIN, fetch).fetch(new Request(ORIGIN + path, { redirect: "manual", ...init }), env, ctx() as any);
const form = (o: Record<string, string>) => ({ method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(o).toString() });
const cookiesOf = (r: Response) => (r.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]).join("; ");
const b64u = (b: Buffer) => b.toString("base64url");

/** A mocked Grok Bot client: DCR, PKCE, authorize, approval code, token exchange. */
async function connect(code = CODE, redirect = CB) {
  const reg = await call("/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name: "Grok Bot", redirect_uris: [redirect, "http://localhost:51234/callback"], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) });
  assert.equal(reg.status, 201, await reg.clone().text()); const client: any = await reg.json();
  const verifier = b64u(randomBytes(32)), challenge = b64u(createHash("sha256").update(verifier).digest()), state = b64u(randomBytes(8));
  const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: redirect, code_challenge: challenge, code_challenge_method: "S256", state, scope: "calendar", resource: `${ORIGIN}/mcp` });
  const page = await call(`/authorize?${q}`);
  const html = await page.text();
  if (page.status !== 200) return { client, page, html } as any;
  const handle = html.match(/name="handle" value="([^"]+)"/)![1]!.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n));
  const ctxField = html.match(/name="ctx" value="([^"]*)"/)![1]!.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n));
  const cookie = cookiesOf(page);
  const submit = (c: string, decision = "approve") => call("/authorize", { ...form({ handle, ctx: ctxField, code: c, decision }), headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookie, Origin: ORIGIN } });
  return { client, verifier, state, html, submit, redirect, page };
}
async function exchange(c: any, location: string) {
  const u = new URL(location); assert.equal(u.searchParams.get("state"), c.state);
  const r = await call("/oauth/token", form({ grant_type: "authorization_code", code: u.searchParams.get("code")!, redirect_uri: c.redirect, client_id: c.client.client_id, code_verifier: c.verifier, resource: `${ORIGIN}/mcp` }));
  assert.equal(r.status, 200, await r.clone().text()); return r.json() as Promise<any>;
}
const mcp = (token: string, method = "tools/list", params: unknown = {}) => call("/mcp", { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });

test("discovery: unauthenticated /mcp challenges with resource metadata; AS metadata lists DCR, token, revocation, S256", async () => {
  await freshEnv();
  const r = await call("/mcp", { method: "POST", body: "{}" }); assert.equal(r.status, 401);
  assert.match(r.headers.get("www-authenticate") ?? "", /resource_metadata=/);
  const m: any = await (await call("/.well-known/oauth-authorization-server")).json();
  assert.equal(m.registration_endpoint, `${ORIGIN}/oauth/register`); assert.equal(m.token_endpoint, `${ORIGIN}/oauth/token`); assert.equal(m.revocation_endpoint, `${ORIGIN}/oauth/token`);
  assert.ok(m.code_challenge_methods_supported.includes("S256"));
});

test("full flow: register with the legacy cursor:// callback, approve with the one-time code, use the token", async () => {
  await freshEnv();
  const c = await connect();
  assert.match(c.html, /Connect an app to your iCloud Calendar\?/); assert.match(c.html, /calls itself “Grok Bot,” but Holdt can’t verify that/); assert.match(c.html, /Access goes to <strong>anysphere\.cursor-mcp<\/strong>|Access goes to <strong>/); assert.match(c.html, /Changes are off/);
  assert.doesNotMatch(c.html, new RegExp(CODE)); // the page never shows the code
  const ok = await c.submit("4829-1376"); assert.equal(ok.status, 302);
  const loc = ok.headers.get("location")!; assert.ok(loc.startsWith(CB + "?"), loc);
  const tok = await exchange(c, loc); assert.ok(tok.access_token && tok.refresh_token); assert.equal(tok.token_type.toLowerCase(), "bearer");
  const list: any = await (await mcp(tok.access_token)).json(); assert.equal(list.result.tools.length, TOOLS.length - REMINDER_TOOLS.size);
  const evs: any = await (await mcp(tok.access_token, "tools/call", { name: "list_calendars", arguments: {} })).json();
  assert.deepEqual(evs.result.structuredContent.calendars.map((x: any) => x.name), ["Home", "Work", "US Holidays"]);
});

test("approval code: single use, wrong-code countdown, lockout after 5, expiry after 15 minutes", async () => {
  await freshEnv();
  const a = await connect(); const w = await a.submit("1111-1111"); assert.equal(w.status, 400);
  const wh = await w.text(); assert.match(wh, /doesn['’]t match/); assert.match(wh, /4 tries left/); assert.match(wh, /calls itself “Grok Bot,”/, "re-shown page still names the client (signed ctx)");
  assert.equal((await a.submit(CODE)).status, 302, "right code still works on the same page after a wrong try");
  const b = await connect(); const used = await b.submit(CODE); assert.equal(used.status, 400); assert.match(await used.text(), /already (used|approved|connected)/);

  await freshEnv(); const c = await connect();
  for (let i = 0; i < 5; i++) await c.submit("0000-0000");
  const locked = await c.submit(CODE); assert.equal(locked.status, 400); assert.match(await locked.text(), /blocked/);

  await freshEnv({ APPROVAL_CODE_ISSUED: String(Date.now() - 16 * 60_000) }); const d = await connect();
  const exp = await d.submit(CODE); assert.equal(exp.status, 400); assert.match(await exp.text(), /expired/);
});

test("deny returns access_denied to the client and issues nothing", async () => {
  await freshEnv(); const c = await connect();
  const r = await c.submit("", "deny"); assert.equal(r.status, 302);
  const u = new URL(r.headers.get("location")!); assert.equal(u.searchParams.get("error"), "access_denied");
  assert.equal((await connect().then((x) => x.submit(CODE))).status, 302, "code was not consumed by a deny");
});

test("tampered consent context can't change who the page says is asking", async () => {
  await freshEnv(); const c = await connect();
  const bad = await call("/authorize", { ...form({ handle: "x", ctx: btoa(JSON.stringify({ clientName: "Apple Inc." })) + ".deadbeef", code: "1", decision: "approve" }) });
  assert.doesNotMatch(await bad.text(), /Apple Inc\./);
});

test("refresh rotates tokens; revocation and setup's epoch rotation both cut access", async () => {
  await freshEnv(); const c = await connect(); const tok = await exchange(c, (await c.submit(CODE)).headers.get("location")!);
  const r = await call("/oauth/token", form({ grant_type: "refresh_token", refresh_token: tok.refresh_token, client_id: c.client.client_id, resource: `${ORIGIN}/mcp` }));
  assert.equal(r.status, 200, await r.clone().text()); const t2: any = await r.json();
  assert.notEqual(t2.access_token, tok.access_token); assert.notEqual(t2.refresh_token, tok.refresh_token);
  assert.equal((await mcp(t2.access_token)).status, 200);
  // RFC 7009 revocation of the refresh token revokes the grant
  const rv = await call("/oauth/token", form({ token: t2.refresh_token, token_type_hint: "refresh_token", client_id: c.client.client_id }));
  assert.equal(rv.status, 200);
  assert.equal((await mcp(t2.access_token)).status, 401);
  const again = await call("/oauth/token", form({ grant_type: "refresh_token", refresh_token: t2.refresh_token, client_id: c.client.client_id }));
  assert.notEqual(again.status, 200);
  // owner-side "revoke all": a new GRANT_EPOCH (rerunning setup) cuts off every existing grant
  await freshEnv(); const d = await connect(); const t3 = await exchange(d, (await d.submit(CODE)).headers.get("location")!);
  env.GRANT_EPOCH = "epoch-2-" + "f".repeat(30);
  const cut = await mcp(t3.access_token); assert.equal(cut.status, 401); assert.match(await cut.text(), /revoked/);
});

test("PKCE is enforced and a code can't be exchanged twice", async () => {
  await freshEnv(); const c = await connect(); const loc = (await c.submit(CODE)).headers.get("location")!;
  const code = new URL(loc).searchParams.get("code")!;
  const bad = await call("/oauth/token", form({ grant_type: "authorization_code", code, redirect_uri: CB, client_id: c.client.client_id, code_verifier: "wrong-verifier-" + "x".repeat(40), resource: `${ORIGIN}/mcp` }));
  assert.equal(bad.status, 400);
  await freshEnv(); const d = await connect(); const loc2 = (await d.submit(CODE)).headers.get("location")!;
  await exchange(d, loc2);
  const twice = await call("/oauth/token", form({ grant_type: "authorization_code", code: new URL(loc2).searchParams.get("code")!, redirect_uri: CB, client_id: d.client.client_id, code_verifier: d.verifier, resource: `${ORIGIN}/mcp` }));
  assert.equal(twice.status, 400);
});

test("redirect policy: only https, loopback http, or cursor: may receive a code", async () => {
  assert.ok(redirectAllowed(CB)); assert.ok(redirectAllowed("http://127.0.0.1:5000/cb")); assert.ok(redirectAllowed("https://app.example/cb"));
  assert.ok(!redirectAllowed("myapp://cb")); assert.ok(!redirectAllowed("http://evil.example/cb")); assert.ok(!redirectAllowed("javascript:alert(1)"));
  await freshEnv(); const c: any = await connect(CODE, "evilapp://steal");
  assert.equal(c.page?.status ?? 200, 400); assert.match(c.html, /can['’]t connect/);
});

test("consent page CSP lets the form's final redirect reach the client (cursor: scheme and https origin)", async () => {
  await freshEnv();
  const a = await connect();
  const csp = a.page.headers.get("content-security-policy") ?? "";
  assert.match(csp, /form-action 'self' cursor:;/, csp);
  assert.match(csp, /frame-ancestors 'none'/); assert.match(csp, /default-src 'none'/);
  const b = await connect(CODE, "https://app.example/oauth/cb");
  const csp2 = b.page.headers.get("content-security-policy") ?? "";
  assert.match(csp2, /form-action 'self' https:\/\/app\.example;/, csp2);
  assert.doesNotMatch(csp2, /\/oauth\/cb/, "only the origin is allowed, not a path");
  // a wrong code re-renders the form, and the re-rendered page keeps the redirect origin in CSP
  const w = await b.submit("1111-1111"); assert.equal(w.status, 400);
  assert.match(w.headers.get("content-security-policy") ?? "", /form-action 'self' https:\/\/app\.example;/);
  const ok = await b.submit(CODE); assert.equal(ok.status, 302); assert.ok(ok.headers.get("location")!.startsWith("https://app.example/oauth/cb?"));
  assert.equal(new URL(ok.headers.get("location")!).searchParams.get("iss"), ORIGIN, "RFC 9207 iss is on the redirect");
});

test("reused code shows 'already approved', not an error to retry", async () => {
  await freshEnv(); const a = await connect(); assert.equal((await a.submit(CODE)).status, 302);
  const b = await connect(); const r = await b.submit(CODE); assert.equal(r.status, 400);
  const h = await r.text(); assert.match(h, /already connected/); assert.doesNotMatch(h, /<form/);
});

test("a revoked grant's 401 points the client back at the resource metadata", async () => {
  await freshEnv(); const d = await connect(); const t = await exchange(d, (await d.submit(CODE)).headers.get("location")!);
  env.GRANT_EPOCH = "epoch-3-" + "g".repeat(30);
  const cut = await mcp(t.access_token); assert.equal(cut.status, 401);
  assert.match(cut.headers.get("www-authenticate") ?? "", new RegExp(`resource_metadata="${ORIGIN}/\\.well-known/oauth-protected-resource/mcp"`));
});

test("SECRET SAFETY (OAuth): no password, approval code, tokens or email in any log line", async () => {
  const blob = logs.join("\n"); assert.ok(logs.length > 0);
  for (const bad of [PASS, CODE, "4829-1376", USER, Buffer.from(`${USER}:${PASS}`).toString("base64")]) assert.ok(!blob.includes(bad), `leaked ${bad.slice(0, 3)}…`);
  for (const [k, v] of kv.m) { assert.ok(!v.v.includes(PASS), k); assert.ok(!v.v.includes(CODE), k); }
});
