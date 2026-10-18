// No-terminal setup (src/setup-web.ts, gate G9): the link, the session, the live Apple check, the sealed record.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { MockCalDav } from "./mock-caldav.js";
import { MockKV } from "./kv-mock.js";
import { MockGuardNS } from "./guard-mock.js";
import { handleRequest } from "../src/worker.js";
import { withSealed, SETUP_TTL_MS, MAX_SETUP_TRIES } from "../src/setup-web.js";
import { setLogSink } from "../src/redact.js";
import { addPasskey } from "../src/passkey.js";

const USER = "owner.setup@example.com", PASS = "wxyz-abcd-efgh-ijkl", ORIGIN = "http://localhost:8787", EVIL = "https://evil.example";
const logs: string[] = []; setLogSink((l) => logs.push(l));
const cal = new MockCalDav({ user: USER, pass: PASS });
before(async () => { await cal.start(); });
after(async () => { await cal.stop(); });
let env: any, kv: MockKV, guard: MockGuardNS;
const newToken = () => { const t = randomBytes(32).toString("base64url"); return { t, h: createHash("sha256").update(t).digest("hex") }; };
function freshEnv(over: Record<string, unknown> = {}) {
  kv = new MockKV(); guard = new MockGuardNS(); const tk = newToken();
  env = { OAUTH_KV: kv, GUARD: guard, CALDAV_URL: cal.base, PASSKEYS: "on", SEAL_KEY: randomBytes(32).toString("base64url"), SETUP_TOKEN_HASH: tk.h, SETUP_TOKEN_ISSUED: String(Date.now()), ...over };
  return tk.t;
}
const ctx = () => ({ waitUntil() {}, passThroughOnException() {}, props: undefined });
const call = (path: string, init: RequestInit = {}) => handleRequest(new Request(ORIGIN + path, { redirect: "manual", ...init }), env, ctx(), fetch);
const post = (path: string, body: unknown, h: Record<string, string> = {}) => call(path, { method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN, ...h }, body: JSON.stringify(body) });
const cookieOf = (r: Response) => (r.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]).join("; ");
async function claim(token: string, h: Record<string, string> = {}) { const r = await post("/setup/claim", { token }, h); return { status: r.status, body: await r.json() as any, cookie: cookieOf(r), raw: r }; }
async function save(cookie: string, body: Record<string, unknown> = {}, h: Record<string, string> = {}) {
  const r = await post("/setup/save", { email: USER, password: PASS, writes: false, timezone: "America/Denver", ...body }, { Cookie: cookie, ...h });
  return { status: r.status, body: await r.json() as any };
}
/** Everything this Worker stores, as one string: KV values and every Durable Object key and value. */
function storageDump() {
  const parts: string[] = [];
  for (const [k, v] of (kv as any).m ?? (kv as any).store ?? new Map()) parts.push(k, typeof v === "string" ? v : JSON.stringify(v));
  for (const g of guard.objs.values()) for (const [k, v] of ((g as any).ctx.storage.m as Map<string, unknown>)) parts.push(k, JSON.stringify(v));
  return parts.join("\n");
}

test("setup: open the link, one Continue, sealed, and the Worker runs with the sealed account", async () => {
  const token = freshEnv();
  const page = await call("/setup"); const html = await page.text();
  assert.equal(page.status, 200); assert.match(html, /Set up Holdt/); assert.ok(!html.includes(token));
  const c = await claim(token); assert.equal(c.status, 200, JSON.stringify(c.body)); assert.equal(c.body.existing, false);
  const sc = c.raw.headers.getSetCookie()[0]!; assert.match(sc, /^__Host-holdt-setup=/); assert.match(sc, /HttpOnly/); assert.match(sc, /Secure/); assert.match(sc, /SameSite=Strict/);
  const s = await save(c.cookie, { writes: true });
  assert.equal(s.status, 200, JSON.stringify(s.body)); assert.equal(s.body.ok, true); assert.equal(s.body.calendars, 3);
  assert.match(s.body.next, /^\/enroll\?from=setup#[A-Za-z0-9_-]{40,}$/);
  const e = await withSealed(env);
  assert.equal(e.ICLOUD_EMAIL, USER); assert.equal(e.ICLOUD_APP_PASSWORD, PASS); assert.equal(e.WRITES_ENABLED, "true"); assert.equal(e.TIMEZONE, "America/Denver");
  assert.ok(e.CONFIRM_SECRET && e.CONFIRM_SECRET.length >= 40); assert.ok(e.GRANT_EPOCH);
  assert.equal(e.ENROLL_TOKEN_HASH, createHash("sha256").update(s.body.next.split("#")[1]).digest("hex"));
  const enroll = await call("/enroll?from=setup"); assert.equal(enroll.status, 200, "the Face ID step opens on the sealed setup");
  const half = await call("/setup"); assert.match(await half.text(), /const NOTOKEN="unfinished"/, "saved but no passkey yet: the page says setup isn't finished, never that it's set up");
  await addPasskey(await withSealed(env), { id: randomBytes(16).toString("base64url"), jwk: {}, alg: -7, signCount: 0, createdAt: Date.now(), label: "iPhone" } as any);
  const again = await call("/setup"); assert.match(await again.text(), /const NOTOKEN="set"/, "with a passkey, a visit without a link says Holdt is set up");
});

test("ATTACK SW1: another site rides the owner's setup session to bind the Worker to its own iCloud account (CSRF)", async () => {
  const token = freshEnv(); const c = await claim(token);
  const s = await save(c.cookie, {}, { Origin: EVIL });
  assert.equal(s.status, 403); assert.equal(await withSealed(env).then((e: any) => e.ICLOUD_EMAIL), undefined, "nothing sealed");
  const form = await call("/setup/save", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: ORIGIN, Cookie: c.cookie }, body: "email=x" });
  assert.equal(form.status, 415, "a plain cross-site form post is refused too");
});

test("ATTACK SW2: replay the setup link after the owner opened it", async () => {
  const token = freshEnv();
  assert.equal((await claim(token)).status, 200);
  const r = await claim(token); assert.equal(r.status, 400); assert.equal(r.body.ended, true); assert.equal(r.cookie, "");
});

test("ATTACK SW3: use a setup link after its 30 minutes", async () => {
  const token = freshEnv({ SETUP_TOKEN_ISSUED: String(Date.now() - SETUP_TTL_MS - 1000) });
  const r = await claim(token); assert.equal(r.status, 400); assert.equal(r.body.ended, true);
});

test("ATTACK SW4: forge a setup session cookie", async () => {
  const token = freshEnv(); const c = await claim(token);
  const [name, val] = c.cookie.split("="); const [id] = val!.split(".");
  for (const forged of [`${name}=${id}.${"A".repeat(43)}`, `${name}=${randomBytes(24).toString("base64url")}.${"B".repeat(43)}`, `${name}=${id}`]) {
    const s = await save(forged); assert.equal(s.status, 403, forged.slice(0, 30));
  }
  assert.equal((await save(c.cookie)).status, 200, "the real cookie still works");
});

test("ATTACK SW5: read the Apple password or account from what the Worker stores, returns or logs", async () => {
  logs.length = 0; const token = freshEnv(); const c = await claim(token);
  const r = await post("/setup/save", { email: USER, password: PASS, writes: false, timezone: "America/Denver" }, { Cookie: c.cookie });
  const body = await r.text(); assert.equal(r.status, 200);
  const dump = storageDump();
  for (const secret of [PASS, PASS.replace(/-/g, ""), USER, token, env.SEAL_KEY]) {
    assert.ok(!dump.includes(secret), "storage holds no readable secret"); assert.ok(!body.includes(secret), "the response carries none");
    assert.ok(!logs.join("\n").includes(secret), "logs carry none");
  }
  const wrongKey = { ...env, SEAL_KEY: randomBytes(32).toString("base64url") };
  assert.equal((await withSealed(wrongKey)).ICLOUD_APP_PASSWORD, undefined, "without SEAL_KEY the record can't be opened");
});

test("ATTACK SW6: flood the setup endpoints from one IP", async () => {
  freshEnv({ RL_APPROVE: { limit: async () => ({ success: false }) } });
  for (const p of ["/setup/claim", "/setup/save"]) { const r = await post(p, {}); assert.equal(r.status, 429, p); assert.equal(r.headers.get("Retry-After"), "60"); }
});

test("ATTACK SW7: another site opens the setup link's claim to take the setup for itself", async () => {
  const token = freshEnv();
  const r = await claim(token, { Origin: EVIL }); assert.equal(r.status, 403); assert.equal(r.cookie, "");
  assert.equal((await claim(token, { Origin: "" })).status, 403, "no Origin is refused too");
  assert.equal((await claim(token)).status, 200, "the refused attempt didn't spend the owner's link");
});

test("ATTACK SW8: a second save on a used session swaps in another account", async () => {
  const token = freshEnv(); const c = await claim(token);
  assert.equal((await save(c.cookie)).status, 200);
  const s = await save(c.cookie, { email: "attacker@evil.example" }); assert.equal(s.status, 403);
  assert.equal((await withSealed(env)).ICLOUD_EMAIL, USER);
});

test("setup refuses without a setup link on the Worker (a fresh deploy can't be claimed by the first visitor)", async () => {
  freshEnv({ SETUP_TOKEN_HASH: undefined, SETUP_TOKEN_ISSUED: undefined });
  for (const t of [newToken().t, "", "x".repeat(43)]) assert.equal((await claim(t)).status, 400);
  freshEnv({ SEAL_KEY: undefined });
  const p = await call("/setup"); assert.equal(p.status, 404); assert.match(await p.text(), /Holdt isn’t fully installed/);
});

test("setup: a wrong password says so on the field, seals nothing, and tries run out", async () => {
  const token = freshEnv(); const c = await claim(token);
  const bad = await save(c.cookie, { password: "zzzz-zzzz-zzzz-zzzz" }); assert.equal(bad.body.ok, false); assert.equal(bad.body.field, "account", "Apple refusing marks the email and the app password together");
  const fmt = await save(c.cookie, { password: "Hunter2!password" }); assert.equal(fmt.body.field, "password"); assert.match(fmt.body.message, /regular Apple Account password/);
  const em = await save(c.cookie, { email: "nope" }); assert.equal(em.body.field, "email");
  assert.equal((await withSealed(env)).ICLOUD_EMAIL, undefined);
  for (let i = 0; i < MAX_SETUP_TRIES; i++) await save(c.cookie, { password: "zzzz-zzzz-zzzz-zzzz" });
  assert.equal((await save(c.cookie)).status, 429, "a session has a fixed number of live checks");
});

test("setup again: a new link replaces the setup and cuts every earlier connection", async () => {
  const t1 = freshEnv(); const c1 = await claim(t1); await save(c1.cookie);
  const before = (await withSealed(env)).GRANT_EPOCH;
  const t2 = newToken(); env.SETUP_TOKEN_HASH = t2.h; env.SETUP_TOKEN_ISSUED = String(Date.now());
  assert.equal((await save(c1.cookie)).status, 403, "an older session ends when a new link is made");
  const c2 = await claim(t2.t); assert.equal(c2.body.existing, true);
  await save(c2.cookie, { writes: true });
  const e = await withSealed(env); assert.notEqual(e.GRANT_EPOCH, before); assert.equal(e.WRITES_ENABLED, "true");
  env.GRANT_EPOCH = "revoke-all-rotated"; assert.match((await withSealed(env)).GRANT_EPOCH, /\.revoke-all-rotated$/, "--revoke-all still cuts connections");
});

test("setup page: copy has no semicolons, never promises Touch ID, no logos, no address, one main landmark, script only by nonce", async () => {
  freshEnv(); const r = await call("/setup"); const html = await r.text();
  const empty = await call("/setup"); assert.match(await empty.text(), /const NOTOKEN="nolink"/, "a fresh server opened without a link asks for the link, it doesn't say a link ended");
  const visible = html.replace(/<style[\s\S]*?<\/style>/g, "").replace(/<script[\s\S]*?<\/script>/g, "").replace(/<svg[\s\S]*?<\/svg>/g, "").replace(/<[^>]+>/g, " ").replace(/&#\d+;/g, "'");
  assert.ok(!visible.includes(";"), visible.match(/.{30};.{30}/)?.[0]);
  assert.ok(!/Touch ID/.test(visible), "a Mac is never promised Touch ID in the markup, the device swap decides");
  assert.ok(!/Face.ID/.test(visible.replace(/passkey/g, "")), "the setup page names no biometric, the passkey page after it does, by device");
  assert.equal((html.match(/<main\b/g) ?? []).length - (html.match(/hidden>\s*<main\b/g) ?? []).length <= 1, true, "at most one visible main landmark");
  assert.equal((html.match(/<h2 class="gh"/g) ?? []).length, 3, "each step is a heading");
  assert.ok(!/@/.test(visible.replace(/test@holdt\.app/g, "")), "no email address on screen");
  assert.ok(!/apple-logo|\uF8FF/i.test(html));
  const csp = r.headers.get("content-security-policy")!; assert.match(csp, /script-src 'nonce-/); assert.match(csp, /frame-ancestors 'none'/);
  assert.match(html, /autocomplete="off"/); assert.match(html, /type="password"/);
});

test("setup page: a reload after the link was opened picks up the same session, and ends with it", async () => {
  const token = freshEnv(); const c = await claim(token); assert.equal(c.status, 200);
  const back = await call("/setup", { headers: { cookie: c.cookie } }); assert.match(await back.text(), /const NOTOKEN="resume"/, "the reloaded tab gets the form back");
  const stranger = await call("/setup"); assert.match(await stranger.text(), /const NOTOKEN="nolink"/, "without the session cookie, nothing resumes");
  assert.equal((await save(c.cookie)).status, 200);
  const after = await call("/setup", { headers: { cookie: c.cookie } }); assert.doesNotMatch(await after.text(), /NOTOKEN="resume/, "a finished session never reopens the form");
});

test("setup page, one-step flow: Apple first, paste checks on its own, the same page saves the passkey, then shows the address", async () => {
  const t = freshEnv(); const html = await (await call("/setup")).text();
  const js = html.match(/<script nonce="[^"]+">([\s\S]*?)<\/script>/)![1]!;
  assert.doesNotThrow(() => new Function(js), "the page script parses");
  const steps = [...html.matchAll(/<h2 class="gh"[^>]*>([^<]*)</g)].map((m) => m[1]!);
  assert.match(steps[0]!, /app-specific password/); assert.match(steps[1]!, /what it may do/); assert.match(steps[2]!, /Paste it here/);
  assert.match(js, /\.length===16&&/, "a full pasted app password starts the Apple check without a button");
  assert.match(js, /navigator\.credentials\.create/); assert.match(js, /\/enroll\/finish/);
  assert.match(html, /id="addr"/); assert.match(html, /Copy address/);
  assert.match(js, /split\('&'\)/, "an email hint can ride in the fragment, never the query");
  // The server side the page relies on: the enroll token from save opens options twice (a cancelled sheet can retry) and is spent only at finish.
  const c = await claim(t); const s = await save(c.cookie);
  const enrollToken = (s.body.next as string).split("#")[1]!;
  for (let i = 0; i < 2; i++) { const o = await post("/enroll/options", { token: enrollToken }); assert.equal(o.status, 200); assert.equal(((await o.json()) as any).ok, true); }
});
