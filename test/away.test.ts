// No typed codes: approve on your iPhone (consent) and add a device from an enrolled one (pairing). Each threat in
// docs/no-typed-codes.md has an ATTACK test here, and scripts/prove-attacks.mjs shows each protection is load-bearing.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { MockCalDav } from "./mock-caldav.js";
import { MockKV } from "./kv-mock.js";
import { providerFor } from "../src/worker.js";
import { loadPasskeys } from "../src/passkey.js";
import { takeConsentAway, AWAY_TTL_MS } from "../src/away.js";
import { setLogSink } from "../src/redact.js";
import { VirtualAuthenticator } from "./vauth.js";

const USER = "owner@example.com", PASS = "wxyz-abcd-efgh-ijkl";
const ORIGIN = "http://localhost:8787", CB = "https://www.cursor.com/agents/mcp/oauth/callback";
const logs: string[] = []; setLogSink((l) => logs.push(l));
const cal = new MockCalDav({ user: USER, pass: PASS });
before(async () => { await cal.start(); }); after(async () => { await cal.stop(); });
let env: any; let kv: MockKV; const ENROLL = "enroll-token-" + "t".repeat(30);
async function freshEnv(over: Record<string, unknown> = {}) {
  kv = new MockKV();
  env = { ICLOUD_EMAIL: USER, ICLOUD_APP_PASSWORD: PASS, CONFIRM_SECRET: "k".repeat(43), GRANT_EPOCH: "epoch-1-" + "e".repeat(30), TIMEZONE: "America/Denver", WRITES_ENABLED: "false", CALDAV_URL: cal.base, OAUTH_KV: kv,
    PASSKEYS: "on", ENROLL_TOKEN_HASH: createHash("sha256").update(ENROLL).digest("hex"), ENROLL_TOKEN_ISSUED: String(Date.now()), ...over };
}
const ctx = () => ({ waitUntil() {}, passThroughOnException() {}, props: undefined });
const MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";
const call = (path: string, init: RequestInit = {}) => providerFor(ORIGIN, fetch).fetch(new Request(ORIGIN + path, { redirect: "manual", ...init }), env, ctx() as any);
const post = (path: string, o: unknown, h: Record<string, string> = {}) => call(path, { method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN, "User-Agent": MAC, ...h }, body: JSON.stringify(o) });
const pj = async (path: string, o: unknown, h: Record<string, string> = {}) => (await post(path, o, h)).json() as Promise<any>;
const unesc = (s: string) => s.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n));
const b64u = (b: Buffer) => b.toString("base64url");

async function enroll(a: VirtualAuthenticator) {
  const o = await pj("/enroll/options", { token: ENROLL }); const r = await a.create(o.publicKey.challenge);
  return pj("/enroll/finish", { token: ENROLL, challenge_token: o.challenge_token, ...r });
}
async function consent() {
  const reg: any = await (await call("/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name: "Grok Bot", redirect_uris: [CB], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) })).json();
  const verifier = b64u(randomBytes(32));
  const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: CB, code_challenge: b64u(createHash("sha256").update(verifier).digest()), code_challenge_method: "S256", state: "s1", scope: "calendar", resource: `${ORIGIN}/mcp` });
  const page = await call(`/authorize?${q}`, { headers: { "User-Agent": MAC } }); const html = await page.text();
  const field = (n: string) => unesc(html.match(new RegExp(`name="${n}" value="([^"]*)"`))?.[1] ?? "");
  const link = unesc(html.match(/data-link="([^"]+)"/)?.[1] ?? "");
  const cookie = (page.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]).join("; ");
  const submit = (f: Record<string, string>) => call("/authorize", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookie, Origin: ORIGIN, "User-Agent": MAC }, body: new URLSearchParams({ handle: field("handle"), ctx: field("ctx"), ...f }).toString() });
  return { page, html, link, secret: link.split("#")[1] ?? "", handle: field("handle"), ctx: field("ctx"), submit };
}
/** The iPhone: open the link (view), then the one tap plus Face ID (approve). */
async function approveOn(a: VirtualAuthenticator, s: string, opt: any = {}) {
  const v = await pj("/ok/view", { s }); if (!v.ok) return v;
  const g = await a.get(v.challenge, opt);
  return pj("/ok/approve", { s, challenge_token: v.challenge_token, ...g });
}

test("approve on your iPhone: scan, Face ID, and the computer's consent finishes with nothing typed", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const c = await consent();
  assert.match(c.html, /<svg class="qr"/); assert.match(c.link, /^http:\/\/localhost:8787\/ok#[\w-]{43}$/); assert.doesNotMatch(c.html, /name="code"/);
  assert.equal((await pj("/authorize/away", { handle: c.handle })).status, "pending");
  const v = await pj("/ok/view", { s: c.secret });
  assert.match(v.html, /Connect Grok Bot to your iCloud Calendar\?/); assert.match(v.html, /From <strong>a\u00a0device that\u00a0says\u00a0it’s\u00a0a\u00a0Mac<\/strong>, just now\./, "the device type is only what its User-Agent claims (red team F5)"); assert.equal(v.device, "Mac");
  assert.match(v.html, /Approve only a request you just started yourself\. Never one someone sent you\./);
  assert.match(v.html, /Never deletes your events\.<span class="sub keep"> It can only take back its own, on\u00a0your\u00a0yes\.<\/span>/);
  assert.equal((await approveOn(a, c.secret)).ok, true);
  assert.equal((await pj("/authorize/away", { handle: c.handle })).status, "approved");
  const r = await c.submit({ away: "1" }); assert.equal(r.status, 302, await r.clone().text());
  assert.ok(new URL(r.headers.get("location")!).searchParams.get("code"));
  assert.ok(logs.some((l) => /connection approved \(on another device\)/.test(l)));
});

test("approve on your iPhone works without script: the QR code shows and I approved on my iPhone posts", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const c = await consent(); assert.match(c.html, /id="awaygo" name="decision" value="away"/);
  const early = await c.submit({ decision: "away" }); assert.equal(early.status, 400); assert.match(await early.text(), /Not approved yet/);
  const c2 = await consent(); await approveOn(a, c2.secret);
  assert.equal((await c2.submit({ decision: "away" })).status, 302);
});

test("ATTACK N1: away links leak nothing: the secret is only in the fragment, KV holds its hash, and it dies after 5 minutes", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const c = await consent();
  assert.ok(![...kv.m.keys(), ...[...kv.m.values()].map(String)].some((x) => x.includes(c.secret)), "KV never holds the secret");
  assert.ok(!logs.some((l) => l.includes(c.secret)));
  const real = Date.now; Date.now = () => real() + AWAY_TTL_MS + 1000;
  try { const v = await pj("/ok/view", { s: c.secret }); assert.equal(v.ok, false); assert.equal(v.gone, "expired"); }
  finally { Date.now = real; }
});

test("ATTACK N2: a link preview or prefetch (GET) of /ok, /pair and /enroll changes nothing, and the real tap still works", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const c = await consent(); const before = [...kv.m.entries()].map(([k, v]) => k + v).sort().join();
  for (const p of ["/ok", `/ok?s=${c.secret}`, "/pair", "/enroll"]) { const r = await call(p, { headers: { "User-Agent": "facebookexternalhit/1.1" } }); assert.equal(r.status, 200, p); assert.doesNotMatch(await r.text(), new RegExp(c.secret)); }
  assert.equal([...kv.m.entries()].map(([k, v]) => k + v).sort().join(), before, "no state changed");
  const v1 = await pj("/ok/view", { s: c.secret }); const v2 = await pj("/ok/view", { s: c.secret });
  assert.ok(v1.ok && v2.ok, "reading the request (even twice) decides nothing");
  assert.equal((await approveOn(a, c.secret)).ok, true);
});

test("ATTACK N3: another site can't drive the approve, deny, pair or refresh endpoints (CSRF)", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const c = await consent();
  for (const p of ["/ok/view", "/ok/approve", "/ok/deny", "/pair/new", "/pair/status", "/authorize/away", "/authorize/away/new", "/enroll/finish"]) {
    assert.equal((await post(p, { s: c.secret }, { Origin: "https://evil.example" })).status, 403, p);
    assert.equal((await call(p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ s: c.secret }) })).status, 403, `${p} without Origin`);
    assert.equal((await call(p, { method: "POST", headers: { "Content-Type": "text/plain", Origin: ORIGIN }, body: JSON.stringify({ s: c.secret }) })).status, 415, `${p} as a simple form post`);
  }
  assert.equal((await pj("/authorize/away", { handle: c.handle })).status, "pending", "nothing was decided");
});

test("ATTACK N4: an approval is decided once and used once, and its Face ID challenge works once", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const c = await consent();
  const v = await pj("/ok/view", { s: c.secret }); const g = await a.get(v.challenge, { bump: 1 });
  assert.equal((await pj("/ok/approve", { s: c.secret, challenge_token: v.challenge_token, ...g })).ok, true);
  const again = await pj("/ok/approve", { s: c.secret, challenge_token: v.challenge_token, ...(await a.get(v.challenge, { bump: 2 })) });
  assert.equal(again.ok, false); assert.equal(again.gone, "decided");
  assert.equal((await pj("/ok/deny", { s: c.secret })).ok, false, "a decided request can't be flipped");
  assert.equal((await takeConsentAway(env, c.handle)).ok, true);
  const twice = await takeConsentAway(env, c.handle); assert.equal(twice.ok, false); assert.equal((twice as any).reason, "used");
  // A challenge from a failed try can't be replayed either.
  const c2 = await consent(); const v2 = await pj("/ok/view", { s: c2.secret });
  assert.equal((await pj("/ok/approve", { s: c2.secret, challenge_token: v2.challenge_token, ...(await a.get(v2.challenge, { origin: "https://evil.example", bump: 3 })) })).ok, false);
  assert.equal((await pj("/ok/approve", { s: c2.secret, challenge_token: v2.challenge_token, ...(await a.get(v2.challenge, { bump: 4 })) })).ok, false, "the spent challenge stays spent");
  assert.equal((await approveOn(a, c2.secret, { bump: 5 })).ok, true, "a fresh view gives a fresh challenge");
});

test("ATTACK N5: someone who sees the QR code but has no enrolled passkey can't approve, and can't claim a device pairing", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const c = await consent();
  const stranger = await new VirtualAuthenticator(ORIGIN).init(); stranger.id = a.id; // claims the owner's credential id
  assert.equal((await approveOn(stranger, c.secret)).ok, false);
  const other = await new VirtualAuthenticator(ORIGIN).init();
  assert.equal((await approveOn(other, c.secret)).ok, false);
  assert.equal((await pj("/authorize/away", { handle: c.handle })).status, "pending");
  assert.equal((await approveOn(a, c.secret)).ok, true, "the owner still can");
  // Pairing: the QR code carries the view secret only. The claim secret never leaves the new device's page.
  const p = await pj("/pair/new", {}); const view = p.link.split("#")[1];
  assert.equal((await approveOn(a, view, { bump: 9 })).ok, true);
  assert.equal((await pj("/pair/status", { claim: view })).status, "gone", "the view secret isn't a claim");
  const attacker = await new VirtualAuthenticator(ORIGIN).init();
  const fake = await pj("/enroll/options", { pair: view }); assert.equal(fake.ok, false);
  const opts = await pj("/pair/status", { claim: p.claim }); assert.equal(opts.status, "approved");
  const forged = await pj("/enroll/finish", { pair: view, challenge_token: opts.challenge_token, ...(await attacker.create(opts.publicKey.challenge)) });
  assert.equal(forged.ok, false); assert.equal((await loadPasskeys(env)).length, 1);
});

test("ATTACK N6: an approval for one connect request can't finish another", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const c1 = await consent(), c2 = await consent();
  await approveOn(a, c1.secret);
  assert.equal((await c2.submit({ away: "1" })).status, 400);
  assert.equal((await c1.submit({ away: "1" })).status, 302);
});

test("ATTACK N7: the approve page shows who is asking, where access goes, and where the request came from (phishing)", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const reg: any = await (await call("/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name: "Grok Bot", redirect_uris: ["http://127.0.0.1:4111/cb"], token_endpoint_auth_method: "none", grant_types: ["authorization_code"], response_types: ["code"] }) })).json();
  const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: "http://127.0.0.1:4111/cb", code_challenge: b64u(randomBytes(32)), code_challenge_method: "S256", state: "s", scope: "calendar", resource: `${ORIGIN}/mcp` });
  const req = new Request(`${ORIGIN}/authorize?${q}`, { headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" } }); (req as any).cf = { city: "Lagos", regionCode: "LA" };
  const html = await (await providerFor(ORIGIN, fetch).fetch(req, env, ctx() as any)).text();
  const s = unesc(html.match(/data-link="([^"]+)"/)![1]!).split("#")[1]!;
  const v = await pj("/ok/view", { s });
  assert.match(v.html, /From <strong>a\u00a0device that\u00a0says\u00a0it’s\u00a0a\u00a0Windows\u00a0PC near\u00a0Lagos,\u00a0LA<\/strong>, just now\./);
  assert.match(v.html, /calls itself “Grok Bot,” but Holdt can’t verify that/, "a borrowed name is never vouched for");
  assert.match(v.html, /Access goes to <strong>127\.0\.0\.1(:4111)?<\/strong>/);
  assert.match(v.html, /This sends access to an app on the computer that asked\./, "never says 'this computer' on the iPhone");
  assert.doesNotMatch(v.html.replace(/<[^>]+>/g, " ").replace(/&#?\w+;/g, " "), /;/, "no semicolons in copy");
});

test("deny on the iPhone: the computer stops, and the request can't be approved after", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const c = await consent();
  assert.equal((await pj("/ok/deny", { s: c.secret })).ok, true);
  assert.equal((await pj("/authorize/away", { handle: c.handle })).status, "denied");
  assert.equal((await approveOn(a, c.secret)).ok, false);
  const r = await c.submit({ away: "1" }); assert.equal(r.status, 400); assert.match(await r.text(), /Your iPhone said no/);
});

test("pairing: a new device shows a QR code, the iPhone approves with Face ID, one tap here makes its own passkey", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const page = await call("/pair"); const html = await page.text();
  assert.match(html, /Add this device/); assert.match(page.headers.get("content-security-policy")!, /script-src 'nonce-/);
  const p = await pj("/pair/new", {}, { "User-Agent": "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X)" });
  assert.match(p.qr, /<svg class="qr"/);
  assert.equal((await pj("/pair/status", { claim: p.claim })).status, "pending");
  const v = await pj("/ok/view", { s: p.link.split("#")[1] });
  assert.match(v.html, /Add a new device\?/); assert.match(v.html, /From <strong>a\u00a0device that\u00a0says\u00a0it’s\u00a0an\u00a0iPad<\/strong>, just now\.<\/p>/); assert.match(v.html, /It can approve Holdt connections\./); assert.match(v.html, /If someone asked you to add it, tap Don/); assert.match(v.html, /holding right now/);
  assert.equal((await approveOn(a, p.link.split("#")[1], { bump: 1 })).ok, true);
  const st = await pj("/pair/status", { claim: p.claim }); assert.equal(st.status, "approved"); assert.ok(st.publicKey);
  const b = await new VirtualAuthenticator(ORIGIN).init();
  const done = await pj("/enroll/finish", { pair: p.claim, challenge_token: st.challenge_token, ...(await b.create(st.publicKey.challenge)) });
  assert.equal(done.ok, true, JSON.stringify(done)); assert.equal((await loadPasskeys(env)).length, 2);
  assert.ok(logs.some((l) => /via approved on another device, 2 on this server/.test(l)));
  const st2 = await pj("/pair/status", { claim: p.claim }); assert.equal(st2.status, "gone", "an approval adds one device");
});

test("pairing with nothing enrolled yet says so, and a pending pairing can't enroll", async () => {
  await freshEnv();
  const p = await pj("/pair/new", {}); assert.equal(p.ok, false); assert.match(p.message, /yet/);
  const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const q = await pj("/pair/new", {}); assert.equal((await pj("/enroll/options", { pair: q.claim })).ok, false);
});
