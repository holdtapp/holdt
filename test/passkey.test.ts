// Passkey one-tap connect: the WebAuthn checks, enrollment, and the consent page, end to end through the OAuth provider.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { MockCalDav } from "./mock-caldav.js";
import { MockKV } from "./kv-mock.js";
import { providerFor } from "../src/worker.js";
import { sha256Hex } from "../src/authorize.js";
import { verifyRegistration, verifyAssertion, derToRaw, cbor } from "../src/webauthn.js";
import { cliAction } from "../setup/server.js";
import { loadPasskeys, addPasskey, bumpPasskey, MAX_PASSKEYS } from "../src/passkey.js";
import { MockGuardNS } from "./guard-mock.js";
import { setLogSink } from "../src/redact.js";
import { VirtualAuthenticator } from "./vauth.js";

const USER = "owner@example.com", PASS = "wxyz-abcd-efgh-ijkl", CODE = "48291376";
const ORIGIN = "http://localhost:8787", CB = "cursor://anysphere.cursor-mcp/oauth/callback";
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
const call = (path: string, init: RequestInit = {}) => providerFor(ORIGIN, fetch).fetch(new Request(ORIGIN + path, { redirect: "manual", ...init }), env, ctx() as any);
const post = (path: string, o: unknown) => call(path, { method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN }, body: JSON.stringify(o) });
const unesc = (s: string) => s.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n));
const b64u = (b: Buffer) => b.toString("base64url");

/** Enroll the way the page does: options as the page opens, then the one click (create) and finish. Nothing typed. */
async function enroll(a: VirtualAuthenticator, token = ENROLL) {
  const o: any = await (await post("/enroll/options", { token })).json(); if (!o.ok) return o;
  const r = await a.create(o.publicKey.challenge);
  return (await post("/enroll/finish", { token, challenge_token: o.challenge_token, ...r })).json() as Promise<any>;
}
/** Turns on an owner recovery code, as `npm run new-code` would. */
const recovery = async () => { env.APPROVAL_CODE_HASH = await sha256Hex(`icloud-mcp-approval:${CODE}`); env.APPROVAL_CODE_ISSUED = String(Date.now()); };
async function consent(cb = CB) {
  const reg: any = await (await call("/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name: "Grok Bot", redirect_uris: [cb], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) })).json();
  const verifier = b64u(randomBytes(32));
  const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: cb, code_challenge: b64u(createHash("sha256").update(verifier).digest()), code_challenge_method: "S256", state: "s1", scope: "calendar", resource: `${ORIGIN}/mcp` });
  const page = await call(`/authorize?${q}`); const html = await page.text();
  const field = (n: string) => unesc(html.match(new RegExp(`name="${n}" value="([^"]*)"`))?.[1] ?? "");
  const o = html.match(/data-o="([^"]+)"/) ? JSON.parse(unesc(html.match(/data-o="([^"]+)"/)![1]!)) : undefined;
  const cookie = (page.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]).join("; ");
  const submit = (f: Record<string, string>) => call("/authorize", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookie, Origin: ORIGIN }, body: new URLSearchParams({ handle: field("handle"), ctx: field("ctx"), ...f }).toString() });
  const viaPasskey = async (a: VirtualAuthenticator, opt: any = {}, extra: Record<string, string> = {}) => { const s = await a.get(o.challenge, opt); return submit({ pk_token: field("pk_token"), pk_id: s.id, pk_cdj: s.clientDataJSON, pk_ad: s.authenticatorData, pk_sig: s.signature, ...extra }); };
  return { page, html, o, submit, viaPasskey, token: field("pk_token"), client: reg, verifier };
}

test("WebAuthn checks: happy path, then every way an assertion can be wrong", async () => {
  const a = await new VirtualAuthenticator(ORIGIN).init();
  const ch = new Uint8Array(randomBytes(32)), ex = { challenge: ch, origin: ORIGIN, rpId: "localhost" };
  const cred = await verifyRegistration(await a.create(b64u(Buffer.from(ch))), ex);
  assert.equal(cred.alg, -7); assert.equal(cred.id, a.credId);
  const ok = (o: any = {}) => a.get(b64u(Buffer.from(ch)), o).then((s) => verifyAssertion(s, cred, ex));
  assert.deepEqual(await ok(), { signCount: 0 });
  await assert.rejects(ok({ origin: "https://evil.example" }), /wrong origin/);
  await assert.rejects(ok({ rpId: "evil.example" }), /wrong RP ID/);
  await assert.rejects(ok({ type: "webauthn.create" }), /wrong ceremony type/);
  await assert.rejects(ok({ crossOrigin: true }), /cross-origin/);
  await assert.rejects(a.get(b64u(randomBytes(32))).then((s) => verifyAssertion(s, cred, ex)), /challenge mismatch/);
  a.uv = false; await assert.rejects(ok(), /user not verified/); a.uv = true;
  const s = await a.get(b64u(Buffer.from(ch))); const sig = Buffer.from(s.signature, "base64url"); sig[sig.length - 1] ^= 1;
  await assert.rejects(verifyAssertion({ ...s, signature: b64u(sig) }, cred, ex), /bad signature|encoding/);
  const other = await new VirtualAuthenticator(ORIGIN).init(); // a different key claiming this credential
  await assert.rejects(other.get(b64u(Buffer.from(ch))).then((x) => verifyAssertion(x, cred, ex)), /bad signature/);
  // counters: synced passkeys stay 0. Once one moves it must keep moving (a step back means a cloned key)
  assert.deepEqual(await ok({ bump: 5 }), { signCount: 5 });
  await assert.rejects(verifyAssertion(await a.get(b64u(Buffer.from(ch))), { ...cred, signCount: 9 }, ex), /counter went backwards/);
  // registration refuses wrong origin, wrong RP and no user verification
  await assert.rejects(verifyRegistration(await a.create(b64u(Buffer.from(ch)), { origin: "https://evil.example" }), ex), /wrong origin/);
  await assert.rejects(verifyRegistration(await a.create(b64u(Buffer.from(ch)), { rpId: "evil.example" }), ex), /wrong RP ID/);
  a.uv = false; await assert.rejects(verifyRegistration(await a.create(b64u(Buffer.from(ch))), ex), /user not verified/);
  // hostile encodings fail closed
  assert.throws(() => derToRaw(new Uint8Array([0x30, 2, 0x02, 0])), /signature encoding/);
  assert.throws(() => cbor(new Uint8Array([0x9f])), /CBOR/);
  assert.throws(() => cbor(new Uint8Array(Array(20).fill(0x81))), /too deep/);
});

test("enroll: page carries a nonce CSP, the token works once and expires, and is checked before anything else", async () => {
  await freshEnv();
  const p = await call("/enroll"); const html = await p.text();
  const csp = p.headers.get("content-security-policy")!; const nonce = csp.match(/'nonce-([a-f0-9]+)'/)?.[1];
  assert.ok(nonce, csp); assert.match(html, new RegExp(`<script nonce="${nonce}">`)); assert.match(csp, /connect-src 'self'/); assert.match(csp, /frame-ancestors 'none'/);
  assert.match(html, /location\.hash/); assert.doesNotMatch(html, new RegExp(ENROLL));
  assert.match((await (await post("/enroll/options", { token: "wrong" })).json() as any).message, /isn't valid/);
  const a = await new VirtualAuthenticator(ORIGIN).init();
  assert.deepEqual(await enroll(a), { ok: true, count: 1 });
  assert.match((await enroll(await new VirtualAuthenticator(ORIGIN).init())).message, /already used/);
  assert.equal((await call("/enroll/finish", { method: "POST", headers: { Origin: "https://evil.example" }, body: "{}" })).status, 403);
  await freshEnv({ ENROLL_TOKEN_ISSUED: String(Date.now() - 11 * 60_000) });
  assert.match((await enroll(a)).message, /expired/);
  await freshEnv({ PASSKEYS: undefined });
  assert.equal((await call("/enroll")).status, 404); assert.match((await enroll(a)).message, /turned off/);
});

test("enroll: a challenge is single use and bound to the enroll token, and a wrong-origin passkey is refused", async () => {
  await freshEnv();
  const a = await new VirtualAuthenticator(ORIGIN).init();
  const o: any = await (await post("/enroll/options", { token: ENROLL })).json();
  const bad = await a.create(o.publicKey.challenge, { origin: "https://evil.example" });
  assert.match((await (await post("/enroll/finish", { token: ENROLL, challenge_token: o.challenge_token, ...bad })).json() as any).message, /wasn't saved/);
  // that challenge is spent even though it failed
  const good = await a.create(o.publicKey.challenge);
  assert.equal((await (await post("/enroll/finish", { token: ENROLL, challenge_token: o.challenge_token, ...good })).json() as any).ok, false);
  assert.equal((await enroll(a)).ok, true, "the link itself is still unused");
});

test("ATTACK N8: opening the setup link, previews and repeated options spend nothing. Only the one click's finish does", async () => {
  await freshEnv();
  const before = [...kv.m.keys()].sort().join();
  for (const path of ["/enroll", `/enroll?t=${ENROLL}`, "/enroll?from=setup"]) assert.equal((await call(path)).status, 200);
  assert.equal([...kv.m.keys()].sort().join(), before, "a GET (a messaging app's link preview) changes nothing");
  for (let i = 0; i < 3; i++) assert.equal(((await (await post("/enroll/options", { token: ENROLL })).json()) as any).ok, true);
  const a = await new VirtualAuthenticator(ORIGIN).init();
  assert.equal((await enroll(a)).ok, true, "the link still works after the page opened and fetched options");
  assert.match((await enroll(await new VirtualAuthenticator(ORIGIN).init())).message, /already used/);
  assert.ok(logs.some((l) => /passkey enrolled: device "unnamed" via setup link, 1 on this server/.test(l)), "each enroll is logged");
});

test("connect: Allow with Face ID approves with no code typed, and the token works", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const c = await consent();
  assert.match(c.html, /Allow with Face ID/); assert.match(c.html, /Approve on your iPhone instead/); assert.equal(c.o.rpId, "localhost"); assert.deepEqual(c.o.ids, [a.credId]);
  assert.doesNotMatch(c.html, /name="code"|approval code/i, "nothing to type in the normal flow");
  const nonce = c.page.headers.get("content-security-policy")!.match(/'nonce-([a-f0-9]+)'/)?.[1]; assert.ok(nonce); assert.match(c.html, new RegExp(`<script nonce="${nonce}">`));
  assert.match(c.page.headers.get("content-security-policy")!, /form-action 'self' cursor:/);
  const r = await c.viaPasskey(a); assert.equal(r.status, 302, await r.clone().text());
  const loc = new URL(r.headers.get("location")!); assert.ok(loc.href.startsWith(CB)); assert.ok(loc.searchParams.get("code"));
  const tok = await call("/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code: loc.searchParams.get("code")!, redirect_uri: CB, client_id: c.client.client_id, code_verifier: c.verifier, resource: `${ORIGIN}/mcp` }).toString() });
  assert.equal(tok.status, 200);
  assert.ok(!logs.some((l) => l.includes(ENROLL)), "enroll token never logged");
});

test("ATTACK P1: a passkey assertion made for another site (phishing origin) is refused", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  assert.equal((await (await consent()).viaPasskey(a, { origin: "https://evil.example" })).status, 400);
});
test("ATTACK P2: an assertion without user verification (no Face ID) is refused", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  a.uv = false; assert.equal((await (await consent()).viaPasskey(a)).status, 400);
});
test("ATTACK P3: an approval captured for one connect request can't approve another app's request", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const c1 = await consent(); const s = await a.get(c1.o.challenge);
  const fields = { pk_token: c1.token, pk_id: s.id, pk_cdj: s.clientDataJSON, pk_ad: s.authenticatorData, pk_sig: s.signature };
  const moved = await (await consent()).submit(fields); assert.equal(moved.status, 400); assert.match(await moved.text(), /Face ID didn['’]t confirm/);
  assert.equal((await c1.submit(fields)).status, 302, "the moved try didn't burn the real one");
});
test("ATTACK P4: a Face ID challenge works once, even after a failed try", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const c = await consent(); assert.equal((await c.viaPasskey(a, { origin: "https://evil.example" })).status, 400);
  const r = await c.viaPasskey(a); assert.equal(r.status, 400, "the challenge was spent by the failed try"); assert.match(await r.text(), /Allow with Face ID/, "the retry page has a fresh button");
});
test("ATTACK P5: a stranger's key claiming the enrolled credential id is refused", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const stranger = await new VirtualAuthenticator(ORIGIN).init(); stranger.id = a.id;
  assert.equal((await (await consent()).viaPasskey(stranger)).status, 400);
});
test("ATTACK P6: a leaked enroll link enrolls only once", async () => {
  await freshEnv(); assert.equal((await enroll(await new VirtualAuthenticator(ORIGIN).init())).ok, true);
  const r = await enroll(await new VirtualAuthenticator(ORIGIN).init()); assert.equal(r.ok, false); assert.match(r.message, /already used/);
  assert.equal((await loadPasskeys(env)).length, 1);
});
test("ATTACK P7: a cloned passkey whose counter steps back is refused", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  assert.equal((await (await consent()).viaPasskey(a, { bump: 7 })).status, 302);
  a.count = 3; assert.equal((await (await consent()).viaPasskey(a)).status, 400);
});
test("ATTACK P8: Don't allow wins even when the form also carries a valid Face ID approval", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const d = await (await consent()).viaPasskey(a, {}, { decision: "deny" }); assert.equal(d.status, 302); assert.equal(new URL(d.headers.get("location")!).searchParams.get("error"), "access_denied");
});
test("connect: a code field shows only while an owner recovery code is live, off means no button and no script", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  assert.doesNotMatch((await consent()).html, /name="code"/);
  await recovery(); const c2 = await consent(); assert.match(c2.html, /name="code"/); assert.equal((await c2.submit({ code: CODE, decision: "approve" })).status, 302);
  assert.doesNotMatch((await consent()).html, /name="code"/, "a used recovery code takes the field away again");
  await freshEnv({ PASSKEYS: "off" }); kv.m.clear();
  const c3 = await consent(); assert.doesNotMatch(c3.html, /<script|name="code"/); assert.match(c3.html, /Face ID is off/); assert.doesNotMatch(c3.page.headers.get("content-security-policy")!, /script-src/);
  await freshEnv(); const c4 = await consent(); assert.doesNotMatch(c4.html, /id="pk"|name="code"/, "nothing enrolled yet: no button and no code");
  assert.match(c4.html, /Waiting for you to turn on Face\u00a0ID\./); assert.match(c4.html, /npm run add-device/);
  assert.match(c4.html, /<details class="owner" open>/, "the command sits in Setup help, not the main copy");
});

test("setup: --add-device opens the link in the browser (no code, no QR), --qr prints the fallback, --reset-passkeys orphans every passkey", async () => {
  const saved: Record<string, string> = {}; let out = ""; const opened: string[] = [];
  await cliAction("--add-device", async (n, v) => { saved[n] = v; }, (s) => (out += s), "https://holdt.example.workers.dev/", {}, async (u) => { opened.push(u); return true; });
  const token = opened[0]?.match(/\/enroll#([\w-]+)$/)?.[1]; assert.ok(token, opened.join());
  assert.equal(saved.APPROVAL_CODE_HASH, undefined, "no approval code"); assert.doesNotMatch(out, /\d{4}-\d{4}|█/); assert.match(out, /Click Save passkey there\. That's the only step\./);
  assert.ok(!out.includes(token!), "the link isn't printed when the browser opened it");
  assert.equal(saved.ENROLL_TOKEN_HASH, createHash("sha256").update(token!).digest("hex")); assert.ok(!Object.values(saved).includes(token!));
  let out2 = ""; const opened2: string[] = [];
  await cliAction("--add-device", async (n, v) => { saved[n] = v; }, (s) => (out2 += s), "https://holdt.example.workers.dev/", {}, async (u) => { opened2.push(u); return true; }, ["--qr"]);
  assert.equal(opened2.length, 0); assert.match(out2, /\/enroll#[\w-]+/); assert.match(out2, /█/, "a terminal QR code for a phone");
  let out3 = "";
  await cliAction("--add-device", async (n, v) => { saved[n] = v; }, (s) => (out3 += s), "https://holdt.example.workers.dev/", {}, async () => false);
  assert.match(out3, /\/enroll#[\w-]+/, "no browser on this machine: the link and QR print instead"); assert.match(out3, /█/);
  const before = { ...saved }; let out4 = "";
  await cliAction("--add-device", async (n, v) => { saved[n] = v; }, (s) => (out4 += s), "", {}, async () => true);
  assert.deepEqual(saved, before, "no WORKER_URL: no token is saved"); assert.match(out4, /Set WORKER_URL/); assert.doesNotMatch(out4, /enroll#/);
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  assert.match((await consent()).html, /Allow with Face ID/);
  await cliAction("--reset-passkeys", async (n, v) => { saved[n] = v; }, (s) => (out += s));
  env.PASSKEY_EPOCH = saved.PASSKEY_EPOCH; assert.doesNotMatch((await consent()).html, /Allow with Face ID/);
  assert.doesNotMatch(out, /Approval codes still work/);
});

const fakeCred = (i: number) => ({ id: `cred-${i}-` + "x".repeat(20), jwk: { kty: "EC" }, alg: -7 as const, signCount: 0, createdAt: Date.now() });
test("ATTACK P9: a stale counter write can't roll a passkey's counter back (Durable Object and KV stores)", async () => {
  for (const over of [{ GUARD: new MockGuardNS() }, {}]) {
    await freshEnv(over);
    const c = fakeCred(1); assert.equal(await addPasskey(env, c), "ok");
    assert.equal(await bumpPasskey(env, c, 7), true);
    assert.equal(await bumpPasskey(env, c, 6), false, "the slower sign-in loses");
    assert.equal(await bumpPasskey(env, c, 7), false, "the same counter twice is a clone");
    await Promise.all([bumpPasskey(env, c, 8), bumpPasskey(env, c, 9)]);
    assert.equal((await loadPasskeys(env))[0]!.signCount, 9);
  }
});
test("ATTACK P10: eleven enrollments at once still leave at most 10 passkeys (Durable Object)", async () => {
  await freshEnv({ GUARD: new MockGuardNS() });
  const r = await Promise.all(Array.from({ length: 11 }, (_, i) => addPasskey(env, fakeCred(i))));
  assert.equal(r.filter((x) => x === "ok").length, MAX_PASSKEYS); assert.equal(r.filter((x) => x === "full").length, 1);
  assert.equal(await addPasskey(env, fakeCred(3)), "dup");
});
test("ATTACK P11: a store holding more than 10 passkeys turns one-tap off instead of trusting them", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  for (let i = 0; i < MAX_PASSKEYS; i++) await kv.put(`passkey:v1:0:extra${i}`, JSON.stringify(fakeCred(i))); // written around enrollment
  const c = await consent(); assert.doesNotMatch(c.html, /Allow with Face ID|id="pk"/);
  const s = await a.get("AAAA");
  const r = await c.submit({ pk_token: "x.y", pk_id: s.id, pk_cdj: s.clientDataJSON, pk_ad: s.authenticatorData, pk_sig: s.signature });
  assert.equal(r.status, 400); assert.match(await r.text(), /paused on this server/);
});

test("ATTACK P12: the setup link is the owner's proof: hash only, fragment only, 10 minutes, once", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init();
  assert.ok(![...kv.m.values()].some((v) => String(v).includes(ENROLL)) && !Object.values(env).includes(ENROLL), "only the hash is stored");
  assert.match((await enroll(a, "x" + ENROLL)).message, /isn't valid/);
  assert.equal((await enroll(a)).ok, true);
  assert.match((await enroll(await new VirtualAuthenticator(ORIGIN).init())).message, /already used/);
  assert.ok(!logs.some((l) => l.includes(ENROLL)), "never logged");
});
test("F3 (red team): a signed consent ctx works only with the consent handle it was made for", async () => {
  await freshEnv(); await enroll(await new VirtualAuthenticator(ORIGIN).init());
  const A = await consent("https://www.cursor.com/agents/mcp/oauth/callback"), B = await consent();
  const f = (h: string, n: string) => unesc(h.match(new RegExp(`name="${n}" value="([^"]*)"`))?.[1] ?? "");
  const away = (handle: string, c: string) => post("/authorize/away/new", { handle, ctx: c });
  assert.equal((await away(f(B.html, "handle"), f(B.html, "ctx"))).status, 200, "its own ctx still works");
  assert.equal((await away(f(B.html, "handle"), f(A.html, "ctx"))).status, 400, "flow A's vouched-for Grok Bot name can't describe flow B's request");
  const retry = await (await B.submit({ ctx: f(A.html, "ctx"), decision: "approve", code: "00000000" })).text();
  assert.doesNotMatch(retry, /Connect Grok Bot/, "the re-shown page doesn't take the name from another flow's ctx");
});

test("a new device shows on the next consent pages and in connection_status for 7 days", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const withNotice = (await consent("https://www.cursor.com/agents/mcp/oauth/callback")).html;
  assert.doesNotMatch(withNotice, /id="pk"[^>]*data-auto/, "with a security notice the sheet waits for a tap, so the notice is read first");
  assert.match((await consent()).html, /A new device was added today at[\s\u00a0]\d+:\d\d[\s\u00a0][AP]M\.(?: |<br>)Not you\? Choose[\s\u00a0]Don’t[\s\u00a0]allow\./);
  const { mcpEndpoint } = await import("../src/worker.js");
  const st = async () => (await (await mcpEndpoint(new Request(ORIGIN + "/mcp", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "connection_status", arguments: {} } }) }), env, { epoch: env.GRANT_EPOCH }, fetch)).json() as any).result.structuredContent;
  const s1 = await st(); assert.equal(s1.passkeys.length, 1); assert.equal(s1.passkeys[0].added_with, "setup link"); assert.match(s1.device_notice, /New device added .*reset-passkeys/);
  const recs = await kv.list({ prefix: "passkey:" }); for (const k of recs.keys) { const c = JSON.parse((await kv.get(k.name))!); c.createdAt -= 8 * 86400_000; await kv.put(k.name, JSON.stringify(c)); }
  const later = (await consent()).html; assert.doesNotMatch(later, /id="pk"[^>]*data-auto/, "an unverified app always waits for a tap");
  assert.doesNotMatch((await consent("https://www.cursor.com/agents/mcp/oauth/callback")).html, /data-auto/, "anyone can register on Grok Bot's callback, so even there the sheet waits for a tap (red team M1/F2)");
  assert.doesNotMatch(later, /was added today|New devices:/); const s2 = await st(); assert.equal(s2.device_notice, undefined); assert.equal(s2.passkeys.length, 1);
});
