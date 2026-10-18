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
    APPROVAL_CODE_HASH: await sha256Hex(`icloud-mcp-approval:${CODE}`), APPROVAL_CODE_ISSUED: String(Date.now()),
    PASSKEYS: "on", ENROLL_TOKEN_HASH: createHash("sha256").update(ENROLL).digest("hex"), ENROLL_TOKEN_ISSUED: String(Date.now()), ...over };
}
const ctx = () => ({ waitUntil() {}, passThroughOnException() {}, props: undefined });
const call = (path: string, init: RequestInit = {}) => providerFor(ORIGIN, fetch).fetch(new Request(ORIGIN + path, { redirect: "manual", ...init }), env, ctx() as any);
const post = (path: string, o: unknown) => call(path, { method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN }, body: JSON.stringify(o) });
const unesc = (s: string) => s.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n));
const b64u = (b: Buffer) => b.toString("base64url");

/** Enroll with the approval code (the default) or with a passkey already on the server (`by`). Afterwards the code is
 * made fresh again, as `npm run setup -- --new-code` would, so a test can still connect with CODE. */
async function enroll(a: VirtualAuthenticator, token = ENROLL, o2: { code?: string; by?: VirtualAuthenticator } = {}) {
  // The code is checked in /enroll/options, before the authenticator creates anything (no orphan passkeys on a typo).
  const o: any = await (await post("/enroll/options", { token, code: o2.by ? "" : (o2.code ?? CODE) })).json(); if (!o.ok) return o;
  const r = await a.create(o.publicKey.challenge);
  const auth = o2.by && o.auth ? { challenge_token: o.auth.challenge_token, ...(await o2.by.get(o.auth.challenge)) } : undefined;
  const out: any = await (await post("/enroll/finish", { token, challenge_token: o.challenge_token, ...r, auth })).json();
  await kv.delete(`approval-used:${env.APPROVAL_CODE_HASH}`); await kv.delete(`approval-fail:${env.APPROVAL_CODE_HASH}`);
  return out;
}
async function consent() {
  const reg: any = await (await call("/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name: "Grok Bot", redirect_uris: [CB], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) })).json();
  const verifier = b64u(randomBytes(32));
  const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: CB, code_challenge: b64u(createHash("sha256").update(verifier).digest()), code_challenge_method: "S256", state: "s1", scope: "calendar", resource: `${ORIGIN}/mcp` });
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
  await freshEnv({ ENROLL_TOKEN_ISSUED: String(Date.now() - 16 * 60_000) });
  assert.match((await enroll(a)).message, /expired/);
  await freshEnv({ PASSKEYS: undefined });
  assert.equal((await call("/enroll")).status, 404); assert.match((await enroll(a)).message, /turned off/);
});

test("enroll: a challenge is single use and bound to the enroll token, and a wrong-origin passkey is refused", async () => {
  await freshEnv();
  const a = await new VirtualAuthenticator(ORIGIN).init();
  const o: any = await (await post("/enroll/options", { token: ENROLL, code: CODE })).json();
  const bad = await a.create(o.publicKey.challenge, { origin: "https://evil.example" });
  assert.match((await (await post("/enroll/finish", { token: ENROLL, challenge_token: o.challenge_token, ...bad })).json() as any).message, /wasn't saved/);
  // that challenge is spent even though it failed
  const good = await a.create(o.publicKey.challenge);
  assert.equal((await (await post("/enroll/finish", { token: ENROLL, challenge_token: o.challenge_token, ...good })).json() as any).ok, false);
  await kv.delete(`approval-used:${env.APPROVAL_CODE_HASH}`); // the code was spent in /enroll/options, as a new code would
  assert.equal((await enroll(a)).ok, true);
});

test("enroll: a wrong code is refused before the authenticator runs, and a code-less finish is refused", async () => {
  await freshEnv();
  const wrong: any = await (await post("/enroll/options", { token: ENROLL, code: "11112222" })).json();
  assert.equal(wrong.ok, false); assert.equal(wrong.field, "code"); assert.equal(wrong.publicKey, undefined, "no creation options, so no passkey can be made");
  const a = await new VirtualAuthenticator(ORIGIN).init();
  const o: any = await (await post("/enroll/options", { token: ENROLL })).json();
  const r = await a.create(o.publicKey.challenge);
  const out: any = await (await post("/enroll/finish", { token: ENROLL, challenge_token: o.challenge_token, ...r })).json();
  assert.equal(out.ok, false); assert.match(out.message, /approval code/);
  assert.equal((await loadPasskeys(env)).length, 0);
});

test("connect: Allow with Face ID approves with no code typed, and the token works", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const c = await consent();
  assert.match(c.html, /Allow with Face ID/); assert.match(c.html, /Use an approval code/); assert.equal(c.o.rpId, "localhost"); assert.deepEqual(c.o.ids, [a.credId]);
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
test("connect: the code fallback still works with passkeys on, and off means no button and no script", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  const c2 = await consent(); assert.equal((await c2.submit({ code: CODE, decision: "approve" })).status, 302);
  await freshEnv({ PASSKEYS: "off" }); kv.m.clear();
  const c3 = await consent(); assert.doesNotMatch(c3.html, /Face ID|<script/); assert.doesNotMatch(c3.page.headers.get("content-security-policy")!, /script-src/);
  await freshEnv(); const c4 = await consent(); assert.doesNotMatch(c4.html, /Face ID/, "nothing enrolled yet: code only");
});

test("setup: --add-device saves only the token's hash and prints a fragment link, --reset-passkeys orphans every passkey", async () => {
  const saved: Record<string, string> = {}; let out = "";
  await cliAction("--add-device", async (n, v) => { saved[n] = v; }, (s) => (out += s), "https://holdt.example.workers.dev/");
  const token = out.match(/\/enroll#([\w-]+)/)?.[1]; assert.ok(token, out);
  assert.match(out, /asks for this approval code.*\d{4}-\d{4}/); assert.match(saved.APPROVAL_CODE_HASH!, /^pbkdf2\$/);
  assert.equal(saved.ENROLL_TOKEN_HASH, createHash("sha256").update(token!).digest("hex")); assert.ok(!Object.values(saved).includes(token!));
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  assert.match((await consent()).html, /Face ID/);
  await cliAction("--reset-passkeys", async (n, v) => { saved[n] = v; }, (s) => (out += s));
  env.PASSKEY_EPOCH = saved.PASSKEY_EPOCH; assert.doesNotMatch((await consent()).html, /Face ID/);
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

test("ATTACK P12: a leaked enroll link alone can't add a device: it needs the approval code", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init();
  const none = await enroll(a, ENROLL, { code: "" }); assert.equal(none.ok, false); assert.match(none.message, /code/);
  const wrong = await enroll(a, ENROLL, { code: "11112222" }); assert.equal(wrong.ok, false); assert.match(wrong.message, /doesn't match/);
  assert.equal((await loadPasskeys(env)).length, 0);
  assert.equal((await enroll(a)).ok, true, "the right code works, and the link was still unused");
  assert.ok(logs.some((l) => /passkey enrolled: device "unnamed" via approval code, 1 on this server/.test(l)), "each enroll is logged");
});
test("ATTACK P13: a second device can be added with an existing passkey, but not with a stranger's", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); assert.equal((await enroll(a)).ok, true);
  env.ENROLL_TOKEN_HASH = createHash("sha256").update(ENROLL + "2").digest("hex");
  const stranger = await new VirtualAuthenticator(ORIGIN).init(); stranger.id = a.id;
  const b = await new VirtualAuthenticator(ORIGIN).init();
  assert.equal((await enroll(b, ENROLL + "2", { by: stranger })).ok, false);
  env.ENROLL_TOKEN_HASH = createHash("sha256").update(ENROLL + "3").digest("hex");
  assert.equal((await enroll(b, ENROLL + "3", { by: a })).ok, true);
  assert.ok(logs.some((l) => /via existing passkey, 2 on this server/.test(l)));
});
test("a new device shows on the next consent pages and in connection_status for 7 days", async () => {
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  assert.match((await consent()).html, /Face ID was turned on for a new device today at \d+:\d\d[\s\u00a0][AP]M\. Not you\? Tap[\s\u00a0]Don’t[\s\u00a0]allow\./);
  const { mcpEndpoint } = await import("../src/worker.js");
  const st = async () => (await (await mcpEndpoint(new Request(ORIGIN + "/mcp", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "connection_status", arguments: {} } }) }), env, { epoch: env.GRANT_EPOCH }, fetch)).json() as any).result.structuredContent;
  const s1 = await st(); assert.equal(s1.passkeys.length, 1); assert.equal(s1.passkeys[0].added_with, "approval code"); assert.match(s1.device_notice, /New device added .*reset-passkeys/);
  const recs = await kv.list({ prefix: "passkey:" }); for (const k of recs.keys) { const c = JSON.parse((await kv.get(k.name))!); c.createdAt -= 8 * 86400_000; await kv.put(k.name, JSON.stringify(c)); }
  assert.doesNotMatch((await consent()).html, /was turned on for/); const s2 = await st(); assert.equal(s2.device_notice, undefined); assert.equal(s2.passkeys.length, 1);
});
