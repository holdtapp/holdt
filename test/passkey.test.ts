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

async function enroll(a: VirtualAuthenticator, token = ENROLL) {
  const o: any = await (await post("/enroll/options", { token })).json(); if (!o.ok) return o;
  const r = await a.create(o.publicKey.challenge);
  return (await post("/enroll/finish", { token, challenge_token: o.challenge_token, ...r })).json() as Promise<any>;
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
  const o: any = await (await post("/enroll/options", { token: ENROLL })).json();
  const bad = await a.create(o.publicKey.challenge, { origin: "https://evil.example" });
  assert.match((await (await post("/enroll/finish", { token: ENROLL, challenge_token: o.challenge_token, ...bad })).json() as any).message, /Couldn't save/);
  // that challenge is spent even though it failed
  const good = await a.create(o.publicKey.challenge);
  assert.equal((await (await post("/enroll/finish", { token: ENROLL, challenge_token: o.challenge_token, ...good })).json() as any).ok, false);
  assert.equal((await enroll(a)).ok, true);
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
  const moved = await (await consent()).submit(fields); assert.equal(moved.status, 400); assert.match(await moved.text(), /Face ID didn&#39;t confirm/);
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
  assert.equal(JSON.parse((await kv.get("passkeys:v1:0"))!).length, 1);
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
  assert.equal(saved.ENROLL_TOKEN_HASH, createHash("sha256").update(token!).digest("hex")); assert.ok(!Object.values(saved).includes(token!));
  await freshEnv(); const a = await new VirtualAuthenticator(ORIGIN).init(); await enroll(a);
  assert.match((await consent()).html, /Face ID/);
  await cliAction("--reset-passkeys", async (n, v) => { saved[n] = v; }, (s) => (out += s));
  env.PASSKEY_EPOCH = saved.PASSKEY_EPOCH; assert.doesNotMatch((await consent()).html, /Face ID/);
});
