// Reviewer test path (src/reviewer.ts): multi-use, 14 days, revocable, bound to the test account, never on production.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync, mkdtempSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MockCalDav } from "./mock-caldav.js";
import { MockKV } from "./kv-mock.js";
import { providerFor } from "../src/worker.js";
import { sha256Hex } from "../src/authorize.js";
import { setLogSink } from "../src/redact.js";
import { normalizeReviewerCode, reviewerState, REVIEWER_TTL_MS, checkReviewerCode } from "../src/reviewer.js";
import { newReviewerCode } from "../setup/reviewer.js";
import { cliAction } from "../setup/server.js";

// The demo account's address must never reach a reviewer. This fixture plays that role.
const USER = "demo.owner@example.com", PASS = "qrst-uvwx-yzab-cdef", CODE = "48291376";
const ORIGIN = "http://localhost:8787", CB = "cursor://anysphere.cursor-mcp/oauth/callback";
const logs: string[] = []; setLogSink((l) => logs.push(l));
const cal = new MockCalDav({ user: USER, pass: PASS });
before(async () => { await cal.start(); });
after(async () => { await cal.stop(); });
let kv: MockKV; let env: any;
const RC = newReviewerCode(USER);

async function freshEnv(over: Record<string, unknown> = {}) {
  kv = new MockKV();
  env = { ICLOUD_EMAIL: USER, ICLOUD_APP_PASSWORD: PASS, CONFIRM_SECRET: "k".repeat(43), GRANT_EPOCH: "epoch-1-" + "e".repeat(30), TIMEZONE: "America/Denver", WRITES_ENABLED: "true", CALDAV_URL: cal.base, OAUTH_KV: kv, PASSKEYS: "on",
    APPROVAL_CODE_HASH: await sha256Hex(`icloud-mcp-approval:${CODE}`), APPROVAL_CODE_ISSUED: String(Date.now()),
    REVIEWER_MODE: "on", REVIEWER_CODE_HASH: RC.hash, REVIEWER_CODE_ISSUED: String(RC.issued), ...over };
}
const ctx = () => ({ waitUntil(_p: Promise<unknown>) {}, passThroughOnException() {}, props: undefined });
const call = (path: string, init: RequestInit = {}) => providerFor(ORIGIN, fetch).fetch(new Request(ORIGIN + path, { redirect: "manual", ...init }), env, ctx() as any);
const form = (o: Record<string, string>) => ({ method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(o).toString() });
const cookiesOf = (r: Response) => (r.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]).join("; ");
const b64u = (b: Buffer) => b.toString("base64url");
const unesc = (s: string) => s.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n));

async function connect() {
  const reg = await call("/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name: "Grok Bot", redirect_uris: [CB], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) });
  assert.equal(reg.status, 201); const client: any = await reg.json();
  const verifier = b64u(randomBytes(32)), challenge = b64u(createHash("sha256").update(verifier).digest()), state = b64u(randomBytes(8));
  const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: CB, code_challenge: challenge, code_challenge_method: "S256", state, scope: "calendar", resource: `${ORIGIN}/mcp` });
  const page = await call(`/authorize?${q}`); const html = await page.text(); assert.equal(page.status, 200);
  const handle = unesc(html.match(/name="handle" value="([^"]+)"/)![1]!), ctxField = unesc(html.match(/name="ctx" value="([^"]*)"/)![1]!), cookie = cookiesOf(page);
  const submit = (c: string, decision = "approve") => call("/authorize", { ...form({ handle, ctx: ctxField, code: c, decision }), headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookie, Origin: ORIGIN } });
  return { client, verifier, state, html, submit };
}
async function exchange(c: any, res: Response) {
  assert.equal(res.status, 302, await res.clone().text());
  const u = new URL(res.headers.get("location")!);
  const r = await call("/oauth/token", form({ grant_type: "authorization_code", code: u.searchParams.get("code")!, redirect_uri: CB, client_id: c.client.client_id, code_verifier: c.verifier, resource: `${ORIGIN}/mcp` }));
  assert.equal(r.status, 200); return r.json() as Promise<any>;
}
const mcp = (token: string, method = "tools/list", params: unknown = {}) => call("/mcp", { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
const tool = async (t: string, name: string, args: unknown = {}) => { const r = await mcp(t, "tools/call", { name, arguments: args }); return { status: r.status, text: await r.text() }; };
async function reviewerToken() { const c = await connect(); return exchange(c, await c.submit(RC.display)); }

test("reviewer code: format is RVW plus 16 Crockford characters, typed loosely it still matches", () => {
  assert.match(RC.display, /^RVW(-[0-9A-HJKMNP-TV-Z]{4}){4}$/);
  assert.equal(normalizeReviewerCode(RC.display.toLowerCase().replace(/-/g, " ")), RC.code);
  assert.equal(normalizeReviewerCode(RC.display.replace(/0/g, "O").replace(/1/g, "l")), RC.code, "O and l read as 0 and 1");
  assert.equal(normalizeReviewerCode("RVW-1234"), undefined); assert.equal(normalizeReviewerCode("12345678"), undefined);
  const seen = new Set(Array.from({ length: 200 }, () => newReviewerCode(USER).code)); assert.equal(seen.size, 200, "fresh randomness each time");
  assert.equal(RC.expiresAt - RC.issued, 14 * 86_400_000);
});

test("reviewer code is multi-use: several reviewers connect with the same code and every connection works", async () => {
  await freshEnv();
  const c = await connect(); assert.match(c.html, /Reviewing Holdt\?/); assert.match(c.html, /inputmode="text"/);
  const tokens = [];
  for (let i = 0; i < 4; i++) tokens.push((await reviewerToken()).access_token);
  for (const t of tokens) { const r = await tool(t, "list_calendars"); assert.equal(r.status, 200); assert.match(r.text, /"Home"/); }
  // the owner's one-time code is untouched by reviewer use and still connects once
  const o = await connect(); assert.equal((await o.submit(CODE)).status, 302);
});

test("ATTACK RV1: reviewer code works for 14 days and then stops, for new and existing reviewer connections", async () => {
  await freshEnv({ REVIEWER_CODE_ISSUED: String(Date.now() - (REVIEWER_TTL_MS - 60_000)) });
  const t = (await reviewerToken()).access_token; assert.equal((await mcp(t)).status, 200, "day 13 still fine");
  env.REVIEWER_CODE_ISSUED = String(Date.now() - REVIEWER_TTL_MS - 1000);
  assert.equal((await mcp(t)).status, 401, "existing reviewer connection cut at day 14");
  const c = await connect(); assert.doesNotMatch(c.html, /Reviewing Holdt\?/, "hint gone once the code has ended");
  const r = await c.submit(RC.display); assert.equal(r.status, 400); assert.match(unesc(await r.text()), /has ended/);
  // a future-dated issue time is refused rather than stretching the window
  assert.equal((await reviewerState({ ...env, REVIEWER_CODE_ISSUED: String(Date.now() + 86_400_000) })).active, false);
});

test("ATTACK RV2: revoke, setting the hash to revoked, or a KV revoke marker, stops the code and cuts reviewer connections, owner stays connected", async () => {
  await freshEnv();
  const rt = (await reviewerToken()).access_token;
  const oc = await connect(); const ot = (await exchange(oc, await oc.submit(CODE))).access_token;
  env.REVIEWER_CODE_HASH = "revoked";
  assert.equal((await mcp(rt)).status, 401); assert.equal((await mcp(ot)).status, 200, "owner connection unaffected");
  const r = await (await connect()).submit(RC.display); assert.equal(r.status, 400);

  await freshEnv(); const rt2 = (await reviewerToken()).access_token;
  const st: any = await reviewerState(env); await kv.put(`reviewer-revoked:${st.id}`, "1");
  assert.equal((await mcp(rt2)).status, 401);
  // a fresh code after revoking works, and the old code's connections stay dead
  const fresh = newReviewerCode(USER); env.REVIEWER_CODE_HASH = fresh.hash; env.REVIEWER_CODE_ISSUED = String(fresh.issued);
  assert.equal((await mcp(rt2)).status, 401, "old code's connection does not come back with a new code");
  const c = await connect(); assert.equal((await c.submit(RC.display)).status, 400, "old code refused");
  const c2 = await connect(); assert.equal((await c2.submit(fresh.display)).status, 302, "new code works");
});

test("ATTACK RV3: scope, a code minted for the test account matches on no other account, and a changed account cuts reviewer connections", async () => {
  await freshEnv({ ICLOUD_EMAIL: "someone.else@example.com" });
  const r = await (await connect()).submit(RC.display); assert.equal(r.status, 400); assert.match(unesc(await r.text()), /doesn['’]t match/);
  await freshEnv(); const t = (await reviewerToken()).access_token; assert.equal((await mcp(t)).status, 200);
  env.ICLOUD_EMAIL = "someone.else@example.com"; assert.equal((await mcp(t)).status, 401);
});

test("ATTACK RV4: production stays closed, without REVIEWER_MODE on, a valid reviewer code connects nothing and the page shows no hint", async () => {
  await freshEnv({ REVIEWER_MODE: undefined });
  const c = await connect(); assert.doesNotMatch(c.html, /Reviewing Holdt\?|reviewer code/i); assert.match(c.html, /inputmode="numeric"/);
  const r = await c.submit(RC.display); assert.equal(r.status, 400); assert.match(unesc(await r.text()), /aren['’]t accepted on this server/);
  // a grant that claims to be a reviewer grant is refused too
  assert.equal((await checkReviewerCode(env, RC.display)).ok, false);
  const wrangler = readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8");
  assert.doesNotMatch(wrangler, /^\s*REVIEWER_MODE\s*=/m, "production wrangler.toml never turns the reviewer path on");
});

test("ATTACK RV5: wrong reviewer codes never lock reviewers out and never charge the owner's approval-code tries", async () => {
  await freshEnv();
  const c = await connect();
  for (let i = 0; i < 12; i++) { const w = await c.submit(`RVW-${"0".repeat(4)}-${"1".repeat(4)}-${"2".repeat(4)}-${String(i).padStart(4, "3")}`); assert.equal(w.status, 400); }
  assert.equal((await c.submit(RC.display)).status, 302, "real reviewer code still works after many wrong tries");
  const o = await connect(); assert.equal((await o.submit(CODE)).status, 302, "owner code was not locked by reviewer misses");
  const bad = await (await connect()).submit("RVW-12"); assert.match(unesc(await bad.text()), /isn['’]t complete/);
});

test("the test account's address never reaches a reviewer: consent page, errors and every read tool", async () => {
  await freshEnv();
  const c = await connect(); const pages = [c.html, await (await c.submit("RVW-0000-0000-0000-0000")).text()];
  const t = (await exchange(c, await c.submit(RC.display))).access_token;
  const out: string[] = [(await mcp(t)).status.toString(), await (await mcp(t)).text()];
  for (const [n, a] of [["connection_status", {}], ["list_calendars", {}], ["list_events", { from: "2026-10-01", to: "2026-12-31" }], ["search_events", { query: "a" }], ["list_changes", {}], ["find_free_time", {}], ["resolve_dates", { phrases: ["tomorrow"] }]] as const) out.push((await tool(t, n, a)).text);
  const ids = [...out.join("").matchAll(/"event_id":"([^"]+)"/g)].map((m) => m[1]);
  for (const id of ids.slice(0, 5)) out.push((await tool(t, "get_event", { event_id: id })).text);
  const blob = [...pages, ...out].join("\n").toLowerCase();
  assert.ok(!blob.includes(USER.toLowerCase()), "demo address leaked to a reviewer");
  assert.ok(!blob.includes("demo.owner"), "local part leaked to a reviewer");
});

test("CLI: mints only for a named demo Worker, writes the code to a 600 file, never prints it, revoke works", async () => {
  const saved: Record<string, string> = {}; const lines: string[] = []; const save = async (n: string, v: string) => { saved[n] = v; };
  const dir = mkdtempSync(join(tmpdir(), "holdt-rv-")); const file = join(dir, "code.txt");
  await cliAction("--new-reviewer-code", save, (s) => lines.push(s), undefined, { workerName: "holdt", account: USER, codeFile: file });
  assert.deepEqual(saved, {}, "refuses the production Worker name"); assert.ok(!existsSync(file));
  await cliAction("--new-reviewer-code", save, (s) => lines.push(s), undefined, { workerName: "holdt-demo", account: USER, codeFile: file });
  const code = readFileSync(file, "utf8").trim(); assert.match(code, /^RVW-/); assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.match(saved.REVIEWER_CODE_HASH!, /^pbkdf2\$/); assert.ok(Number(saved.REVIEWER_CODE_ISSUED) > 0);
  const printed = lines.join("\n"); assert.ok(!printed.includes(code) && !printed.includes(code.replace(/-/g, "")), "code printed"); assert.ok(!printed.includes(USER), "address printed");
  assert.doesNotMatch(printed, /;/, "no semicolons in user-facing copy");
  // the saved hash verifies on a Worker for the same account
  await freshEnv({ REVIEWER_CODE_HASH: saved.REVIEWER_CODE_HASH, REVIEWER_CODE_ISSUED: saved.REVIEWER_CODE_ISSUED });
  assert.equal((await (await connect()).submit(code)).status, 302);
  await cliAction("--revoke-reviewer", save, (s) => lines.push(s), undefined, { workerName: "holdt-demo" });
  assert.equal(saved.REVIEWER_CODE_HASH, "revoked");
  await assert.rejects(() => cliAction("--new-reviewer-code", save, () => {}, undefined, { workerName: "holdt-demo", account: "", codeFile: file }), /HOLDT_REVIEWER_ACCOUNT/);
});

test("SECRET SAFETY (reviewer): no reviewer code, its hash, the demo address or the password in any log line or KV value", async () => {
  const blob = logs.join("\n"); assert.ok(logs.some((l) => /reviewer code/.test(l)));
  for (const bad of [RC.code, RC.display, RC.hash, USER, PASS]) assert.ok(!blob.includes(bad), `leaked ${bad.slice(0, 3)}…`);
  for (const [k, v] of kv.m) for (const bad of [RC.code, RC.display, USER, PASS]) assert.ok(!v.v.includes(bad), k);
});

test("reviewer-facing copy has no semicolons", () => {
  const src = readFileSync(new URL("../src/reviewer.ts", import.meta.url), "utf8");
  const lines = src.split("\n").filter((l) => /message|const ENDED/.test(l));
  const msgs = lines.flatMap((l) => [...l.matchAll(/"([A-Z][^"]{12,})"/g)].map((m) => m[1]!));
  assert.ok(msgs.length >= 4, String(msgs.length)); for (const m of msgs) assert.doesNotMatch(m, /;/, m);
  const auth = readFileSync(new URL("../src/authorize.ts", import.meta.url), "utf8");
  const hint = auth.match(/Reviewing Holdt\?[^<]*/)![0]; assert.doesNotMatch(hint, /;/);
  const doc = readFileSync(new URL("../docs/reviewer-testing.md", import.meta.url), "utf8");
  assert.doesNotMatch(doc.split("## For the owner")[0]!, /;/, "reviewer section of the doc");
  assert.doesNotMatch(doc, /@(?!holdt\.app\b)[a-z0-9-]+\.[a-z]/i, "only test@holdt.app may appear as an address");
});
