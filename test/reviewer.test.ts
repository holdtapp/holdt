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

/** The reviewer's one tap on the reviewer link page: the fragment's code, posted same-origin. Returns the pass cookie. */
async function claim(code: string, over: Record<string, string> = {}) {
  const r = await call("/review/claim", { method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN, ...over }, body: JSON.stringify({ code }) });
  return { status: r.status, body: await r.json() as any, cookie: cookiesOf(r) };
}
async function connect(pass = "") {
  const reg = await call("/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name: "Grok Bot", redirect_uris: [CB], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) });
  assert.equal(reg.status, 201); const client: any = await reg.json();
  const verifier = b64u(randomBytes(32)), challenge = b64u(createHash("sha256").update(verifier).digest()), state = b64u(randomBytes(8));
  const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: CB, code_challenge: challenge, code_challenge_method: "S256", state, scope: "calendar", resource: `${ORIGIN}/mcp` });
  const page = await call(`/authorize?${q}`, pass ? { headers: { Cookie: pass } } : {}); const html = await page.text(); assert.equal(page.status, 200);
  const handle = unesc(html.match(/name="handle" value="([^"]+)"/)![1]!), ctxField = unesc(html.match(/name="ctx" value="([^"]*)"/)![1]!), cookie = cookiesOf(page);
  const submit = (c: string, decision = "approve") => call("/authorize", { ...form({ handle, ctx: ctxField, code: c, decision }), headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: [cookie, pass].filter(Boolean).join("; "), Origin: ORIGIN } });
  const allow = () => submit("", "reviewer");
  return { client, verifier, state, html, submit, allow };
}
async function exchange(c: any, res: Response) {
  assert.equal(res.status, 302, await res.clone().text());
  const u = new URL(res.headers.get("location")!);
  const r = await call("/oauth/token", form({ grant_type: "authorization_code", code: u.searchParams.get("code")!, redirect_uri: CB, client_id: c.client.client_id, code_verifier: c.verifier, resource: `${ORIGIN}/mcp` }));
  assert.equal(r.status, 200); return r.json() as Promise<any>;
}
const mcp = (token: string, method = "tools/list", params: unknown = {}) => call("/mcp", { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
const tool = async (t: string, name: string, args: unknown = {}) => { const r = await mcp(t, "tools/call", { name, arguments: args }); return { status: r.status, text: await r.text() }; };
async function passFor(code = RC.display) { const c = await claim(code); assert.equal(c.status, 200, JSON.stringify(c.body)); return c.cookie; }
async function reviewerToken(pass?: string) { const c = await connect(pass ?? await passFor()); assert.match(c.html, /Allow as reviewer/); return exchange(c, await c.allow()); }

test("reviewer code: format is RVW plus 16 Crockford characters, typed loosely it still matches", () => {
  assert.match(RC.display, /^RVW(-[0-9A-HJKMNP-TV-Z]{4}){4}$/);
  assert.equal(normalizeReviewerCode(RC.display.toLowerCase().replace(/-/g, " ")), RC.code);
  assert.equal(normalizeReviewerCode(RC.display.replace(/0/g, "O").replace(/1/g, "l")), RC.code, "O and l read as 0 and 1");
  assert.equal(normalizeReviewerCode("RVW-1234"), undefined); assert.equal(normalizeReviewerCode("12345678"), undefined);
  const seen = new Set(Array.from({ length: 200 }, () => newReviewerCode(USER).code)); assert.equal(seen.size, 200, "fresh randomness each time");
  assert.equal(RC.expiresAt - RC.issued, 14 * 86_400_000);
});

test("reviewer link is one tap and multi-use: the page is static, the tap earns a pass, consent is one button, several reviewers connect", async () => {
  await freshEnv();
  const pg = await call("/review"); const html = await pg.text();
  assert.equal(pg.status, 200); assert.deepEqual(pg.headers.getSetCookie?.() ?? [], [], "GET /review sets no cookie and changes nothing");
  assert.match(html, /Turn on reviewer access/); assert.match(html, /location\.hash/); assert.match(html, /history\.replaceState/, "the fragment is stripped from the address bar");
  assert.doesNotMatch(html, /<input|inputmode/, "nothing to type");
  const before = await connect(); assert.match(before.html, /Reviewing Holdt\? Open the reviewer link/); assert.doesNotMatch(before.html, /inputmode="text"|RVW/);
  const tokens = [];
  for (let i = 0; i < 4; i++) tokens.push((await reviewerToken()).access_token);
  for (const t of tokens) { const r = await tool(t, "list_calendars"); assert.equal(r.status, 200); assert.match(r.text, /"Home"/); }
  // one pass serves the same reviewer again and again
  const pass = await passFor(); for (let i = 0; i < 2; i++) assert.equal(typeof (await reviewerToken(pass)).access_token, "string");
  // the owner's one-time code is untouched by reviewer use and still connects once
  const o = await connect(); assert.equal((await o.submit(CODE)).status, 302);
});

test("ATTACK RV1: reviewer access works for 14 days and then stops, for new and existing reviewer connections and for an issued pass", async () => {
  await freshEnv({ REVIEWER_CODE_ISSUED: String(Date.now() - (REVIEWER_TTL_MS - 60_000)) });
  const pass = await passFor();
  const t = (await reviewerToken(pass)).access_token; assert.equal((await mcp(t)).status, 200, "day 13 still fine");
  env.REVIEWER_CODE_ISSUED = String(Date.now() - REVIEWER_TTL_MS - 1000);
  assert.equal((await mcp(t)).status, 401, "existing reviewer connection cut at day 14");
  const c = await connect(pass); assert.doesNotMatch(c.html, /Reviewing Holdt\?|Allow as reviewer/, "hint and button gone once the link has ended");
  const r = await c.allow(); assert.equal(r.status, 400); assert.match(unesc(await r.text()), /has ended/);
  const cl = await claim(RC.display); assert.equal(cl.status, 400); assert.equal(cl.body.ended, true); assert.equal(cl.cookie, "");
  // a future-dated issue time is refused rather than stretching the window
  assert.equal((await reviewerState({ ...env, REVIEWER_CODE_ISSUED: String(Date.now() + 86_400_000) })).active, false);
});

test("ATTACK RV2: revoke, setting the hash to revoked, or a KV revoke marker, stops the link and cuts reviewer connections, owner stays connected", async () => {
  await freshEnv();
  const pass = await passFor(); const rt = (await reviewerToken(pass)).access_token;
  const oc = await connect(); const ot = (await exchange(oc, await oc.submit(CODE))).access_token;
  env.REVIEWER_CODE_HASH = "revoked";
  assert.equal((await mcp(rt)).status, 401); assert.equal((await mcp(ot)).status, 200, "owner connection unaffected");
  assert.equal((await (await connect(pass)).allow()).status, 400); assert.equal((await claim(RC.display)).status, 400);

  await freshEnv(); const pass2 = await passFor(); const rt2 = (await reviewerToken(pass2)).access_token;
  const st: any = await reviewerState(env); await kv.put(`reviewer-revoked:${st.id}`, "1");
  assert.equal((await mcp(rt2)).status, 401);
  // a fresh link after revoking works, and the old link, its pass and its connections stay dead
  const fresh = newReviewerCode(USER); env.REVIEWER_CODE_HASH = fresh.hash; env.REVIEWER_CODE_ISSUED = String(fresh.issued);
  assert.equal((await mcp(rt2)).status, 401, "old link's connection does not come back with a new link");
  assert.equal((await claim(RC.display)).status, 400, "old link refused");
  assert.equal((await (await connect(pass2)).allow()).status, 400, "old pass refused");
  assert.equal((await (await connect(await passFor(fresh.display))).allow()).status, 302, "new link works");
});

test("ATTACK RV3: scope, a link minted for the test account matches on no other account, and a changed account cuts reviewer connections and passes", async () => {
  await freshEnv({ ICLOUD_EMAIL: "someone.else@example.com" });
  const cl = await claim(RC.display); assert.equal(cl.status, 400); assert.match(cl.body.message, /doesn['’]t match/); assert.equal(cl.cookie, "");
  await freshEnv(); const pass = await passFor(); const t = (await reviewerToken(pass)).access_token; assert.equal((await mcp(t)).status, 200);
  env.ICLOUD_EMAIL = "someone.else@example.com"; assert.equal((await mcp(t)).status, 401);
  assert.equal((await (await connect(pass)).allow()).status, 400, "pass bound to the old account");
});

test("ATTACK RV4: production stays closed, without REVIEWER_MODE on, the link page does nothing, a claim earns nothing and the consent page shows no hint", async () => {
  await freshEnv(); const pass = await passFor();
  env.REVIEWER_MODE = undefined;
  const pg = await call("/review"); assert.equal(pg.status, 404); assert.doesNotMatch(await pg.text(), /<script/);
  const cl = await claim(RC.display); assert.equal(cl.status, 400); assert.equal(cl.cookie, ""); assert.match(cl.body.message, /don['’]t work on this server/);
  const c = await connect(pass); assert.doesNotMatch(c.html, /Reviewing Holdt\?|reviewer/i);
  assert.equal((await c.allow()).status, 400, "an old pass is dead on a server without reviewer mode");
  assert.equal((await checkReviewerCode(env, RC.display)).ok, false);
  const wrangler = readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8");
  assert.doesNotMatch(wrangler, /^\s*REVIEWER_MODE\s*=/m, "production wrangler.toml never turns the reviewer path on");
});

test("ATTACK RV5: wrong reviewer links never lock reviewers out and never charge the owner's approval-code tries", async () => {
  await freshEnv();
  for (let i = 0; i < 12; i++) { const w = await claim(`RVW-${"0".repeat(4)}-${"1".repeat(4)}-${"2".repeat(4)}-${String(i).padStart(4, "3")}`); assert.equal(w.status, 400); assert.equal(w.body.ended, false); }
  assert.equal((await claim(RC.display)).status, 200, "real link still works after many wrong tries");
  const o = await connect(); assert.equal((await o.submit(CODE)).status, 302, "owner code was not locked by reviewer misses");
  assert.match((await claim("RVW-12")).body.message, /isn['’]t complete/);
});

test("ATTACK RL1: reviewer claim CSRF, a cross-site or form-encoded POST earns no pass", async () => {
  await freshEnv();
  const x = await claim(RC.display, { Origin: "https://evil.example" }); assert.equal(x.status, 403); assert.equal(x.cookie, "");
  const f = await call("/review/claim", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: ORIGIN }, body: `code=${encodeURIComponent(RC.display)}` });
  assert.ok(f.status >= 400); assert.deepEqual(f.headers.getSetCookie?.() ?? [], []);
  const g = await call(`/review/claim?code=${encodeURIComponent(RC.display)}`); assert.ok(g.status >= 400); assert.deepEqual(g.headers.getSetCookie?.() ?? [], [], "never consumed on GET");
});

test("ATTACK RL2: a forged or tampered reviewer pass connects nothing", async () => {
  await freshEnv();
  const good = await passFor(); const [name, val] = [good.slice(0, good.indexOf("=")), good.slice(good.indexOf("=") + 1)];
  const st: any = await reviewerState(env);
  const data = Buffer.from(JSON.stringify({ rc: st.id, acct: st.acct, exp: Date.now() + REVIEWER_TTL_MS })).toString("base64");
  for (const bad of [`${name}=${data}.AAAA`, `${name}=${data}.${val.split(".")[1]}`, `${name}=${val.split(".")[0]}.${val.split(".")[1]!.slice(0, -2)}xx`, `${name}=garbage`]) {
    const c = await connect(bad); assert.doesNotMatch(c.html, /Allow as reviewer/); assert.equal((await c.allow()).status, 400, bad.slice(0, 30));
  }
  // a pass signed with another server's secret is refused too
  const other = { ...env, CONFIRM_SECRET: "z".repeat(43) }; const { mintReviewerPass } = await import("../src/reviewer.js");
  const foreign = (await mintReviewerPass(other, { via: "reviewer", rc: st.id, acct: st.acct }))!.cookie.split(";")[0]!;
  assert.equal((await (await connect(foreign)).allow()).status, 400);
});

test("ATTACK RL3: a reviewer pass does not outlive a revoke or a rotated link", async () => {
  await freshEnv(); const pass = await passFor();
  const fresh = newReviewerCode(USER); env.REVIEWER_CODE_HASH = fresh.hash; env.REVIEWER_CODE_ISSUED = String(fresh.issued);
  assert.equal((await (await connect(pass)).allow()).status, 400, "pass from the rotated link");
  await freshEnv(); const p2 = await passFor(); const st: any = await reviewerState(env); await kv.put(`reviewer-revoked:${st.id}`, "1");
  assert.equal((await (await connect(p2)).allow()).status, 400, "pass after a KV revoke");
});

test("ATTACK RL4: a reviewer pass expires with the link, never past 14 days, and its cookie is HttpOnly, Secure and host-only", async () => {
  await freshEnv({ REVIEWER_CODE_ISSUED: String(Date.now() - REVIEWER_TTL_MS + 5_000) });
  const r = await call("/review/claim", { method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN }, body: JSON.stringify({ code: RC.display }) });
  const sc = (r.headers.getSetCookie?.() ?? [])[0]!; assert.match(sc, /^__Host-holdt-rv=/); assert.match(sc, /HttpOnly/); assert.match(sc, /Secure/); assert.match(sc, /SameSite=Lax/); assert.match(sc, /Path=\//); assert.doesNotMatch(sc, /Domain=/i);
  assert.ok(Number(sc.match(/Max-Age=(\d+)/)![1]) <= 5, "pass ends when the link ends");
  const pass = sc.split(";")[0]!;
  assert.ok(pass.length > 20);
  // the pass's own clock is checked: even if the same link were live again later (re-dated issue time), a pass never lasts past 14 days
  const { readReviewerPass } = await import("../src/reviewer.js");
  await freshEnv(); const p = await passFor(); const v: any = JSON.parse(Buffer.from(p.split("=")[1]!.split(".")[0]!, "base64").toString());
  assert.ok(v.exp - Date.now() <= REVIEWER_TTL_MS, "never past 14 days");
  const later = Date.now() + REVIEWER_TTL_MS + 60_000, redated = { ...env, REVIEWER_CODE_ISSUED: String(later - 3_600_000) };
  assert.equal((await reviewerState(redated, later)).active, true, "the link itself is live at that moment");
  assert.equal((await readReviewerPass(redated, p, later)).ok, false, "but the 14-day pass is not");
  assert.equal((await readReviewerPass(env, p, Date.now())).ok, true, "and the same pass is fine today");
});

test("the test account's address never reaches a reviewer: link page, consent page, errors and every read tool", async () => {
  await freshEnv();
  const pass = await passFor();
  const c = await connect(pass); const pages = [await (await call("/review")).text(), JSON.stringify((await claim("RVW-0000-0000-0000-0000")).body), c.html, await (await (await connect("__Host-holdt-rv=x.y")).allow()).text()];
  const t = (await exchange(c, await c.allow())).access_token;
  const out: string[] = [(await mcp(t)).status.toString(), await (await mcp(t)).text()];
  for (const [n, a] of [["connection_status", {}], ["list_calendars", {}], ["list_events", { from: "2026-10-01", to: "2026-12-31" }], ["search_events", { query: "a" }], ["list_changes", {}], ["find_free_time", {}], ["resolve_dates", { phrases: ["tomorrow"] }]] as const) out.push((await tool(t, n, a)).text);
  const ids = [...out.join("").matchAll(/"event_id":"([^"]+)"/g)].map((m) => m[1]);
  for (const id of ids.slice(0, 5)) out.push((await tool(t, "get_event", { event_id: id })).text);
  const blob = [...pages, ...out].join("\n").toLowerCase();
  assert.ok(!blob.includes(USER.toLowerCase()), "demo address leaked to a reviewer");
  assert.ok(!blob.includes("demo.owner"), "local part leaked to a reviewer");
});

test("CLI: mints only for a named demo Worker, writes the one-tap link to a 600 file, never prints it, revoke works", async () => {
  const saved: Record<string, string> = {}; const lines: string[] = []; const save = async (n: string, v: string) => { saved[n] = v; };
  const dir = mkdtempSync(join(tmpdir(), "holdt-rv-")); const file = join(dir, "link.txt");
  await cliAction("--new-reviewer-code", save, (s) => lines.push(s), undefined, { workerName: "holdt", account: USER, codeFile: file });
  assert.deepEqual(saved, {}, "refuses the production Worker name"); assert.ok(!existsSync(file));
  await cliAction("--new-reviewer-code", save, (s) => lines.push(s), "https://holdt-demo.example.workers.dev/mcp", { workerName: "holdt-demo", account: USER, codeFile: file });
  const link = readFileSync(file, "utf8").trim(); assert.match(link, /^https:\/\/holdt-demo\.example\.workers\.dev\/review#RVW-/); assert.equal(statSync(file).mode & 0o777, 0o600);
  const code = link.split("#")[1]!;
  assert.match(saved.REVIEWER_CODE_HASH!, /^pbkdf2\$/); assert.ok(Number(saved.REVIEWER_CODE_ISSUED) > 0);
  const printed = lines.join("\n"); assert.ok(!printed.includes(code) && !printed.includes(code.replace(/-/g, "")), "code printed"); assert.ok(!printed.includes(USER), "address printed");
  assert.doesNotMatch(printed, /;/, "no semicolons in user-facing copy");
  // the saved hash verifies on a Worker for the same account, via the link's tap
  await freshEnv({ REVIEWER_CODE_HASH: saved.REVIEWER_CODE_HASH, REVIEWER_CODE_ISSUED: saved.REVIEWER_CODE_ISSUED });
  assert.equal((await (await connect(await passFor(code))).allow()).status, 302);
  await cliAction("--revoke-reviewer", save, (s) => lines.push(s), undefined, { workerName: "holdt-demo" });
  assert.equal(saved.REVIEWER_CODE_HASH, "revoked");
  await assert.rejects(() => cliAction("--new-reviewer-code", save, () => {}, undefined, { workerName: "holdt-demo", account: "", codeFile: file }), /HOLDT_REVIEWER_ACCOUNT/);
});

test("SECRET SAFETY (reviewer): no reviewer code, its hash, the demo address or the password in any log line or KV value", async () => {
  const blob = logs.join("\n"); assert.ok(logs.some((l) => /reviewer/.test(l)));
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
