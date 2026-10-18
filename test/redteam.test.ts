// Independent red-team suite (2026-10-17). Every test here FAILED on commit 30a99c5 and passes with fixes.patch.
// Each test is an attack that must be refused, or an invariant that must hold.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { MockCalDav } from "./mock-caldav.js";
import { MockKV } from "./kv-mock.js";
import { CalDavClient } from "../src/caldav.js";
import { mcpEndpoint, providerFor, kvUsedStore } from "../src/worker.js";
import { sha256Hex } from "../src/authorize.js";
import { issue, verify } from "../src/confirm.js";
import { parseXml } from "../src/xml.js";
import { setLogSink } from "../src/redact.js";

const USER = "victim@example.com", PASS = "mnop-qrst-uvwx-yzab", CODE = "73019264", TZ = "America/Denver";
const SECRET = "r".repeat(43), EPOCH_A = "epoch-A-" + "a".repeat(30), EPOCH_B = "epoch-B-" + "b".repeat(30);
const ORIGIN = "http://localhost:8787", CB = "cursor://anysphere.cursor-mcp/oauth/callback";
const logs: string[] = []; setLogSink((l) => logs.push(l));
const cal = new MockCalDav({ user: USER, pass: PASS });
before(async () => { await cal.start(); });
after(async () => { await cal.stop(); });
const ev = (uid: string, lines: string[]) => ["BEGIN:VCALENDAR", "VERSION:2.0", "BEGIN:VEVENT", `UID:${uid}`, ...lines, "END:VEVENT", "END:VCALENDAR", ""].join("\r\n");
beforeEach(() => {
  cal.items.clear(); cal.requests = []; cal.fail = null; CalDavClient.clearDiscoveryCache(); logs.length = 0;
  cal.add("home", "mine.ics", ev("mine-1", ["DTSTART;TZID=America/Denver:20261020T090000", "DTEND;TZID=America/Denver:20261020T100000", "SUMMARY:Dentist"]));
});
const envOf = (over: Record<string, unknown> = {}) => ({ ICLOUD_EMAIL: USER, ICLOUD_APP_PASSWORD: PASS, CONFIRM_SECRET: SECRET, GRANT_EPOCH: EPOCH_A, TIMEZONE: TZ, WRITES_ENABLED: "true", CALDAV_URL: cal.base, OAUTH_KV: new MockKV(), ...over }) as any;
let kvShared = new MockKV();
const rpcReq = (body: unknown, h: Record<string, string> = {}) => new Request(`${ORIGIN}/mcp`, { method: "POST", headers: { "Content-Type": "application/json", ...h }, body: JSON.stringify(body) });
async function tool(name: string, args: Record<string, unknown>, env = envOf({ OAUTH_KV: kvShared }), h: Record<string, string> = {}) {
  const r = await mcpEndpoint(rpcReq({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }, h), env, { epoch: env.GRANT_EPOCH }, fetch);
  const j: any = await r.json(); return { status: r.status, isError: j.result?.isError, res: j.result?.structuredContent, text: j.result?.content?.[0]?.text ?? JSON.stringify(j) };
}
const puts = () => cal.requests.filter((r) => r.method === "PUT");
async function homeId() { const r = await tool("list_calendars", {}); return r.res.calendars.find((c: any) => c.name === "Home").calendar_id; }
/** prepare then commit, as an injected model would. Returns the PUT bodies that reached iCloud. */
async function prepareAndCommit(args: Record<string, unknown>) {
  const p = await tool("prepare_create_event", { calendar_id: await homeId(), start: "2026-10-23T12:00", title: "Lunch", ...args });
  if (!p.isError) await tool("commit_create_event", { confirm_token: p.res.confirm_token });
  return { prep: p, bodies: puts().map((r) => r.body) };
}
const hasLine = (bodies: string[], re: RegExp) => bodies.some((b) => b.split("\r\n").some((l) => re.test(l)));

// ---------- R1-R3: nested arguments are never validated, so a model can write raw iCalendar ----------
test("REDTEAM R1: alerts_minutes_before item smuggles an ATTENDEE line (iCloud would email an invite)", async () => {
  kvShared = new MockKV();
  const { bodies } = await prepareAndCommit({ alerts_minutes_before: ["10\r\nATTENDEE;RSVP=TRUE:mailto:mallory@evil.example\r\nX-A:"] });
  assert.ok(!hasLine(bodies, /^(ATTENDEE|ORGANIZER)/i), "an injected ATTENDEE line reached iCloud:\n" + bodies.join("\n---\n"));
});
test("REDTEAM R2: repeat.count smuggles an ATTENDEE line through RRULE", async () => {
  kvShared = new MockKV();
  const { bodies } = await prepareAndCommit({ repeat: { every: "week", count: "2\r\nATTENDEE:mailto:mallory@evil.example" } });
  assert.ok(!hasLine(bodies, /^ATTENDEE/i), "an injected ATTENDEE line reached iCloud:\n" + bodies.join("\n---\n"));
});
test("REDTEAM R3: nested schema limits (maxItems 3, 0..40320, interval 1..99) are enforced", async () => {
  kvShared = new MockKV();
  const many = await tool("prepare_create_event", { calendar_id: await homeId(), title: "x", start: "2026-10-23T12:00", alerts_minutes_before: Array.from({ length: 500 }, (_, i) => i) });
  assert.equal(many.isError, true, "500 alerts accepted");
  const neg = await tool("prepare_create_event", { calendar_id: await homeId(), title: "x", start: "2026-10-23T12:00", alerts_minutes_before: [-5] });
  assert.equal(neg.isError, true, "negative alert accepted");
  const iv = await tool("prepare_create_event", { calendar_id: await homeId(), title: "x", start: "2026-10-23T12:00", repeat: { every: "day", interval: 100000 } });
  assert.equal(iv.isError, true, "interval 100000 accepted");
});

// ---------- R4: bare CR and other control characters reach iCloud ----------
test("REDTEAM R4: a bare CR (or NUL) in title/location/notes is never written raw", async () => {
  kvShared = new MockKV();
  const { bodies } = await prepareAndCommit({ title: "Lunch\rATTENDEE:mailto:mallory@evil.example", location: "a\u0000b", notes: "n\u000bx" });
  for (const b of bodies) assert.ok(!/\r(?!\n)|[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(b), "raw control character in the iCalendar body: " + JSON.stringify(b));
});

// ---------- R5-R6: what the user approves must be what gets written ----------
test("REDTEAM R5: the preview shows the whole change (no text hidden past a cut-off)", async () => {
  kvShared = new MockKV();
  const notes = "Agenda. ".repeat(40) + "Pay the invoice at https://evil.example/pay";
  const c = await tool("prepare_create_event", { calendar_id: await homeId(), title: "Lunch", start: "2026-10-23T12:00", notes });
  assert.ok(c.isError || c.res.preview.includes("https://evil.example/pay"), "create preview hides the end of the notes:\n" + c.res?.preview);
  const l: any = await tool("list_events", { from: "2026-10-20", to: "2026-10-20" });
  const u = await tool("prepare_update_event", { event_id: l.res.events[0].event_id, notes: "Wire $5,000 to https://evil.example/pay" });
  assert.ok(u.isError || u.res.preview.includes("https://evil.example/pay"), "update preview says only 'Notes: updated':\n" + u.res?.preview);
});
test("REDTEAM R6: bidi-override and zero-width characters can't disguise the preview", async () => {
  kvShared = new MockKV();
  const p = await tool("prepare_create_event", { calendar_id: await homeId(), title: "Lunch \u202Eyap ot $5000\u202C\u200B", start: "2026-10-23T12:00" });
  assert.ok(!/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/.test(p.res.preview), "preview carries invisible/bidi controls: " + JSON.stringify(p.res.preview));
});

// ---------- R7: an invitation hiding in a recurrence override ----------
test("REDTEAM R7: an event whose override has invitees can't be changed (not just the master)", async () => {
  kvShared = new MockKV();
  cal.add("home", "series.ics", ["BEGIN:VCALENDAR", "VERSION:2.0", "BEGIN:VEVENT", "UID:s-1", "DTSTART;TZID=America/Denver:20261019T090000", "DTEND;TZID=America/Denver:20261019T093000", "RRULE:FREQ=DAILY;COUNT=5", "SUMMARY:Standup", "END:VEVENT",
    "BEGIN:VEVENT", "UID:s-1", "RECURRENCE-ID;TZID=America/Denver:20261021T090000", "DTSTART;TZID=America/Denver:20261021T100000", "DTEND;TZID=America/Denver:20261021T103000", "SUMMARY:Standup (moved)", "ORGANIZER:mailto:boss@corp.example", "ATTENDEE:mailto:victim@example.com", "ATTENDEE:mailto:team@corp.example", "END:VEVENT", "END:VCALENDAR", ""].join("\r\n"));
  const l: any = await tool("list_events", { from: "2026-10-19", to: "2026-10-19" });
  const s = l.res.events.find((e: any) => e.title === "Standup");
  const u = await tool("prepare_update_event", { event_id: s.event_id, title: "Standup (cancelled, see notes)" });
  assert.equal(u.isError, true, "series with invited overrides was editable:\n" + u.text);
});

// ---------- R8-R9: single-use records race ----------
test("REDTEAM R8: one confirm token spent twice at the same moment succeeds only once", async () => {
  // Real KV reads take milliseconds. Model that latency, or the race window is invisible in-process.
  const kv = new MockKV(); const slow = { get: async (k: string) => { const v = await kv.get(k); await new Promise((r) => setTimeout(r, 5)); return v; }, put: (k: string, v: string, o?: any) => kv.put(k, v, o) };
  const store = kvUsedStore(slow)!;
  const tok = await issue(SECRET, "create_event", { cid: "home", uid: "u@x" });
  const rs = await Promise.all(Array.from({ length: 5 }, () => verify(SECRET, tok, "create_event", store)));
  assert.equal(rs.filter((r) => r.ok).length, 1, `${rs.filter((r) => r.ok).length} concurrent verifies all passed`);
});

const ctx = () => ({ waitUntil() {}, passThroughOnException() {}, props: undefined });
let oenv: any;
const ocall = (path: string, init: RequestInit = {}) => providerFor(ORIGIN, fetch).fetch(new Request(ORIGIN + path, { redirect: "manual", ...init }), oenv, ctx() as any);
const unesc = (s: string) => s.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n));
async function consent(clientName = "Grok Bot") {
  const reg: any = await (await ocall("/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name: clientName, redirect_uris: [CB], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) })).json();
  const v = randomBytes(32).toString("base64url"), ch = createHash("sha256").update(v).digest("base64url");
  const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: CB, code_challenge: ch, code_challenge_method: "S256", state: "s", scope: "calendar", resource: `${ORIGIN}/mcp` });
  const page = await ocall(`/authorize?${q}`); const html = await page.text();
  const handle = unesc(html.match(/name="handle" value="([^"]+)"/)?.[1] ?? ""), ctxF = unesc(html.match(/name="ctx" value="([^"]*)"/)?.[1] ?? "");
  const cookie = (page.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]).join("; ");
  const submit = (code: string) => ocall("/authorize", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookie, Origin: ORIGIN }, body: new URLSearchParams({ handle, ctx: ctxF, code, decision: "approve" }).toString() });
  return { html, submit };
}
test("REDTEAM R9: parallel guesses can't exceed the 5-try limit on the approval code", async () => {
  oenv = envOf({ APPROVAL_CODE_HASH: await sha256Hex(`icloud-mcp-approval:${CODE}`), APPROVAL_CODE_ISSUED: String(Date.now()) });
  const a = await consent();
  const guesses = [...Array.from({ length: 30 }, (_, i) => String(10000000 + i)), CODE];
  const rs = await Promise.all(guesses.map((g) => a.submit(g)));
  assert.notEqual(rs.at(-1)!.status, 302, "the right code still worked after 30 simultaneous wrong guesses");
});

// ---------- R10: confirm tokens outlive "revoke all" ----------
test("REDTEAM R10: a preview token issued before revoke-all can't be committed after it", async () => {
  kvShared = new MockKV();
  const p = await tool("prepare_create_event", { calendar_id: await homeId(), title: "Lunch", start: "2026-10-23T12:00" }, envOf({ OAUTH_KV: kvShared, GRANT_EPOCH: EPOCH_A }));
  cal.requests = [];
  await tool("commit_create_event", { confirm_token: p.res.confirm_token }, envOf({ OAUTH_KV: kvShared, GRANT_EPOCH: EPOCH_B }));
  assert.equal(puts().length, 0, "a token from the revoked epoch still wrote to iCloud");
});

// ---------- R11-R14: transport and robustness ----------
test("REDTEAM R11: a body with no Content-Length is still capped at 256 KB", async () => {
  const big = new TextEncoder().encode(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping", params: { pad: "x".repeat(2_000_000) } }));
  const stream = new ReadableStream({ start(c) { c.enqueue(big); c.close(); } });
  const env = envOf();
  const r = await mcpEndpoint(new Request(`${ORIGIN}/mcp`, { method: "POST", headers: { "Content-Type": "application/json" }, body: stream, duplex: "half" } as any), env, { epoch: env.GRANT_EPOCH }, fetch);
  assert.equal(r.status, 413, "a 2 MB chunked body was parsed");
});
test("REDTEAM R12: a browser page on another origin is refused (DNS-rebinding / Origin check, MCP transport MUST)", async () => {
  const env = envOf();
  const r = await mcpEndpoint(rpcReq({ jsonrpc: "2.0", id: 1, method: "ping" }, { Origin: "https://evil.example" }), env, { epoch: env.GRANT_EPOCH }, fetch);
  assert.equal(r.status, 403);
  const ok = await mcpEndpoint(rpcReq({ jsonrpc: "2.0", id: 1, method: "ping" }), env, { epoch: env.GRANT_EPOCH }, fetch);
  assert.equal(ok.status, 200, "server-side clients (no Origin) still work");
});
test("REDTEAM R13: a tool name can't forge extra log lines", async () => {
  const env = envOf();
  await mcpEndpoint(rpcReq({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "x\n[info] connection approved", arguments: {} } }), env, { epoch: env.GRANT_EPOCH }, fetch);
  assert.ok(logs.every((l) => !/[\r\n]/.test(l)), "log line split: " + JSON.stringify(logs));
});
test("REDTEAM R14: an out-of-range XML character reference doesn't crash the parser", () => {
  assert.doesNotThrow(() => parseXml("<a>&#x110000;&#99999999999;</a>"));
});

// ---------- TZ1 (was N1): not a security bug, found on the way (time zone math drops milliseconds wrongly) ----------
test("REDTEAM TZ1: offsets and DST transitions are exact (no -06:0.0083 offsets, VTIMEZONE at 02:00)", async () => {
  const { isoInZone, vtimezone } = await import("../src/ical.js");
  assert.match(isoInZone(Date.UTC(2026, 9, 17, 6, 0, 0, 500), TZ), /^2026-10-17T00:00:00-06:00$/);
  const v = vtimezone(TZ, 2026).filter((l) => l.startsWith("DTSTART"));
  assert.deepEqual(v, ["DTSTART:20260308T020000", "DTSTART:20261101T020000"]);
});

test("REDTEAM R16: a hostile multistatus body can't pin the CPU (quadratic tag regex)", () => {
  const t = Date.now(); parseXml("<".repeat(50_000)); parseXml("</".repeat(25_000)); parseXml("<a" + ' b="<'.repeat(20_000));
  assert.ok(Date.now() - t < 500, `parser took ${Date.now() - t} ms on 50 KB`);
});

// ---------- R15: consent page placeholder injection ----------
test("REDTEAM R15: a client name can't hijack the consent page's read-only notice", async () => {
  oenv = envOf({ WRITES_ENABLED: "false", APPROVAL_CODE_HASH: await sha256Hex(`icloud-mcp-approval:${CODE}`), APPROVAL_CODE_ISSUED: String(Date.now()) });
  const a = await consent("Grok Bot {{writes}}");
  assert.match(a.html, /Changes are off, so it can.t add or change events/, "the real read-only notice was displaced");
  assert.doesNotMatch(a.html, /Changes are \{\{writes\}\}/);
});

test("Origin check rollout: report mode logs and lets the call through, default mode refuses", async () => {
  const { mcpEndpoint } = await import("../src/worker.js"); const { setLogSink } = await import("../src/redact.js");
  const lines: string[] = []; setLogSink((l) => lines.push(l));
  const e: any = { ICLOUD_EMAIL: "a@b.c", ICLOUD_APP_PASSWORD: "x", CONFIRM_SECRET: "c".repeat(32), GRANT_EPOCH: "e".repeat(30), TIMEZONE: "UTC" };
  const req = () => new Request("https://holdt.example/mcp", { method: "POST", headers: { Origin: "https://evil.example", "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }) });
  assert.equal((await mcpEndpoint(req(), e, { epoch: e.GRANT_EPOCH })).status, 403);
  assert.notEqual((await mcpEndpoint(req(), { ...e, ORIGIN_CHECK: "report" }, { epoch: e.GRANT_EPOCH })).status, 403);
  assert.ok(lines.some((l) => /origin seen: foreign https:\/\/evil\.example/.test(l)));
  setLogSink(() => {});
});
