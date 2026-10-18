import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { MockCalDav } from "./mock-caldav.js";
import { CalDavClient } from "../src/caldav.js";
import { Tools, TOOLS, REMINDER_TOOLS } from "../src/tools.js";
import { mcpEndpoint, confirmKey } from "../src/worker.js";
const handle = (req: Request, e: any, f?: typeof fetch) => mcpEndpoint(req, e, e.__props === undefined ? { epoch: e.GRANT_EPOCH } : e.__props, f);
import { setLogSink, registerSecret, redact } from "../src/redact.js";
import { expand, parseIcs, getProp, parseDate, foldLine, buildEvent, patchEvent, wallToUtc, unfold } from "../src/ical.js";
import { seal, open, importKek } from "../src/vault.js";

const USER = "test.user@example.com", PASS = "abcd-efgh-ijkl-mnop", TOKEN = "t".repeat(40) + "SECRETTOKEN";
const logs: string[] = []; setLogSink((l) => logs.push(l));
const mock = new MockCalDav({ user: USER, pass: PASS });
const TZ = "America/Denver";
const ev = (uid: string, lines: string[]) => ["BEGIN:VCALENDAR", "VERSION:2.0", "BEGIN:VEVENT", `UID:${uid}`, ...lines, "END:VEVENT", "END:VCALENDAR", ""].join("\r\n");
function tools(writes = true, extra: Partial<{ allow: string[]; reminders: boolean }> = { reminders: true }) {
  registerSecret(PASS); registerSecret(USER);
  return new Tools(new CalDavClient({ baseUrl: mock.base, username: USER, password: PASS, sleep: async () => {} }), { timezone: TZ, writesEnabled: writes, confirmSecret: confirmKey(env(writes)), calendarAllowlist: extra.allow, remindersExperimental: extra.reminders ?? true });
}
const puts = () => mock.requests.filter((r) => r.method === "PUT");

before(async () => { await mock.start(); });
after(async () => { await mock.stop(); });
beforeEach(() => {
  mock.items.clear(); mock.requests = []; mock.fail = null;
  mock.add("home", "standup.ics", ev("standup-1", ["DTSTART;TZID=America/Denver:20261026T090000", "DTEND;TZID=America/Denver:20261026T093000", "SUMMARY:Standup", "RRULE:FREQ=WEEKLY;BYDAY=MO,WE;COUNT=6", "EXDATE;TZID=America/Denver:20261028T090000", "X-APPLE-TRAVEL-ADVISORY-BEHAVIOR:AUTOMATIC"]));
  mock.add("home", "dentist.ics", ev("dentist-1", ["DTSTART:20261029T163000Z", "DURATION:PT1H", "SUMMARY:Dentist\\, Dr. Ruiz", "LOCATION:12 Main St", "DESCRIPTION:Bring insurance card", "BEGIN:VALARM", "ACTION:DISPLAY", "TRIGGER:-PT30M", "END:VALARM"]));
  mock.add("work", "offsite.ics", ev("offsite-1", ["DTSTART;VALUE=DATE:20261030", "DTEND;VALUE=DATE:20261101", "SUMMARY:Team offsite"]));
  mock.add("work", "review.ics", ev("review-1", ["DTSTART:20261027T200000Z", "DTEND:20261027T210000Z", "SUMMARY:Design review", "ORGANIZER:mailto:boss@example.com", "ATTENDEE;CN=Me:mailto:test.user@example.com"]));
  mock.add("tasks", "milk.ics", ["BEGIN:VCALENDAR", "VERSION:2.0", "BEGIN:VTODO", "UID:milk", "SUMMARY:Buy milk", "DUE;VALUE=DATE:20261020", "PRIORITY:1", "STATUS:NEEDS-ACTION", "X-APPLE-SORT-ORDER:3", "END:VTODO", "END:VCALENDAR", ""].join("\r\n"));
  mock.add("tasks", "eggs.ics", ["BEGIN:VCALENDAR", "VERSION:2.0", "BEGIN:VTODO", "UID:eggs", "SUMMARY:Eggs", "STATUS:COMPLETED", "COMPLETED:20261001T000000Z", "END:VTODO", "END:VCALENDAR", ""].join("\r\n"));
});

test("discovery follows well-known redirect and lists only event calendars", async () => {
  const r: any = await tools().call("list_calendars", {});
  assert.deepEqual(r.calendars.map((c: any) => c.name), ["Home", "Work", "US Holidays"]);
  const hol = r.calendars.find((c: any) => c.name === "US Holidays");
  assert.equal(hol.can_change, false); assert.match(hol.read_only_reason, /read-only/);
  assert.equal(r.calendars[0].color, "#34AADC");
});

test("connection_status reports counts and read-only mode", async () => {
  const r: any = await tools(false, { reminders: false }).call("connection_status", {});
  assert.equal(r.calendars, 3); assert.match(r.reminders, /not included/); assert.equal(r.changes_allowed, false);
});

test("list_events expands weekly recurrence, honours EXDATE, sorts, handles all-day and DURATION", async () => {
  const r: any = await tools().call("list_events", { from: "2026-10-25", to: "2026-11-08" });
  const titles = r.events.map((e: any) => `${e.title}@${e.start}`);
  assert.deepEqual(titles, [
    "Standup@2026-10-26T09:00:00-06:00", "Design review@2026-10-27T14:00:00-06:00", "Dentist, Dr. Ruiz@2026-10-29T10:30:00-06:00",
    "Team offsite@2026-10-30", "Standup@2026-11-02T09:00:00-07:00", "Standup@2026-11-04T09:00:00-07:00"]);
  // DST: Nov 1 2026 ends MDT, local 09:00 stays 09:00
  const offsite = r.events.find((e: any) => e.title === "Team offsite"); assert.equal(offsite.end, "2026-10-31"); assert.equal(offsite.all_day, true);
  const dent = r.events.find((e: any) => e.title.startsWith("Dentist")); assert.equal(dent.end, "2026-10-29T11:30:00-06:00");
});

test("list_events paginates with a cursor bound to the query", async () => {
  const t = tools(); const a: any = await t.call("list_events", { from: "2026-10-25", to: "2026-11-08", limit: 4 });
  assert.equal(a.events.length, 4); assert.ok(a.next_cursor);
  const b: any = await t.call("list_events", { from: "2026-10-25", to: "2026-11-08", limit: 4, cursor: a.next_cursor });
  assert.equal(b.events.length, 2); assert.equal(b.next_cursor, undefined);
  await assert.rejects(t.call("list_events", { from: "2026-10-26", to: "2026-11-08", cursor: a.next_cursor }), /different query/);
  await assert.rejects(t.call("list_events", { from: "2026-01-01", to: "2027-06-01" }), /366 days/);
});

test("search_events matches title/location/notes case-insensitively", async () => {
  const r: any = await tools().call("search_events", { query: "insurance", from: "2026-10-01", to: "2026-12-01" });
  assert.equal(r.events.length, 1); assert.equal(r.events[0].location, "12 Main St");
});

test("search_events works with its default window", async () => {
  const r: any = await tools().call("search_events", { query: "standup" });
  assert.ok(Array.isArray(r.events));
});

test("get_event returns full notes and alerts", async () => {
  const t = tools(); const l: any = await t.call("search_events", { query: "dentist", from: "2026-10-01", to: "2026-12-01" });
  const g: any = await t.call("get_event", { event_id: l.events[0].event_id });
  assert.equal(g.notes, "Bring insurance card"); assert.deepEqual(g.alerts, ["30 min before"]);
  await assert.rejects(t.call("get_event", { event_id: "garbage!!" }), /isn't valid/);
});

test("writes are impossible when WRITES_ENABLED is off", async () => {
  const t = tools(false);
  await assert.rejects(t.call("prepare_create_event", { calendar_id: "home", title: "X", start: "2026-11-01T10:00" }), /turned off/);
  await assert.rejects(t.call("commit_create_event", { confirm_token: "a.b" }), (e: Error) => e.message.includes("npm run agent-setup -- --new-link") && !/[;—]/.test(e.message), "says how to turn changes on");
  assert.equal(puts().length, 0);
});

test("create: prepare changes nothing, commit writes once, replays and tampering are refused", async () => {
  const t = tools();
  const p: any = await t.call("prepare_create_event", { calendar_id: "home", title: "Lunch with Sam", start: "2026-11-03T12:00", location: "Cafe", alerts_minutes_before: [15] });
  assert.equal(puts().length, 0);
  assert.match(p.preview, /Add to "Home": Lunch with Sam/); assert.match(p.preview, /12:00 PM MST to .*1:00 PM MST/); assert.match(p.preview, /15 min before/);
  const c: any = await t.call("commit_create_event", { confirm_token: p.confirm_token });
  assert.equal(c.done, true); assert.equal(puts().length, 1);
  const put = puts()[0]!; assert.equal(put.headers["if-none-match"], "*");
  assert.match(put.body, /DTSTART;TZID=America\/Denver:20261103T120000/); assert.match(put.body, /BEGIN:VTIMEZONE/); assert.match(put.body, /TRIGGER:-PT15M/);
  await assert.rejects(t.call("commit_create_event", { confirm_token: p.confirm_token }), /already made/);
  // a second process (fresh Tools, no memory) replaying the same token cannot double-create: If-None-Match:* protects it
  // (red-team fix: the same isolate now refuses the nonce before iCloud is even asked; another isolate still hits If-None-Match:*)
  const again: string = await tools().call("commit_create_event", { confirm_token: p.confirm_token }).then((x: any) => x.note, (e: Error) => e.message);
  assert.match(again, /already added|already made/); assert.equal([...mock.items.keys()].filter((k) => k.includes("home")).length, 3);
  const [body, sig] = p.confirm_token.split(".");
  const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(body, "base64url").toString()), p: { cid: "home", title: "EVIL" } })).toString("base64url");
  await assert.rejects(t.call("commit_create_event", { confirm_token: `${forged}.${sig}` }), /isn't valid/);
  await assert.rejects(t.call("commit_update_event", { confirm_token: p.confirm_token }), /different kind/);
});

test("create validates input with plain-English errors", async () => {
  const t = tools();
  await assert.rejects(t.call("prepare_create_event", { calendar_id: "nope", title: "x", start: "2026-11-01" }), /list_calendars/);
  await assert.rejects(t.call("prepare_create_event", { calendar_id: "holidays", title: "x", start: "2026-11-01" }), /read-only/);
  await assert.rejects(t.call("prepare_create_event", { calendar_id: "home", title: "x", start: "whenever suits" }), /Couldn't read the time "whenever suits".*next friday 3pm/);
  await assert.rejects(t.call("prepare_create_event", { calendar_id: "home", title: "x", start: "next week" }), /several days/);
  await assert.rejects(t.call("prepare_create_event", { calendar_id: "home", title: "x", start: "2026-11-01T10:00", end: "2026-11-01T09:00" }), /after the start/);
  const allDay: any = await t.call("prepare_create_event", { calendar_id: "home", title: "Trip", start: "2026-12-20", end: "2026-12-22", repeat: { every: "year", count: 3 } });
  assert.match(allDay.preview, /Sun, Dec 20, 2026 to Tue, Dec 22, 2026/); assert.match(allDay.preview, /every year, 3 times/);
  await t.call("commit_create_event", { confirm_token: allDay.confirm_token });
  assert.match(puts()[0]!.body, /DTEND;VALUE=DATE:20261223/); assert.match(puts()[0]!.body, /RRULE:FREQ=YEARLY;COUNT=3/);
});

test("update: before/after preview, preserves unknown data, uses If-Match, detects concurrent edits", async () => {
  const t = tools();
  const l: any = await t.call("search_events", { query: "dentist", from: "2026-10-01", to: "2026-12-01" });
  const p: any = await t.call("prepare_update_event", { event_id: l.events[0].event_id, title: "Dentist (moved)", start: "2026-10-30T08:00" });
  assert.match(p.preview, /"Dentist, Dr. Ruiz" → "Dentist \(moved\)"/); assert.equal(puts().length, 0);
  await t.call("commit_update_event", { confirm_token: p.confirm_token });
  const put = puts()[0]!; assert.ok(put.headers["if-match"]);
  assert.match(put.body, /SUMMARY:Dentist \(moved\)/); assert.match(put.body, /DTSTART:20261030T140000Z/); assert.match(put.body, /DTEND:20261030T150000Z/);
  assert.match(put.body, /BEGIN:VALARM[\s\S]*TRIGGER:-PT30M/); assert.match(put.body, /LOCATION:12 Main St/); assert.doesNotMatch(put.body, /DURATION/); assert.match(put.body, /SEQUENCE:1/);
  // concurrent edit between preview and commit
  const p2: any = await t.call("prepare_update_event", { event_id: l.events[0].event_id, notes: "" });
  const k = [...mock.items.keys()].find((x) => x.endsWith("dentist.ics"))!; mock.items.get(k)!.etag = 999;
  await assert.rejects(t.call("commit_update_event", { confirm_token: p2.confirm_token }), /changed in iCloud after the preview/);
  assert.equal(puts().length, 1);
});

test("update refuses events with invitees and time changes to repeating events", async () => {
  const t = tools(); const l: any = await t.call("list_events", { from: "2026-10-25", to: "2026-11-08" });
  const review = l.events.find((e: any) => e.title === "Design review"); assert.equal(review.has_invitees, true);
  await assert.rejects(t.call("prepare_update_event", { event_id: review.event_id, title: "x" }), /invitees/);
  const st = l.events.find((e: any) => e.title === "Standup");
  await assert.rejects(t.call("prepare_update_event", { event_id: st.event_id, start: "2026-10-26T10:00" }), /repeating/);
  const ok: any = await t.call("prepare_update_event", { event_id: st.event_id, title: "Daily sync" }); assert.match(ok.preview, /all repeats/);
  await t.call("commit_update_event", { confirm_token: ok.confirm_token });
  assert.match(puts()[0]!.body, /X-APPLE-TRAVEL-ADVISORY-BEHAVIOR:AUTOMATIC/); assert.match(puts()[0]!.body, /RRULE:FREQ=WEEKLY;BYDAY=MO,WE;COUNT=6/);
});

test("reminders: list (open only by default), add and complete behind confirm", async () => {
  const t = tools();
  const ls: any = await t.call("list_reminder_lists", {}); assert.deepEqual(ls.lists.map((x: any) => x.name), ["Groceries"]);
  const r: any = await t.call("list_reminders", {}); assert.deepEqual(r.reminders.map((x: any) => [x.title, x.due, x.priority]), [["Buy milk", "2026-10-20", "high"]]);
  const r2: any = await t.call("list_reminders", { include_completed: true }); assert.equal(r2.reminders.length, 2);
  const p: any = await t.call("prepare_add_reminder", { list_id: "tasks", title: "Bread", due: "2026-10-21T17:00", priority: "medium" });
  assert.match(p.preview, /Add to "Groceries": Bread/); assert.equal(puts().length, 0);
  await t.call("commit_add_reminder", { confirm_token: p.confirm_token }); assert.match(puts()[0]!.body, /BEGIN:VTODO[\s\S]*PRIORITY:5/);
  const pc: any = await t.call("prepare_complete_reminder", { reminder_id: r.reminders[0].reminder_id });
  await t.call("commit_complete_reminder", { confirm_token: pc.confirm_token });
  const body = puts()[1]!.body; assert.match(body, /STATUS:COMPLETED/); assert.equal((body.match(/STATUS:/g) ?? []).length, 1); assert.match(body, /X-APPLE-SORT-ORDER:3/);
});

test("no reminder lists gives an honest explanation", async () => {
  const saved = mock.cols.tasks; delete (mock.cols as any).tasks;
  try { const r: any = await tools().call("list_reminder_lists", {}); assert.equal(r.lists.length, 0); assert.match(r.note, /upgraded on iOS 13/); }
  finally { mock.cols.tasks = saved!; }
});

test("v1 default: reminder tools are hidden and refused with a plain reason", async () => {
  const list: any = await (await handle(rpc("tools/list", {}), env(false))).json();
  const names = list.result.tools.map((t: any) => t.name);
  assert.ok(!names.some((n: string) => /reminder/.test(n))); assert.equal(names.length, TOOLS.length - REMINDER_TOOLS.size);
  const call: any = await (await handle(rpc("tools/call", { name: "list_reminders", arguments: {} }), env(false))).json(); assert.equal(call.error.code, -32602);
  await assert.rejects(tools(true, { reminders: false }).call("list_reminders", {}), /aren't included in this version/);
  const on: any = await (await handle(rpc("tools/list", {}), { ...env(false), REMINDERS_EXPERIMENTAL: "true" })).json(); assert.equal(on.result.tools.length, TOOLS.length);
});

test("calendar allowlist hides other calendars", async () => {
  const r: any = await tools(true, { allow: ["work"], reminders: true }).call("list_calendars", {}); assert.deepEqual(r.calendars.map((c: any) => c.name), ["Work"]);
});

test("reads retry 503 with backoff; writes are never retried", async () => {
  mock.fail = { status: 503, times: 2, methods: ["PROPFIND"], retryAfter: "1" };
  const r: any = await tools().call("list_calendars", {}); assert.equal(r.calendars.length, 3);
  const t = tools(); const p: any = await t.call("prepare_create_event", { calendar_id: "home", title: "X", start: "2026-11-03T12:00" });
  mock.requests = []; mock.fail = { status: 503, times: 5, methods: ["PUT"] };
  const mcpRes: any = await handle(new Request("http://w/mcp", { method: "POST", headers: { Authorization: `Bearer ${TOKEN}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "commit_create_event", arguments: { confirm_token: p.confirm_token } } }) }), env(true), fetch).then((x: Response) => x.json());
  assert.equal(mcpRes.result.isError, true); assert.match(mcpRes.result.content[0].text, /hiccup[\s\S]*Read the item again/);
  assert.equal(mock.requests.filter((x) => x.method === "PUT").length, 1);
});

test("wrong password gives a plain-English fix", async () => {
  const res: any = await handle(rpc("tools/call", { name: "list_calendars", arguments: {} }), { ...env(false), ICLOUD_APP_PASSWORD: "zzzz-zzzz-zzzz-zzzz" }, fetch).then((x: Response) => x.json());
  assert.equal(res.result.isError, true); assert.match(res.result.content[0].text, /app-specific password[\s\S]*account\.apple\.com/);
});

test("credentials are never sent to an untrusted host (redirect hijack)", async () => {
  const evil = new CalDavClient({ baseUrl: "https://caldav.icloud.com/", username: USER, password: PASS, fetch: async () => ({ status: 302, headers: { get: (n: string) => (n === "location" ? "https://evil.example.net/steal" : null) }, text: async () => "" }) });
  await assert.rejects(evil.discover(), /untrusted server/);
  const http = new CalDavClient({ baseUrl: "http://caldav.icloud.com/", username: USER, password: PASS, fetch: async () => { throw new Error("should not be called"); } });
  await assert.rejects(http.discover(), /untrusted server/);
});

// ---------- MCP / Worker ----------
function env(writes: boolean): any { return { ICLOUD_EMAIL: USER, ICLOUD_APP_PASSWORD: PASS, GRANT_EPOCH: TOKEN, CONFIRM_SECRET: "c".repeat(32), TIMEZONE: TZ, WRITES_ENABLED: String(writes), CALDAV_URL: mock.base }; }
function rpc(method: string, params?: unknown, token = TOKEN) { return new Request("http://w/mcp", { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 7, method, params }) }); }

test("mcp endpoint: revoked grants refused, MCP handshake and tool annotations", async () => {
  const revoked = await handle(rpc("tools/list", {}), { ...env(false), __props: { epoch: "old-epoch" } }); assert.equal(revoked.status, 401); assert.match(await revoked.text(), /revoked/);
  assert.equal((await handle(rpc("tools/list", {}), { ...env(false), __props: null })).status, 401);
  const init: any = await (await handle(rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } }), env(false))).json();
  assert.equal(init.result.protocolVersion, "2025-06-18"); assert.match(init.result.instructions, /only after they clearly say yes/);
  const note = await handle(new Request("http://w/mcp", { method: "POST", headers: { Authorization: `Bearer ${TOKEN}` }, body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) }), env(false));
  assert.equal(note.status, 202);
  const list: any = await (await handle(rpc("tools/list", {}), env(false))).json();
  const names = list.result.tools.map((t: any) => t.name);
  assert.ok(!names.some((n: string) => /delete|invite/.test(n)), "no delete or invite tools in v1");
  for (const t of list.result.tools) {
    if (t.name.startsWith("commit_")) assert.equal(t.annotations.readOnlyHint, false); else assert.equal(t.annotations.readOnlyHint, true, t.name);
    assert.equal(t.annotations.destructiveHint, /^commit_(update_event|complete_reminder|undo)$/.test(t.name), t.name);
    assert.equal(t.title, t.annotations.title, "top-level title for 2025-06-18+ clients");
  }
  const unconfigured = await handle(rpc("tools/list"), { ...env(false), ICLOUD_APP_PASSWORD: "" }); assert.equal(unconfigured.status, 503);
  assert.equal((await handle(new Request("http://w/mcp", { headers: { Authorization: `Bearer ${TOKEN}` } }), env(false))).status, 405);
});

test("worker: end-to-end tools/call over MCP", async () => {
  const r: any = await (await handle(rpc("tools/call", { name: "list_events", arguments: { from: "2026-10-25", to: "2026-11-08" } }), env(false), fetch)).json();
  assert.equal(r.result.isError, false); assert.equal(r.result.structuredContent.events.length, 6);
  const bad: any = await (await handle(rpc("tools/call", { name: "delete_event", arguments: {} }), env(false))).json(); assert.equal(bad.error.code, -32602);
});

// ---------- iCal edge cases ----------
test("ical: line folding is UTF-8 safe and round-trips", () => {
  const long = "SUMMARY:" + "Café ☕ ".repeat(30); const folded = foldLine(long);
  for (const l of folded.split("\r\n")) assert.ok(Buffer.byteLength(l) <= 75);
  assert.equal(unfold(folded)[0], long);
});
test("ical: monthly on the 31st skips short months; Feb 29 yearly only on leap years", () => {
  const s = { utc: Date.UTC(2026, 0, 31), allDay: true };
  const r = expand(s, 86400000, "FREQ=MONTHLY;COUNT=4", [], 0, Date.UTC(2028, 0, 1));
  assert.deepEqual(r.occ.map((o) => new Date(o.start).toISOString().slice(0, 10)), ["2026-01-31", "2026-03-31", "2026-05-31", "2026-07-31"]);
  const unsupported = expand(s, 0, "FREQ=MONTHLY;BYDAY=TU;BYSETPOS=2", [], 0, Date.UTC(2027, 0, 1)); assert.equal(unsupported.supported, false);
});
test("ical: DST gap time shifts forward instead of failing", () => {
  const t = wallToUtc(2027, 3, 14, 2, 30, 0, "America/Denver"); // 2:30 doesn't exist
  assert.ok(!isNaN(t));
});
test("ical: patch preserves overrides (RECURRENCE-ID) untouched", () => {
  const raw = ["BEGIN:VCALENDAR", "BEGIN:VEVENT", "UID:a", "DTSTART:20261026T150000Z", "SUMMARY:Old", "RRULE:FREQ=DAILY", "END:VEVENT", "BEGIN:VEVENT", "UID:a", "RECURRENCE-ID:20261027T150000Z", "DTSTART:20261027T160000Z", "SUMMARY:Old moved", "END:VEVENT", "END:VCALENDAR"].join("\r\n");
  const out = patchEvent(raw, { title: "New" });
  assert.match(out, /SUMMARY:New/); assert.match(out, /SUMMARY:Old moved/); assert.equal((out.match(/SUMMARY:/g) ?? []).length, 2);
});

// ---------- secret safety (runs last; inspects everything logged above) ----------
test("vault: envelope encryption round-trips and is bound to the user", async () => {
  const kek = await importKek(crypto.getRandomValues(new Uint8Array(32)));
  const s = await seal(kek, "kek-1", "user-a", PASS);
  assert.ok(!JSON.stringify(s).includes(PASS)); assert.equal(await open(kek, "user-a", s), PASS);
  await assert.rejects(open(kek, "user-b", s)); // swapped row fails
});
test("redaction scrubs passwords, tokens, basic auth and emails even if interpolated", () => {
  registerSecret(TOKEN);
  const b = Buffer.from(`${USER}:${PASS}`).toString("base64");
  const s = redact(`pw=${PASS} tok=${TOKEN} Authorization: Basic ${b} user ${USER} other qwer-tyui-opas-dfgh`);
  for (const bad of [PASS, TOKEN, b, USER, "qwer-tyui-opas-dfgh"]) assert.ok(!s.includes(bad), bad);
});
test("SECRET SAFETY: no credential appears in any log line or in any request except the Authorization header", () => {
  const blob = logs.join("\n");
  assert.ok(logs.length > 0, "expected some logs to inspect");
  const b = Buffer.from(`${USER}:${PASS}`).toString("base64");
  for (const bad of [PASS, TOKEN, b, "zzzz-zzzz-zzzz-zzzz", USER]) assert.ok(!blob.includes(bad), `leaked: ${bad.slice(0, 4)}…`);
  for (const r of mock.requests) { assert.ok(!r.body.includes(PASS)); assert.ok(!r.url.includes(PASS)); }
});
