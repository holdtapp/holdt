// Regression tests for the Oct 16-17 2026 live-test findings and the expert audit.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { MockCalDav } from "./mock-caldav.js";
import { CalDavClient } from "../src/caldav.js";
import { Tools } from "../src/tools.js";
import { mcpEndpoint, kvUsedStore } from "../src/worker.js";
import { handleRpc, SUPPORTED } from "../src/mcp.js";
import { expand, parseUserTime, dayStartIn, vtimezone, parseIcs } from "../src/ical.js";
import { MockKV } from "./kv-mock.js";
import { setLogSink } from "../src/redact.js";

const USER = "audit.user@example.com", PASS = "qrst-uvwx-yzab-cdef", TZ = "America/Denver", EPOCH = "e".repeat(40);
const logs: string[] = []; setLogSink((l) => logs.push(l));
const mock = new MockCalDav({ user: USER, pass: PASS });
const ev = (uid: string, lines: string[]) => ["BEGIN:VCALENDAR", "VERSION:2.0", "BEGIN:VEVENT", `UID:${uid}`, ...lines, "END:VEVENT", "END:VCALENDAR", ""].join("\r\n");
const dav = () => new CalDavClient({ baseUrl: mock.base, username: USER, password: PASS, sleep: async () => {} });
const tools = (writes = true, usedStore?: any) => new Tools(dav(), { timezone: TZ, writesEnabled: writes, confirmSecret: "s".repeat(32), usedStore });
const env = (over: Record<string, unknown> = {}): any => ({ ICLOUD_EMAIL: USER, ICLOUD_APP_PASSWORD: PASS, GRANT_EPOCH: EPOCH, CONFIRM_SECRET: "s".repeat(32), TIMEZONE: TZ, WRITES_ENABLED: "true", CALDAV_URL: mock.base, OAUTH_KV: new MockKV(), ...over });
const rpc = (body: unknown, headers: Record<string, string> = {}) => new Request("http://w/mcp", { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
const ymd = (ms: number) => new Date(ms).toISOString().slice(0, 10);

before(async () => { await mock.start(); });
after(async () => { await mock.stop(); });
beforeEach(() => {
  mock.items.clear(); mock.requests = []; mock.fail = null; CalDavClient.clearDiscoveryCache();
  mock.add("home", "saturday.ics", ev("sat-1", ["DTSTART;VALUE=DATE:20261017", "DTEND;VALUE=DATE:20261018", "SUMMARY:Saturday chores"]));
  mock.add("home", "friday-night.ics", ev("fri-1", ["DTSTART;TZID=America/Denver:20261016T200000", "DTEND;TZID=America/Denver:20261016T220000", "SUMMARY:Friday movie"]));
  mock.add("work", "late.ics", ev("late-1", ["DTSTART;TZID=America/Denver:20261017T233000", "DTEND;TZID=America/Denver:20261017T235500", "SUMMARY:Late deploy"]));
});

// ---------- (a) bare dates mean days in the user's zone ----------
test("list_events: a bare date is that whole day in the user's zone (not UTC midnight)", async () => {
  const r: any = await tools().call("list_events", { from: "2026-10-17", to: "2026-10-17" });
  assert.equal(r.from, "2026-10-17T00:00:00-06:00"); assert.equal(r.to, "2026-10-18T00:00:00-06:00");
  assert.deepEqual(r.events.map((e: any) => e.title), ["Saturday chores", "Late deploy"], "all-day first, then timed; Friday 8 PM is not Saturday");
  const fri: any = await tools().call("list_events", { from: "2026-10-16", to: "2026-10-16" });
  assert.deepEqual(fri.events.map((e: any) => e.title), ["Friday movie"], "Saturday's all-day event doesn't leak into Friday");
});

test("list_events: a timed window still uses exact instants, and all-day events float to the user's day", async () => {
  // 5 PM Fri to 1 AM Sat local: the movie, and the first hour of Saturday (so the all-day event)
  const r: any = await tools().call("list_events", { from: "2026-10-16T17:00", to: "2026-10-17T01:00" });
  assert.deepEqual(r.events.map((e: any) => e.title), ["Friday movie", "Saturday chores"]);
  const sat = r.events[1]; assert.equal(sat.start, "2026-10-17"); assert.equal(sat.end, "2026-10-17"); assert.equal(sat.all_day, true);
});

test("search_events: bare-date window is the user's day", async () => {
  const r: any = await tools().call("search_events", { query: "a", from: "2026-10-17", to: "2026-10-17" });
  assert.deepEqual(r.events.map((e: any) => e.title).sort(), ["Late deploy", "Saturday chores"]);
});

test("prepare_create_event: an all-day date stays that date (DATE value, no zone shift)", async () => {
  const t = tools(); const cal: any = ((await t.call("list_calendars", {})) as any).calendars[0];
  const p: any = await t.call("prepare_create_event", { calendar_id: cal.calendar_id, title: "Pumpkin patch", start: "2026-10-17" });
  assert.match(p.preview, /Sat, Oct 17, 2026 \(all day\)/);
  await t.call("commit_create_event", { confirm_token: p.confirm_token });
  const put = mock.requests.find((r) => r.method === "PUT")!.body;
  assert.match(put, /DTSTART;VALUE=DATE:20261017/); assert.match(put, /DTEND;VALUE=DATE:20261018/);
});

test("repeat.until with a bare date includes that whole local day (timed) and uses a DATE (all-day)", async () => {
  const t = tools(); const cal: any = ((await t.call("list_calendars", {})) as any).calendars[0];
  const p: any = await t.call("prepare_create_event", { calendar_id: cal.calendar_id, title: "Evening walk", start: "2026-10-19T19:00", end: "2026-10-19T19:30", repeat: { every: "day", until: "2026-10-21" } });
  await t.call("commit_create_event", { confirm_token: p.confirm_token });
  const put = mock.requests.filter((r) => r.method === "PUT").at(-1)!.body;
  assert.match(put, /RRULE:FREQ=DAILY;UNTIL=20261022T055959Z/, "end of Oct 21 in Denver, in UTC");
  const r: any = await tools().call("list_events", { from: "2026-10-19", to: "2026-10-25", calendar_ids: [cal.calendar_id] });
  assert.deepEqual(r.events.filter((e: any) => e.title === "Evening walk").map((e: any) => e.start), ["2026-10-19T19:00:00-06:00", "2026-10-20T19:00:00-06:00", "2026-10-21T19:00:00-06:00"], "Oct 21 at 7 PM is not dropped");
  const q: any = await t.call("prepare_create_event", { calendar_id: cal.calendar_id, title: "Trip", start: "2026-10-19", repeat: { every: "week", until: "2026-11-30" } });
  await t.call("commit_create_event", { confirm_token: q.confirm_token });
  assert.match(mock.requests.filter((r) => r.method === "PUT").at(-1)!.body, /RRULE:FREQ=WEEKLY;UNTIL=20261130\r\n/);
  await assert.rejects(t.call("prepare_create_event", { calendar_id: cal.calendar_id, title: "x", start: "2026-10-19T09:00", repeat: { every: "day", until: "2026-10-01" } }), /after the start/);
});

test("a new repeating 9 AM event stays 9 AM after DST ends (TZID + VTIMEZONE, not UTC)", async () => {
  const t = tools(); const cal: any = ((await t.call("list_calendars", {})) as any).calendars[0];
  const p: any = await t.call("prepare_create_event", { calendar_id: cal.calendar_id, title: "Standup", start: "2026-10-26T09:00", end: "2026-10-26T09:15", repeat: { every: "week", count: 3 } });
  await t.call("commit_create_event", { confirm_token: p.confirm_token });
  const body = mock.requests.filter((r) => r.method === "PUT").at(-1)!.body;
  assert.match(body, /DTSTART;TZID=America\/Denver:20261026T090000/);
  assert.match(body, /BEGIN:DAYLIGHT[\s\S]*TZOFFSETFROM:-0700[\s\S]*TZOFFSETTO:-0600[\s\S]*RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=2SU/);
  assert.match(body, /BEGIN:STANDARD[\s\S]*TZOFFSETTO:-0700[\s\S]*RRULE:FREQ=YEARLY;BYMONTH=11;BYDAY=1SU/);
  const r: any = await tools().call("list_events", { from: "2026-10-26", to: "2026-11-10", calendar_ids: [cal.calendar_id] });
  assert.deepEqual(r.events.filter((e: any) => e.title === "Standup").map((e: any) => e.start), ["2026-10-26T09:00:00-06:00", "2026-11-02T09:00:00-07:00", "2026-11-09T09:00:00-07:00"]);
  // other zones: EU last-Sunday rules, southern hemisphere, and no-DST zones
  const eu = vtimezone("Europe/Berlin", 2026).join("\n"); assert.match(eu, /BYMONTH=3;BYDAY=-1SU/); assert.match(eu, /BYMONTH=10;BYDAY=-1SU/);
  const au = vtimezone("Australia/Sydney", 2026).join("\n"); assert.match(au, /BEGIN:DAYLIGHT[\s\S]*BYMONTH=10;BYDAY=1SU/); assert.match(au, /BEGIN:STANDARD[\s\S]*BYMONTH=4;BYDAY=1SU/);
  const jp = vtimezone("Asia/Tokyo", 2026).join("\n"); assert.match(jp, /TZOFFSETFROM:\+0900\nTZOFFSETTO:\+0900/); assert.doesNotMatch(jp, /RRULE/);
  assert.equal(parseIcs(body).children[0]!.children.filter((c) => c.type === "VTIMEZONE").length, 1);
});

// ---------- (b) no internal fields leak ----------
test("get_event and list_events return no internal fields (_sort)", async () => {
  const t = tools(); const r: any = await t.call("list_events", { from: "2026-10-16", to: "2026-10-18" });
  for (const e of r.events) assert.ok(!Object.keys(e).some((k) => k.startsWith("_")), JSON.stringify(Object.keys(e)));
  const g: any = await t.call("get_event", { event_id: r.events[0].event_id });
  assert.ok(!("_sort" in g)); assert.equal(g.title, "Friday movie"); assert.deepEqual(g.alerts, []);
});

// ---------- (c) Workers 'Illegal invocation' ----------
test("default fetch works when the runtime rejects an unbound/rebound fetch (Workers 'Illegal invocation')", async () => {
  const real = globalThis.fetch;
  // Workers throws if fetch is called with `this` set to anything other than the global scope.
  const strict = function (this: unknown, ...a: Parameters<typeof fetch>) { if (this !== undefined && this !== globalThis) throw new TypeError("Illegal invocation"); return real(...a); };
  (globalThis as any).fetch = strict;
  try {
    const cols = await new CalDavClient({ baseUrl: mock.base, username: USER, password: PASS }).listCollections();
    assert.ok(cols.length >= 2);
    const res: any = await (await mcpEndpoint(rpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "list_calendars", arguments: {} } }), env(), { epoch: EPOCH })).json();
    assert.equal(res.result.isError, false, JSON.stringify(res)); assert.ok(res.result.structuredContent.calendars.length >= 2);
  } finally { (globalThis as any).fetch = real; }
});

// ---------- (d) errors the model can act on ----------
test("bad input gets a specific, fixable message instead of 'Something went wrong'", async () => {
  const call = async (name: string, args: unknown) => ((await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }, () => tools())) as any).result;
  const a = await call("list_events", { from: "whenever suits" }); assert.equal(a.isError, true); assert.match(a.content[0].text, /Couldn't read the time "whenever suits"/);
  const b = await call("list_events", { start: "2026-10-17" }); assert.match(b.content[0].text, /Unknown argument: start\. Allowed: from, to/);
  const c = await call("search_events", {}); assert.match(c.content[0].text, /Missing required argument: query/);
  const d = await call("list_events", { limit: 5000 }); assert.match(d.content[0].text, /limit must be between 1 and 200/);
  const e = await call("get_event", { event_id: "!!!" }); assert.match(e.content[0].text, /isn't valid/);
  const f = await call("list_events", { from: "2026-02-30" }); assert.match(f.content[0].text, /Couldn't read the time/);
  assert.ok(![a, b, c, d, e, f].some((x) => /Something went wrong/.test(x.content[0].text)));
  assert.equal(parseUserTime("2026-10-17 9:05", TZ).utc, parseUserTime("2026-10-17T09:05", TZ).utc, "space separator accepted");
});

// ---------- recurrence patterns iCloud actually writes ----------
test("recurrence: monthly ordinals (2nd Tuesday, last Friday), month-day lists, yearly BYMONTH (Thanksgiving)", () => {
  const at = (iso: string) => ({ utc: Date.parse(iso), allDay: false, tz: "America/Denver" });
  const day = (y: number, m: number, d: number) => ({ utc: Date.UTC(y, m - 1, d), allDay: true });
  const run = (s: any, rule: string, to = Date.UTC(2027, 6, 1)) => expand(s, 3600000, rule, [], 0, to);
  const tue = run(at("2026-10-13T16:00:00Z"), "FREQ=MONTHLY;BYDAY=2TU;COUNT=4");
  assert.equal(tue.supported, true);
  assert.deepEqual(tue.occ.map((o) => new Date(o.start).toISOString()), ["2026-10-13T16:00:00.000Z", "2026-11-10T17:00:00.000Z", "2026-12-08T17:00:00.000Z", "2027-01-12T17:00:00.000Z"], "10 AM local stays 10 AM across DST");
  assert.deepEqual(run(day(2026, 10, 30), "FREQ=MONTHLY;BYDAY=-1FR;COUNT=3").occ.map((o) => ymd(o.start)), ["2026-10-30", "2026-11-27", "2026-12-25"]);
  assert.deepEqual(run(day(2026, 10, 1), "FREQ=MONTHLY;BYMONTHDAY=1,15;COUNT=4").occ.map((o) => ymd(o.start)), ["2026-10-01", "2026-10-15", "2026-11-01", "2026-11-15"]);
  assert.deepEqual(run(day(2026, 10, 31), "FREQ=MONTHLY;BYMONTHDAY=-1;COUNT=3").occ.map((o) => ymd(o.start)), ["2026-10-31", "2026-11-30", "2026-12-31"]);
  assert.deepEqual(run(day(2026, 11, 26), "FREQ=YEARLY;BYMONTH=11;BYDAY=4TH;COUNT=3", Date.UTC(2030, 0, 1)).occ.map((o) => ymd(o.start)), ["2026-11-26", "2027-11-25", "2028-11-23"]);
  assert.deepEqual(run(day(2026, 10, 1), "FREQ=MONTHLY;INTERVAL=2;BYDAY=1TH;COUNT=3").occ.map((o) => ymd(o.start)), ["2026-10-01", "2026-12-03", "2027-02-04"]);
  assert.deepEqual(run(day(2026, 10, 19), "FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR;COUNT=6").occ.map((o) => ymd(o.start)), ["2026-10-19", "2026-10-20", "2026-10-21", "2026-10-22", "2026-10-23", "2026-10-26"]);
  assert.equal(run(day(2026, 10, 1), "FREQ=YEARLY;BYDAY=20MO").supported, false);
  assert.equal(run(day(2026, 10, 1), "FREQ=MONTHLY;BYDAY=TU;BYSETPOS=-1").supported, false);
  assert.equal(dayStartIn(Date.UTC(2026, 10, 1), TZ), Date.parse("2026-11-01T06:00:00Z"), "DST-change day starts at local midnight (MDT)");
});

// ---------- MCP 2026-07-28 (stateless) and older clients ----------
test("MCP: server/discover, per-request _meta version, unsupported version and header mismatch", async () => {
  const meta = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} };
  const d: any = await (await mcpEndpoint(rpc({ jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: meta } }), env(), { epoch: EPOCH })).json();
  assert.deepEqual(d.result.supportedVersions, SUPPORTED); assert.equal(d.result.resultType, "complete"); assert.equal(d.result.cacheScope, "public"); assert.ok(d.result.ttlMs > 0);
  assert.equal(d.result._meta["io.modelcontextprotocol/serverInfo"].name, "holdt");
  const l: any = await (await mcpEndpoint(rpc({ jsonrpc: "2.0", id: 2, method: "tools/list", params: { _meta: meta } }, { "MCP-Protocol-Version": "2026-07-28" }), env(), { epoch: EPOCH })).json();
  assert.equal(l.result.resultType, "complete"); assert.ok(l.result.tools.length >= 7); assert.ok(l.result.ttlMs > 0);
  const c: any = await (await mcpEndpoint(rpc({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { _meta: meta, name: "connection_status", arguments: {} } }), env(), { epoch: EPOCH })).json();
  assert.equal(c.result.resultType, "complete"); assert.equal(c.result.structuredContent.timezone, TZ);
  const bad = await mcpEndpoint(rpc({ jsonrpc: "2.0", id: 4, method: "tools/list", params: { _meta: { ...meta, "io.modelcontextprotocol/protocolVersion": "2099-01-01" } } }), env(), { epoch: EPOCH });
  assert.equal(bad.status, 400); const bj: any = await bad.json(); assert.equal(bj.error.code, -32022); assert.deepEqual(bj.error.data.supported, SUPPORTED); assert.equal(bj.error.data.requested, "2099-01-01");
  const mm = await mcpEndpoint(rpc({ jsonrpc: "2.0", id: 5, method: "tools/list", params: { _meta: meta } }, { "MCP-Protocol-Version": "2025-06-18" }), env(), { epoch: EPOCH });
  assert.equal(mm.status, 400); assert.equal(((await mm.json()) as any).error.code, -32020);
  const hdr = await mcpEndpoint(rpc({ jsonrpc: "2.0", id: 6, method: "tools/list" }, { "MCP-Protocol-Version": "1999-01-01" }), env(), { epoch: EPOCH });
  assert.equal(hdr.status, 400);
  // legacy clients see exactly the old shapes
  const init: any = await (await mcpEndpoint(rpc({ jsonrpc: "2.0", id: 7, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {} } }), env(), { epoch: EPOCH })).json();
  assert.equal(init.result.protocolVersion, "2025-11-25"); assert.equal(init.result.resultType, undefined);
  const legacy: any = await (await mcpEndpoint(rpc({ jsonrpc: "2.0", id: 8, method: "tools/list" }), env(), { epoch: EPOCH })).json();
  assert.equal(legacy.result.resultType, undefined); assert.equal(legacy.result.ttlMs, undefined);
});

test("MCP: every read tool declares an outputSchema its structuredContent satisfies (required keys present)", async () => {
  const list: any = ((await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/list" }, () => tools())) as any).result.tools;
  const t = tools(); const evs: any = await t.call("list_events", { from: "2026-10-16", to: "2026-10-18" });
  const results: Record<string, any> = { connection_status: await t.call("connection_status", {}), list_calendars: await t.call("list_calendars", {}), list_events: evs, search_events: await t.call("search_events", { query: "movie" }), get_event: await t.call("get_event", { event_id: evs.events[0].event_id }) };
  for (const [name, res] of Object.entries(results)) {
    const schema = list.find((x: any) => x.name === name).outputSchema; assert.ok(schema, name);
    for (const k of schema.required ?? []) assert.ok(k in res, `${name} missing ${k}`);
    for (const [k, v] of Object.entries(res)) { const want = schema.properties[k]?.type; if (want && v !== undefined) assert.equal(Array.isArray(v) ? "array" : Number.isInteger(v) && want === "integer" ? "integer" : typeof v, want, `${name}.${k}`); }
  }
  for (const e of [...evs.events, results.get_event]) for (const k of list.find((x: any) => x.name === "get_event").outputSchema.required) assert.ok(k in e, k);
});

// ---------- confirm tokens are single-use across requests ----------
test("a commit token can't be replayed in a later request (KV-backed nonce store)", async () => {
  const kv = new MockKV(); const store = kvUsedStore(kv)!;
  const a = tools(true, store); const cal: any = ((await a.call("list_calendars", {})) as any).calendars[0];
  const r: any = await a.call("list_events", { from: "2026-10-16", to: "2026-10-16", calendar_ids: [cal.calendar_id] });
  const p: any = await a.call("prepare_update_event", { event_id: r.events[0].event_id, title: "Friday movie night" });
  assert.equal(((await a.call("commit_update_event", { confirm_token: p.confirm_token })) as any).done, true);
  const b = tools(true, store); // a fresh request, as on the Worker
  await assert.rejects(b.call("commit_update_event", { confirm_token: p.confirm_token }), /already made/);
  assert.equal(mock.requests.filter((x) => x.method === "PUT").length, 1);
  assert.ok([...kv.m.keys()].some((k) => k.startsWith("confirm-used:")));
});

test("list_events: paging without from still works (the cursor keeps the first call's window)", async () => {
  for (let i = 0; i < 5; i++) mock.add("home", `soon-${i}.ics`, ev(`soon-${i}`, [`DTSTART:${new Date(Date.now() + (i + 1) * 3600_000).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "")}`, "DURATION:PT30M", `SUMMARY:Soon ${i}`]));
  const t = tools(); const p1: any = await t.call("list_events", { limit: 2 });
  assert.ok(p1.next_cursor); await new Promise((r) => setTimeout(r, 5));
  const p2: any = await t.call("list_events", { limit: 2, cursor: p1.next_cursor });
  assert.equal(p2.from, p1.from); assert.notDeepEqual(p2.events.map((e: any) => e.title), p1.events.map((e: any) => e.title));
});

test("discovery is cached per isolate: a second tool call skips the two discovery PROPFINDs", async () => {
  await tools().call("list_calendars", {}); const first = mock.requests.length; mock.requests = [];
  await tools().call("list_calendars", {}); const second = mock.requests.length;
  assert.ok(second < first, `${second} < ${first}`);
  assert.ok(!mock.requests.some((r) => r.url.includes("well-known")));
});

test("SECRET SAFETY (audit): nothing secret in any log line", () => {
  const blob = logs.join("\n");
  for (const bad of [PASS, USER, Buffer.from(`${USER}:${PASS}`).toString("base64")]) assert.ok(!blob.includes(bad));
});
