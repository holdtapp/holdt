// Fuzz every tool input with line breaks, control characters and smuggled iCalendar lines, through the real
// MCP endpoint (schema validation included), committing every preview that comes back. Then check every byte
// Holdt sent to iCloud: one property per line, no control characters, and never an ATTENDEE or ORGANIZER.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { makeMock, seed, USER, PASS, TZ } from "./helpers.js";
import { mcpEndpoint } from "../src/worker.js";
import { TOOLS } from "../src/tools.js";
import { strictSchemaProblems } from "../src/mcp.js";
import { unfold, assertSafeIcs, buildEvent } from "../src/ical.js";
import { setLogSink } from "../src/redact.js";
import { MockKV } from "./kv-mock.js";

setLogSink(() => {});
const mock = makeMock(); before(() => mock.start()); after(() => mock.stop());
const EPOCH = "e".repeat(40);
let kv: MockKV;
const env = () => ({ ICLOUD_EMAIL: USER, ICLOUD_APP_PASSWORD: PASS, GRANT_EPOCH: EPOCH, CONFIRM_SECRET: "c".repeat(32), TIMEZONE: TZ, WRITES_ENABLED: "true", CALDAV_URL: mock.base, OAUTH_KV: kv });
async function call(name: string, args: unknown) {
  const req = new Request("http://w/mcp", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) });
  const j: any = await (await mcpEndpoint(req, env() as any, { epoch: EPOCH })).json();
  return j.result?.structuredContent ?? (j.result?.content?.[0]?.text ? safeJson(j.result.content[0].text) : undefined);
}
const safeJson = (s: string) => { try { return JSON.parse(s); } catch { return undefined; } };

const PAYLOADS = ["\r\nATTENDEE:mailto:x@evil.example", "\nORGANIZER:mailto:x@evil.example", "\rATTENDEE:mailto:x@evil.example", "x\u0000ATTENDEE:mailto:x", "\u2028ATTENDEE:mailto:x", "\u0085ATTENDEE:mailto:x",
  "\u000bATTENDEE:mailto:x", "\\nATTENDEE:mailto:x", "a;ATTENDEE=x:y", "\u202egnp.exe", "\u200b\ufeff", "\r\n BEGIN:VALARM\r\nACTION:EMAIL", "\t\r\n\tATTENDEE:mailto:x", "%0d%0aATTENDEE:mailto:x"];
// A valid base call for every tool. Each string, number and list field is then replaced by every payload.
async function bases(): Promise<Record<string, Record<string, unknown>>> {
  const ev: any = await call("search_events", { query: "Dentist", from: "2026-10-01", to: "2026-11-30" });
  return {
    connection_status: {}, list_calendars: {}, list_changes: { limit: 5 },
    list_events: { from: "2026-10-26", to: "2026-10-27", calendar_ids: ["home"], limit: 5 },
    search_events: { query: "Standup", from: "2026-10-01", to: "2026-11-30", limit: 5 },
    get_event: { event_id: ev.events[0].event_id },
    resolve_dates: { phrases: ["next friday 3pm"] },
    find_free_time: { from: "2026-10-26", to: "2026-10-27", calendar_ids: ["home"], min_minutes: 30, working_hours: { start: "09:00", end: "17:00", days: ["mon"] } },
    prepare_create_event: { calendar_id: "home", title: "Fuzz", start: "2026-11-03T12:00", end: "2026-11-03T13:00", location: "Here", notes: "Notes", alerts_minutes_before: [10], repeat: { every: "week", interval: 1, count: 3 } },
    prepare_update_event: { event_id: ev.events[0].event_id, title: "Fuzz", location: "There", notes: "N" },
    prepare_undo: { revert_token: "x.y" }, commit_create_event: { confirm_token: "x.y" }, commit_update_event: { confirm_token: "x.y" }, commit_undo: { confirm_token: "x.y" },
  };
}
function mutations(base: Record<string, unknown>): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  const visit = (v: unknown, set: (x: unknown) => void) => {
    if (typeof v === "string") for (const p of PAYLOADS) { set(v + p); set(p); }
    else if (typeof v === "number" || typeof v === "boolean") for (const p of PAYLOADS.slice(0, 4)) { set(`${v}${p}`); set([v, p]); }
    else if (Array.isArray(v)) { v.forEach((x, i) => visit(x, (y) => { const c = [...v]; c[i] = y; set(c); })); set([...v, PAYLOADS[0]]); }
    else if (v && typeof v === "object") for (const k of Object.keys(v)) visit((v as any)[k], (y) => set({ ...(v as any), [k]: y }));
  };
  for (const k of Object.keys(base)) visit(base[k], (y) => out.push({ ...base, [k]: y }));
  for (const p of PAYLOADS.slice(0, 3)) out.push({ ...base, [`extra${p}`]: "x" });
  return out;
}
function checkWrites() {
  for (const r of mock.requests.filter((x) => x.method === "PUT")) {
    assert.doesNotMatch(r.body, /\r(?!\n)/, "no bare CR");
    for (const l of unfold(r.body)) {
      assert.match(l, /^[A-Za-z][A-Za-z0-9-]*(;[^:]*)?:/, `one property per line: ${JSON.stringify(l).slice(0, 80)}`);
      assert.doesNotMatch(l, /[\u0000-\u0008\u000a-\u001f\u007f]/, "no control characters");
      assert.doesNotMatch(l, /^(ATTENDEE|ORGANIZER|ATTACH)[;:]/i, `no smuggled ${l.slice(0, 20)}`);
      assert.doesNotMatch(l, /^ACTION:EMAIL/i);
    }
  }
}

test("schema rule: every tool input is strictly typed and bounded", () => {
  assert.deepEqual(strictSchemaProblems(TOOLS), []);
});

test("fuzz: CR/LF/control characters in every tool input never reach an ICS line", async () => {
  seed(mock); kv = new MockKV(); let calls = 0, commits = 0;
  const b = await bases();
  for (const t of TOOLS) assert.ok(t.name in b || /reminder/.test(t.name), `fuzz base missing for ${t.name}`);
  for (const [name, base] of Object.entries(b)) for (const args of mutations(base)) {
    calls++; const r: any = await call(name, args);
    if (r?.confirm_token) { const commit = name.replace("prepare_", "commit_"); const c: any = await call(commit === "commit_undo" ? "commit_undo" : commit, { confirm_token: r.confirm_token }); if (c?.done) commits++; }
  }
  checkWrites();
  assert.ok(calls > 400, `ran ${calls} fuzz calls`);
  assert.ok(commits > 0, "some fuzzed previews were valid and committed, so the write path was exercised");
});

test("output invariant: no ICS with a control character, a broken line or a new invitee ever leaves Holdt", () => {
  assert.throws(() => assertSafeIcs("BEGIN:VCALENDAR\r\nSUMMARY:x\rATTENDEE:y\r\nEND:VCALENDAR\r\n"), /malformed/);
  assert.throws(() => assertSafeIcs("BEGIN:VCALENDAR\r\nnot a property\r\nEND:VCALENDAR\r\n"), /malformed/);
  assert.throws(() => assertSafeIcs("BEGIN:VCALENDAR\r\nATTENDEE:mailto:x\r\nEND:VCALENDAR\r\n"), /invitee/);
  assert.doesNotThrow(() => assertSafeIcs("BEGIN:VCALENDAR\r\nATTENDEE:mailto:x\r\nEND:VCALENDAR\r\n", 1));
  const ics = buildEvent("u@x", { title: "Tab\there", start: { utc: Date.UTC(2026, 10, 3, 19), allDay: false }, end: { utc: Date.UTC(2026, 10, 3, 20), allDay: false }, tz: TZ });
  assert.ok(assertSafeIcs(ics));
});
