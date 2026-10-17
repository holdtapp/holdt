// iCloud never stores an event byte-for-byte: it adds X-APPLE-* properties, refreshes DTSTAMP/LAST-MODIFIED/SEQUENCE,
// reorders and refolds lines, and serves a different ETag than the PUT response named. Undo must survive all of that
// (live, every undo of an add was refused as "edited") and must still refuse after a real edit by the user.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { makeMock, seed, makeTools } from "./helpers.js";
import { MockKV } from "./kv-mock.js";
import { kvUsedStore } from "../src/worker.js";
import { canonicalEvent } from "../src/fingerprint.js";
import { unfold, foldLine } from "../src/ical.js";

const mock = makeMock();
before(() => mock.start()); after(() => mock.stop());
let kv: MockKV; beforeEach(() => { seed(mock); kv = new MockKV(); });
const T = () => makeTools(mock, { journal: kv as any, owner: "test.user@example.com", usedStore: kvUsedStore(kv) });
const STAMP = "20261017T180000Z";

/** What iCloud does to an event it stores (from real iCloud exports): nothing a person would call an edit. */
function icloudRewrite(ics: string): string {
  const out: string[] = []; let props: string[] | null = null, alarms: string[][] = [], alarm: string[] | null = null;
  for (const l of unfold(ics)) {
    if (l === "BEGIN:VEVENT") { props = []; alarms = []; continue; }
    if (props && l === "BEGIN:VALARM") { alarm = [l]; continue; }
    if (alarm) { alarm.push(l); if (l === "END:VALARM") { if (!alarm.includes("X-APPLE-DEFAULT-ALARM:TRUE")) alarms.push(alarm); alarm = null; } continue; }
    if (props && l === "END:VEVENT") {
      const kept = props.filter((x) => !/^(DTSTAMP|LAST-MODIFIED|SEQUENCE|CREATED|X-APPLE-[A-Z-]+)[;:]/.test(x)).map((x) =>
        x.startsWith("RRULE:") ? "RRULE:" + x.slice(6).split(";").filter((y) => !y.startsWith("WKST=")).reverse().join(";") + ";WKST=SU" : x.replace(/\\,/g, ","));
      out.push("BEGIN:VEVENT", ...kept.reverse(), `DTSTAMP:${STAMP}`, `LAST-MODIFIED:${STAMP}`, "SEQUENCE:1", `CREATED:${STAMP}`,
        "X-APPLE-TRAVEL-ADVISORY-BEHAVIOR:AUTOMATIC", "X-APPLE-CREATOR-IDENTITY:com.apple.mobilecal", "X-APPLE-CREATOR-TEAM-IDENTITY:0000000000",
        ...alarms.flatMap((a) => [a[0]!, "X-WR-ALARMUID:1B2C", ...a.slice(1).filter((y) => !y.startsWith("X-WR-ALARMUID")).reverse().filter((y) => y !== "END:VALARM" && y !== "BEGIN:VALARM"), "END:VALARM"]),
        "BEGIN:VALARM", "X-WR-ALARMUID:9D1C1D6A-0000-4000-8000-000000000000", "UID:9D1C1D6A-0000-4000-8000-000000000000", "TRIGGER;VALUE=DATE-TIME:19760401T005545Z",
        "ACTION:NONE", "X-APPLE-DEFAULT-ALARM:TRUE", "END:VALARM", "END:VEVENT");
      props = null; continue;
    }
    if (props) { props.push(l); continue; }
    out.push(l.startsWith("PRODID:") ? "PRODID:-//Apple Inc.//iCloud Web Calendar//EN" : l);
  }
  return out.flatMap((l) => foldLine(l).split("\r\n")).join("\r\n") + "\r\n";
}
const href = () => [...mock.items.keys()].find((k) => mock.items.get(k)!.ics.includes("Weekly sync"))!;
const edit = (f: (ics: string) => string) => { const h = href(); mock.items.set(h, { ics: f(mock.items.get(h)!.ics), etag: mock.etagSeq++ }); };
async function addWeekly(t = T()) {
  const p: any = await t.call("prepare_create_event", { calendar_id: "home", title: "Weekly sync, team", start: "2026-11-03T12:00", location: "Room 4, 2nd floor", notes: "Agenda; bring notes", repeat: { every: "week", count: 4 } });
  return (await t.call("commit_create_event", { confirm_token: p.confirm_token })) as any;
}

test("REDTEAM U1: an add stays undoable after iCloud rewrites it (X-APPLE props, new DTSTAMP/SEQUENCE, reordered, refolded, new ETag)", async () => {
  mock.onPut = icloudRewrite; // the PUT response's ETag is already stale, exactly as on iCloud
  const c = await addWeekly(); mock.onPut = null;
  const putEtag = mock.requests.filter((r) => r.method === "PUT").length; assert.ok(putEtag);
  edit(icloudRewrite); // and iCloud may touch it again later
  const stored = mock.items.get(href())!.ics;
  assert.match(stored, /X-APPLE-TRAVEL-ADVISORY-BEHAVIOR/); assert.match(stored, /SEQUENCE:1/); assert.match(stored, /WKST=SU/);
  const p: any = await T().call("prepare_undo", { revert_token: c.revert_token });
  edit(icloudRewrite); // even between the preview and the yes
  const r: any = await T().call("commit_undo", { confirm_token: p.confirm_token });
  assert.match(r.message, /Removed "Weekly sync, team"/); assert.equal(href(), undefined);
});

test("REDTEAM U2: an edit stays revertible after iCloud rewrites it", async () => {
  const s: any = await T().call("search_events", { query: "Dentist", from: "2026-10-01", to: "2026-11-30" });
  const u: any = await T().call("prepare_update_event", { event_id: s.events[0].event_id, title: "Dentist (moved)" });
  mock.onPut = icloudRewrite; const cu: any = await T().call("commit_update_event", { confirm_token: u.confirm_token }); mock.onPut = null;
  const h = [...mock.items.keys()].find((k) => mock.items.get(k)!.ics.includes("Dentist (moved)"))!;
  mock.items.set(h, { ics: icloudRewrite(mock.items.get(h)!.ics), etag: mock.etagSeq++ });
  const p: any = await T().call("prepare_undo", { revert_token: cu.revert_token });
  const r: any = await T().call("commit_undo", { confirm_token: p.confirm_token });
  assert.match(r.message, /back the way it was/); assert.match(mock.items.get(h)!.ics, /SUMMARY:Dentist\r?\n/);
});

const EDITS: [string, (ics: string) => string][] = [
  ["title changed", (x) => x.replace(/SUMMARY:Weekly sync\\?, team/, "SUMMARY:Weekly sync, whole team")],
  ["time moved", (x) => x.replace(/DTSTART;TZID=America\/Denver:20261103T120000/, "DTSTART;TZID=America/Denver:20261103T130000")],
  ["one occurrence moved (override)", (x) => { const uid = /UID:([^\r\n]+)/.exec(x)![1]; return x.replace("END:VCALENDAR", `BEGIN:VEVENT\r\nUID:${uid}\r\nRECURRENCE-ID;TZID=America/Denver:20261110T120000\r\nDTSTART;TZID=America/Denver:20261110T150000\r\nDTEND;TZID=America/Denver:20261110T160000\r\nSUMMARY:Weekly sync\\, team\r\nDTSTAMP:${STAMP}\r\nEND:VEVENT\r\nEND:VCALENDAR`); }],
  ["one occurrence deleted (EXDATE)", (x) => x.replace(/(RRULE:[^\r\n]*COUNT=4[^\r\n]*)/, "$1\r\nEXDATE;TZID=America/Denver:20261117T120000")],
  ["repeat changed", (x) => x.replace("COUNT=4", "COUNT=6")],
  ["location changed", (x) => x.replace(/LOCATION:Room 4\\?, 2nd floor/, "LOCATION:Room 9")],
  ["alert added", (x) => x.replace("END:VEVENT", "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nDESCRIPTION:Reminder\r\nEND:VALARM\r\nEND:VEVENT")],
];
for (const [name, f] of EDITS) test(`REDTEAM U3: a real user edit still blocks undo, even mixed with an iCloud rewrite: ${name}`, async () => {
  mock.onPut = icloudRewrite; const c = await addWeekly(); mock.onPut = null;
  const before = mock.items.get(href())!.ics; edit(f); assert.notEqual(mock.items.get(href())!.ics, before, "the edit applied");
  edit(icloudRewrite);
  await assert.rejects(T().call("prepare_undo", { revert_token: c.revert_token }), /edited after Holdt's change/);
  assert.ok(href(), "still there");
});

test("REDTEAM U4: canonical form ignores iCloud noise and keeps every user field", () => {
  const base = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a\r\nDTSTAMP:20260101T000000Z\r\nDTSTART;TZID=America/Denver:20261103T120000\r\nDTEND;TZID=America/Denver:20261103T130000\r\nSUMMARY:A\\, b\r\nRRULE:FREQ=WEEKLY;COUNT=4\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
  assert.equal(canonicalEvent(icloudRewrite(base)), canonicalEvent(base));
  for (const [a, b] of [["SUMMARY:A\\, b", "SUMMARY:A\\, c"], ["T120000\r\nDTEND", "T120500\r\nDTEND"], ["COUNT=4", "COUNT=5"], ["TZID=America/Denver:20261103T130000", "TZID=America/New_York:20261103T130000"], ["END:VEVENT", "STATUS:CANCELLED\r\nEND:VEVENT"], ["END:VEVENT", "TRANSP:TRANSPARENT\r\nEND:VEVENT"], ["END:VEVENT", "ATTENDEE:mailto:x@example.com\r\nEND:VEVENT"]] as const)
    assert.notEqual(canonicalEvent(base.replace(a, b)), canonicalEvent(base), `${a} -> ${b}`);
});

test("REDTEAM U5: a change logged before 1.0.2 (no fingerprint) keeps the exact-ETag rule, never a looser one", async () => {
  mock.onPut = icloudRewrite; const c = await addWeekly(); mock.onPut = null;
  const k = (await kv.list({ prefix: "chg:" })).keys[0]!.name;
  const rec = JSON.parse((await kv.get(k))!); assert.ok(rec.afterFp);
  delete rec.afterFp; rec.afterEtag = `"${mock.items.get(href())!.etag - 1}"`; // the PUT response's ETag, which is what 1.0.1 stored
  await kv.put(k, JSON.stringify(rec));
  await assert.rejects(T().call("prepare_undo", { revert_token: c.revert_token }), /edited after Holdt's change/);
  assert.ok(href());
});
