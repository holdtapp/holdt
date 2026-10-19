import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { makeMock, seed, makeTools } from "./helpers.js";
import { MockKV } from "./kv-mock.js";
import { kvUsedStore } from "../src/worker.js";
import { randomBytes } from "node:crypto";

const mock = makeMock();
before(() => mock.start()); after(() => mock.stop());
let kv: MockKV; beforeEach(() => { seed(mock); kv = new MockKV(); });
const T = (o: Record<string, unknown> = {}) => makeTools(mock, { journal: kv as any, owner: "test.user@example.com", usedStore: kvUsedStore(kv), ...o });
const method = (m: string) => mock.requests.filter((r) => r.method === m);
async function addOne(t = T()) {
  const p: any = await t.call("prepare_create_event", { calendar_id: "home", title: "Holdt test", start: "2026-11-03T12:00" });
  return (await t.call("commit_create_event", { confirm_token: p.confirm_token })) as any;
}
async function dentistId(t = T()) { return ((await t.call("search_events", { query: "Dentist", from: "2026-10-01", to: "2026-11-30" })) as any).events[0].event_id; }

test("undo a create: preview, yes, removed with If-Match, logged, and never twice", async () => {
  const c = await addOne(); assert.ok(c.revert_token); assert.match(c.undo, /24 hours/);
  const href = [...mock.items.keys()].find((k) => k.includes("/home/") && mock.items.get(k)!.ics.includes("Holdt test"))!;
  const p: any = await T().call("prepare_undo", { revert_token: c.revert_token });
  assert.match(p.preview, /^Remove "Holdt test" from Home\.\nHoldt added it .+\. Nothing else is touched\.$/);
  assert.equal(method("DELETE").length, 0, "prepare changes nothing");
  const r: any = await T().call("commit_undo", { confirm_token: p.confirm_token });
  assert.match(r.message, /Removed "Holdt test", which Holdt had added/);
  assert.equal(mock.items.has(href), false);
  const del = method("DELETE"); assert.equal(del.length, 1); assert.ok(del[0]!.headers["if-match"]);
  await assert.rejects(T().call("prepare_undo", { revert_token: c.revert_token }), /already taken back/);
  const l: any = await T().call("list_changes", {});
  assert.deepEqual(l.changes.map((x: any) => [x.what, x.title, !!x.undone, x.can_undo]), [["took back a change", "Holdt test", false, false], ["added", "Holdt test", true, false]]);
});

test("undo an edit restores the exact prior event", async () => {
  const id = await dentistId(); const href = [...mock.items.keys()].find((k) => k.endsWith("dentist.ics"))!;
  const before = mock.items.get(href)!.ics;
  const p: any = await T().call("prepare_update_event", { event_id: id, title: "Dentist (moved)", location: "" });
  const c: any = await T().call("commit_update_event", { confirm_token: p.confirm_token }); assert.ok(c.revert_token);
  assert.match(mock.items.get(href)!.ics, /Dentist \(moved\)/);
  const u: any = await T().call("prepare_undo", { revert_token: c.revert_token });
  assert.match(u.preview, /Title: "Dentist \(moved\)" → "Dentist"/); assert.match(u.preview, /Where: "" → "12 Main St"/);
  await T().call("commit_undo", { confirm_token: u.confirm_token });
  assert.equal(mock.items.get(href)!.ics, before);
  assert.equal(method("DELETE").length, 0, "an edit undo never removes anything");
});

test("undo refuses when the event was edited since Holdt's change", async () => {
  const id = await dentistId(); const href = [...mock.items.keys()].find((k) => k.endsWith("dentist.ics"))!;
  const p: any = await T().call("prepare_update_event", { event_id: id, notes: "Holdt note" });
  const c: any = await T().call("commit_update_event", { confirm_token: p.confirm_token });
  mock.items.set(href, { ics: mock.items.get(href)!.ics.replace("Holdt note", "Edited on iPhone"), etag: mock.etagSeq++ });
  await assert.rejects(T().call("prepare_undo", { revert_token: c.revert_token }), /edited after Holdt's change/);
  assert.match(mock.items.get(href)!.ics, /Edited on iPhone/);
});

test("undo refuses when the event changes between preview and yes", async () => {
  const c = await addOne(); const href = [...mock.items.keys()].find((k) => mock.items.get(k)!.ics.includes("Holdt test"))!;
  const p: any = await T().call("prepare_undo", { revert_token: c.revert_token });
  mock.items.set(href, { ics: mock.items.get(href)!.ics.replace("SUMMARY:Holdt test", "SUMMARY:Holdt test (moved by me)"), etag: mock.etagSeq++ });
  await assert.rejects(T().call("commit_undo", { confirm_token: p.confirm_token }), /changed after the undo preview/);
  assert.ok(mock.items.has(href)); assert.equal(method("DELETE").length, 0);
});

test("an added event can only be removed within 24 hours", async () => {
  const c = await addOne(); const later = Date.now() + 25 * 3600_000; kv.now = () => later;
  await assert.rejects(T({ now: () => later }).call("prepare_undo", { revert_token: c.revert_token }), /only removes events it added itself, within 24 hours/);
  const l: any = await T({ now: () => later }).call("list_changes", {});
  assert.equal(l.changes[0].can_undo, false); assert.equal(l.changes[0].revert_token, undefined);
});

test("list_changes hands out fresh revert tokens that work", async () => {
  await addOne();
  const l: any = await T().call("list_changes", { limit: 5 });
  assert.equal(l.changes.length, 1); assert.equal(l.changes[0].can_undo, true);
  const p: any = await T().call("prepare_undo", { revert_token: l.changes[0].revert_token }); assert.match(p.preview, /^Remove/);
});

test("no change log configured: commits still work, with no revert token", async () => {
  const t = makeTools(mock);
  const p: any = await t.call("prepare_create_event", { calendar_id: "home", title: "No log", start: "2026-11-03T12:00" });
  const c: any = await t.call("commit_create_event", { confirm_token: p.confirm_token });
  assert.equal(c.done, true); assert.equal(c.revert_token, undefined);
  assert.match(((await t.call("list_changes", {})) as any).note, /isn't available/);
});

test("read-only connections can't undo either", async () => {
  const c = await addOne();
  await assert.rejects(T({ writesEnabled: false }).call("prepare_undo", { revert_token: c.revert_token }), /turned off/);
});

test("a revert token can't be spent as a commit token, and vice versa", async () => {
  const c = await addOne();
  await assert.rejects(T().call("commit_undo", { confirm_token: c.revert_token }), /different kind of change/);
  const p: any = await T().call("prepare_undo", { revert_token: c.revert_token });
  await assert.rejects(T().call("prepare_undo", { revert_token: p.confirm_token }), /different kind of change/);
});

test("ATTACK E6: undo re-checks that the calendar is still writable, at preview and at yes", async () => {
  const c = await addOne();
  const p: any = await T().call("prepare_undo", { revert_token: c.revert_token });
  const before = mock.requests.length;
  mock.cols.home!.readOnly = true;
  try {
    await assert.rejects(T().call("prepare_undo", { revert_token: c.revert_token }), /read-only in iCloud now/);
    await assert.rejects(T().call("commit_undo", { confirm_token: p.confirm_token }), /read-only in iCloud now/);
    assert.equal(mock.requests.slice(before).filter((r) => r.method === "DELETE" || r.method === "PUT").length, 0, "nothing was sent to iCloud");
  } finally { mock.cols.home!.readOnly = false; }
});

// Change log sealing (P2). A storage-only reader sees ciphertext, and undo still restores the exact old bytes.
const sealKey = randomBytes(32).toString("base64url");
const rawLog = () => [...kv.m].filter(([k]) => k.startsWith("chg:")).map(([, e]) => e.v).join("\n");
async function withNotes() {
  const href = [...mock.items.keys()].find((k) => k.endsWith("dentist.ics"))!;
  mock.items.set(href, { ics: mock.items.get(href)!.ics.replace("LOCATION:12 Main St", "LOCATION:12 Main St\r\nDESCRIPTION:Gate code 4417"), etag: mock.etagSeq++ });
  return { href, before: mock.items.get(href)!.ics };
}

test("ATTACK E7: a storage-only reader can't read the title or pre-edit event in the change log, and undo restores the exact old bytes", async () => {
  const t = () => T({ sealKey }); const { href, before } = await withNotes();
  const p: any = await t().call("prepare_update_event", { event_id: await dentistId(t()), title: "Checkup", location: "", notes: "" });
  const c: any = await t().call("commit_update_event", { confirm_token: p.confirm_token });
  assert.ok(rawLog().length > 0);
  for (const s of ["Dentist", "Gate code 4417", "12 Main St", "Checkup"]) assert.ok(!rawLog().includes(s), `raw KV holds "${s}"`);
  const l: any = await t().call("list_changes", {}); assert.equal(l.changes[0].title, "Checkup");
  const u: any = await t().call("prepare_undo", { revert_token: c.revert_token });
  assert.match(u.preview, /Title: "Checkup" → "Dentist"/);
  await t().call("commit_undo", { confirm_token: u.confirm_token });
  assert.equal(mock.items.get(href)!.ics, before);
  for (const s of ["Dentist", "Gate code 4417", "12 Main St", "Checkup"]) assert.ok(!rawLog().includes(s), `raw KV holds "${s}" after undo`);
});

test("change log entries written in plain text before SEAL_KEY was set still undo exactly", async () => {
  const { href, before } = await withNotes();
  const p: any = await T().call("prepare_update_event", { event_id: await dentistId(), notes: "" });
  const c: any = await T().call("commit_update_event", { confirm_token: p.confirm_token });
  assert.match(rawLog(), /Gate code 4417/, "without SEAL_KEY the log is plain text");
  const u: any = await T({ sealKey }).call("prepare_undo", { revert_token: c.revert_token });
  await T({ sealKey }).call("commit_undo", { confirm_token: u.confirm_token });
  assert.equal(mock.items.get(href)!.ics, before);
});

test("ATTACK E8: a change sealed under another SEAL_KEY can't be undone and nothing is written", async () => {
  const p: any = await T({ sealKey }).call("prepare_update_event", { event_id: await dentistId(), title: "Checkup" });
  const c: any = await T({ sealKey }).call("commit_update_event", { confirm_token: p.confirm_token });
  const other = () => T({ sealKey: randomBytes(32).toString("base64url") }); const puts = method("PUT").length;
  await assert.rejects(other().call("prepare_undo", { revert_token: c.revert_token }), /can't read that change well enough/);
  const u: any = await T({ sealKey }).call("prepare_undo", { revert_token: c.revert_token });
  await assert.rejects(other().call("commit_undo", { confirm_token: u.confirm_token }), /can't read that change well enough/);
  const l: any = await other().call("list_changes", {});
  assert.equal(l.changes[0].title, "(can't be read)"); assert.equal(l.changes[0].can_undo, false); assert.equal(l.changes[0].revert_token, undefined);
  assert.equal(method("PUT").length, puts, "nothing was sent to iCloud");
});

test("an added event logged under another SEAL_KEY can't be removed, and no request is sent", async () => {
  const c = await addOne(T({ sealKey }));
  const u: any = await T({ sealKey }).call("prepare_undo", { revert_token: c.revert_token });
  const other = () => T({ sealKey: randomBytes(32).toString("base64url") }); const sent = mock.requests.length;
  await assert.rejects(other().call("prepare_undo", { revert_token: c.revert_token }), /can't read that change well enough/);
  await assert.rejects(other().call("commit_undo", { confirm_token: u.confirm_token }), /can't read that change well enough/);
  assert.equal(mock.requests.length, sent, "no request reached iCloud");
  assert.equal(((await other().call("list_changes", {})) as any).changes[0].can_undo, false);
  assert.ok([...mock.items.values()].some((x) => x.ics.includes("Holdt test")), "the event is still there");
});
