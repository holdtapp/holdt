import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { makeMock, seed, makeTools } from "./helpers.js";
import { MockKV } from "./kv-mock.js";
import { kvUsedStore } from "../src/worker.js";

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
  mock.items.set(href, { ics: mock.items.get(href)!.ics, etag: mock.etagSeq++ });
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
