// Live, commit_undo failed every time with "The event changed in iCloud since it was read": the DELETE's If-Match was
// refused (412) although the content was untouched. These cover every way the ETag can arrive in a form If-Match
// can't use, a spurious 412, and that a real edit (before or between attempts) still blocks the write.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { makeMock, seed, makeTools } from "./helpers.js";
import { MockKV } from "./kv-mock.js";
import { kvUsedStore } from "../src/worker.js";
import { ifMatchValue, etagForm } from "../src/caldav.js";

const mock = makeMock();
before(() => mock.start()); after(() => mock.stop());
let kv: MockKV; beforeEach(() => { seed(mock); kv = new MockKV(); });
const T = () => makeTools(mock, { journal: kv as any, owner: "test.user@example.com", usedStore: kvUsedStore(kv) });
const writes = () => mock.requests.filter((r) => (r.method === "DELETE" || r.method === "PUT") && r.headers["if-match"]);
const href = () => [...mock.items.keys()].find((k) => mock.items.get(k)!.ics.includes("Holdt undo test"));
async function addAndPreview() {
  const p: any = await T().call("prepare_create_event", { calendar_id: "home", title: "Holdt undo test (safe to delete)", start: "2026-10-18T11:00", repeat: { every: "week", count: 4 } });
  const c: any = await T().call("commit_create_event", { confirm_token: p.confirm_token });
  return (await T().call("prepare_undo", { revert_token: c.revert_token })) as any;
}
async function editAndPreview() {
  const s: any = await T().call("search_events", { query: "Dentist", from: "2026-10-01", to: "2026-11-30" });
  const u: any = await T().call("prepare_update_event", { event_id: s.events[0].event_id, title: "Dentist (moved)" });
  const cu: any = await T().call("commit_update_event", { confirm_token: u.confirm_token });
  return (await T().call("prepare_undo", { revert_token: cu.revert_token })) as any;
}
const strongQuoted = () => { for (const w of writes()) assert.match(String(w.headers["if-match"]), /^"[^"]+"$/, "If-Match is a strong, quoted tag"); };

test("REDTEAM V1: a GET ETag header weakened in transit (W/) doesn't break update, undo of an add, or undo of an edit", async () => {
  mock.getEtag = (e) => `W/${e}`;
  const p = await addAndPreview(); await T().call("commit_undo", { confirm_token: p.confirm_token }); assert.equal(href(), undefined);
  const q = await editAndPreview(); const r: any = await T().call("commit_undo", { confirm_token: q.confirm_token }); assert.match(r.message, /back the way it was/);
  strongQuoted();
});

test("REDTEAM V2: a GET ETag header that differs in value from getetag doesn't matter, the multiget ETag is used", async () => {
  mock.getEtag = (e) => `"hdr-${e.replace(/"/g, "")}-x"`;
  const p = await addAndPreview(); await T().call("commit_undo", { confirm_token: p.confirm_token }); assert.equal(href(), undefined);
  const q = await editAndPreview(); await T().call("commit_undo", { confirm_token: q.confirm_token });
  strongQuoted();
});

test("REDTEAM V3: a bare (unquoted) getetag is quoted for If-Match", async () => {
  mock.reportEtag = (e) => e.replace(/"/g, "");
  const p = await addAndPreview(); await T().call("commit_undo", { confirm_token: p.confirm_token }); assert.equal(href(), undefined);
  strongQuoted();
});

test("REDTEAM V4: a spurious 412 is retried once after a fresh read and check; two in a row refuse with nothing removed", async () => {
  let p = await addAndPreview(); mock.spurious412 = 1;
  await T().call("commit_undo", { confirm_token: p.confirm_token }); assert.equal(href(), undefined);
  assert.equal(mock.requests.filter((r) => r.method === "DELETE").length, 2);
  seed(mock); kv = new MockKV();
  p = await addAndPreview(); mock.spurious412 = 2;
  await assert.rejects(T().call("commit_undo", { confirm_token: p.confirm_token }), /changed in iCloud since it was read/);
  assert.ok(href(), "still there"); assert.equal(mock.requests.filter((r) => r.method === "DELETE").length, 2, "exactly one retry");
  const q = await editAndPreview(); mock.spurious412 = 1;
  const r: any = await T().call("commit_undo", { confirm_token: q.confirm_token }); assert.match(r.message, /back the way it was/);
});

test("REDTEAM V5: a real edit, before the yes or in the gap after a 412, still refuses and removes nothing", async () => {
  let p = await addAndPreview(); const h = href()!;
  mock.items.set(h, { ics: mock.items.get(h)!.ics.replace("SUMMARY:Holdt undo test (safe to delete)", "SUMMARY:Holdt undo test (keep, edited)"), etag: mock.etagSeq++ });
  await assert.rejects(T().call("commit_undo", { confirm_token: p.confirm_token }), /changed after the undo preview/);
  assert.ok(href()); assert.equal(mock.requests.filter((r) => r.method === "DELETE").length, 0);
  seed(mock); kv = new MockKV();
  p = await addAndPreview(); const h2 = href()!; mock.spurious412 = 1;
  mock.after412 = () => mock.items.set(h2, { ics: mock.items.get(h2)!.ics.replace(/DTSTART;TZID=America\/Denver:20261018T110000/, "DTSTART;TZID=America/Denver:20261018T140000"), etag: mock.etagSeq++ });
  await assert.rejects(T().call("commit_undo", { confirm_token: p.confirm_token }), /changed after the undo preview/);
  assert.ok(mock.items.has(h2), "the edited event stays");
  const q = await editAndPreview(); const dh = [...mock.items.keys()].find((k) => k.endsWith("dentist.ics"))!; mock.spurious412 = 1;
  mock.after412 = () => mock.items.set(dh, { ics: mock.items.get(dh)!.ics.replace("Dentist (moved)", "Dentist (moved again by me)"), etag: mock.etagSeq++ });
  await assert.rejects(T().call("commit_undo", { confirm_token: q.confirm_token }), /changed after the undo preview/);
  assert.match(mock.items.get(dh)!.ics, /moved again by me/, "the user's edit survives");
});

test("REDTEAM V6: without multiget support, the GET header is used and a weak W/ is dropped for If-Match", async () => {
  mock.noMultiget = true; mock.getEtag = (e) => `W/${e}`;
  const p = await addAndPreview(); await T().call("commit_undo", { confirm_token: p.confirm_token }); assert.equal(href(), undefined);
  strongQuoted();
});

test("If-Match normalisation and ETag log form never expose the value", () => {
  assert.equal(ifMatchValue('W/"abc"'), '"abc"'); assert.equal(ifMatchValue("abc"), '"abc"'); assert.equal(ifMatchValue('"C=1@U=x"'), '"C=1@U=x"');
  assert.equal(etagForm('W/"secretvalue"'), "weak,quoted,len=15"); assert.equal(etagForm("abc"), "strong,bare,len=3"); assert.equal(etagForm(""), "none");
});
