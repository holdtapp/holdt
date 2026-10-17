// Item 4 wiring: tools accept plain-English dates, resolved in the user's zone against the fixed clock.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { makeMock, seed, makeTools } from "./helpers.js";

const mock = makeMock();
before(() => mock.start()); after(() => mock.stop()); beforeEach(() => seed(mock));

const NOW = Date.parse("2026-10-17T12:00:00Z"); // Sat Oct 17 2026, 06:00 MDT

test("resolve_dates reads phrases, shows its reading, and reports bad ones without throwing", async () => {
  const t = makeTools(mock, { now: () => NOW });
  const r: any = await t.call("resolve_dates", { phrases: ["next friday 3pm", "end of month", "this weekend", "nonsense words"] });
  assert.equal(r.timezone, "America/Denver");
  assert.equal(r.results[0].start, "2026-10-23T15:00:00-06:00"); // "next" = the Mon to Sun week after this one
  assert.equal(r.results[0].reads_as.length > 0, true);
  assert.equal(r.results[1].start, "2026-10-31"); assert.equal(r.results[1].all_day, true);
  assert.equal(r.results[2].start, "2026-10-17"); assert.equal(r.results[2].end, "2026-10-18");
  assert.match(r.results[3].error, /Couldn't read the time/);
});

test("prepare_create_event takes phrases; a bare end time follows the start's day", async () => {
  const t = makeTools(mock, { now: () => NOW });
  const p: any = await t.call("prepare_create_event", { calendar_id: "home", title: "Call Mom", start: "tomorrow at 3pm", end: "4pm" });
  assert.match(p.preview, /When: Sun, Oct 18, 2026, 3:00 PM MDT to Sun, Oct 18, 2026, 4:00 PM MDT/);
  const d: any = await t.call("prepare_create_event", { calendar_id: "home", title: "Trip", start: "nov 2" });
  assert.match(d.preview, /Mon, Nov 2, 2026/);
});

test("list_events and find_free_time take phrase bounds, and a range phrase covers its whole span", async () => {
  const t = makeTools(mock, { now: () => NOW });
  const a: any = await t.call("list_events", { from: "oct 26", to: "oct 28" });
  const b: any = await t.call("list_events", { from: "2026-10-26", to: "2026-10-28" });
  assert.ok(a.events.length > 0);
  assert.deepEqual(a.events.map((e: any) => e.event_id), b.events.map((e: any) => e.event_id));
  const f: any = await t.call("find_free_time", { from: "next week", to: "next week", min_minutes: 30 });
  assert.ok(f.free.length > 0, JSON.stringify(f).slice(0, 300));
  assert.ok(f.free.every((s: any) => s.start >= "2026-10-19" && s.end <= "2026-10-26T00:00:00-06:00"));
});
