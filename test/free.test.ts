import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { makeMock, seed, makeTools } from "./helpers.js";
import { merge, subtract, nearestSlots, workWindows, parseWorkingHours } from "../src/free.js";
import { wallToUtc } from "../src/ical.js";

const mock = makeMock();
before(() => mock.start()); after(() => mock.stop()); beforeEach(() => seed(mock));
const spans = (r: any) => r.free.map((f: any) => `${f.start.slice(5, 16)}-${f.end.slice(11, 16)}${f.end.slice(19)}`);

test("merge and subtract intervals", () => {
  assert.deepEqual(merge([[5, 8], [1, 3], [2, 4], [8, 9]]), [[1, 4], [5, 9]]);
  assert.deepEqual(subtract([[0, 10]], [[2, 3], [5, 7], [9, 12]]), [[0, 2], [3, 5], [7, 9]]);
  assert.deepEqual(subtract([[0, 10]], [[-5, 20]]), []);
  assert.deepEqual(subtract([[0, 4], [6, 10]], [[3, 7]]), [[0, 3], [7, 10]]);
});

test("nearestSlots picks the closest quarter-hour slots on both sides", () => {
  const M = 60000; const free: [number, number][] = [[0, 60 * M], [120 * M, 240 * M], [300 * M, 310 * M]];
  const r = nearestSlots(free, 30 * M, 90 * M, 3);
  assert.deepEqual(r, [[0, 30 * M], [30 * M, 60 * M], [120 * M, 150 * M]]); // the 10-minute gap is too short
});

test("working-hours windows keep 9 to 5 local across the DST change", () => {
  const tz = "America/Denver"; const from = wallToUtc(2026, 10, 30, 0, 0, 0, tz), to = wallToUtc(2026, 11, 3, 0, 0, 0, tz);
  const w = workWindows(from, to, tz, parseWorkingHours(true)!);
  assert.equal(w.length, 2); // Fri Oct 30, Mon Nov 2
  assert.equal(new Date(w[0]![0]).toISOString(), "2026-10-30T15:00:00.000Z"); // 09:00 MDT
  assert.equal(new Date(w[1]![0]).toISOString(), "2026-11-02T16:00:00.000Z"); // 09:00 MST
});

test("find_free_time: working hours, recurrence, EXDATE, invites, Free and cancelled events", async () => {
  const r: any = await makeTools(mock).call("find_free_time", { from: "2026-10-26", to: "2026-10-28", working_hours: true });
  assert.deepEqual(spans(r), [
    "10-26T09:30-17:00-06:00", // Mon: standup 9:00-9:30
    "10-27T09:00-14:00-06:00", "10-27T15:00-17:00-06:00", // Tue: review 14-15. Focus (TRANSP) and the cancelled event don't block
    "10-28T09:00-17:00-06:00"]); // Wed: standup skipped by EXDATE
  assert.equal(r.timezone, "America/Denver"); assert.match(r.note, /09:00 to 17:00/);
  assert.equal(r.total_free_minutes, 450 + 300 + 120 + 480);
});

test("find_free_time: repeats keep local time after DST ends", async () => {
  const r: any = await makeTools(mock).call("find_free_time", { from: "2026-11-02", to: "2026-11-02", working_hours: true });
  assert.deepEqual(spans(r), ["11-02T09:30-17:00-07:00"]);
});

test("find_free_time: all-day events are free by default and busy with all_day_blocks", async () => {
  const t = makeTools(mock);
  const a: any = await t.call("find_free_time", { from: "2026-10-30", to: "2026-10-30", working_hours: true });
  assert.deepEqual(spans(a), ["10-30T09:00-17:00-06:00"]);
  const b: any = await t.call("find_free_time", { from: "2026-10-30", to: "2026-10-30", working_hours: true, all_day_blocks: true });
  assert.deepEqual(b.free, []);
});

test("find_free_time: whole day without working hours, min_minutes, custom hours and days", async () => {
  const t = makeTools(mock);
  const a: any = await t.call("find_free_time", { from: "2026-10-29", to: "2026-10-29" });
  assert.deepEqual(spans(a), ["10-29T00:00-10:30-06:00", "10-29T11:30-00:00-06:00"]);
  const b: any = await t.call("find_free_time", { from: "2026-10-26", to: "2026-10-27", working_hours: { start: "08:00", end: "09:15", days: ["monday", "tue"] }, min_minutes: 60 });
  assert.deepEqual(spans(b), ["10-26T08:00-09:00-06:00", "10-27T08:00-09:15-06:00"]);
  const c: any = await t.call("find_free_time", { from: "2026-10-26", to: "2026-10-27", calendar_ids: ["work"], working_hours: true });
  assert.deepEqual(spans(c), ["10-26T09:00-17:00-06:00", "10-27T09:00-14:00-06:00", "10-27T15:00-17:00-06:00"]);
});

test("find_free_time: clear errors for bad input", async () => {
  const t = makeTools(mock);
  await assert.rejects(t.call("find_free_time", { from: "2026-10-01", to: "2026-12-31" }), /62 days/);
  await assert.rejects(t.call("find_free_time", { working_hours: { start: "17:00", end: "09:00" } }), /after working_hours.start/);
  await assert.rejects(t.call("find_free_time", { working_hours: { days: ["funday"] } }), /isn't a day name/);
  await assert.rejects(t.call("find_free_time", { min_minutes: 2 }), /5 to 1440/);
});
