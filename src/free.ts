// Free/busy arithmetic. Pure functions on [start, end) intervals in UTC ms, so they are easy to test and to reason about.
import { wallToUtc, toFloating } from "./ical.js";
import { UserError } from "./errors.js";

export type Iv = [number, number];
const DAY = 86400000, MIN = 60000;

/** Sort and join overlapping or touching intervals. */
export function merge(iv: Iv[]): Iv[] {
  const s = iv.filter(([a, b]) => b > a).sort((x, y) => x[0] - y[0]); const out: Iv[] = [];
  for (const [a, b] of s) { const last = out[out.length - 1]; if (last && a <= last[1]) last[1] = Math.max(last[1], b); else out.push([a, b]); }
  return out;
}
/** The parts of each window not covered by any busy interval. */
export function subtract(windows: Iv[], busy: Iv[]): Iv[] {
  const b = merge(busy); const out: Iv[] = [];
  for (const [ws, we] of merge(windows)) {
    let cur = ws;
    for (const [bs, be] of b) { if (be <= cur) continue; if (bs >= we) break; if (bs > cur) out.push([cur, bs]); cur = Math.max(cur, be); if (cur >= we) break; }
    if (cur < we) out.push([cur, we]);
  }
  return out;
}

export interface WorkingHours { start: string; end: string; days: number[] } // days: 0=Sun..6=Sat
const DAY_NAMES = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
export const DEFAULT_HOURS: WorkingHours = { start: "09:00", end: "17:00", days: [1, 2, 3, 4, 5] };
function hm(s: unknown, what: string): [number, number] {
  const m = typeof s === "string" ? s.trim().match(/^(\d{1,2}):(\d{2})$/) : null;
  if (!m || +m[1]! > 24 || +m[2]! > 59 || (+m[1]! === 24 && +m[2]! !== 0)) throw new UserError(`working_hours.${what} must look like 09:00 or 17:30.`);
  return [+m[1]!, +m[2]!];
}
/** Accepts true (Mon-Fri 9-5) or { start, end, days }. Days are names like "mon" or "Monday". */
export function parseWorkingHours(v: unknown): WorkingHours | undefined {
  if (v === undefined || v === false || v === null) return undefined;
  if (v === true) return DEFAULT_HOURS;
  if (typeof v !== "object") throw new UserError("working_hours must be true or { start, end, days }.");
  const o = v as Record<string, unknown>;
  const start = (o.start as string) ?? DEFAULT_HOURS.start, end = (o.end as string) ?? DEFAULT_HOURS.end;
  const [sh, sm] = hm(start, "start"), [eh, em] = hm(end, "end");
  if (eh * 60 + em <= sh * 60 + sm) throw new UserError("working_hours.end must be after working_hours.start (overnight hours aren't supported).");
  let days = DEFAULT_HOURS.days;
  if (o.days !== undefined) {
    if (!Array.isArray(o.days) || !o.days.length) throw new UserError("working_hours.days must list days, like [\"mon\", \"tue\"].");
    days = o.days.map((d) => { const i = DAY_NAMES.indexOf(String(d).trim().toLowerCase().slice(0, 3)); if (i < 0) throw new UserError(`"${String(d).slice(0, 20)}" isn't a day name.`); return i; });
  }
  return { start, end, days: [...new Set(days)].sort() };
}
/** The working-hours windows inside [from, to), built on the user's wall clock so DST days keep 9 to 5. */
export function workWindows(from: number, to: number, tz: string, wh: WorkingHours): Iv[] {
  const [sh, sm] = hm(wh.start, "start"), [eh, em] = hm(wh.end, "end"); const out: Iv[] = [];
  const first = Math.floor(toFloating(from, tz) / DAY) * DAY, last = Math.floor(toFloating(to, tz) / DAY) * DAY;
  for (let d = first; d <= last; d += DAY) {
    const x = new Date(d); if (!wh.days.includes(x.getUTCDay())) continue;
    const y = x.getUTCFullYear(), mo = x.getUTCMonth() + 1, dd = x.getUTCDate();
    const a = Math.max(from, wallToUtc(y, mo, dd, sh, sm, 0, tz)), b = Math.min(to, wallToUtc(y, mo, dd, eh, em, 0, tz));
    if (b > a) out.push([a, b]);
  }
  return out;
}
/** Up to n slots of length dur, each inside a free interval, nearest to target first. Starts snap to the quarter hour. */
export function nearestSlots(free: Iv[], dur: number, target: number, n = 3, step = 15 * MIN): Iv[] {
  const c: number[] = [];
  for (const [a, b] of free) {
    if (b - a < dur) continue;
    const lo = Math.ceil(a / step) * step, hi = Math.floor((b - dur) / step) * step; if (hi < lo) continue;
    const t = Math.min(Math.max(Math.round(target / step) * step, lo), hi); c.push(t);
  }
  return c.sort((x, y) => Math.abs(x - target) - Math.abs(y - target) || x - y).slice(0, n).sort((x, y) => x - y).map((s) => [s, s + dur]);
}
