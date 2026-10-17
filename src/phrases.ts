// Plain-English dates, resolved deterministically in the user's zone. Same input, same clock, same answer.
// Rules (documented so the model and the user can predict them):
//  - A weekday ("friday", "this friday") is the next one on or after today. "next friday" is the one in next week
//    (weeks run Monday to Sunday). "last friday" is the most recent one before today.
//  - A date without a year ("oct 20", "10/20") is the next one on or after today. Numeric dates are month/day.
//  - A time without a date ("3pm", "noon") is the next time that clock time comes around.
//  - A bare hour without am/pm: 1 to 7 means pm, 8 to 11 means am, 12 means noon. "evening", "afternoon",
//    "tonight" force pm and "morning" forces am. 24-hour times like 15:00 or 09:30 are taken literally.
//  - "in 3 days", "in 1 month" move the calendar date (Jan 31 plus 1 month is Feb 28). "in 2 hours" moves the clock.
//  - Ranges: "next week" (Mon to Sun), "this weekend" (Sat to Sun), "next month", "next year".
//  - "end of the week" is Friday (the coming Friday on a weekend).
//  - Wall times that don't exist (the hour skipped when DST starts) move forward by an hour.
import { ITime, wallToUtc, toFloating } from "./ical.js";
import { UserError } from "./errors.js";

const DAY = 86400000;
export interface Resolved { start: ITime; end?: ITime; kind: "day" | "time" | "range" }
const WD: Record<string, number> = { sun: 0, sunday: 0, mon: 1, monday: 1, tue: 2, tues: 2, tuesday: 2, wed: 3, weds: 3, wednesday: 3, thu: 4, thur: 4, thurs: 4, thursday: 4, fri: 5, friday: 5, sat: 6, saturday: 6 };
const MON: Record<string, number> = { jan: 1, january: 1, feb: 2, february: 2, mar: 3, march: 3, apr: 4, april: 4, may: 5, jun: 6, june: 6, jul: 7, july: 7, aug: 8, august: 8, sep: 9, sept: 9, september: 9, oct: 10, october: 10, nov: 11, november: 11, dec: 12, december: 12 };
const NUM: Record<string, number> = { a: 1, an: 1, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10, eleven: 11, twelve: 12, couple: 2, "a couple of": 2, "a few": 3, few: 3 };
const ORD: Record<string, number> = { first: 1, "1st": 1, second: 2, "2nd": 2, third: 3, "3rd": 3, fourth: 4, "4th": 4, fifth: 5, "5th": 5, last: -1 };
const WDS = Object.keys(WD).join("|"), MONS = Object.keys(MON).join("|");

const ymd = (dm: number) => { const x = new Date(dm); return [x.getUTCFullYear(), x.getUTCMonth() + 1, x.getUTCDate()] as const; };
const dateOf = (y: number, m: number, d: number) => { const t = Date.UTC(y, m - 1, d); const [yy, mm, dd] = ymd(t); return yy === y && mm === m && dd === d ? t : undefined; };
const lastDay = (y: number, m: number) => new Date(Date.UTC(y, m, 0)).getUTCDate();
/** Calendar-month arithmetic that clamps to the month's last day (Jan 31 + 1 month = Feb 28). */
function addMonths(dm: number, n: number) { const [y, m, d] = ymd(dm); const t = new Date(Date.UTC(y, m - 1 + n, 1)); const Y = t.getUTCFullYear(), M = t.getUTCMonth() + 1; return Date.UTC(Y, M - 1, Math.min(d, lastDay(Y, M))); }
const dow = (dm: number) => new Date(dm).getUTCDay();
const monday = (dm: number) => dm - ((dow(dm) + 6) % 7) * DAY;
const num = (s: string) => (/^\d+$/.test(s) ? Number(s) : NUM[s]);

interface DatePart { start: number; end?: number; tonight?: boolean }
function datePart(s: string, today: number): DatePart | undefined {
  let m: RegExpMatchArray | null;
  if (s === "" ) return undefined;
  if (s === "today") return { start: today };
  if (s === "tonight") return { start: today, tonight: true };
  if (/^(tomorrow|tmrw|tmr|tomorow)$/.test(s)) return { start: today + DAY };
  if (s === "yesterday") return { start: today - DAY };
  if (/^(the )?day after tomorrow$/.test(s)) return { start: today + 2 * DAY };
  if (/^(the )?day before yesterday$/.test(s)) return { start: today - 2 * DAY };
  if ((m = s.match(new RegExp(`^(?:(this|next|last|coming|upcoming) )?(${WDS})$`)))) {
    const w = WD[m[2]!]!, rel = m[1];
    if (rel === "next") return { start: monday(today) + 7 * DAY + ((w + 6) % 7) * DAY };
    if (rel === "last") { const back = (dow(today) - w + 7) % 7 || 7; return { start: today - back * DAY }; }
    return { start: today + ((w - dow(today) + 7) % 7) * DAY };
  }
  if ((m = s.match(/^(this|next|last) (week|weekend|month|year)$/))) {
    const k = m[2], step = m[1] === "next" ? 1 : m[1] === "last" ? -1 : 0; const [y, mo] = ymd(today);
    if (k === "week") { const a = monday(today) + step * 7 * DAY; return { start: a, end: a + 6 * DAY }; }
    if (k === "weekend") { const d = dow(today); const sat = d === 0 ? today - DAY : today + ((6 - d + 7) % 7) * DAY; const a = sat + step * 7 * DAY; return { start: d === 0 && step === 0 ? today : a, end: a + DAY }; }
    if (k === "month") { const a = addMonths(Date.UTC(y, mo - 1, 1), step); const [Y, M] = ymd(a); return { start: a, end: Date.UTC(Y, M - 1, lastDay(Y, M)) }; }
    return { start: Date.UTC(y + step, 0, 1), end: Date.UTC(y + step, 11, 31) };
  }
  if ((m = s.match(/^(end|start|beginning|first day|last day) of (?:the )?(?:(this|next) )?(week|month|year)$/))) {
    const edge = /^(start|beginning|first day)$/.test(m[1]!) ? "start" : "end", step = m[2] === "next" ? 1 : 0; const [y, mo] = ymd(today);
    if (m[3] === "week") { // a work week ends Friday. "end of the week" on a weekend means the coming Friday.
      const a = monday(today) + step * 7 * DAY; if (edge === "start") return { start: a };
      const fri = a + 4 * DAY; return { start: step === 0 && fri < today ? fri + 7 * DAY : fri };
    }
    if (m[3] === "month") { const a = addMonths(Date.UTC(y, mo - 1, 1), step); const [Y, M] = ymd(a); return { start: edge === "start" ? a : Date.UTC(Y, M - 1, lastDay(Y, M)) }; }
    return { start: edge === "start" ? Date.UTC(y + step, 0, 1) : Date.UTC(y + step, 11, 31) };
  }
  if ((m = s.match(new RegExp(`^(first|second|third|fourth|fifth|last|1st|2nd|3rd|4th|5th) (${WDS}) (?:of|in) (?:(the|this|next) month|(${MONS})(?: (\\d{4}))?)$`)))) {
    const n = ORD[m[1]!]!, w = WD[m[2]!]!; const [y, mo] = ymd(today);
    let Y: number, M: number;
    if (m[4]) { M = MON[m[4]]!; Y = m[5] ? +m[5] : y; if (!m[5] && Date.UTC(Y, M - 1, lastDay(Y, M)) < today) Y++; }
    else { const a = addMonths(Date.UTC(y, mo - 1, 1), m[3] === "next" ? 1 : 0); [Y, M] = ymd(a) as unknown as [number, number]; }
    if (n > 0) { const first = Date.UTC(Y, M - 1, 1); const d = first + ((w - dow(first) + 7) % 7) * DAY + (n - 1) * 7 * DAY; if (ymd(d)[1] !== M) throw new UserError(`There's no ${m[1]} ${m[2]} in that month.`); return { start: d }; }
    const last = Date.UTC(Y, M - 1, lastDay(Y, M)); return { start: last - ((dow(last) - w + 7) % 7) * DAY };
  }
  const md = (M: number, D: number, Y?: number) => {
    if (Y !== undefined) { const t = dateOf(Y, M, D); if (t === undefined) throw bad(s); return { start: t }; }
    const [y] = ymd(today);
    for (let k = 0; k < 8; k++) { const t = dateOf(y + k, M, D); if (t !== undefined && t >= today) return { start: t }; } // Feb 29 waits for a leap year
    throw bad(s);
  };
  if ((m = s.match(new RegExp(`^(${MONS}) (\\d{1,2})(?:st|nd|rd|th)?(?: (\\d{4}))?$`)))) return md(MON[m[1]!]!, +m[2]!, m[3] ? +m[3] : undefined);
  if ((m = s.match(new RegExp(`^(\\d{1,2})(?:st|nd|rd|th)? (?:of )?(${MONS})(?: (\\d{4}))?$`)))) return md(MON[m[2]!]!, +m[1]!, m[3] ? +m[3] : undefined);
  if ((m = s.match(/^(\d{1,2})\/(\d{1,2})(?:\/(\d{4}|\d{2}))?$/))) { if (+m[1]! > 12) throw new UserError(`Couldn't read "${s}". Numeric dates are month/day, like 10/20.`); return md(+m[1]!, +m[2]!, m[3] ? (m[3].length === 2 ? 2000 + +m[3] : +m[3]) : undefined); }
  if ((m = s.match(/^(?:in )?(\d+|an?|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|a couple of|a few) (days?|weeks?|months?|years?)(?: (from|after) (.+)| ago)?$/))) {
    const n = num(m[1]!)!; if (!s.startsWith("in ") && !m[3] && !s.endsWith(" ago")) return undefined;
    const base = m[4] ? (m[4] === "now" ? { start: today } : datePart(m[4], today)) : { start: today }; if (!base || base.end) return undefined;
    const sign = s.endsWith(" ago") ? -1 : 1, u = m[2]!.replace(/s$/, "");
    return { start: u === "day" ? base.start + sign * n * DAY : u === "week" ? base.start + sign * 7 * n * DAY : addMonths(base.start, sign * n * (u === "year" ? 12 : 1)) };
  }
  return undefined;
}
const bad = (s: string) => new UserError(`Couldn't read the date "${String(s).slice(0, 40)}". Try a date like 2026-10-20, oct 20, next friday or in 3 days.`);

interface TimePart { h: number; mi: number; pm?: boolean; am?: boolean; roll: boolean }
function hourFrom(hs: string, ms: string | undefined, ap: string | undefined, ctx: { pm?: boolean; am?: boolean }) {
  let h = +hs; const mi = ms ? +ms : 0; if (mi > 59) return undefined;
  if (ap) { if (h < 1 || h > 12) return undefined; const p = ap.startsWith("p"); h = (h % 12) + (p ? 12 : 0); return { h, mi }; }
  if (h > 23) return undefined;
  if (hs.length === 2 && hs.startsWith("0") || h === 0 || h >= 13) return { h, mi }; // 24-hour clock
  if (ctx.pm) return { h: h === 12 ? 12 : h + 12, mi }; if (ctx.am) return { h: h === 12 ? 0 : h, mi };
  return { h: h === 12 ? 12 : h <= 7 ? h + 12 : h, mi };
}

/** Resolve a phrase like "next friday 3pm" or "end of month" at instant now in zone tz. Throws UserError if it can't. */
export function resolvePhrase(input: string, now: number, tz: string): Resolved {
  // "in 99999 months" and friends overflow the calendar: NaN, a RangeError deep in Intl, or a year past 9999 that
  // iCalendar can't write. Refuse them like any other phrase we can't read.
  let r: Resolved;
  try { r = resolveInner(input, now, tz); } catch (e) { if (e instanceof RangeError) throw bad(String(input ?? "")); throw e; }
  for (const x of [r.start, r.end]) if (x && !(Number.isFinite(x.utc) && x.utc >= MIN_UTC && x.utc <= MAX_UTC)) throw new UserError(`"${String(input).slice(0, 40)}" lands outside the years 1900 to 9999.`);
  return r;
}
const MIN_UTC = Date.UTC(1900, 0, 1), MAX_UTC = Date.UTC(9999, 11, 31);
function resolveInner(input: string, now: number, tz: string): Resolved {
  if (typeof input !== "string" || !input.trim()) throw bad(String(input ?? ""));
  let s = input.toLowerCase().replace(/a\.m\.?/g, "am").replace(/p\.m\.?/g, "pm").replace(/[,!?]+/g, " ").replace(/\.$/, "").replace(/\s+/g, " ").trim().replace(/^(on|by) /, "");
  const today = Math.floor(toFloating(now, tz) / DAY) * DAY;
  if (s === "now" || s === "right now") return { start: { utc: now, allDay: false, tz }, kind: "time" };
  let m = s.match(/^(?:in )?(\d+|an?|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|half an|a couple of|a few) (minutes?|mins?|hours?|hrs?)(?: from now| ago)?$/);
  if (m && (s.startsWith("in ") || / (from now|ago)$/.test(s))) { const n = m[1] === "half an" ? 0.5 : num(m[1]!)!; const unit = /^h/.test(m[2]!) ? 3600000 : 60000; return { start: { utc: now + (s.endsWith(" ago") ? -1 : 1) * n * unit, allDay: false, tz }, kind: "time" }; }
  // Pull out the time of day, if any.
  const ctx: { pm?: boolean; am?: boolean } = {}; let t: TimePart | undefined; let noRoll = false;
  const take = (re: RegExp, f: (m: RegExpMatchArray) => TimePart | undefined) => { if (t) return; const x = s.match(re); if (!x) return; const v = f(x); if (!v) throw new UserError(`Couldn't read the time in "${input.slice(0, 40)}".`); t = v; s = (s.slice(0, x.index) + " " + s.slice(x.index! + x[0].length)).replace(/\s+/g, " ").trim(); };
  if (/\b(evening|afternoon|tonight)\b/.test(s)) ctx.pm = true; if (/\bmorning\b/.test(s)) ctx.am = true;
  take(/\b(?:at )?(\d{1,2})(?::(\d{2}))? ?(am|pm|a|p)\b/, (x) => { const v = hourFrom(x[1]!, x[2], x[3], ctx); return v && { ...v, roll: true }; });
  take(/\b(?:at )?(\d{1,2}):(\d{2})\b/, (x) => { const v = hourFrom(x[1]!, x[2], undefined, ctx); return v && { ...v, roll: true }; });
  take(/\bat (\d{1,2})\b(?!(?:st|nd|rd|th|\/| (?:days?|weeks?|months?)))/, (x) => { const v = hourFrom(x[1]!, undefined, undefined, ctx); return v && { ...v, roll: true }; });
  take(/\b(?:at )?(noon|midday|midnight)\b/, (x) => ({ h: x[1] === "midnight" ? 0 : 12, mi: 0, roll: true }));
  take(/\b(?:(this|in the) )?(morning|afternoon|evening)\b/, (x) => { if (x[1] === "this") noRoll = true; return { h: x[2] === "morning" ? 9 : x[2] === "afternoon" ? 14 : 18, mi: 0, roll: true }; });
  take(/\b(?:by )?(end of (?:the )?day|eod|close of business|cob)\b/, () => ({ h: 17, mi: 0, roll: false }));
  // "tomorrow morning at 7": the clock time won, the part of day only set am/pm. Drop it from the date words.
  if (t) s = s.replace(/\b(?:(this|in the) )?(morning|afternoon|evening)\b/, (_m, w) => { if (w === "this") noRoll = true; return " "; }).replace(/\s+/g, " ").trim();
  s = s.replace(/^(on|at|the) |\s(at|on)$/g, "").trim();
  let d = s ? datePart(s, today) : undefined;
  if (s && !d && !t) { const x = s.match(/^(.*\S) (\d{1,2})$/); const dd = x && !MON[x[1]!.split(" ").pop()!] ? datePart(x[1]!, today) : undefined; if (dd && !dd.end) { const v = hourFrom(x![2]!, undefined, undefined, ctx); if (v) { d = dd; t = { ...v, roll: true }; s = x![1]!; } } }
  if (s && !d) throw bad(input);
  if (d?.tonight && !t) t = { h: 20, mi: 0, roll: false };
  if (!t) { if (!d) throw bad(input); return d.end !== undefined ? { start: { utc: d.start, allDay: true }, end: { utc: d.end, allDay: true }, kind: "range" } : { start: { utc: d.start, allDay: true }, kind: "day" }; }
  if (d?.end !== undefined) throw new UserError(`"${input.slice(0, 40)}" is a span of days, so give one day for a time, like next monday at 3pm.`);
  const at = (dm: number) => { const [y, mo, dd] = ymd(dm); return wallToUtc(y, mo, dd, t!.h, t!.mi, 0, tz); };
  let day = d?.start ?? today; let utc = at(day);
  if (!d && !noRoll && t.roll && utc < now) { day += DAY; utc = at(day); }
  return { start: { utc, allDay: false, tz }, kind: "time" };
}
