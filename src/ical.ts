// iCalendar (RFC 5545) subset: parse VEVENT/VTODO, expand common RRULEs,
// build new events, and patch existing ones while preserving unknown data.
import { UserError } from "./errors.js";

export interface Prop { name: string; params: Record<string, string>; value: string }
export interface Component { type: string; props: Prop[]; children: Component[] }

export function unfold(text: string): string[] {
  return text.replace(/\r\n/g, "\n").replace(/\n[ \t]/g, "").split("\n").filter((l) => l.length);
}
export function parseLine(line: string): Prop {
  // split name;params:value respecting quoted param values
  let i = 0, inQ = false;
  for (; i < line.length; i++) { const c = line[i]; if (c === '"') inQ = !inQ; else if (c === ":" && !inQ) break; }
  const head = line.slice(0, i), value = line.slice(i + 1);
  const parts = head.match(/(?:[^;"]|"[^"]*")+/g) ?? [head];
  const params: Record<string, string> = {};
  for (const p of parts.slice(1)) { const k = p.indexOf("="); if (k > 0) params[p.slice(0, k).toUpperCase()] = p.slice(k + 1).replace(/^"|"$/g, ""); }
  return { name: parts[0]!.toUpperCase(), params, value };
}
export function parseIcs(text: string): Component {
  const root: Component = { type: "ROOT", props: [], children: [] }; const stack = [root];
  for (const line of unfold(text)) {
    const p = parseLine(line);
    if (p.name === "BEGIN") { const c: Component = { type: p.value.toUpperCase(), props: [], children: [] }; stack[stack.length - 1]!.children.push(c); stack.push(c); }
    else if (p.name === "END") { if (stack.length > 1) stack.pop(); }
    else stack[stack.length - 1]!.props.push(p);
  }
  return root;
}
export const getProp = (c: Component, n: string) => c.props.find((p) => p.name === n);
export function unescapeText(v: string) { return v.replace(/\\n/gi, "\n").replace(/\\([,;\\])/g, "$1"); }
/** RFC 5545 TEXT. Every line break form (CRLF, CR, LF, U+2028/9) becomes \\n, and other control characters are dropped,
 * so user text can never start a new property line. */
export function escapeText(v: string) { return v.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").replace(/\\/g, "\\\\").replace(/;/g, "\\;").replace(/,/g, "\\,").replace(/\r\n|\r|\n|\u2028|\u2029/g, "\\n"); }

// ---------- time ----------
/** Offset (ms) of zone at a UTC instant. */
const FMT = new Map<string, Intl.DateTimeFormat>(); // building a formatter is the slow part, so keep one per zone
export function zoneOffset(utcMs: number, tz: string): number {
  let f = FMT.get(tz);
  if (!f) { f = new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }); FMT.set(tz, f); }
  const o: Record<string, number> = {};
  utcMs = Math.floor(utcMs / 1000) * 1000; // the formatter has whole seconds, so compare whole seconds (else every offset is off by the ms)
  for (const p of f.formatToParts(new Date(utcMs))) if (p.type !== "literal") o[p.type] = Number(p.value);
  return Date.UTC(o.year!, o.month! - 1, o.day!, o.hour! % 24, o.minute!, o.second!) - utcMs;
}
/** Convert wall-clock time in tz to UTC ms (handles DST gaps by shifting forward). */
export function wallToUtc(y: number, mo: number, d: number, h: number, mi: number, s: number, tz: string): number {
  const guess = Date.UTC(y, mo - 1, d, h, mi, s);
  const t1 = guess - zoneOffset(guess, tz), t2 = guess - zoneOffset(t1, tz);
  if (t1 === t2) return t1;
  const fits = (t: number) => t + zoneOffset(t, tz) === guess;
  // Fall back (a wall time that happens twice): the first one. Spring forward (a wall time that never happens): an hour later.
  if (fits(t1) && fits(t2)) return Math.min(t1, t2);
  if (fits(t1)) return t1; if (fits(t2)) return t2;
  return Math.max(t1, t2);
}
export function isValidZone(tz: string) { try { new Intl.DateTimeFormat("en-US", { timeZone: tz }); return true; } catch { return false; } }

export interface ITime { utc: number; allDay: boolean; tz?: string }
export function parseDate(p: Prop | undefined, fallbackTz = "UTC"): ITime | undefined {
  if (!p) return undefined;
  const v = p.value.trim();
  const m = v.match(/^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})(Z)?)?$/);
  if (!m) return undefined;
  const [y, mo, d] = [+m[1]!, +m[2]!, +m[3]!];
  if (p.params.VALUE === "DATE" || m[4] === undefined) return { utc: Date.UTC(y, mo - 1, d), allDay: true };
  const [h, mi, s] = [+m[4]!, +m[5]!, +m[6]!];
  if (m[7]) return { utc: Date.UTC(y, mo - 1, d, h, mi, s), allDay: false, tz: "UTC" };
  let tz = p.params.TZID ?? fallbackTz;
  if (!isValidZone(tz)) tz = fallbackTz; // unknown Windows/custom TZIDs fall back
  return { utc: wallToUtc(y, mo, d, h, mi, s, tz), allDay: false, tz };
}
export function fmtUtc(ms: number) { return new Date(ms).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, ""); }
export function fmtDate(ms: number) { return new Date(ms).toISOString().slice(0, 10).replace(/-/g, ""); }
/** ISO string in the given zone with offset, e.g. 2026-10-16T09:00:00-06:00 */
export function isoInZone(ms: number, tz: string): string {
  const off = zoneOffset(ms, tz); const local = new Date(ms + off).toISOString().slice(0, 19);
  const sign = off >= 0 ? "+" : "-"; const a = Math.abs(off) / 60000;
  return `${local}${sign}${String(Math.floor(a / 60)).padStart(2, "0")}:${String(a % 60).padStart(2, "0")}`;
}
/** Parse user input "2026-10-20T09:00" (wall time in tz), with offset/Z, or "2026-10-20" (all-day).
 * An all-day value keeps the calendar date at UTC midnight (iCalendar DATE values have no zone).
 * Use dayStartIn() to turn that date into the real instant the day starts in a zone. */
export function parseUserTime(input: string, tz: string): ITime {
  if (typeof input !== "string") throw new UserError("Times must be text, like 2026-10-20T09:00 or 2026-10-20.");
  const s = input.trim().replace(/^(\d{4}-\d{2}-\d{2})[ T](\d{1,2}:\d{2})/, (_, d, t) => `${d}T${t.padStart(5, "0")}`);
  const d = s.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (d) { const utc = Date.UTC(+d[1]!, +d[2]! - 1, +d[3]!); if (!sameYmd(utc, +d[1]!, +d[2]!, +d[3]!)) throw badTime(input); return { utc, allDay: true }; }
  const w = s.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (w) { if (!sameYmd(Date.UTC(+w[1]!, +w[2]! - 1, +w[3]!), +w[1]!, +w[2]!, +w[3]!) || +w[4]! > 23 || +w[5]! > 59) throw badTime(input); return { utc: wallToUtc(+w[1]!, +w[2]!, +w[3]!, +w[4]!, +w[5]!, +(w[6] ?? 0), tz), allDay: false, tz }; }
  const t = Date.parse(s);
  if (/^\d{4}-\d{2}-\d{2}T/.test(s) && /([zZ]|[+-]\d{2}:?\d{2})$/.test(s) && !isNaN(t)) return { utc: t, allDay: false, tz };
  throw badTime(input);
}
const badTime = (s: string) => new UserError(`Couldn't read the time "${String(s).slice(0, 40)}". Use 2026-10-20T09:00 for a time or 2026-10-20 for a whole day.`);
const sameYmd = (utc: number, y: number, m: number, d: number) => { const x = new Date(utc); return x.getUTCFullYear() === y && x.getUTCMonth() === m - 1 && x.getUTCDate() === d; };
/** The instant a calendar date (held as UTC midnight) begins in tz, e.g. 2026-10-17 -> 2026-10-17T06:00Z for America/Denver. */
export function dayStartIn(dateUtcMidnight: number, tz: string): number {
  const x = new Date(dateUtcMidnight);
  return wallToUtc(x.getUTCFullYear(), x.getUTCMonth() + 1, x.getUTCDate(), 0, 0, 0, tz);
}
/** Map a real instant into "floating" time in tz: the UTC-midnight-based clock that all-day dates live on. */
export function toFloating(utcMs: number, tz: string): number { return utcMs + zoneOffset(utcMs, tz); }

// ---------- recurrence ----------
const DAYS = ["SU", "MO", "TU", "WE", "TH", "FR", "SA"];
export interface Occ { start: number; end: number }
/** Expand occurrences overlapping [from, to). Supports DAILY/WEEKLY/MONTHLY/YEARLY with INTERVAL, COUNT, UNTIL,
 * WKST, BYDAY (weekly days, or monthly/yearly ordinals like 2TU and -1FR), BYMONTHDAY (lists, negatives) and BYMONTH
 * (yearly), plus EXDATE. Returns supported=false for rules it cannot expand faithfully (e.g. BYSETPOS, BYWEEKNO). */
export function expand(start: ITime, durMs: number, rrule: string | undefined, exdates: number[], from: number, to: number, cap = 1000): { occ: Occ[]; supported: boolean } {
  if (!rrule) return { occ: start.utc < to && start.utc + Math.max(durMs, 1) > from ? [{ start: start.utc, end: start.utc + durMs }] : [], supported: true };
  const r: Record<string, string> = {};
  for (const kv of rrule.split(";")) { const [k, v] = kv.split("="); if (k && v) r[k.toUpperCase()] = v.toUpperCase(); }
  const freq = r.FREQ; const interval = Math.max(1, Number(r.INTERVAL ?? 1) || 1);
  const allowed = new Set(["FREQ", "INTERVAL", "COUNT", "UNTIL", "BYDAY", "BYMONTHDAY", "BYMONTH", "WKST"]);
  const NO = { occ: [] as Occ[], supported: false };
  if (!freq || !["DAILY", "WEEKLY", "MONTHLY", "YEARLY"].includes(freq) || Object.keys(r).some((k) => !allowed.has(k))) return NO;
  const byday: { n: number; dow: number }[] | undefined = r.BYDAY ? r.BYDAY.split(",").map((x) => { const m = x.match(/^([+-]?\d{1,2})?(SU|MO|TU|WE|TH|FR|SA)$/); return m ? { n: m[1] ? Number(m[1]) : 0, dow: DAYS.indexOf(m[2]!) } : { n: NaN, dow: -1 }; }) : undefined;
  const bymd = r.BYMONTHDAY ? r.BYMONTHDAY.split(",").map(Number) : undefined;
  const bymonth = r.BYMONTH ? r.BYMONTH.split(",").map(Number) : undefined;
  if (byday?.some((b) => b.dow < 0 || isNaN(b.n) || Math.abs(b.n) > 5)) return NO;
  if (bymd?.some((d) => !Number.isInteger(d) || d === 0 || Math.abs(d) > 31)) return NO;
  if (bymonth?.some((m) => !Number.isInteger(m) || m < 1 || m > 12)) return NO;
  if (freq === "DAILY" && (byday || bymd || bymonth)) return NO;
  if (freq === "WEEKLY" && (byday?.some((b) => b.n) || bymd || bymonth)) return NO;
  if (freq === "MONTHLY" && bymonth) return NO;
  if (freq === "YEARLY" && byday && !bymonth) return NO; // "20th Monday of the year" style rules
  const count = r.COUNT ? Number(r.COUNT) : Infinity;
  const until = r.UNTIL ? parseDate({ name: "UNTIL", params: {}, value: r.UNTIL }, start.tz ?? "UTC") : undefined;
  // An all-day UNTIL date includes that whole day.
  const untilMs = until ? until.utc + (until.allDay && !start.allDay ? DAY_MS - 1 : 0) : Infinity;
  const tz = start.allDay ? "UTC" : start.tz ?? "UTC";
  // work in wall-clock fields of tz so DST keeps local time stable
  const wall = new Date(start.utc + (start.allDay ? 0 : zoneOffset(start.utc, tz)));
  const [Y, M, D, h, mi, s] = [wall.getUTCFullYear(), wall.getUTCMonth(), wall.getUTCDate(), wall.getUTCHours(), wall.getUTCMinutes(), wall.getUTCSeconds()];
  const toUtc = (y: number, m: number, d: number) => start.allDay ? Date.UTC(y, m, d) : wallToUtc(y, m + 1, d, h, mi, s, tz);
  const ex = new Set(exdates);
  const occ: Occ[] = []; let n = 0;
  const emit = (t: number) => { if (t > untilMs || n >= count) return false; n++; if (!ex.has(t) && t < to && t + Math.max(durMs, 1) > from) occ.push({ start: t, end: t + durMs }); return t < to && occ.length < cap; };
  const base = Date.UTC(Y, M, D);
  if (freq === "WEEKLY") {
    const days = (byday ? byday.map((b) => b.dow) : [new Date(base).getUTCDay()]);
    const wkst = Math.max(0, DAYS.indexOf(r.WKST ?? "MO"));
    const baseDow = new Date(base).getUTCDay();
    const weekStart = base - ((baseDow - wkst + 7) % 7) * DAY_MS;
    const order = [...new Set(days)].sort((a, b) => ((a - wkst + 7) % 7) - ((b - wkst + 7) % 7));
    for (let w = 0; w < 20000; w += interval) {
      for (const dow of order) {
        const day = new Date(weekStart + (w * 7 + ((dow - wkst + 7) % 7)) * DAY_MS);
        if (day.getTime() < base) continue;
        if (!emit(toUtc(day.getUTCFullYear(), day.getUTCMonth(), day.getUTCDate()))) return { occ, supported: true };
      }
    }
    return { occ, supported: true };
  }
  if (freq === "DAILY") {
    for (let i = 0; i < 100000; i += interval) { const x = new Date(Date.UTC(Y, M, D + i)); if (!emit(toUtc(x.getUTCFullYear(), x.getUTCMonth(), x.getUTCDate()))) return { occ, supported: true }; }
    return { occ, supported: true };
  }
  // MONTHLY / YEARLY: build each period's candidate days, then emit them in order.
  const daysIn = (y: number, m: number): number[] => {
    const dim = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
    let out: number[] | undefined;
    if (bymd) out = bymd.map((d) => (d < 0 ? dim + d + 1 : d)).filter((d) => d >= 1 && d <= dim);
    if (byday) {
      const hits: number[] = [];
      for (const b of byday) {
        const all: number[] = []; for (let d = 1; d <= dim; d++) if (new Date(Date.UTC(y, m, d)).getUTCDay() === b.dow) all.push(d);
        if (!b.n) hits.push(...all); else { const pick = b.n > 0 ? all[b.n - 1] : all[all.length + b.n]; if (pick) hits.push(pick); }
      }
      out = out ? out.filter((d) => hits.includes(d)) : hits;
    }
    if (!out) out = D <= dim ? [D] : []; // RFC 5545: invalid dates (e.g. Feb 30) are skipped
    return [...new Set(out)].sort((a, b) => a - b);
  };
  for (let i = 0; i < 20000; i += interval) {
    const months: [number, number][] = freq === "MONTHLY"
      ? [[new Date(Date.UTC(Y, M + i, 1)).getUTCFullYear(), new Date(Date.UTC(Y, M + i, 1)).getUTCMonth()]]
      : (bymonth ?? [M + 1]).slice().sort((a, b) => a - b).map((mm) => [Y + i, mm - 1] as [number, number]);
    for (const [y, m] of months) for (const d of daysIn(y, m)) {
      if (Date.UTC(y, m, d) < base) continue;
      if (!emit(toUtc(y, m, d))) return { occ, supported: true };
    }
  }
  return { occ, supported: true };
}
const DAY_MS = 86400000;

// ---------- serialize ----------
export function foldLine(line: string): string {
  const enc = new TextEncoder(); if (enc.encode(line).length <= 75) return line;
  const out: string[] = []; let cur = ""; let len = 0; const limit = () => (out.length ? 74 : 75);
  for (const ch of line) { const b = enc.encode(ch).length; if (len + b > limit()) { out.push(cur); cur = ""; len = 0; } cur += ch; len += b; }
  out.push(cur); return out.map((l, i) => (i ? " " + l : l)).join("\r\n");
}
export function propLine(name: string, value: string, params: Record<string, string> = {}): string {
  // Invariant: a property is exactly one logical line. Nothing caller-supplied may carry a line break or control character.
  if ([name, value, ...Object.keys(params), ...Object.values(params)].some((x) => /[\u0000-\u0008\u000a-\u001f\u007f]/.test(String(x)))) throw new Error(`refusing to write a control character into ${String(name).slice(0, 20)}`);
  const ps = Object.entries(params).map(([k, v]) => `;${k}=${/[:;,]/.test(v) ? `"${v}"` : v}`).join("");
  return foldLine(`${name}${ps}:${value}`);
}
export function timeProp(name: string, t: ITime, tz?: string): string {
  if (t.allDay) return propLine(name, fmtDate(t.utc), { VALUE: "DATE" });
  if (tz && tz !== "UTC" && isValidZone(tz)) return propLine(name, fmtUtc(t.utc + zoneOffset(t.utc, tz)).replace(/Z$/, ""), { TZID: tz });
  return propLine(name, fmtUtc(t.utc));
}
const fmtOff = (ms: number) => { const m = Math.round(ms / 60000), a = Math.abs(m); return `${m < 0 ? "-" : "+"}${String(Math.floor(a / 60)).padStart(2, "0")}${String(a % 60).padStart(2, "0")}`; };
/** A VTIMEZONE for tz, derived from the zone's real transitions in `year`, so a repeating 9 AM event stays 9 AM across DST
 * in every client (an event written in UTC would drift an hour). Yearly rules use the iCalendar nth-weekday form. */
export function vtimezone(tz: string, year: number): string[] {
  const jan = Date.UTC(year, 0, 1), days = (Date.UTC(year + 1, 0, 1) - jan) / DAY_MS;
  const shifts: { at: number; from: number; to: number }[] = [];
  let prev = zoneOffset(jan, tz);
  for (let d = 1; d <= days; d++) {
    const t = jan + d * DAY_MS, o = zoneOffset(t, tz);
    if (o === prev) continue;
    let lo = t - DAY_MS, hi = t; while (hi - lo > 1000) { const mid = Math.floor((lo + hi) / 2); if (zoneOffset(mid, tz) === prev) lo = mid; else hi = mid; }
    shifts.push({ at: hi, from: prev, to: o }); prev = o;
  }
  const L = ["BEGIN:VTIMEZONE", propLine("TZID", tz)];
  if (!shifts.length) L.push("BEGIN:STANDARD", `DTSTART:${year}0101T000000`, `TZOFFSETFROM:${fmtOff(prev)}`, `TZOFFSETTO:${fmtOff(prev)}`, "END:STANDARD");
  for (const sh of shifts) {
    const local = new Date(sh.at + sh.from); // wall clock just before the change
    const y = local.getUTCFullYear(), m = local.getUTCMonth(), d = local.getUTCDate();
    const dim = new Date(Date.UTC(y, m + 1, 0)).getUTCDate(); const nth = d + 7 > dim ? -1 : Math.ceil(d / 7);
    const kind = sh.to > sh.from ? "DAYLIGHT" : "STANDARD";
    L.push(`BEGIN:${kind}`, `DTSTART:${fmtUtc(sh.at + sh.from).replace(/Z$/, "")}`, `TZOFFSETFROM:${fmtOff(sh.from)}`, `TZOFFSETTO:${fmtOff(sh.to)}`,
      shifts.length === 2 ? `RRULE:FREQ=YEARLY;BYMONTH=${m + 1};BYDAY=${nth}${DAYS[local.getUTCDay()]}` : "", `END:${kind}`);
  }
  L.push("END:VTIMEZONE");
  return L.filter(Boolean);
}

export interface EventInput { title: string; start: ITime; end: ITime; location?: string; notes?: string; alertsMinutesBefore?: number[]; rrule?: string; /** User's zone. Timed events are written with TZID and a VTIMEZONE, as Apple Calendar does. */ tz?: string }
export function buildEvent(uid: string, e: EventInput, now = Date.now()): string {
  const tz = !e.start.allDay && e.tz && e.tz !== "UTC" && isValidZone(e.tz) ? e.tz : undefined;
  const L = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Holdt//Holdt for iCloud Calendar//EN", "CALSCALE:GREGORIAN",
    ...(tz ? vtimezone(tz, new Date(e.start.utc).getUTCFullYear()) : []), "BEGIN:VEVENT",
    propLine("UID", uid), propLine("DTSTAMP", fmtUtc(now)), propLine("CREATED", fmtUtc(now)), propLine("LAST-MODIFIED", fmtUtc(now)),
    timeProp("DTSTART", e.start, tz), timeProp("DTEND", e.end, tz), propLine("SUMMARY", escapeText(e.title))];
  if (e.location) L.push(propLine("LOCATION", escapeText(e.location)));
  if (e.notes) L.push(propLine("DESCRIPTION", escapeText(e.notes)));
  if (e.rrule) L.push(propLine("RRULE", e.rrule));
  for (const m of e.alertsMinutesBefore ?? []) if (!Number.isInteger(m) || m < 0 || m > 40320) throw new UserError("Alerts must be whole minutes between 0 and 40320.");
  for (const m of e.alertsMinutesBefore ?? []) L.push("BEGIN:VALARM", "ACTION:DISPLAY", propLine("DESCRIPTION", escapeText(e.title)), `TRIGGER:-PT${Math.round(m)}M`, propLine("X-WR-ALARMUID", `${uid}-a${m}`), "END:VALARM");
  L.push("END:VEVENT", "END:VCALENDAR");
  return assertSafeIcs(L.join("\r\n") + "\r\n");
}

const INVITE_LINE = /^(ATTENDEE|ORGANIZER)[;:]/i;
/** Last check before any ICS leaves Holdt. Every unfolded line must be NAME[;params]:value with no control characters,
 * and Holdt may never add an ATTENDEE or ORGANIZER line (that is how a calendar server decides to email invitations).
 * `invitesBefore` is how many such lines the stored event already had (patches keep them, never add). */
export function assertSafeIcs(ics: string, invitesBefore = 0): string {
  const lines = unfold(ics); let invites = 0;
  for (const l of lines) {
    if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(l) || !/^[A-Za-z][A-Za-z0-9-]*(;[^:]*)?:/.test(l)) throw new Error("refusing to write a malformed calendar line");
    if (INVITE_LINE.test(l)) invites++;
  }
  if (invites > invitesBefore) throw new Error("refusing to add an invitee to an event");
  return ics;
}
export const countInviteLines = (ics: string) => unfold(ics).filter((l) => INVITE_LINE.test(l)).length;

export interface EventPatch { title?: string; start?: ITime; end?: ITime; location?: string | null; notes?: string | null }
/** Patch the master VEVENT in raw ICS, preserving every line we don't manage (attendees, X- props, alarms, overrides). */
export function patchEvent(raw: string, patch: EventPatch, now = Date.now()): string {
  const lines = raw.replace(/\r\n/g, "\n").replace(/\n[ \t]/g, "").split("\n");
  const out: string[] = []; let depth = 0; let inMaster = false; let isOverride = false; let buf: string[] = [];
  const replace: Record<string, string | null> = {};
  if (patch.title !== undefined) replace.SUMMARY = propLine("SUMMARY", escapeText(patch.title));
  if (patch.start) replace.DTSTART = timeProp("DTSTART", patch.start);
  if (patch.end) { replace.DTEND = timeProp("DTEND", patch.end); replace.DURATION = null; }
  if (patch.location !== undefined) replace.LOCATION = patch.location ? propLine("LOCATION", escapeText(patch.location)) : null;
  if (patch.notes !== undefined) replace.DESCRIPTION = patch.notes ? propLine("DESCRIPTION", escapeText(patch.notes)) : null;
  replace["LAST-MODIFIED"] = propLine("LAST-MODIFIED", fmtUtc(now)); replace.DTSTAMP = propLine("DTSTAMP", fmtUtc(now));
  let seq = 0;
  for (const line of lines) {
    if (!line) continue;
    const p = parseLine(line);
    if (p.name === "BEGIN") { depth++; if (p.value === "VEVENT" && depth === 2) { inMaster = true; isOverride = false; buf = []; } }
    if (inMaster && depth === 2 && p.name !== "BEGIN" && p.name !== "END") {
      if (p.name === "RECURRENCE-ID") isOverride = true;
      if (p.name === "SEQUENCE") seq = Number(p.value) || 0;
    }
    if (inMaster) buf.push(line); else out.push(foldLine(line));
    if (p.name === "END") {
      if (p.value === "VEVENT" && depth === 2 && inMaster) {
        inMaster = false;
        if (isOverride) out.push(...buf.map(foldLine));
        else {
          const seen = new Set<string>(); const res: string[] = []; let d2 = 0;
          for (const b of buf) {
            const q = parseLine(b);
            if (q.name === "BEGIN") d2++;
            if (q.name === "END" && d2 === 1 && q.value === "VEVENT") {
              for (const [k, v] of Object.entries(replace)) if (!seen.has(k) && v) res.push(v);
              if (!seen.has("SEQUENCE")) res.push(`SEQUENCE:${seq + 1}`);
            }
            if (q.name === "END") d2--;
            if (d2 === 1 && q.name in replace && q.name !== "BEGIN") { if (!seen.has(q.name)) { seen.add(q.name); const v = replace[q.name]; if (v) res.push(v); } continue; }
            if (d2 === 1 && q.name === "SEQUENCE") { seen.add("SEQUENCE"); res.push(`SEQUENCE:${seq + 1}`); continue; }
            res.push(foldLine(b));
          }
          out.push(...res);
        }
        seq = 0;
      }
      depth--;
    }
  }
  return assertSafeIcs(out.join("\r\n") + "\r\n", countInviteLines(raw));
}
