// iCalendar (RFC 5545) subset: parse VEVENT/VTODO, expand common RRULEs,
// build new events, and patch existing ones while preserving unknown data.

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
export function escapeText(v: string) { return v.replace(/\\/g, "\\\\").replace(/;/g, "\\;").replace(/,/g, "\\,").replace(/\r?\n/g, "\\n"); }

// ---------- time ----------
/** Offset (ms) of zone at a UTC instant. */
function zoneOffset(utcMs: number, tz: string): number {
  const f = new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const o: Record<string, number> = {};
  for (const p of f.formatToParts(new Date(utcMs))) if (p.type !== "literal") o[p.type] = Number(p.value);
  return Date.UTC(o.year!, o.month! - 1, o.day!, o.hour! % 24, o.minute!, o.second!) - utcMs;
}
/** Convert wall-clock time in tz to UTC ms (handles DST gaps by shifting forward). */
export function wallToUtc(y: number, mo: number, d: number, h: number, mi: number, s: number, tz: string): number {
  const guess = Date.UTC(y, mo - 1, d, h, mi, s);
  let off = zoneOffset(guess, tz); let t = guess - off;
  const off2 = zoneOffset(t, tz); if (off2 !== off) t = guess - off2;
  return t;
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
/** Parse user input "2026-10-20T09:00" (wall time in tz), with offset/Z, or "2026-10-20" (all-day). */
export function parseUserTime(s: string, tz: string): ITime {
  const d = s.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (d) return { utc: Date.UTC(+d[1]!, +d[2]! - 1, +d[3]!), allDay: true };
  const w = s.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (w) return { utc: wallToUtc(+w[1]!, +w[2]!, +w[3]!, +w[4]!, +w[5]!, +(w[6] ?? 0), tz), allDay: false, tz };
  const t = Date.parse(s);
  if (/[zZ]|[+-]\d{2}:?\d{2}$/.test(s) && !isNaN(t)) return { utc: t, allDay: false, tz };
  throw new Error(`Couldn't read the time "${s}". Use 2026-10-20T09:00 or 2026-10-20.`);
}

// ---------- recurrence ----------
const DAYS = ["SU", "MO", "TU", "WE", "TH", "FR", "SA"];
export interface Occ { start: number; end: number }
/** Expand occurrences overlapping [from, to). Supports DAILY/WEEKLY/MONTHLY/YEARLY, INTERVAL, COUNT, UNTIL, BYDAY (weekly),
 * BYMONTHDAY (monthly), EXDATE. Returns supported=false for rules it cannot expand faithfully. */
export function expand(start: ITime, durMs: number, rrule: string | undefined, exdates: number[], from: number, to: number, cap = 1000): { occ: Occ[]; supported: boolean } {
  if (!rrule) return { occ: start.utc < to && start.utc + Math.max(durMs, 1) > from ? [{ start: start.utc, end: start.utc + durMs }] : [], supported: true };
  const r: Record<string, string> = {};
  for (const kv of rrule.split(";")) { const [k, v] = kv.split("="); if (k && v) r[k.toUpperCase()] = v; }
  const freq = r.FREQ; const interval = Math.max(1, Number(r.INTERVAL ?? 1));
  const allowed = new Set(["FREQ", "INTERVAL", "COUNT", "UNTIL", "BYDAY", "BYMONTHDAY", "WKST"]);
  if (!freq || !["DAILY", "WEEKLY", "MONTHLY", "YEARLY"].includes(freq) || Object.keys(r).some((k) => !allowed.has(k))) return { occ: [], supported: false };
  if (r.BYDAY && (freq !== "WEEKLY" || /\d/.test(r.BYDAY))) return { occ: [], supported: false };
  if (r.BYMONTHDAY && freq !== "MONTHLY") return { occ: [], supported: false };
  const count = r.COUNT ? Number(r.COUNT) : Infinity;
  const until = r.UNTIL ? parseDate({ name: "UNTIL", params: {}, value: r.UNTIL }, start.tz ?? "UTC")?.utc ?? Infinity : Infinity;
  const tz = start.allDay ? "UTC" : start.tz ?? "UTC";
  // work in wall-clock fields of tz so DST keeps local time stable
  const wall = new Date(start.utc + (start.allDay ? 0 : zoneOffset(start.utc, tz)));
  const [Y, M, D, h, mi, s] = [wall.getUTCFullYear(), wall.getUTCMonth(), wall.getUTCDate(), wall.getUTCHours(), wall.getUTCMinutes(), wall.getUTCSeconds()];
  const toUtc = (y: number, m: number, d: number) => start.allDay ? Date.UTC(y, m, d) : wallToUtc(y, m + 1, d, h, mi, s, tz);
  const ex = new Set(exdates);
  const occ: Occ[] = []; let n = 0;
  const emit = (t: number) => { if (t > until || n >= count) return false; n++; if (!ex.has(t) && t < to && t + Math.max(durMs, 1) > from) occ.push({ start: t, end: t + durMs }); return t < to && occ.length < cap; };
  if (freq === "WEEKLY") {
    const byday = (r.BYDAY ? r.BYDAY.split(",") : [DAYS[new Date(Date.UTC(Y, M, D)).getUTCDay()]!]).map((x) => DAYS.indexOf(x)).filter((x) => x >= 0).sort();
    const wkst = DAYS.indexOf(r.WKST ?? "MO");
    const base = Date.UTC(Y, M, D); const baseDow = new Date(base).getUTCDay();
    const weekStart = base - ((baseDow - wkst + 7) % 7) * 86400000;
    for (let w = 0; w < 5000; w += interval) {
      for (const dow of [...byday].sort((a, b) => ((a - wkst + 7) % 7) - ((b - wkst + 7) % 7))) {
        const day = new Date(weekStart + (w * 7 + ((dow - wkst + 7) % 7)) * 86400000);
        if (day.getTime() < base) continue;
        if (!emit(toUtc(day.getUTCFullYear(), day.getUTCMonth(), day.getUTCDate()))) return { occ, supported: true };
      }
    }
    return { occ, supported: true };
  }
  for (let i = 0; i < 20000; i += interval) {
    let y = Y, m = M, d = D;
    if (freq === "DAILY") { const x = new Date(Date.UTC(Y, M, D + i)); y = x.getUTCFullYear(); m = x.getUTCMonth(); d = x.getUTCDate(); }
    else if (freq === "MONTHLY") { const x = new Date(Date.UTC(Y, M + i, 1)); y = x.getUTCFullYear(); m = x.getUTCMonth(); if (r.BYMONTHDAY) d = Number(r.BYMONTHDAY); }
    else { y = Y + i; }
    const dim = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
    if (d < 0) d = dim + d + 1;
    if (d > dim) continue; // RFC 5545: invalid dates (e.g. Feb 30) are skipped
    if (!emit(toUtc(y, m, d))) return { occ, supported: true };
  }
  return { occ, supported: true };
}

// ---------- serialize ----------
export function foldLine(line: string): string {
  const enc = new TextEncoder(); if (enc.encode(line).length <= 75) return line;
  const out: string[] = []; let cur = ""; let len = 0; const limit = () => (out.length ? 74 : 75);
  for (const ch of line) { const b = enc.encode(ch).length; if (len + b > limit()) { out.push(cur); cur = ""; len = 0; } cur += ch; len += b; }
  out.push(cur); return out.map((l, i) => (i ? " " + l : l)).join("\r\n");
}
export function propLine(name: string, value: string, params: Record<string, string> = {}): string {
  const ps = Object.entries(params).map(([k, v]) => `;${k}=${/[:;,]/.test(v) ? `"${v}"` : v}`).join("");
  return foldLine(`${name}${ps}:${value}`);
}
export function timeProp(name: string, t: ITime): string {
  if (t.allDay) return propLine(name, fmtDate(t.utc), { VALUE: "DATE" });
  return propLine(name, fmtUtc(t.utc));
}

export interface EventInput { title: string; start: ITime; end: ITime; location?: string; notes?: string; alertsMinutesBefore?: number[]; rrule?: string }
export function buildEvent(uid: string, e: EventInput, now = Date.now()): string {
  const L = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//icloud-mcp//EN", "CALSCALE:GREGORIAN", "BEGIN:VEVENT",
    propLine("UID", uid), propLine("DTSTAMP", fmtUtc(now)), propLine("CREATED", fmtUtc(now)), propLine("LAST-MODIFIED", fmtUtc(now)),
    timeProp("DTSTART", e.start), timeProp("DTEND", e.end), propLine("SUMMARY", escapeText(e.title))];
  if (e.location) L.push(propLine("LOCATION", escapeText(e.location)));
  if (e.notes) L.push(propLine("DESCRIPTION", escapeText(e.notes)));
  if (e.rrule) L.push(propLine("RRULE", e.rrule));
  for (const m of e.alertsMinutesBefore ?? []) L.push("BEGIN:VALARM", "ACTION:DISPLAY", propLine("DESCRIPTION", escapeText(e.title)), `TRIGGER:-PT${Math.round(m)}M`, propLine("X-WR-ALARMUID", `${uid}-a${m}`), "END:VALARM");
  L.push("END:VEVENT", "END:VCALENDAR");
  return L.join("\r\n") + "\r\n";
}

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
  return out.join("\r\n") + "\r\n";
}
