// What "the user edited this event" means for undo. iCloud rewrites every event it stores: it adds X-APPLE-* and
// X-WR-* properties, refreshes DTSTAMP, LAST-MODIFIED and SEQUENCE, reorders and refolds lines, re-escapes text, and the
// ETag it reports moves with all of that (the ETag on the PUT response is not the ETag of what a later GET returns).
// Comparing ETags therefore made every undo look like it was blocked by an edit. This fingerprint covers only what a
// person can change and see: any change to these fields, in the main event or in any single-occurrence override
// (RECURRENCE-ID), still counts as an edit and blocks undo.
import { parseIcs, unescapeText, Component, Prop } from "./ical.js";

const TEXT = new Set(["SUMMARY", "LOCATION", "DESCRIPTION", "URL"]);
const TIME = new Set(["DTSTART", "DTEND", "RECURRENCE-ID"]);
const KEEP = new Set([...TEXT, ...TIME, "UID", "DURATION", "RRULE", "EXDATE", "RDATE", "ATTENDEE", "ORGANIZER", "STATUS", "TRANSP"]);
const DEFAULTS: Record<string, string> = { STATUS: "CONFIRMED", TRANSP: "OPAQUE" };

const tidy = (v: string) => v.replace(/\r/g, "").trim();
function params(p: Prop, keep: string[]) {
  return keep.map((k) => { let v = p.params[k]; if (v === undefined) return ""; if (k === "VALUE" && v.toUpperCase() === "DATE-TIME") return ""; if (k !== "TZID") v = v.toUpperCase(); return `${k}=${v}`; }).filter(Boolean).join(";");
}
function rrule(v: string) {
  const parts = v.toUpperCase().split(";").filter(Boolean).map((x) => x.trim());
  const m = new Map(parts.map((x) => { const i = x.indexOf("="); return [x.slice(0, i), x.slice(i + 1)] as [string, string]; }));
  // WKST only changes the result for weekly rules with INTERVAL>1 and BYDAY, or BYWEEKNO; elsewhere servers add or drop it freely.
  const wkstMatters = (m.get("FREQ") === "WEEKLY" && Number(m.get("INTERVAL") ?? 1) > 1 && m.has("BYDAY")) || m.has("BYWEEKNO");
  if (!wkstMatters || m.get("WKST") === "MO") m.delete("WKST");
  if (m.get("INTERVAL") === "1") m.delete("INTERVAL");
  return [...m].map(([k, x]) => `${k}=${k.startsWith("BY") ? x.split(",").sort().join(",") : x}`).sort().join(";");
}
function propKey(p: Prop): string | undefined {
  if (!KEEP.has(p.name)) return undefined;
  if (TEXT.has(p.name)) return `${p.name}:${tidy(unescapeText(p.value))}`;
  if (TIME.has(p.name)) return `${p.name};${params(p, ["TZID", "VALUE", "RANGE"])}:${p.value.trim().toUpperCase()}`;
  if (p.name === "RRULE") return `RRULE:${rrule(p.value)}`;
  if (p.name === "EXDATE" || p.name === "RDATE") return p.value.split(",").map((x) => `${p.name};${params(p, ["TZID", "VALUE"])}:${x.trim().toUpperCase()}`).join("\n");
  if (p.name === "ATTENDEE") return `ATTENDEE:${p.value.trim().toLowerCase()};${params(p, ["PARTSTAT", "ROLE"])}`;
  if (p.name === "ORGANIZER") return `ORGANIZER:${p.value.trim().toLowerCase()}`;
  if (p.name in DEFAULTS) { const v = p.value.trim().toUpperCase(); return v === DEFAULTS[p.name] ? undefined : `${p.name}:${v}`; }
  return `${p.name}:${p.value.trim()}`;
}
function alarmKey(a: Component): string | undefined {
  // Alerts iCloud injects from the account's default-alert setting are not the user's edit to this event.
  if (a.props.some((p) => p.name === "X-APPLE-DEFAULT-ALARM" && /^true$/i.test(p.value.trim()))) return undefined;
  const g = (n: string) => a.props.find((p) => p.name === n);
  const t = g("TRIGGER"); const act = (g("ACTION")?.value ?? "").trim().toUpperCase();
  return `ALARM:${act}|${t ? `${params(t, ["RELATED", "VALUE"])}:${t.value.trim().toUpperCase()}` : ""}`;
}
function eventKey(ev: Component): string {
  const lines = ev.props.flatMap((p) => (propKey(p) ?? "").split("\n")).filter(Boolean).sort();
  const alarms = ev.children.filter((c) => c.type === "VALARM").map(alarmKey).filter((x): x is string => !!x).sort();
  return [...lines, ...alarms].join("\n");
}

/** Canonical text of the user-meaningful content of every VEVENT (master plus overrides), order-independent. */
export function canonicalEvent(ics: string): string {
  const evs = parseIcs(ics).children.flatMap((c) => c.children).filter((c) => c.type === "VEVENT");
  return evs.map(eventKey).sort().join("\n--\n");
}
/** SHA-256 of canonicalEvent, prefixed with a version so a future canonical form can't be confused with this one. */
export async function eventFingerprint(ics: string): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalEvent(ics))));
  return "f1:" + [...h].map((b) => b.toString(16).padStart(2, "0")).join("");
}
