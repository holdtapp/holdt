// Reminders probe: does this Apple Account expose its REAL Reminders lists over CalDAV?
// Usage (credentials only via env, never as arguments):
//   ICLOUD_EMAIL=you@icloud.com ICLOUD_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx \
//   EXPECTED_LISTS="Reminders,Groceries" npm run probe:reminders
// Optional: PROBE_WRITE=yes adds ONE reminder titled "Grok Bot probe (safe to delete)" to the first
// CalDAV list so you can check whether it shows up on your iPhone. Nothing is ever deleted.
import { CalDavClient, CalDavError } from "../src/caldav.js";
import { parseIcs, getProp, propLine, fmtUtc } from "../src/ical.js";
import { registerSecret, redact } from "../src/redact.js";
import { normalizeAppPassword, normalizeEmail, explainFailure } from "../setup/validate.js";

export interface ProbeResult { verdict: "REAL_LISTS_VISIBLE" | "PARTIAL" | "NO_CALDAV_LISTS" | "LISTS_VISIBLE_UNVERIFIED" | "AUTH_FAILED" | "ERROR"; calendars: number; lists: { name: string; open: number; completed: number }[]; missing: string[]; extra: string[]; wrote?: string; message: string }

export async function probe(env: Record<string, string | undefined>, log: (s: string) => void = console.log): Promise<ProbeResult> {
  const e = normalizeEmail(env.ICLOUD_EMAIL ?? ""), p = normalizeAppPassword(env.ICLOUD_APP_PASSWORD ?? "");
  const base = { calendars: 0, lists: [], missing: [], extra: [] };
  if (!e.ok) return { ...base, verdict: "ERROR", message: `ICLOUD_EMAIL: ${e.message}` };
  if (!p.ok) return { ...base, verdict: "ERROR", message: `ICLOUD_APP_PASSWORD: ${p.message}` };
  registerSecret(e.value); registerSecret(p.value);
  const dav = new CalDavClient({ baseUrl: env.CALDAV_URL ?? "https://caldav.icloud.com/", username: e.value, password: p.value });
  try {
    const cols = await dav.listCollections();
    const cals = cols.filter((c) => c.components.includes("VEVENT"));
    const todo = cols.filter((c) => c.components.includes("VTODO") && !c.components.includes("VEVENT"));
    const lists = [];
    for (const l of todo) {
      let open = 0, completed = 0;
      for (const r of await dav.query(l.href, "VTODO")) for (const t of parseIcs(r.ics).children.flatMap((x) => x.children).filter((x) => x.type === "VTODO")) {
        if (/COMPLETED/i.test(getProp(t, "STATUS")?.value ?? "") || getProp(t, "COMPLETED")) completed++; else open++;
      }
      lists.push({ name: l.name, open, completed });
    }
    const expected = (env.EXPECTED_LISTS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    const seen = new Set(lists.map((l) => l.name.toLowerCase()));
    const missing = expected.filter((x) => !seen.has(x.toLowerCase()));
    const extra = lists.map((l) => l.name).filter((n) => expected.length && !expected.some((x) => x.toLowerCase() === n.toLowerCase()));
    let wrote: string | undefined;
    if (env.PROBE_WRITE === "yes" && todo[0]) {
      const uid = `grokbot-probe-${crypto.randomUUID()}`; const now = Date.now();
      const ics = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//icloud-mcp probe//EN", "BEGIN:VTODO", propLine("UID", uid), propLine("DTSTAMP", fmtUtc(now)), "SUMMARY:Grok Bot probe (safe to delete)", "STATUS:NEEDS-ACTION", "END:VTODO", "END:VCALENDAR", ""].join("\r\n");
      await dav.put(new URL(`${uid}.ics`, todo[0].href.endsWith("/") ? todo[0].href : todo[0].href + "/").toString(), ics, { create: true });
      wrote = todo[0].name;
    }
    let verdict: ProbeResult["verdict"]; let message: string;
    if (!todo.length) { verdict = "NO_CALDAV_LISTS"; message = "No reminder lists are visible over CalDAV. This matches Apple's upgraded Reminders (iOS 13+), which keeps lists out of CalDAV. Real Reminders can't be reached this way for this account. Calendar still works."; }
    else if (!expected.length) { verdict = "LISTS_VISIBLE_UNVERIFIED"; message = "Some reminder lists are visible over CalDAV. Set EXPECTED_LISTS to the list names you see in the Reminders app on your iPhone to check they are the real ones."; }
    else if (!missing.length) { verdict = "REAL_LISTS_VISIBLE"; message = "Every list you named is visible over CalDAV. Confirm the open counts match your iPhone. If PROBE_WRITE was used, check the probe reminder appears on your phone within a minute."; }
    else { verdict = "PARTIAL"; message = `Only some lists are visible over CalDAV. Missing: ${missing.join(", ")}. The visible ones are probably old (pre-upgrade) CalDAV lists, not your real Reminders.`; }
    const out: ProbeResult = { verdict, calendars: cals.length, lists, missing, extra, wrote, message };
    log(redact(JSON.stringify(out, null, 2)));
    return out;
  } catch (err) {
    const code = err instanceof CalDavError ? err.code : "unknown";
    const out: ProbeResult = { ...base, verdict: code === "authentication" ? "AUTH_FAILED" : "ERROR", message: explainFailure(code) };
    log(redact(JSON.stringify(out, null, 2))); return out;
  }
}

if (process.argv[1]?.endsWith("reminders-probe.ts")) {
  probe(process.env).then((r) => process.exit(r.verdict === "ERROR" || r.verdict === "AUTH_FAILED" ? 1 : 0));
}
