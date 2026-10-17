import { CalDavClient, CalDavError, Collection, Resource } from "./caldav.js";
import { parseIcs, getProp, parseDate, expand, unescapeText, buildEvent, patchEvent, parseUserTime, isoInZone, ITime, Component, propLine, escapeText, fmtUtc, fmtDate, foldLine, isValidZone } from "./ical.js";
import { issue, verify } from "./confirm.js";
import { log } from "./redact.js";

export interface Config { timezone: string; writesEnabled: boolean; calendarAllowlist?: string[]; confirmSecret: string; /** Experimental, off in v1: Apple's upgraded Reminders aren't reachable over CalDAV (verified on a real account, Oct 16 2026). */ remindersExperimental?: boolean }
export const REMINDER_TOOLS = new Set(["list_reminder_lists", "list_reminders", "prepare_add_reminder", "commit_add_reminder", "prepare_complete_reminder", "commit_complete_reminder"]);
export const toolsFor = (cfg: { remindersExperimental?: boolean }) => TOOLS.filter((t) => cfg.remindersExperimental || !REMINDER_TOOLS.has(t.name));
export interface ToolDef { name: string; description: string; inputSchema: Record<string, unknown>; annotations: Record<string, boolean | string> }
type Args = Record<string, any>;

const DAY = 86400000;
const str = (d: string) => ({ type: "string", description: d });
const RO = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };
const PREP = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };
const COMMIT = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true };

export const TOOLS: ToolDef[] = [
  { name: "connection_status", description: "Check the iCloud connection: whether sign-in works, how many calendars and reminder lists were found, the time zone, and whether changes are allowed. Read-only.", inputSchema: { type: "object", properties: {}, additionalProperties: false }, annotations: { title: "Connection status", ...RO } },
  { name: "list_calendars", description: "List the user's iCloud calendars (events only; reminder lists are in list_reminder_lists). Returns calendar_id, name, color, and whether it can be changed. Read-only.", inputSchema: { type: "object", properties: {}, additionalProperties: false }, annotations: { title: "List calendars", ...RO } },
  { name: "list_events", description: "List events between two times, with repeating events expanded into each occurrence, sorted by start. Times are in the user's time zone unless they include an offset. Window up to 366 days. Read-only.", inputSchema: { type: "object", properties: { from: str("Start, e.g. 2026-10-20 or 2026-10-20T09:00. Default: now."), to: str("End (exclusive). Default: 7 days after from."), calendar_ids: { type: "array", items: { type: "string" }, description: "Only these calendars. Default: all." }, limit: { type: "integer", minimum: 1, maximum: 200, description: "Default 50." }, cursor: str("next_cursor from a previous call, with the same filters.") }, additionalProperties: false }, annotations: { title: "List events", ...RO } },
  { name: "search_events", description: "Find events whose title, location or notes contain the text (case-insensitive). Default window: 30 days ago to 365 days ahead (up to 400 days). Read-only.", inputSchema: { type: "object", properties: { query: str("Text to look for."), from: str("Optional start."), to: str("Optional end."), limit: { type: "integer", minimum: 1, maximum: 100 } }, required: ["query"], additionalProperties: false }, annotations: { title: "Search events", ...RO } },
  { name: "get_event", description: "Read one event by event_id, including notes and alerts. Read-only.", inputSchema: { type: "object", properties: { event_id: str("From list_events or search_events.") }, required: ["event_id"], additionalProperties: false }, annotations: { title: "Get event", ...RO } },
  { name: "prepare_create_event", description: "Step 1 of 2 to add an event. Changes nothing. Returns a plain-English preview and a confirm_token. Show the preview to the user and call commit_create_event only after they say yes.", inputSchema: { type: "object", properties: { calendar_id: str("Where to add it (from list_calendars)."), title: str("Event title."), start: str("2026-10-20T09:00 (timed) or 2026-10-20 (all-day)."), end: str("Same format as start. All-day end is the last day, inclusive. Default: 1 hour after start, or the same day for all-day."), location: str("Optional."), notes: str("Optional."), alerts_minutes_before: { type: "array", items: { type: "integer", minimum: 0, maximum: 40320 }, maxItems: 3, description: "Optional alerts, e.g. [10, 60]." }, repeat: { type: "object", properties: { every: { type: "string", enum: ["day", "week", "month", "year"] }, interval: { type: "integer", minimum: 1, maximum: 99 }, count: { type: "integer", minimum: 1, maximum: 730 }, until: str("Last date, e.g. 2026-12-31.") }, required: ["every"], additionalProperties: false } }, required: ["calendar_id", "title", "start"], additionalProperties: false }, annotations: { title: "Preview a new event", ...PREP } },
  { name: "commit_create_event", description: "Step 2 of 2. Adds the event exactly as previewed. Only call after the user explicitly said yes to that preview.", inputSchema: { type: "object", properties: { confirm_token: str("From prepare_create_event.") }, required: ["confirm_token"], additionalProperties: false }, annotations: { title: "Add the previewed event", ...COMMIT } },
  { name: "prepare_update_event", description: "Step 1 of 2 to change an event's title, time, location or notes. Changes nothing. Returns a before/after preview and a confirm_token. Events with invitees, and the time of repeating events, can't be changed in this version.", inputSchema: { type: "object", properties: { event_id: str("From list_events."), title: str("New title."), start: str("New start."), end: str("New end."), location: str("New location, or empty to remove."), notes: str("New notes, or empty to remove.") }, required: ["event_id"], additionalProperties: false }, annotations: { title: "Preview an event change", ...PREP } },
  { name: "commit_update_event", description: "Step 2 of 2. Applies the change exactly as previewed. Only call after the user explicitly said yes. Fails safely if the event changed in iCloud meanwhile.", inputSchema: { type: "object", properties: { confirm_token: str("From prepare_update_event.") }, required: ["confirm_token"], additionalProperties: false }, annotations: { title: "Apply the previewed change", ...COMMIT } },
  { name: "list_reminder_lists", description: "List reminder (to-do) lists that iCloud shares over CalDAV. Important: lists in Apple's upgraded Reminders app (iOS 13 and later) are usually NOT shared this way, so this may be empty or show only older lists. Read-only.", inputSchema: { type: "object", properties: {}, additionalProperties: false }, annotations: { title: "List reminder lists", ...RO } },
  { name: "list_reminders", description: "List reminders in one list or all CalDAV reminder lists. Open reminders only unless include_completed is true. Read-only.", inputSchema: { type: "object", properties: { list_id: str("Optional, from list_reminder_lists."), include_completed: { type: "boolean" }, limit: { type: "integer", minimum: 1, maximum: 200 } }, additionalProperties: false }, annotations: { title: "List reminders", ...RO } },
  { name: "prepare_add_reminder", description: "Step 1 of 2 to add a reminder to a CalDAV reminder list. Changes nothing. Returns a preview and confirm_token.", inputSchema: { type: "object", properties: { list_id: str("From list_reminder_lists."), title: str("Reminder text."), due: str("Optional, 2026-10-20 or 2026-10-20T17:00."), notes: str("Optional."), priority: { type: "string", enum: ["none", "low", "medium", "high"] } }, required: ["list_id", "title"], additionalProperties: false }, annotations: { title: "Preview a new reminder", ...PREP } },
  { name: "commit_add_reminder", description: "Step 2 of 2. Adds the reminder exactly as previewed, after the user's yes.", inputSchema: { type: "object", properties: { confirm_token: str("From prepare_add_reminder.") }, required: ["confirm_token"], additionalProperties: false }, annotations: { title: "Add the previewed reminder", ...COMMIT } },
  { name: "prepare_complete_reminder", description: "Step 1 of 2 to mark a reminder done. Changes nothing. Returns a preview and confirm_token.", inputSchema: { type: "object", properties: { reminder_id: str("From list_reminders.") }, required: ["reminder_id"], additionalProperties: false }, annotations: { title: "Preview completing a reminder", ...PREP } },
  { name: "commit_complete_reminder", description: "Step 2 of 2. Marks the reminder done, after the user's yes.", inputSchema: { type: "object", properties: { confirm_token: str("From prepare_complete_reminder.") }, required: ["confirm_token"], additionalProperties: false }, annotations: { title: "Complete the previewed reminder", ...COMMIT } },
];

export class UserError extends Error {}
const enc64 = (s: string) => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const dec64 = (s: string) => { try { return decodeURIComponent(escape(atob(s.replace(/-/g, "+").replace(/_/g, "/")))); } catch { throw new UserError("That id isn't valid. List the items again and use an id from the result."); } };

export class Tools {
  private used = new Set<string>();
  private cols?: Collection[];
  constructor(private dav: CalDavClient, private cfg: Config) { if (!isValidZone(cfg.timezone)) throw new Error("TIMEZONE is not a valid IANA zone, e.g. America/Denver"); }

  private async collections(): Promise<Collection[]> {
    if (!this.cols) {
      let cs = await this.dav.listCollections();
      if (this.cfg.calendarAllowlist?.length) { const allow = new Set(this.cfg.calendarAllowlist.map((s) => s.toLowerCase())); cs = cs.filter((c) => allow.has(c.name.toLowerCase())); }
      this.cols = cs;
    }
    return this.cols;
  }
  private async calendars() { return (await this.collections()).filter((c) => c.components.includes("VEVENT")); }
  private async taskLists() { return (await this.collections()).filter((c) => c.components.includes("VTODO") && !c.components.includes("VEVENT")); }
  private async col(id: string, kind: "VEVENT" | "VTODO") {
    const c = (kind === "VEVENT" ? await this.calendars() : await this.taskLists()).find((x) => x.id === id);
    if (!c) throw new UserError(kind === "VEVENT" ? `No calendar with id "${id}". Call list_calendars for valid ids.` : `No reminder list with id "${id}". Call list_reminder_lists for valid ids.`);
    return c;
  }
  private itemId(c: Collection, href: string) { return enc64(`${c.id}\n${href}`); }
  private async fromItemId(id: string, kind: "VEVENT" | "VTODO") {
    const [cid, href] = dec64(id).split("\n"); if (!cid || !href) throw new UserError("That id isn't valid.");
    const c = await this.col(cid, kind);
    if (!new URL(href).pathname.startsWith(new URL(c.href).pathname)) throw new UserError("That id isn't valid.");
    return { c, href };
  }
  private requireWrites() {
    if (!this.cfg.writesEnabled) throw new UserError("Changes are turned off for this connection, so I can only read. To allow changes (each one still needs your yes), set WRITES_ENABLED=true in your Worker settings and redeploy.");
  }
  private t(s: string | undefined, def: number) { return s ? parseUserTime(s, this.cfg.timezone) : { utc: def, allDay: false }; }
  private show(t: ITime) {
    if (t.allDay) return new Intl.DateTimeFormat("en-US", { timeZone: "UTC", weekday: "short", month: "short", day: "numeric", year: "numeric" }).format(t.utc);
    return new Intl.DateTimeFormat("en-US", { timeZone: this.cfg.timezone, weekday: "short", month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit", timeZoneName: "short" }).format(t.utc);
  }

  async call(name: string, a: Args): Promise<unknown> {
    if (REMINDER_TOOLS.has(name) && !this.cfg.remindersExperimental) throw new UserError("Reminders aren't included in this version. Apple keeps the Reminders app's lists in a private store that outside connectors can't reach. You can ask me to put a timed event with an alert on your calendar instead.");
    switch (name) {
      case "connection_status": {
        const cs = await this.collections();
        return { connected: true, calendars: cs.filter((c) => c.components.includes("VEVENT")).length, reminders: this.cfg.remindersExperimental ? `experimental: ${cs.filter((c) => c.components.includes("VTODO") && !c.components.includes("VEVENT")).length} CalDAV list(s)` : "not included (Apple doesn't share the Reminders app over CalDAV)", timezone: this.cfg.timezone, changes_allowed: this.cfg.writesEnabled, note: this.cfg.writesEnabled ? "Changes are allowed, and each one needs a preview and your yes." : "Read-only. Changes are turned off." };
      }
      case "list_calendars": return { calendars: (await this.calendars()).map((c) => ({ calendar_id: c.id, name: c.name, color: c.color, can_change: c.writable && this.cfg.writesEnabled, read_only_reason: !c.writable ? "iCloud marks this calendar read-only (e.g. subscribed or shared view-only)" : !this.cfg.writesEnabled ? "changes are turned off for this connection" : undefined })) };
      case "list_events": return this.listEvents(a);
      case "search_events": {
        if (!a.query || typeof a.query !== "string") throw new UserError("Give some text to search for.");
        const now = Date.now();
        const from = this.t(a.from, now - 30 * DAY).utc, to = this.t(a.to, now + 365 * DAY).utc;
        const all = await this.eventsBetween(from, to, undefined, 2000, 400);
        const q = a.query.toLowerCase();
        const hits = all.filter((e) => [e.title, e.location, e.notes].some((x) => x?.toLowerCase().includes(q)));
        const limit = Math.min(a.limit ?? 25, 100);
        return { events: hits.slice(0, limit), total_matches: hits.length, truncated: hits.length > limit };
      }
      case "get_event": {
        const { c, href } = await this.fromItemId(a.event_id, "VEVENT");
        const r = await this.dav.get(href);
        const ev = this.master(r.ics); if (!ev) throw new UserError("That item isn't an event.");
        return this.normEvent(c, r, ev, undefined, true);
      }
      case "prepare_create_event": {
        this.requireWrites();
        const c = await this.col(a.calendar_id, "VEVENT");
        if (!c.writable) throw new UserError(`"${c.name}" is read-only in iCloud. Pick another calendar.`);
        if (!a.title?.trim()) throw new UserError("The event needs a title.");
        const start = parseUserTime(a.start, this.cfg.timezone);
        let end = a.end ? parseUserTime(a.end, this.cfg.timezone) : start.allDay ? { ...start } : { ...start, utc: start.utc + 3600000 };
        if (start.allDay !== end.allDay) throw new UserError("Start and end must both be dates (all-day) or both be times.");
        if (start.allDay) end = { ...end, utc: end.utc + DAY }; // inclusive -> exclusive
        if (end.utc <= start.utc) throw new UserError("The end must be after the start.");
        if (end.utc - start.utc > 366 * DAY) throw new UserError("Events longer than a year aren't supported.");
        const rrule = a.repeat ? this.rrule(a.repeat) : undefined;
        const uid = `${crypto.randomUUID()}@icloud-mcp`;
        const payload = { cid: c.id, uid, title: a.title.trim(), start, end, location: a.location?.trim() || undefined, notes: a.notes?.trim() || undefined, alerts: a.alerts_minutes_before, rrule };
        const lines = [`Add to "${c.name}": ${payload.title}`, `When: ${this.show(start)}${start.allDay ? (end.utc - start.utc > DAY ? ` to ${this.show({ ...end, utc: end.utc - DAY })}` : " (all day)") : ` to ${this.show(end)}`}`];
        if (rrule) lines.push(`Repeats: ${this.describeRepeat(a.repeat)}`);
        if (payload.location) lines.push(`Where: ${payload.location}`);
        if (payload.alerts?.length) lines.push(`Alerts: ${payload.alerts.map((m: number) => humanMinutes(m)).join(", ")} before`);
        if (payload.notes) lines.push(`Notes: ${payload.notes.slice(0, 200)}`);
        return { preview: lines.join("\n"), confirm_token: await issue(this.cfg.confirmSecret, "create_event", payload), expires_in_minutes: 10, next_step: "Show this preview. Call commit_create_event only if the user says yes." };
      }
      case "commit_create_event": {
        this.requireWrites();
        const v = await verify<any>(this.cfg.confirmSecret, a.confirm_token, "create_event", this.used); if (!v.ok) throw new UserError(v.reason);
        const p = v.payload; const c = await this.col(p.cid, "VEVENT");
        const href = new URL(`${encodeURIComponent(p.uid.replace(/@.*/, ""))}.ics`, c.href.endsWith("/") ? c.href : c.href + "/").toString();
        const ics = buildEvent(p.uid, { title: p.title, start: p.start, end: p.end, location: p.location, notes: p.notes, alertsMinutesBefore: p.alerts, rrule: p.rrule });
        try { await this.dav.put(href, ics, { create: true }); }
        catch (e) { if (e instanceof CalDavError && e.code === "conflict") return { done: true, note: "This event was already added. Nothing was added twice." }; throw e; }
        log.info("event created");
        return { done: true, event_id: this.itemId(c, href), message: `Added "${p.title}" to ${c.name}.` };
      }
      case "prepare_update_event": {
        this.requireWrites();
        const { c, href } = await this.fromItemId(a.event_id, "VEVENT");
        if (!c.writable) throw new UserError(`"${c.name}" is read-only in iCloud.`);
        const r = await this.dav.get(href); const ev = this.master(r.ics); if (!ev) throw new UserError("That item isn't an event.");
        if (ev.props.some((p) => p.name === "ATTENDEE")) throw new UserError("This event has invitees. Changing it could email them, and this version never sends invitations or updates. Change it in the Calendar app instead.");
        const cur = this.normEvent(c, r, ev, undefined, true);
        const recurring = !!getProp(ev, "RRULE");
        if (recurring && (a.start || a.end)) throw new UserError("Changing the time of a repeating event isn't supported yet. You can change its title, location or notes.");
        const patch: any = {}; const diff: string[] = [];
        if (a.title !== undefined) { if (!a.title.trim()) throw new UserError("The title can't be empty."); patch.title = a.title.trim(); diff.push(`Title: "${cur.title}" → "${patch.title}"`); }
        const oldStart = parseDate(getProp(ev, "DTSTART"), this.cfg.timezone)!; const oldEnd = endOf(ev, oldStart, this.cfg.timezone);
        if (a.start || a.end) {
          let s = a.start ? parseUserTime(a.start, this.cfg.timezone) : oldStart;
          let e = a.end ? parseUserTime(a.end, this.cfg.timezone) : { ...oldEnd, utc: s.utc + (oldEnd.utc - oldStart.utc) };
          if (a.end && e.allDay) e = { ...e, utc: e.utc + DAY };
          if (s.allDay !== e.allDay) throw new UserError("Start and end must both be dates or both be times.");
          if (e.utc <= s.utc) throw new UserError("The end must be after the start.");
          patch.start = s; patch.end = e;
          diff.push(`When: ${this.show(oldStart)} → ${this.show(s)}`);
        }
        if (a.location !== undefined) { patch.location = a.location.trim() || null; diff.push(`Where: "${cur.location ?? ""}" → "${patch.location ?? "(none)"}"`); }
        if (a.notes !== undefined) { patch.notes = a.notes.trim() || null; diff.push(`Notes: ${patch.notes ? "updated" : "removed"}`); }
        if (!diff.length) throw new UserError("Nothing to change. Give a new title, start, end, location or notes.");
        const payload = { cid: c.id, href, etag: r.etag, patch };
        return { preview: [`Change "${cur.title}" in ${c.name}${recurring ? " (all repeats)" : ""}:`, ...diff].join("\n"), confirm_token: await issue(this.cfg.confirmSecret, "update_event", payload), expires_in_minutes: 10, next_step: "Show this preview. Call commit_update_event only if the user says yes." };
      }
      case "commit_update_event": {
        this.requireWrites();
        const v = await verify<any>(this.cfg.confirmSecret, a.confirm_token, "update_event", this.used); if (!v.ok) throw new UserError(v.reason);
        const { cid, href, etag, patch } = v.payload; const c = await this.col(cid, "VEVENT");
        const r = await this.dav.get(href);
        if (etag && r.etag && r.etag !== etag) throw new UserError("This event changed in iCloud after the preview. Nothing was changed. Ask for a fresh preview.");
        await this.dav.put(href, patchEvent(r.ics, patch), { etag: r.etag || etag });
        log.info("event updated");
        return { done: true, event_id: this.itemId(c, href), message: "Updated." };
      }
      case "list_reminder_lists": {
        const ls = await this.taskLists();
        return { lists: ls.map((l) => ({ list_id: l.id, name: l.name, can_change: l.writable && this.cfg.writesEnabled })), note: ls.length ? undefined : "No reminder lists are shared over CalDAV. That's normal if Reminders was upgraded on iOS 13 or later, because Apple keeps those lists in a separate store that outside apps can't reach this way." };
      }
      case "list_reminders": {
        const ls = a.list_id ? [await this.col(a.list_id, "VTODO")] : await this.taskLists();
        const out: any[] = [];
        for (const l of ls) for (const r of await this.dav.query(l.href, "VTODO")) for (const t of parseIcs(r.ics).children.flatMap((x) => x.children).filter((x) => x.type === "VTODO")) {
          const done = /^(COMPLETED)$/i.test(getProp(t, "STATUS")?.value ?? "") || !!getProp(t, "COMPLETED");
          if (done && !a.include_completed) continue;
          const due = parseDate(getProp(t, "DUE"), this.cfg.timezone);
          out.push({ reminder_id: this.itemId(l, r.href), list: l.name, title: unescapeText(getProp(t, "SUMMARY")?.value ?? "(no title)"), due: due ? (due.allDay ? new Date(due.utc).toISOString().slice(0, 10) : isoInZone(due.utc, this.cfg.timezone)) : undefined, completed: done, priority: prio(Number(getProp(t, "PRIORITY")?.value ?? 0)), notes: trunc(unescapeText(getProp(t, "DESCRIPTION")?.value ?? ""), 300) || undefined });
        }
        out.sort((x, y) => (x.due ?? "9999").localeCompare(y.due ?? "9999"));
        const limit = Math.min(a.limit ?? 100, 200);
        return { reminders: out.slice(0, limit), truncated: out.length > limit, note: ls.length ? undefined : "No reminder lists are shared over CalDAV (see list_reminder_lists)." };
      }
      case "prepare_add_reminder": {
        this.requireWrites();
        const l = await this.col(a.list_id, "VTODO"); if (!l.writable) throw new UserError(`"${l.name}" is read-only.`);
        if (!a.title?.trim()) throw new UserError("The reminder needs some text.");
        const due = a.due ? parseUserTime(a.due, this.cfg.timezone) : undefined;
        const payload = { lid: l.id, uid: `${crypto.randomUUID()}@icloud-mcp`, title: a.title.trim(), due, notes: a.notes?.trim() || undefined, priority: a.priority ?? "none" };
        return { preview: [`Add to "${l.name}": ${payload.title}`, due ? `Due: ${this.show(due)}` : "", payload.priority !== "none" ? `Priority: ${payload.priority}` : ""].filter(Boolean).join("\n"), confirm_token: await issue(this.cfg.confirmSecret, "add_reminder", payload), expires_in_minutes: 10, next_step: "Show this preview. Call commit_add_reminder only if the user says yes." };
      }
      case "commit_add_reminder": {
        this.requireWrites();
        const v = await verify<any>(this.cfg.confirmSecret, a.confirm_token, "add_reminder", this.used); if (!v.ok) throw new UserError(v.reason);
        const p = v.payload; const l = await this.col(p.lid, "VTODO");
        const href = new URL(`${encodeURIComponent(p.uid.replace(/@.*/, ""))}.ics`, l.href.endsWith("/") ? l.href : l.href + "/").toString();
        const now = Date.now();
        const L = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//icloud-mcp//EN", "BEGIN:VTODO", propLine("UID", p.uid), propLine("DTSTAMP", fmtUtc(now)), propLine("CREATED", fmtUtc(now)), propLine("SUMMARY", escapeText(p.title)), "STATUS:NEEDS-ACTION"];
        if (p.due) L.push(p.due.allDay ? propLine("DUE", fmtDate(p.due.utc), { VALUE: "DATE" }) : propLine("DUE", fmtUtc(p.due.utc)));
        if (p.notes) L.push(propLine("DESCRIPTION", escapeText(p.notes)));
        const pr = { none: 0, high: 1, medium: 5, low: 9 }[p.priority as string] ?? 0; if (pr) L.push(`PRIORITY:${pr}`);
        L.push("END:VTODO", "END:VCALENDAR");
        try { await this.dav.put(href, L.join("\r\n") + "\r\n", { create: true }); }
        catch (e) { if (e instanceof CalDavError && e.code === "conflict") return { done: true, note: "Already added. Nothing was added twice." }; throw e; }
        return { done: true, reminder_id: this.itemId(l, href), message: `Added "${p.title}" to ${l.name}.` };
      }
      case "prepare_complete_reminder": {
        this.requireWrites();
        const { c, href } = await this.fromItemId(a.reminder_id, "VTODO");
        const r = await this.dav.get(href); const t = parseIcs(r.ics).children.flatMap((x) => x.children).find((x) => x.type === "VTODO");
        if (!t) throw new UserError("That item isn't a reminder.");
        return { preview: `Mark done in "${c.name}": ${unescapeText(getProp(t, "SUMMARY")?.value ?? "(no title)")}`, confirm_token: await issue(this.cfg.confirmSecret, "complete_reminder", { lid: c.id, href, etag: r.etag }), expires_in_minutes: 10, next_step: "Show this preview. Call commit_complete_reminder only if the user says yes." };
      }
      case "commit_complete_reminder": {
        this.requireWrites();
        const v = await verify<any>(this.cfg.confirmSecret, a.confirm_token, "complete_reminder", this.used); if (!v.ok) throw new UserError(v.reason);
        const { href, etag } = v.payload; const r = await this.dav.get(href);
        if (etag && r.etag && r.etag !== etag) throw new UserError("This reminder changed after the preview. Nothing was changed. Ask for a fresh preview.");
        await this.dav.put(href, completeTodo(r.ics), { etag: r.etag || etag });
        return { done: true, message: "Marked done." };
      }
      default: throw new UserError(`Unknown tool "${name}".`);
    }
  }

  private rrule(rp: Args) {
    const f = { day: "DAILY", week: "WEEKLY", month: "MONTHLY", year: "YEARLY" }[rp.every as string]; if (!f) throw new UserError("repeat.every must be day, week, month or year.");
    let r = `FREQ=${f}`; if (rp.interval && rp.interval > 1) r += `;INTERVAL=${rp.interval}`;
    if (rp.count && rp.until) throw new UserError("Use either repeat.count or repeat.until, not both.");
    if (rp.count) r += `;COUNT=${rp.count}`;
    if (rp.until) { const u = parseUserTime(rp.until, this.cfg.timezone); r += `;UNTIL=${fmtUtc(u.utc + (u.allDay ? DAY - 1000 : 0))}`; }
    return r;
  }
  private describeRepeat(rp: Args) { const n = rp.interval > 1 ? `every ${rp.interval} ${rp.every}s` : `every ${rp.every}`; return n + (rp.count ? `, ${rp.count} times` : rp.until ? `, until ${rp.until}` : ""); }

  private master(ics: string): Component | undefined { return parseIcs(ics).children.flatMap((x) => x.children).find((x) => x.type === "VEVENT" && !getProp(x, "RECURRENCE-ID")); }

  private normEvent(c: Collection, r: Resource, ev: Component, occ?: { start: number; end: number }, full = false) {
    const tz = this.cfg.timezone;
    const s = parseDate(getProp(ev, "DTSTART"), tz)!; const e = endOf(ev, s, tz);
    const start = occ?.start ?? s.utc, end = occ?.end ?? e.utc;
    const fmtT = (ms: number) => (s.allDay ? new Date(ms).toISOString().slice(0, 10) : isoInZone(ms, tz));
    const notes = unescapeText(getProp(ev, "DESCRIPTION")?.value ?? "");
    return { event_id: this.itemId(c, r.href), calendar_id: c.id, calendar: c.name, title: unescapeText(getProp(ev, "SUMMARY")?.value ?? "(no title)"), start: fmtT(start), end: s.allDay ? fmtT(end - DAY) : fmtT(end), all_day: s.allDay, location: unescapeText(getProp(ev, "LOCATION")?.value ?? "") || undefined, notes: (full ? notes : trunc(notes, 280)) || undefined, repeating: !!getProp(ev, "RRULE"), has_invitees: ev.props.some((p) => p.name === "ATTENDEE"), alerts: full ? ev.children.filter((x) => x.type === "VALARM").map((x) => getProp(x, "TRIGGER")?.value) : undefined, _sort: start };
  }

  private async eventsBetween(from: number, to: number, ids?: string[], cap = 5000, maxDays = 366) {
    if (!(to > from)) throw new UserError("The end must be after the start.");
    if (to - from > maxDays * DAY) throw new UserError(`Please ask for ${maxDays} days or less at a time.`);
    let cals = await this.calendars(); if (ids?.length) { cals = cals.filter((c) => ids.includes(c.id)); if (!cals.length) throw new UserError("None of those calendar ids exist. Call list_calendars."); }
    const out: ReturnType<Tools["normEvent"]>[] = []; const unexpandable: string[] = [];
    for (const c of cals) for (const r of await this.dav.query(c.href, "VEVENT", { from, to })) {
      const comps = parseIcs(r.ics).children.flatMap((x) => x.children).filter((x) => x.type === "VEVENT");
      const ev = comps.find((x) => !getProp(x, "RECURRENCE-ID")); const overrides = comps.filter((x) => getProp(x, "RECURRENCE-ID"));
      if (ev) {
        const s = parseDate(getProp(ev, "DTSTART"), this.cfg.timezone); if (!s) continue;
        const e = endOf(ev, s, this.cfg.timezone);
        const ex = ev.props.filter((p) => p.name === "EXDATE").flatMap((p) => p.value.split(",").map((v) => parseDate({ ...p, value: v }, this.cfg.timezone)?.utc)).filter((x): x is number => x !== undefined);
        const ovIds = overrides.map((o) => parseDate(getProp(o, "RECURRENCE-ID"), this.cfg.timezone)?.utc).filter((x): x is number => x !== undefined);
        const { occ, supported } = expand(s, e.utc - s.utc, getProp(ev, "RRULE")?.value, [...ex, ...ovIds], from, to);
        if (!supported) { unexpandable.push(unescapeText(getProp(ev, "SUMMARY")?.value ?? "")); out.push({ ...this.normEvent(c, r, ev), repeating: true, note: "Repeats in a pattern this version can't expand; showing the first occurrence." } as any); }
        for (const o of occ) out.push(this.normEvent(c, r, ev, o));
      }
      for (const o of overrides) { const s = parseDate(getProp(o, "DTSTART"), this.cfg.timezone); if (!s) continue; const e = endOf(o, s, this.cfg.timezone); if (s.utc < to && e.utc > from && !/CANCELLED/i.test(getProp(o, "STATUS")?.value ?? "")) out.push({ ...this.normEvent(c, r, o), repeating: true }); }
      if (out.length > cap) break;
    }
    out.sort((x, y) => x._sort - y._sort || x.title.localeCompare(y.title));
    return out.map(({ _sort, ...rest }) => rest);
  }

  private async listEvents(a: Args) {
    const now = Date.now();
    let from = this.t(a.from, now).utc; const to = a.to ? this.t(a.to, 0).utc : from + 7 * DAY;
    const limit = Math.min(a.limit ?? 50, 200);
    let offset = 0;
    if (a.cursor) { const c = dec64(a.cursor).split("|"); offset = Number(c[1]); if (c[0] !== `${from}:${to}:${(a.calendar_ids ?? []).join(",")}` || !(offset >= 0)) throw new UserError("That cursor belongs to a different query. Start again without a cursor."); }
    const all = await this.eventsBetween(from, to, a.calendar_ids);
    const page = all.slice(offset, offset + limit);
    const next = offset + limit < all.length ? enc64(`${from}:${to}:${(a.calendar_ids ?? []).join(",")}|${offset + limit}`) : undefined;
    return { timezone: this.cfg.timezone, from: isoInZone(from, this.cfg.timezone), to: isoInZone(to, this.cfg.timezone), events: page, next_cursor: next, total: all.length };
  }
}

function endOf(ev: Component, s: ITime, tz: string): ITime {
  const e = parseDate(getProp(ev, "DTEND"), tz); if (e) return e;
  const d = getProp(ev, "DURATION")?.value; if (d) return { ...s, utc: s.utc + durMs(d) };
  return { ...s, utc: s.utc + (s.allDay ? DAY : 0) };
}
export function durMs(d: string) { const m = d.match(/^([+-])?P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/); if (!m) return 0; const v = ((+(m[2] ?? 0) * 7 + +(m[3] ?? 0)) * 86400 + +(m[4] ?? 0) * 3600 + +(m[5] ?? 0) * 60 + +(m[6] ?? 0)) * 1000; return m[1] === "-" ? -v : v; }
const trunc = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
const prio = (p: number) => (p === 0 ? "none" : p <= 4 ? "high" : p === 5 ? "medium" : "low");
function humanMinutes(m: number) { return m % 1440 === 0 && m ? `${m / 1440} day${m === 1440 ? "" : "s"}` : m % 60 === 0 && m ? `${m / 60} hour${m === 60 ? "" : "s"}` : `${m} min`; }
export function completeTodo(raw: string, now = Date.now()): string {
  const lines = raw.replace(/\r\n/g, "\n").replace(/\n[ \t]/g, "").split("\n").filter(Boolean);
  const out: string[] = []; let inTodo = false; let depth = 0;
  for (const l of lines) {
    if (/^BEGIN:/i.test(l)) depth++;
    if (/^BEGIN:VTODO$/i.test(l)) inTodo = true;
    if (inTodo && /^END:VTODO$/i.test(l)) { out.push("STATUS:COMPLETED", `COMPLETED:${fmtUtc(now)}`, "PERCENT-COMPLETE:100", `LAST-MODIFIED:${fmtUtc(now)}`); inTodo = false; }
    if (inTodo && depth === 2 && /^(STATUS|COMPLETED|PERCENT-COMPLETE|LAST-MODIFIED)[;:]/i.test(l)) { if (/^END:/i.test(l)) depth--; continue; }
    out.push(foldLine(l));
    if (/^END:/i.test(l)) depth--;
  }
  return out.join("\r\n") + "\r\n";
}
