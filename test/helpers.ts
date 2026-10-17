// Shared fixtures for the v1 test files: a mock iCloud with a known week of events, and a Tools factory.
import { MockCalDav } from "./mock-caldav.js";
import { CalDavClient } from "../src/caldav.js";
import { Tools, Config } from "../src/tools.js";
import { registerSecret } from "../src/redact.js";

export const USER = "test.user@example.com", PASS = "abcd-efgh-ijkl-mnop", TZ = "America/Denver", SECRET = "c".repeat(32);
export const ev = (uid: string, lines: string[]) => ["BEGIN:VCALENDAR", "VERSION:2.0", "BEGIN:VEVENT", `UID:${uid}`, ...lines, "END:VEVENT", "END:VCALENDAR", ""].join("\r\n");
export function makeMock() { return new MockCalDav({ user: USER, pass: PASS }); }
export function seed(mock: MockCalDav) {
  mock.items.clear(); mock.requests = []; mock.fail = null;
  mock.add("home", "standup.ics", ev("standup-1", ["DTSTART;TZID=America/Denver:20261026T090000", "DTEND;TZID=America/Denver:20261026T093000", "SUMMARY:Standup", "RRULE:FREQ=WEEKLY;BYDAY=MO,WE;COUNT=6", "EXDATE;TZID=America/Denver:20261028T090000"]));
  mock.add("home", "dentist.ics", ev("dentist-1", ["DTSTART:20261029T163000Z", "DURATION:PT1H", "SUMMARY:Dentist", "LOCATION:12 Main St"]));
  mock.add("work", "offsite.ics", ev("offsite-1", ["DTSTART;VALUE=DATE:20261030", "DTEND;VALUE=DATE:20261101", "SUMMARY:Team offsite"]));
  mock.add("work", "review.ics", ev("review-1", ["DTSTART:20261027T200000Z", "DTEND:20261027T210000Z", "SUMMARY:Design review", "ORGANIZER:mailto:boss@example.com", "ATTENDEE;CN=Me:mailto:test.user@example.com"]));
  mock.add("home", "focus.ics", ev("focus-1", ["DTSTART;TZID=America/Denver:20261027T100000", "DTEND;TZID=America/Denver:20261027T120000", "SUMMARY:Focus (shown as free)", "TRANSP:TRANSPARENT"]));
  mock.add("home", "gone.ics", ev("gone-1", ["DTSTART;TZID=America/Denver:20261027T150000", "DTEND;TZID=America/Denver:20261027T160000", "SUMMARY:Cancelled thing", "STATUS:CANCELLED"]));
}
export function makeTools(mock: MockCalDav, cfg: Partial<Config> = {}, user = USER) {
  registerSecret(PASS); registerSecret(USER);
  return new Tools(new CalDavClient({ baseUrl: mock.base, username: user === USER ? USER : user, password: PASS, sleep: async () => {} }), { timezone: TZ, writesEnabled: true, confirmSecret: SECRET, ...cfg });
}
