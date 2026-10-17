// 200+ plain-English date phrases with hand-checked answers, including DST changes, month ends and leap years.
// Expected values are written out by hand, or (for the generated families) computed with plain Date.UTC arithmetic
// independent of the parser.
import { test } from "node:test";
import assert from "node:assert/strict";
import { resolvePhrase } from "../src/phrases.js";
import { isoInZone } from "../src/ical.js";

const show = (r: any, tz: string) => r.kind === "time" ? (() => { const s = isoInZone(r.start.utc, tz); return s.slice(0, 16) + s.slice(19); })() : new Date(r.start.utc).toISOString().slice(0, 10) + (r.end ? ".." + new Date(r.end.utc).toISOString().slice(0, 10) : "");
const run = (now: string, tz: string, cases: [string, string][]) => { for (const [p, want] of cases) { let got: string; try { got = show(resolvePhrase(p, Date.parse(now), tz), tz); } catch { got = "ERR"; } assert.equal(got, want, `"${p}" at ${now} in ${tz}`); } return cases.length; };
let total = 0;

// Saturday Oct 17 2026, 00:07 in Denver (MDT, -06:00). This week is Mon Oct 12 to Sun Oct 18.
const SAT = "2026-10-17T06:07:00Z", D = "America/Denver";
const HAND: [string, string][] = [
  ["today", "2026-10-17"], ["Today", "2026-10-17"], ["tomorrow", "2026-10-18"], ["tmrw", "2026-10-18"], ["yesterday", "2026-10-16"],
  ["day after tomorrow", "2026-10-19"], ["the day after tomorrow", "2026-10-19"], ["day before yesterday", "2026-10-15"],
  ["tonight", "2026-10-17T20:00-06:00"], ["this morning", "2026-10-17T09:00-06:00"], ["this afternoon", "2026-10-17T14:00-06:00"], ["this evening", "2026-10-17T18:00-06:00"],
  ["noon", "2026-10-17T12:00-06:00"], ["midnight", "2026-10-18T00:00-06:00"], ["3pm", "2026-10-17T15:00-06:00"], ["3 pm", "2026-10-17T15:00-06:00"], ["3 p.m.", "2026-10-17T15:00-06:00"],
  ["9am", "2026-10-17T09:00-06:00"], ["12:05am", "2026-10-18T00:05-06:00"], ["00:10", "2026-10-17T00:10-06:00"], ["15:30", "2026-10-17T15:30-06:00"], ["at 4", "2026-10-17T16:00-06:00"], ["at 9", "2026-10-17T09:00-06:00"],
  ["monday", "2026-10-19"], ["Tuesday", "2026-10-20"], ["wed", "2026-10-21"], ["thursday", "2026-10-22"], ["fri", "2026-10-23"], ["saturday", "2026-10-17"], ["sunday", "2026-10-18"],
  ["this friday", "2026-10-23"], ["this sunday", "2026-10-18"], ["coming tuesday", "2026-10-20"],
  ["next monday", "2026-10-19"], ["next friday", "2026-10-23"], ["next saturday", "2026-10-24"], ["next sunday", "2026-10-25"],
  ["last friday", "2026-10-16"], ["last saturday", "2026-10-10"], ["last monday", "2026-10-12"], ["last sunday", "2026-10-11"],
  ["next week", "2026-10-19..2026-10-25"], ["this week", "2026-10-12..2026-10-18"], ["last week", "2026-10-05..2026-10-11"],
  ["this weekend", "2026-10-17..2026-10-18"], ["next weekend", "2026-10-24..2026-10-25"],
  ["next month", "2026-11-01..2026-11-30"], ["this month", "2026-10-01..2026-10-31"], ["last month", "2026-09-01..2026-09-30"], ["next year", "2027-01-01..2027-12-31"],
  ["end of month", "2026-10-31"], ["end of the month", "2026-10-31"], ["end of next month", "2026-11-30"], ["start of next month", "2026-11-01"], ["beginning of next month", "2026-11-01"],
  ["first day of next month", "2026-11-01"], ["last day of the month", "2026-10-31"], ["end of year", "2026-12-31"], ["end of the year", "2026-12-31"], ["start of next year", "2027-01-01"],
  ["end of the week", "2026-10-23"], ["end of next week", "2026-10-23"], ["start of next week", "2026-10-19"],
  ["eod", "2026-10-17T17:00-06:00"], ["end of day", "2026-10-17T17:00-06:00"], ["tomorrow eod", "2026-10-18T17:00-06:00"], ["friday by end of day", "2026-10-23T17:00-06:00"],
  ["oct 20", "2026-10-20"], ["October 20th", "2026-10-20"], ["20 october", "2026-10-20"], ["20th of October", "2026-10-20"], ["oct 20 2027", "2027-10-20"], ["October 20, 2027", "2027-10-20"],
  ["oct 15", "2027-10-15"], ["oct 17", "2026-10-17"], ["dec 25", "2026-12-25"], ["jan 1", "2027-01-01"], ["feb 29", "2028-02-29"], ["sept 3", "2027-09-03"],
  ["10/20", "2026-10-20"], ["10/20/2027", "2027-10-20"], ["1/5", "2027-01-05"], ["12/31/26", "2026-12-31"],
  ["first monday of november", "2026-11-02"], ["last friday of the month", "2026-10-30"], ["2nd tuesday of next month", "2026-11-10"], ["third thursday of november", "2026-11-19"],
  ["fourth thursday of november", "2026-11-26"], ["last sunday of october", "2026-10-25"], ["first friday of december 2026", "2026-12-04"], ["1st wednesday of this month", "2026-10-07"],
  ["first monday of january", "2027-01-04"], ["last monday of may", "2027-05-31"],
  ["in 2 days", "2026-10-19"], ["in two days", "2026-10-19"], ["in 3 weeks", "2026-11-07"], ["in 1 month", "2026-11-17"], ["in a week", "2026-10-24"], ["in a month", "2026-11-17"], ["in a year", "2027-10-17"],
  ["a week from today", "2026-10-24"], ["2 weeks from tomorrow", "2026-11-01"], ["3 days ago", "2026-10-14"], ["a week ago", "2026-10-10"], ["a week from friday", "2026-10-30"], ["in a couple of days", "2026-10-19"], ["in a few days", "2026-10-20"],
  ["in 2 hours", "2026-10-17T02:07-06:00"], ["in 90 minutes", "2026-10-17T01:37-06:00"], ["in half an hour", "2026-10-17T00:37-06:00"], ["in an hour", "2026-10-17T01:07-06:00"], ["30 minutes from now", "2026-10-17T00:37-06:00"], ["now", "2026-10-17T00:07-06:00"],
  ["tomorrow at 3pm", "2026-10-18T15:00-06:00"], ["tomorrow 9", "2026-10-18T09:00-06:00"], ["next tue 3pm", "2026-10-20T15:00-06:00"], ["friday 9:30am", "2026-10-23T09:30-06:00"],
  ["oct 20 at 2pm", "2026-10-20T14:00-06:00"], ["3pm tomorrow", "2026-10-18T15:00-06:00"], ["monday morning", "2026-10-19T09:00-06:00"], ["tuesday afternoon", "2026-10-20T14:00-06:00"],
  ["noon tomorrow", "2026-10-18T12:00-06:00"], ["tonight at 8:30", "2026-10-17T20:30-06:00"], ["tonight at 9", "2026-10-17T21:00-06:00"], ["tomorrow at 7", "2026-10-18T19:00-06:00"], ["tomorrow morning at 7", "2026-10-18T07:00-06:00"],
  ["tomorrow evening at 6:45", "2026-10-18T18:45-06:00"], ["on Friday, at 3 p.m.", "2026-10-23T15:00-06:00"], ["10/20 at 9am", "2026-10-20T09:00-06:00"], ["first monday of november at 10am", "2026-11-02T10:00-07:00"],
  ["nov 1 at 9am", "2026-11-01T09:00-07:00"], ["nov 1 at 1:30am", "2026-11-01T01:30-06:00"], ["in 2 weeks at 10am", "2026-10-31T10:00-06:00"], ["in 3 weeks at 10am", "2026-11-07T10:00-07:00"], ["next sunday at noon", "2026-10-25T12:00-06:00"],
  ["blah", "ERR"], ["feb 30", "ERR"], ["13/45", "ERR"], ["next week at 3pm", "ERR"], ["at 25", "ERR"], ["14:75", "ERR"], ["fifth monday of november", "2026-11-30"], ["fifth friday of november", "ERR"], ["", "ERR"],
];
test("hand-checked phrases (Sat Oct 17 2026, Denver)", () => { total += run(SAT, D, HAND); });

test("generated families: day, week and month arithmetic, month-day and numeric dates, clock times", () => {
  const ymd = (y: number, m: number, d: number) => new Date(Date.UTC(y, m - 1, d)).toISOString().slice(0, 10);
  const C: [string, string][] = [];
  for (let n = 1; n <= 40; n++) C.push([`in ${n} days`, ymd(2026, 10, 17 + n)]);
  for (let n = 1; n <= 10; n++) C.push([`${n} days ago`, ymd(2026, 10, 17 - n)]);
  for (let n = 1; n <= 10; n++) C.push([`in ${n} weeks`, ymd(2026, 10, 17 + 7 * n)]);
  const MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];
  MONTHS.forEach((m, i) => { for (const d of [1, 15]) { const y = Date.UTC(2026, i, d) >= Date.UTC(2026, 9, 17) ? 2026 : 2027; C.push([`${m} ${d}`, ymd(y, i + 1, d)]); } });
  for (let m = 1; m <= 12; m++) C.push([`${m}/10`, ymd(Date.UTC(2026, m - 1, 10) >= Date.UTC(2026, 9, 17) ? 2026 : 2027, m, 10)]);
  for (let h = 1; h <= 12; h++) { C.push([`tomorrow at ${h}am`, `2026-10-18T${String(h % 12).padStart(2, "0")}:00-06:00`]); C.push([`tomorrow at ${h}pm`, `2026-10-18T${String((h % 12) + 12).padStart(2, "0")}:00-06:00`]); }
  for (let n = 1; n <= 12; n++) { const s = isoInZone(Date.parse(SAT) + n * 3600_000, D); C.push([`in ${n} hours`, s.slice(0, 16) + s.slice(19)]); }
  ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"].forEach((w, i) => { C.push([`next ${w}`, ymd(2026, 10, 19 + i)]); const wd = (i + 1) % 7; C.push([`last ${w}`, ymd(2026, 10, 17 - (((6 - wd + 7) % 7) || 7))]); });
  total += run(SAT, D, C);
});

test("month ends and leap years", () => {
  total += run("2027-01-31T17:00:00Z", D, [["in 1 month", "2027-02-28"], ["in 2 months", "2027-03-31"], ["end of month", "2027-01-31"], ["end of next month", "2027-02-28"], ["next month", "2027-02-01..2027-02-28"], ["tomorrow", "2027-02-01"], ["in 1 year", "2028-01-31"], ["last day of next month", "2027-02-28"], ["feb 29", "2028-02-29"]]);
  total += run("2028-02-10T19:00:00Z", D, [["end of month", "2028-02-29"], ["feb 29", "2028-02-29"], ["in 3 weeks", "2028-03-02"], ["last thursday of the month", "2028-02-24"]]);
  total += run("2028-02-29T19:00:00Z", D, [["in 1 year", "2029-02-28"], ["tomorrow", "2028-03-01"], ["yesterday", "2028-02-28"], ["in 1 month", "2028-03-29"], ["a year ago", "2027-02-28"]]);
  total += run("2026-12-31T23:30:00-07:00", D, [["tomorrow", "2027-01-01"], ["next month", "2027-01-01..2027-01-31"], ["in 1 hour", "2027-01-01T00:30-07:00"], ["this weekend", "2027-01-02..2027-01-03"], ["next year", "2027-01-01..2027-12-31"], ["end of the year", "2026-12-31"]]);
});

test("daylight saving changes", () => {
  // Day before US DST starts (Sun Mar 14 2027, 02:00 jumps to 03:00).
  total += run("2027-03-13T19:00:00Z", D, [["tomorrow at 2:30am", "2027-03-14T03:30-06:00"], ["tomorrow at 9am", "2027-03-14T09:00-06:00"], ["in 24 hours", "2027-03-14T13:00-06:00"], ["in 1 day", "2027-03-14"], ["tonight", "2027-03-13T20:00-07:00"], ["tomorrow at 1:59am", "2027-03-14T01:59-07:00"], ["tomorrow at 3am", "2027-03-14T03:00-06:00"]]);
  // Day before DST ends (Sun Nov 1 2026, 02:00 back to 01:00).
  total += run("2026-10-31T16:00:00Z", D, [["tomorrow at 10am", "2026-11-01T10:00-07:00"], ["in 24 hours", "2026-11-01T09:00-07:00"], ["next week", "2026-11-02..2026-11-08"], ["monday at 9", "2026-11-02T09:00-07:00"], ["tomorrow at 1:30am", "2026-11-01T01:30-06:00"]]);
  // Other zones: London (DST ends Oct 25 2026) and Tokyo (no DST, ahead of UTC: already Saturday afternoon).
  total += run("2026-10-24T12:00:00Z", "Europe/London", [["tomorrow at 9am", "2026-10-25T09:00+00:00"], ["today at 9pm", "2026-10-24T21:00+01:00"], ["in 2 days", "2026-10-26"]]);
  total += run(SAT, "Asia/Tokyo", [["today", "2026-10-17"], ["tonight", "2026-10-17T20:00+09:00"], ["tomorrow at 8am", "2026-10-18T08:00+09:00"], ["3pm", "2026-10-18T15:00+09:00"], ["4pm", "2026-10-17T16:00+09:00"], ["noon", "2026-10-18T12:00+09:00"]]);
});

test("at least 200 phrases checked", () => { assert.ok(total >= 200, `only ${total}`); });
