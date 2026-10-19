// Red-team round 3 (rc-test-11, 54cae58). Each test failed on 54cae58 and passes with its "Security:" commit.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { makeMock, seed, makeTools } from "./helpers.js";

const mock = makeMock();
before(() => mock.start()); after(() => mock.stop());
beforeEach(() => seed(mock));
const NOW = () => Date.parse("2026-10-17T06:00:00Z");
const dentistId = async (t: ReturnType<typeof makeTools>) => ((await t.call("search_events", { query: "Dentist", from: "2026-10-01", to: "2026-11-30" })) as any).events[0].event_id;

test("REDTEAM F1: an update with only a new end shows that end, and is held to the 366-day cap", async () => {
  const t = makeTools(mock, { now: NOW }); const id = await dentistId(t);
  const p: any = await t.call("prepare_update_event", { event_id: id, end: "2027-08-01T00:00" });
  const when = p.preview.split("\n").find((l: string) => l.startsWith("When:"));
  assert.match(when, /Thu, Oct 29, 2026, 10:30 AM MDT to Thu, Oct 29, 2026, 11:30 AM MDT → Thu, Oct 29, 2026, 10:30 AM MDT to Sun, Aug 1, 2027, 12:00 AM MDT/, when);
  await assert.rejects(t.call("prepare_update_event", { event_id: id, end: "2027-12-01T00:00" }), /longer than a year/);
  const s: any = await t.call("prepare_update_event", { event_id: id, start: "2026-10-30T09:00" });
  assert.match(s.preview, /→ Fri, Oct 30, 2026, 9:00 AM MDT to Fri, Oct 30, 2026, 10:00 AM MDT/);
});

test("REDTEAM F2: the iPhone approval page never says access goes to Grok Bot alone", async () => {
  const { askHtml } = await import("../src/authorize.js");
  const h = askHtml("consent", "Denver, US", "just now", { redirectUri: "https://www.cursor.com/agents/mcp/oauth/callback" }, "off, so it can't add or change events");
  assert.match(h, /Access goes to the Grok Bot account that started this connect\./);
  assert.doesNotMatch(h, /alone/);
});
