// Every token or id one tool hands out must fit the input limits of the tool that takes it back, through the real
// MCP validator (handleRpc), with no handcrafted tokens. Unit tests that call Tools directly skip the schema, which is
// how a 200-character revert_token limit reached production while ~330-character tokens were being issued.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { makeMock, seed, makeTools, USER } from "./helpers.js";
import { MockKV } from "./kv-mock.js";
import { kvUsedStore } from "../src/worker.js";
import { handleRpc } from "../src/mcp.js";
import { TOOLS } from "../src/tools.js";

const mock = makeMock(); before(() => mock.start()); after(() => mock.stop());
let kv: MockKV; beforeEach(() => { seed(mock); kv = new MockKV(); });
const NOW = Date.UTC(2026, 9, 20, 15);

/** Output field -> every [tool, input path] that consumes it. Arrays of ids use "field[]". */
const FLOWS: Record<string, [string, string][]> = {
  calendar_id: [["prepare_create_event", "calendar_id"], ["list_events", "calendar_ids[]"], ["find_free_time", "calendar_ids[]"]],
  event_id: [["get_event", "event_id"], ["prepare_update_event", "event_id"]],
  next_cursor: [["list_events", "cursor"]],
  revert_token: [["prepare_undo", "revert_token"]],
  "confirm_token@prepare_create_event": [["commit_create_event", "confirm_token"]],
  "confirm_token@prepare_update_event": [["commit_update_event", "confirm_token"]],
  "confirm_token@prepare_undo": [["commit_undo", "confirm_token"]],
};
const limitOf = (tool: string, path: string): number => {
  const p = (TOOLS.find((t) => t.name === tool)!.inputSchema as any).properties[path.replace("[]", "")];
  return path.endsWith("[]") ? p.items.maxLength : p.maxLength;
};

test("REDTEAM T1: every produced token and id round-trips through the real validator, with 2x headroom", async () => {
  const T = () => makeTools(mock, { journal: kv as any, owner: USER, usedStore: kvUsedStore(kv), now: () => NOW });
  const seen: Record<string, string[]> = {};
  const call = async (name: string, args: unknown) => {
    const r: any = await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }, T);
    assert.equal(r.result.isError, false, `${name}: ${r.result.content?.[0]?.text}`);
    const out = r.result.structuredContent;
    const grab = (o: any) => { if (!o || typeof o !== "object") return; for (const [k, v] of Object.entries(o)) {
      if (typeof v === "string" && (k in FLOWS || k === "confirm_token")) (seen[k === "confirm_token" ? `confirm_token@${name}` : k] ??= []).push(v);
      else if (typeof v === "object") grab(v);
    } };
    grab(out); return out;
  };
  // Worst-case content: every free-text field at its limit, so the create and update tokens are as long as they get.
  const big = { title: "T".repeat(255), location: "L".repeat(500), notes: "N\u00e9".repeat(2000) };
  const cals = await call("list_calendars", {});
  const home = cals.calendars.find((c: any) => c.name === "Home").calendar_id;
  await call("list_events", { from: "2026-10-01", to: "2026-12-31", calendar_ids: [home], limit: 1 });
  const p = await call("prepare_create_event", { calendar_id: home, start: "2026-11-03T12:00", ...big, alerts_minutes_before: [10, 60] });
  const c = await call("commit_create_event", { confirm_token: p.confirm_token });
  await call("get_event", { event_id: c.event_id });
  const u = await call("prepare_update_event", { event_id: c.event_id, ...big, title: "U".repeat(255) });
  const cu = await call("commit_update_event", { confirm_token: u.confirm_token });
  await call("list_changes", {});
  await call("find_free_time", { from: "2026-11-02", to: "2026-11-04", calendar_ids: [home] });
  await call("search_events", { query: "Dentist", from: "2026-10-01", to: "2026-12-31" });
  // the ACTUAL revert tokens from both commits go into prepare_undo and the ACTUAL undo token into commit_undo
  const pu = await call("prepare_undo", { revert_token: cu.revert_token });
  const done = await call("commit_undo", { confirm_token: pu.confirm_token });
  assert.match(done.message, /back|restored|Put/i);
  // an add, taken back with its own real tokens (the first event's revert_token is now stale: it was edited and restored)
  const p2 = await call("prepare_create_event", { calendar_id: home, start: "2026-11-05T12:00", ...big });
  const c2 = await call("commit_create_event", { confirm_token: p2.confirm_token });
  const pc = await call("prepare_undo", { revert_token: c2.revert_token });
  const gone = await call("commit_undo", { confirm_token: pc.confirm_token });
  assert.match(gone.message, /Removed/);
  // cursor flow
  const page = await call("list_events", { from: "2026-10-01", to: "2026-12-31", limit: 1 });
  assert.ok(page.next_cursor, "seed has more than one event");
  await call("list_events", { from: "2026-10-01", to: "2026-12-31", limit: 1, cursor: page.next_cursor });
  // the most calendars a caller may pass (50 UUID-style ids) must still give a cursor the same call accepts back
  const many = [home, ...Array.from({ length: 49 }, (_, i) => `${String(i).padStart(8, "0")}-1111-4222-8333-444455556666`)];
  const wide = await call("list_events", { from: "2026-10-01", to: "2026-12-31", limit: 1, calendar_ids: many });
  if (wide.next_cursor) await call("list_events", { from: "2026-10-01", to: "2026-12-31", limit: 1, calendar_ids: many, cursor: wide.next_cursor });

  const report: string[] = [];
  for (const [field, consumers] of Object.entries(FLOWS)) {
    const vals = seen[field] ?? []; assert.ok(vals.length, `${field} was produced`);
    const max = Math.max(...vals.map((v) => v.length));
    for (const [tool, path] of consumers) {
      const lim = limitOf(tool, path);
      report.push(`${field} max ${max} -> ${tool}.${path} limit ${lim}`);
      assert.ok(max * 2 <= lim, `${field} (${max} chars) needs 2x headroom under ${tool}.${path} (${lim})`);
    }
  }
  console.log(report.join("\n"));
});

test("REDTEAM T2: every id or token input in every tool has room for what the server issues (static check)", () => {
  // Any input named *_token, event/reminder/list id or cursor must allow at least 1024 characters, calendar ids 1000.
  for (const t of TOOLS) for (const [k, s] of Object.entries((t.inputSchema as any).properties ?? {})) {
    const p: any = s; const lim = p.type === "array" ? p.items?.maxLength : p.maxLength;
    if (/_token$|^cursor$|^(event|reminder|list)_id$/.test(k)) assert.ok(lim >= 1024, `${t.name}.${k} limit ${lim}`);
    if (/^calendar_ids?$/.test(k)) assert.ok(lim >= 1000, `${t.name}.${k} limit ${lim}`);
  }
});
