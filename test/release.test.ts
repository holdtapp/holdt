// v1.0 release checks: every client sees every tool, whatever protocol version it speaks and whether writes are on.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { makeMock, seed, makeTools } from "./helpers.js";
import { mcpEndpoint } from "../src/worker.js";
import { SUPPORTED, SERVER_INFO } from "../src/mcp.js";
import { TOOLS, REMINDER_TOOLS } from "../src/tools.js";
import { setLogSink } from "../src/redact.js";

const mock = makeMock(); before(() => mock.start()); after(() => mock.stop()); beforeEach(() => seed(mock));
const EPOCH = "epoch-" + "e".repeat(30);
const env = (writes: boolean): any => ({ ICLOUD_EMAIL: "test.user@example.com", ICLOUD_APP_PASSWORD: "abcd-efgh-ijkl-mnop", GRANT_EPOCH: EPOCH, CONFIRM_SECRET: "c".repeat(32), TIMEZONE: "America/Denver", WRITES_ENABLED: String(writes), CALDAV_URL: mock.base });
const post = (body: unknown, e: any, h: Record<string, string> = {}) => mcpEndpoint(new Request("http://w/mcp", { method: "POST", headers: { "Content-Type": "application/json", ...h }, body: JSON.stringify(body) }), e, { epoch: EPOCH });
const NEW = ["find_free_time", "resolve_dates", "list_changes", "prepare_undo", "commit_undo"];

test("tools/list returns all v1 tools for every supported protocol version, read-only or not", async () => {
  const want = TOOLS.filter((t) => !REMINDER_TOOLS.has(t.name)).map((t) => t.name);
  assert.equal(want.length, 14); for (const n of NEW) assert.ok(want.includes(n), n);
  for (const writes of [false, true]) for (const v of SUPPORTED) {
    const stateless = v === "2026-07-28";
    if (!stateless) { const i: any = await (await post({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: v, capabilities: {}, clientInfo: { name: "c", version: "1" } } }, env(writes))).json(); assert.equal(i.result.protocolVersion, v); assert.equal(i.result.serverInfo.version, SERVER_INFO.version); }
    const l: any = await (await post({ jsonrpc: "2.0", id: 2, method: "tools/list", params: stateless ? { _meta: { "io.modelcontextprotocol/protocolVersion": v } } : {} }, env(writes), { "MCP-Protocol-Version": v })).json();
    assert.deepEqual(l.result.tools.map((t: any) => t.name), want, `${v} writes=${writes}`);
  }
});

test("serverInfo.version is the release version (clients may cache tool lists per server version)", () => {
  assert.equal(SERVER_INFO.version, JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version);
  assert.equal(SERVER_INFO.version, "1.0.2");
});

test("the request log names the protocol version and the tool count, and nothing else new", async () => {
  const logs: string[] = []; setLogSink((l) => logs.push(l));
  await post({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "c", version: "1" } } }, env(false));
  await post({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, env(false), { "MCP-Protocol-Version": "2025-06-18" });
  await post({ jsonrpc: "2.0", id: 3, method: "initialize", params: { protocolVersion: "evil\nline", capabilities: {} } }, env(false));
  assert.ok(logs.some((l) => /mcp initialize\(v=2025-06-18\) ok/.test(l)), logs.join("|"));
  assert.ok(logs.some((l) => /mcp tools\/list\(n=14,v=2025-06-18\) ok/.test(l)), logs.join("|"));
  assert.ok(logs.some((l) => /initialize\(v=\?\)/.test(l)) && !logs.some((l) => /evil/.test(l)), "odd versions never reach the log");
});

test("the read-only refusal points at the real place to change it", async () => {
  await assert.rejects(makeTools(mock, { writesEnabled: false }).call("prepare_create_event", { calendar_id: "home", title: "x", start: "2026-11-01T10:00" }),
    /Workers & Pages > holdt > Settings > Variables and Secrets, edit the WRITES_ENABLED secret to true.*npx wrangler secret put WRITES_ENABLED/);
  await assert.rejects(makeTools(mock, { writesEnabled: false }).call("prepare_undo", { revert_token: "a.b" }), /Changes are turned off/);
});

test("list_events: to as a bare date includes that whole day, and the result's to is the exclusive end", async () => {
  mock.add("home", "late.ics", ["BEGIN:VCALENDAR", "VERSION:2.0", "BEGIN:VEVENT", "UID:late-1", "DTSTART;TZID=America/Denver:20261020T233000", "DTEND;TZID=America/Denver:20261020T234500", "SUMMARY:Late call", "END:VEVENT", "END:VCALENDAR", ""].join("\r\n"));
  const r: any = await makeTools(mock).call("list_events", { from: "2026-10-20", to: "2026-10-20" });
  assert.ok(r.events.some((e: any) => e.title === "Late call"));
  assert.equal(r.from, "2026-10-20T00:00:00-06:00"); assert.equal(r.to, "2026-10-21T00:00:00-06:00");
  const t = TOOLS.find((x) => x.name === "list_events")!;
  assert.match((t.inputSchema as any).properties.to.description, /date alone includes that whole day/);
  assert.match((t.outputSchema as any).properties.to.description, /exclusive.*whole day/);
});
