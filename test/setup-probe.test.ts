import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { MockCalDav } from "./mock-caldav.js";
import { createSetupServer } from "../setup/server.js";
import { normalizeAppPassword, normalizeEmail } from "../setup/validate.js";
import { probe } from "../scripts/reminders-probe.js";

const USER = "probe.user@example.com", PASS = "qwer-tyui-opas-dfgh";
const mock = new MockCalDav({ user: USER, pass: PASS });
before(() => mock.start()); after(() => mock.stop());

test("password format check: auto-formats, catches main passwords and wrong lengths", () => {
  assert.deepEqual(normalizeAppPassword(" QWER tyui-OPAS dfgh "), { ok: true, value: "qwer-tyui-opas-dfgh" });
  assert.match((normalizeAppPassword("MyDog2024!") as any).message, /regular Apple Account password/);
  assert.match((normalizeAppPassword("abcd-efgh-ijkl") as any).message, /12 letters/);
  assert.match((normalizeAppPassword("") as any).message, /Paste/);
  assert.equal(normalizeEmail(" You@iCloud.com ").ok, true); assert.equal(normalizeEmail("nope").ok, false);
});

test("setup server: one-time key, live 'Found N calendars', plain-English errors, secrets only to the saver", async () => {
  const saved: Record<string, string> = {}; const stderr: string[] = []; const origErr = console.error; console.error = (s: string) => stderr.push(String(s));
  const { server, key } = createSetupServer({ caldavUrl: mock.base, workerName: "w", saveSecret: async (n, v) => { saved[n] = v; } });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r())); const port = (server.address() as any).port;
  const call = (path: string, body: unknown, k = key) => fetch(`http://127.0.0.1:${port}${path}?k=${k}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(async (r) => ({ status: r.status, j: await r.json() as any }));
  try {
    assert.equal((await call("/api/test", {}, "wrongkeywrongkeywrongkey")).status, 403);
    const page = await fetch(`http://127.0.0.1:${port}/?k=${key}`); assert.equal(page.status, 200); assert.match(await page.text(), /Open Apple's password page/);
    assert.match((await call("/api/save", {})).j.message, /test first/);
    const bad = await call("/api/test", { email: USER, password: "zzzz-zzzz-zzzz-zzzz" });
    assert.equal(bad.j.ok, false); assert.equal(bad.j.field, "password"); assert.match(bad.j.message, /didn't accept/);
    const main = await call("/api/test", { email: USER, password: "Hunter2024!" }); assert.match(main.j.message, /regular Apple Account password/);
    const good = await call("/api/test", { email: USER.toUpperCase(), password: "QWERTYUIOPASDFGH", timezone: "America/Denver" });
    assert.equal(good.j.ok, true); assert.deepEqual(good.j.calendars, ["Home", "Work", "US Holidays"]); assert.equal(good.j.reminderLists, undefined);
    const s = await call("/api/save", { allowChanges: false });
    assert.equal(s.j.ok, true); assert.match(s.j.approvalCode, /^\d{4}-\d{4}$/); assert.equal(s.j.mcpToken, undefined);
    assert.equal(saved.ICLOUD_APP_PASSWORD, PASS); assert.equal(saved.ICLOUD_EMAIL, USER); assert.equal(saved.WRITES_ENABLED, "false"); assert.equal(saved.TIMEZONE, "America/Denver");
    assert.ok(saved.GRANT_EPOCH.length >= 30); assert.ok(saved.CONFIRM_SECRET.length >= 40); assert.equal(saved.MCP_TOKEN, undefined);
    const { createHash } = await import("node:crypto");
    assert.equal(saved.APPROVAL_CODE_HASH, createHash("sha256").update(`icloud-mcp-approval:${s.j.approvalCode.replace("-", "")}`).digest("hex"));
    assert.ok(!Object.values(saved).includes(s.j.approvalCode.replace("-", "")), "only the hash of the code is stored");
    assert.match((await call("/api/save", {})).j.message, /test first/, "password forgotten after save");
    for (const v of [JSON.stringify(good.j), JSON.stringify(bad.j), stderr.join("\n")]) { assert.ok(!v.includes(PASS)); assert.ok(!v.includes("zzzz-zzzz-zzzz-zzzz")); }
  } finally { console.error = origErr; server.close(); }
});

test("reminders probe: reports lists, compares with what the user sees, never leaks credentials", async () => {
  const out: string[] = [];
  const r = await probe({ ICLOUD_EMAIL: USER, ICLOUD_APP_PASSWORD: PASS, CALDAV_URL: mock.base, EXPECTED_LISTS: "Groceries, Reminders" }, (s) => out.push(s));
  assert.equal(r.verdict, "PARTIAL"); assert.deepEqual(r.missing, ["Reminders"]); assert.equal(r.calendars, 3);
  const r2 = await probe({ ICLOUD_EMAIL: USER, ICLOUD_APP_PASSWORD: PASS, CALDAV_URL: mock.base, EXPECTED_LISTS: "groceries" }, (s) => out.push(s));
  assert.equal(r2.verdict, "REAL_LISTS_VISIBLE");
  const saved = mock.cols.tasks; delete (mock.cols as any).tasks;
  const r3 = await probe({ ICLOUD_EMAIL: USER, ICLOUD_APP_PASSWORD: PASS, CALDAV_URL: mock.base }, (s) => out.push(s)); mock.cols.tasks = saved!;
  assert.equal(r3.verdict, "NO_CALDAV_LISTS"); assert.match(r3.message, /upgraded Reminders/);
  const r4 = await probe({ ICLOUD_EMAIL: USER, ICLOUD_APP_PASSWORD: "aaaa-bbbb-cccc-dddd", CALDAV_URL: mock.base }, (s) => out.push(s));
  assert.equal(r4.verdict, "AUTH_FAILED");
  const before = mock.requests.filter((x) => x.method === "PUT").length;
  const r5 = await probe({ ICLOUD_EMAIL: USER, ICLOUD_APP_PASSWORD: PASS, CALDAV_URL: mock.base, PROBE_WRITE: "yes" }, (s) => out.push(s));
  assert.equal(r5.wrote, "Groceries"); assert.equal(mock.requests.filter((x) => x.method === "PUT").length, before + 1);
  assert.equal(mock.requests.filter((x) => x.method === "DELETE").length, 0);
  const blob = out.join("\n"); assert.ok(!blob.includes(PASS)); assert.ok(!blob.includes(USER)); assert.ok(!blob.includes("aaaa-bbbb-cccc-dddd"));
});

test("setup CLI: --new-code stores only a hash; --revoke-all rotates the epoch", async () => {
  const { cliAction } = await import("../setup/server.js");
  const saved: Record<string, string> = {}; const out: string[] = [];
  assert.equal(await cliAction("--new-code", async (n, v) => { saved[n] = v; }, (s) => out.push(s)), true);
  const shown = out.join("").match(/(\d{4})-(\d{4})/)!; assert.ok(shown);
  assert.ok(!JSON.stringify(saved).includes(shown[1]! + shown[2]!)); assert.ok(saved.APPROVAL_CODE_HASH && saved.APPROVAL_CODE_ISSUED);
  assert.equal(await cliAction("--revoke-all", async (n, v) => { saved[n] = v; }, () => {}), true); assert.ok(saved.GRANT_EPOCH);
  assert.equal(await cliAction("--bogus", async () => {}, () => {}), false);
});
