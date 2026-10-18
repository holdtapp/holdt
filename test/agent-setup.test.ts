// `npm run agent-setup` (setup/agent.ts): the install your Grok Bot runs on your computer. Secrets never printed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, statSync, existsSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { agentSetup, linkFile, APPLE_PAGE, type Run } from "../setup/agent.js";

function fake(o: { authed?: boolean; kvIds?: string[]; secrets?: string[] } = {}) {
  const calls: { args: string[]; input?: string }[] = [];
  const run: Run = async (args, opt = {}) => {
    calls.push({ args, input: opt.input });
    const a = args.join(" ");
    if (a === "whoami") return { code: 0, out: o.authed === false ? "You are not authenticated. Please run `wrangler login`." : "You are logged in with an OAuth Token" };
    if (a === "login") return { code: 0, out: "Successfully logged in." };
    if (a === "kv namespace list") return { code: 0, out: JSON.stringify((o.kvIds ?? []).map((id) => ({ id, title: "x" }))) };
    if (a === "kv namespace create OAUTH_KV") return { code: 0, out: 'Add the following to your configuration file:\n[[kv_namespaces]]\nbinding = "OAUTH_KV"\nid = "0123456789abcdef0123456789abcdef"\n' };
    if (a === "deploy") return { code: 0, out: "Uploaded holdt\nDeployed holdt triggers\n  https://holdt.someone.workers.dev\nCurrent Version ID: x" };
    if (args[0] === "secret" && args[1] === "list") return { code: 0, out: JSON.stringify((o.secrets ?? []).map((name) => ({ name, type: "secret_text" }))) };
    if (args[0] === "secret" && args[1] === "put") return { code: 0, out: "Success" };
    return { code: 1, out: "unexpected " + a };
  };
  return { run, calls };
}
/** A copy of the public wrangler.toml, with its placeholder KV id or, given kvId, an install that already has its own. */
function home(kvId?: string) { const h = mkdtempSync(join(tmpdir(), "holdt-agent-")); const toml = join(h, "wrangler.toml"); copyFileSync(new URL("../wrangler.toml", import.meta.url), toml); if (kvId) writeFileSync(toml, readFileSync(toml, "utf8").replace('id = "REPLACE_WITH_YOUR_KV_ID"', `id = "${kvId}"`)); return { h, toml }; }
const OWN_KV = "fedcba9876543210fedcba9876543210";

test("agent setup: signs in, makes storage, deploys, seals nothing in the open, opens the one-time link, prints no secret", async () => {
  const { h, toml } = home(); assert.match(readFileSync(toml, "utf8"), /id = "REPLACE_WITH_YOUR_KV_ID"/, "the public wrangler.toml ships a placeholder, not a real id");
  const f = fake({ authed: false }); const logs: string[] = []; const tabs: string[] = [];
  const url = await agentSetup({ run: f.run, open: async (u) => { tabs.push(u); return true; }, log: (s) => logs.push(s), toml, home: h, workerName: "holdt", now: () => 1_000 });
  assert.equal(url, "https://holdt.someone.workers.dev");
  assert.ok(f.calls.some((c) => c.args[0] === "login"));
  assert.match(readFileSync(toml, "utf8"), /id = "0123456789abcdef0123456789abcdef"/, "the user's own storage id goes in wrangler.toml");
  assert.doesNotMatch(readFileSync(toml, "utf8"), /REPLACE_WITH_YOUR_KV_ID/, "the placeholder is swapped out");
  const puts = f.calls.filter((c) => c.args[1] === "put");
  assert.deepEqual(puts.map((c) => c.args[2]), ["SEAL_KEY", "SETUP_TOKEN_HASH", "SETUP_TOKEN_ISSUED"]);
  assert.ok(puts.every((c) => typeof c.input === "string" && !c.args.includes(c.input!)), "values only on stdin, never as arguments");
  const opened = tabs[0]!; assert.equal(tabs[1], APPLE_PAGE, "Apple's page opens second, so it's in front");
  const token = opened.split("#")[1]!; assert.match(opened, /^https:\/\/holdt\.someone\.workers\.dev\/setup#[A-Za-z0-9_-]{43}$/);
  assert.equal(puts[1]!.input, createHash("sha256").update(token).digest("hex"));
  const all = logs.join("\n"); assert.ok(!all.includes(token) && !all.includes(puts[0]!.input!), "neither the link's token nor SEAL_KEY is printed");
  assert.ok(!all.includes(";"), "status lines have no semicolons");
});

test("agent setup: an existing SEAL_KEY is never replaced, and with no browser the link goes to a 600 file", async () => {
  const kvId = OWN_KV, { h, toml } = home(kvId);
  const f = fake({ kvIds: [kvId], secrets: ["SEAL_KEY"] }); const logs: string[] = [];
  await agentSetup({ run: f.run, open: async () => false, log: (s) => logs.push(s), toml, home: h, workerName: "holdt" });
  assert.ok(!f.calls.some((c) => c.args[2] === "SEAL_KEY"), "SEAL_KEY kept, so the sealed setup stays readable");
  assert.ok(!f.calls.some((c) => c.args.join(" ") === "kv namespace create OAUTH_KV"), "existing storage reused");
  const file = linkFile(h, "holdt"); assert.ok(existsSync(file)); assert.equal(statSync(file).mode & 0o777, 0o600);
  const link = readFileSync(file, "utf8").trim(); assert.ok(!logs.join("\n").includes(link.split("#")[1]!));
  const again = fake({ secrets: ["SEAL_KEY"] });
  await agentSetup({ run: again.run, open: async () => true, log: () => {}, toml, home: h, workerName: "holdt" }, { newLink: true });
  assert.ok(!again.calls.some((c) => c.args[0] === "deploy"), "a new link doesn't redeploy");
  assert.deepEqual(again.calls.filter((c) => c.args[1] === "put").map((c) => c.args[2]), ["SETUP_TOKEN_HASH", "SETUP_TOKEN_ISSUED"]);
});

test("agent setup: the Apple email rides only in the link fragment, never in a log, and a bad one is dropped", async () => {
  const kvId = OWN_KV, { h, toml } = home(kvId);
  const tabs: string[] = []; const logs: string[] = [];
  await agentSetup({ run: fake({ kvIds: [kvId], secrets: ["SEAL_KEY"] }).run, open: async (u) => { tabs.push(u); return true; }, log: (s) => logs.push(s), toml, home: h, workerName: "holdt", email: "test@holdt.app" });
  assert.match(tabs[0]!, /\/setup#[A-Za-z0-9_-]{43}&e=test%40holdt\.app$/);
  assert.ok(!logs.join("\n").includes("test@holdt.app"), "the email isn't printed");
  tabs.length = 0;
  await agentSetup({ run: fake({ kvIds: [kvId], secrets: ["SEAL_KEY"] }).run, open: async (u) => { tabs.push(u); return true; }, log: () => {}, toml, home: h, workerName: "holdt", email: "x#y&z" }, { newLink: true });
  assert.match(tabs[0]!, /\/setup#[A-Za-z0-9_-]{43}$/, "a malformed hint is left out");
});
