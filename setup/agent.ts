// `npm run agent-setup`: what your Grok Bot runs on your computer to install Holdt with no terminal work from you
// (docs/agent-setup.md). It signs in to Cloudflare (you click Allow once in your browser), makes the storage Holdt
// needs, deploys, and opens the one-time setup page in your browser. You never type a command.
//
// Secrets rule: the setup link and SEAL_KEY are made here and never printed. Secrets go to `wrangler secret put` on
// stdin. The link opens in this computer's browser. If there's no browser, it goes to a file only you can read.
import { spawn } from "node:child_process";
import { randomBytes, createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { openInBrowser } from "./server.js";
import { redact } from "../src/redact.js";

const WRANGLER = fileURLToPath(new URL(`../node_modules/.bin/wrangler${process.platform === "win32" ? ".cmd" : ""}`, import.meta.url));
export type Run = (args: string[], o?: { input?: string; interactive?: boolean }) => Promise<{ code: number; out: string }>;
export interface AgentDeps { run: Run; open: (url: string) => Promise<boolean>; log: (s: string) => void; toml: string; home: string; workerName: string; now?: () => number }

export const wranglerRun: Run = (args, o = {}) => new Promise((resolve) => {
  const p = spawn(WRANGLER, args, { stdio: [o.input === undefined ? (o.interactive ? "inherit" : "ignore") : "pipe", "pipe", "pipe"] });
  let out = ""; p.stdout?.on("data", (d) => (out += d)); p.stderr?.on("data", (d) => (out += d));
  p.on("close", (code) => resolve({ code: code ?? 1, out }));
  p.on("error", () => resolve({ code: 1, out: "wrangler not found. Run npm install first." }));
  if (o.input !== undefined) p.stdin?.end(o.input);
});

export const linkFile = (home: string, name: string) => join(home, ".holdt", `setup-link-${name}.txt`);
const urlFile = (home: string, name: string) => join(home, ".holdt", `worker-url-${name}.txt`);
function writePrivate(file: string, text: string) { mkdirSync(dirname(file), { recursive: true, mode: 0o700 }); writeFileSync(file, text, { mode: 0o600 }); chmodSync(file, 0o600); }

/** Full install, or with newLink only a fresh setup link for a Worker that's already deployed. Resolves the Worker URL. */
export async function agentSetup(d: AgentDeps, o: { newLink?: boolean } = {}): Promise<string> {
  const say = (s: string) => d.log(redact(s));
  const must = async (args: string[], what: string, opt?: Parameters<Run>[1]) => { const r = await d.run(args, opt); if (r.code !== 0) throw new Error(`${what} failed: ${redact(r.out).slice(-400)}`); return r.out; };
  let url = "";
  if (!o.newLink) {
    const who = await d.run(["whoami"]);
    if (who.code !== 0 || /not authenticated|You are not logged in/i.test(who.out)) {
      say("Step 1 of 4. Cloudflare is opening in the browser. Ask the user to click Allow there.");
      await must(["login"], "Cloudflare sign-in", { interactive: true });
    } else say("Step 1 of 4. Signed in to Cloudflare already.");
    const toml = readFileSync(d.toml, "utf8");
    const kvId = toml.match(/binding = "OAUTH_KV"\s*\nid = "([0-9a-f]{32})"/)?.[1];
    const list = await d.run(["kv", "namespace", "list"]);
    let have = false; try { have = !!kvId && (JSON.parse(list.out) as { id: string }[]).some((n) => n.id === kvId); } catch { have = false; }
    if (!have) {
      const made = await must(["kv", "namespace", "create", "OAUTH_KV"], "Making Holdt's storage");
      const id = made.match(/id = "([0-9a-f]{32})"/)?.[1]; if (!id) throw new Error("Making Holdt's storage: no id in Cloudflare's answer");
      writeFileSync(d.toml, kvId ? toml.replace(`id = "${kvId}"`, `id = "${id}"`) : toml.replace(/(binding = "OAUTH_KV"\s*\n)id = "[^"]*"/, `$1id = "${id}"`));
      say("Step 2 of 4. Made Holdt's storage on the user's Cloudflare account.");
    } else say("Step 2 of 4. Holdt's storage is already there.");
    const dep = await must(["deploy"], "Deploy");
    url = dep.match(/https:\/\/[a-z0-9-]+\.[a-z0-9-]+\.workers\.dev/)?.[0] ?? "";
    if (!url) throw new Error("Deploy finished but no workers.dev address came back. Check the Workers subdomain in the Cloudflare dashboard.");
    writePrivate(urlFile(d.home, d.workerName), url + "\n");
    say(`Step 3 of 4. Deployed Holdt to ${url}.`);
  } else {
    try { url = readFileSync(urlFile(d.home, d.workerName), "utf8").trim(); } catch { url = process.env.WORKER_URL?.replace(/\/(mcp)?\/*$/, "") ?? ""; }
    if (!url) throw new Error("No Worker address on file. Run npm run agent-setup first, or set WORKER_URL.");
  }
  const secrets = await d.run(["secret", "list", "--name", d.workerName]);
  let names: string[] = []; try { names = (JSON.parse(secrets.out) as { name: string }[]).map((s) => s.name); } catch { names = []; }
  const put = (n: string, v: string) => must(["secret", "put", n, "--name", d.workerName], `Saving ${n}`, { input: v });
  // SEAL_KEY is made once. Making a new one would leave the sealed setup unreadable, so it's never replaced here.
  if (!names.includes("SEAL_KEY")) await put("SEAL_KEY", randomBytes(32).toString("base64url"));
  const token = randomBytes(32).toString("base64url");
  await put("SETUP_TOKEN_HASH", createHash("sha256").update(token).digest("hex"));
  await put("SETUP_TOKEN_ISSUED", String((d.now ?? Date.now)()));
  const link = `${url}/setup#${token}`;
  if (await d.open(link)) say("Step 4 of 4. The Holdt setup page is open in the browser. Ask the user to follow it: make an Apple app-specific password on Apple’s page, enter it on the Holdt page with their Apple Account email, press Continue, then save the passkey (Face ID on an iPhone, Touch ID or password on a Mac). The link works once, for 30 minutes. Run npm run agent-setup -- --new-link for a fresh one.");
  else { const f = linkFile(d.home, d.workerName); writePrivate(f, link + "\n"); say(`Step 4 of 4. No browser here. The one-time setup link is in ${f}, readable only by this user. Ask the user to open that file and click the link. Never paste it into a chat.`); }
  say(`When setup is done, the user adds ${url}/mcp in Grok Bot under Connect Apps, Add custom MCP server.`);
  return url;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const workerName = process.env.WORKER_NAME ?? "holdt";
  agentSetup({ run: wranglerRun, open: openInBrowser, log: console.log, toml: fileURLToPath(new URL("../wrangler.toml", import.meta.url)), home: homedir(), workerName }, { newLink: process.argv.includes("--new-link") })
    .catch((e) => { console.error(redact(String(e?.message ?? e))); process.exit(1); });
}
