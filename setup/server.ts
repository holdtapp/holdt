// Guided setup: `npm run setup`. Opens ONE local page (127.0.0.1 only, one-time key in the URL),
// takes a single paste, tests it live against iCloud, then stores secrets with `wrangler secret put`
// via stdin. The password is never written to disk, never logged, never put on a command line.
import http from "node:http";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import { CalDavClient, CalDavError } from "../src/caldav.js";
import { normalizeAppPassword, normalizeEmail, explainFailure } from "./validate.js";
import { registerSecret, redact } from "../src/redact.js";
import { createHash, randomInt, pbkdf2Sync } from "node:crypto";

/** 8-digit one-time approval code, shown as 1234-5678. Only its salted hash is stored. */
/** 8-digit code. Only a salted PBKDF2 hash goes to Cloudflare (20,000 rounds keeps the Worker check near 4 ms of CPU). */
export const CODE_ROUNDS = 20_000;
export function newApprovalCode() { const c = String(randomInt(0, 100_000_000)).padStart(8, "0"); const salt = randomBytes(16).toString("base64url"); return { code: c, display: `${c.slice(0, 4)}-${c.slice(4)}`, hash: `pbkdf2$${CODE_ROUNDS}$${salt}$${pbkdf2Sync(c, Buffer.from(salt, "base64url"), CODE_ROUNDS, 32, "sha256").toString("hex")}` }; }

export interface SetupDeps { caldavUrl: string; saveSecret: (name: string, value: string) => Promise<void>; workerName: string; workerUrl?: string }

export function wranglerSaver(workerName: string) {
  return (name: string, value: string) => new Promise<void>((resolve, reject) => {
    const p = spawn("npx", ["wrangler", "secret", "put", name, "--name", workerName], { stdio: ["pipe", "ignore", "pipe"] });
    let err = ""; p.stderr.on("data", (d) => (err += d));
    p.on("close", (c) => (c === 0 ? resolve() : reject(new Error(`wrangler exited ${c}: ${redact(err).slice(0, 300)}`))));
    p.stdin.end(value);
  });
}

export function createSetupServer(deps: SetupDeps) {
  const key = randomBytes(18).toString("base64url");
  const html = readFileSync(fileURLToPath(new URL("./index.html", import.meta.url)), "utf8");
  let lastGood: { email: string; password: string; timezone: string } | null = null;
  let attempts = 0;
  const server = http.createServer(async (req, res) => {
    const send = (s: number, body: unknown, type = "application/json") => { res.writeHead(s, { "Content-Type": type, "Cache-Control": "no-store", "X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'", "Referrer-Policy": "no-referrer" }); res.end(type === "application/json" ? JSON.stringify(body) : body); };
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const given = Buffer.from(url.searchParams.get("k") ?? req.headers["x-setup-key"]?.toString() ?? "");
    if (given.length !== key.length || !timingSafeEqual(given, Buffer.from(key))) return send(403, { error: "Open the link printed in your terminal." });
    if (req.headers.host && !/^(127\.0\.0\.1|localhost):\d+$/.test(req.headers.host)) return send(403, { error: "bad host" }); // DNS-rebinding guard
    if (req.method === "GET" && url.pathname === "/") return send(200, html, "text/html; charset=utf-8");
    if (req.method !== "POST") return send(405, { error: "method" });
    let raw = ""; for await (const c of req) { raw += c; if (raw.length > 10_000) return send(413, { error: "too large" }); }
    let body: any; try { body = JSON.parse(raw); } catch { return send(400, { error: "bad json" }); }
    if (url.pathname === "/api/test") {
      if (++attempts > 10) return send(429, { ok: false, message: "Too many tries. Wait a minute so Apple doesn't lock things up, then restart setup." });
      const e = normalizeEmail(body.email); if (!e.ok) return send(200, { ok: false, field: "email", message: e.message });
      const p = normalizeAppPassword(body.password); if (!p.ok) return send(200, { ok: false, field: "password", message: p.message });
      registerSecret(p.value); registerSecret(e.value);
      try {
        const cols = await new CalDavClient({ baseUrl: deps.caldavUrl, username: e.value, password: p.value, maxRetries: 2 }).listCollections();
        const cals = cols.filter((c) => c.components.includes("VEVENT")); 
        lastGood = { email: e.value, password: p.value, timezone: typeof body.timezone === "string" ? body.timezone : "UTC" };
        return send(200, { ok: true, calendars: cals.map((c) => c.name) });
      } catch (err) {
        const code = err instanceof CalDavError ? err.code : "unknown";
        console.error(redact(`[setup] live test failed: ${code}`));
        return send(200, { ok: false, field: code === "authentication" ? "password" : undefined, message: explainFailure(code) });
      }
    }
    if (url.pathname === "/api/save") {
      if (!lastGood) return send(400, { ok: false, message: "Run the test first." });
      const confirm = randomBytes(32).toString("base64url"); const epoch = randomBytes(24).toString("base64url"); const ac = newApprovalCode();
      try {
        await deps.saveSecret("ICLOUD_EMAIL", lastGood.email);
        await deps.saveSecret("ICLOUD_APP_PASSWORD", lastGood.password);
        await deps.saveSecret("CONFIRM_SECRET", confirm);
        await deps.saveSecret("GRANT_EPOCH", epoch); // new epoch = every older connection is cut off
        await deps.saveSecret("TIMEZONE", lastGood.timezone);
        await deps.saveSecret("WRITES_ENABLED", body.allowChanges === true ? "true" : "false");
        await deps.saveSecret("APPROVAL_CODE_HASH", ac.hash);
        await deps.saveSecret("APPROVAL_CODE_ISSUED", String(Date.now()));
      } catch (err) { console.error(redact(err)); return send(200, { ok: false, message: "Couldn't save to Cloudflare. Make sure you ran `npx wrangler login` and `npx wrangler deploy` first, then press Save again." }); }
      lastGood = null; // forget the password in this process
      const mcpUrl = deps.workerUrl ? `${deps.workerUrl.replace(/\/+$/, "")}/mcp` : undefined;
      return send(200, { ok: true, mcpUrl, approvalCode: ac.display, writesEnabled: body.allowChanges === true });
    }
    return send(404, { error: "not found" });
  });
  return { server, key };
}

/** `npm run setup -- --new-code` (fresh approval code) and `--revoke-all` (cut off every connection). */
export async function cliAction(flag: string, save: (n: string, v: string) => Promise<void>, out: (s: string) => void) {
  if (flag === "--new-code") {
    const ac = newApprovalCode();
    await save("APPROVAL_CODE_HASH", ac.hash); await save("APPROVAL_CODE_ISSUED", String(Date.now()));
    out(`\n  New approval code (works once, for 15 minutes):  ${ac.display}\n  In Grok Bot, connect the server again and enter it on the approval page.\n`);
    return true;
  }
  if (flag === "--revoke-all") {
    await save("GRANT_EPOCH", randomBytes(24).toString("base64url"));
    out("\n  Done. Every existing connection to this server is cut off. Reconnect from Grok Bot with a new code (npm run setup -- --new-code).\n");
    return true;
  }
  return false;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const workerName = process.env.WORKER_NAME ?? "holdt";
  const flag = process.argv[2] ?? "";
  if (flag) { cliAction(flag, wranglerSaver(workerName), console.log).then((ok) => { if (!ok) { console.log("Unknown option. Use --new-code or --revoke-all."); process.exit(2); } }, (e) => { console.error(redact(e)); process.exit(1); }); }
  else {
  const { server, key } = createSetupServer({ caldavUrl: process.env.CALDAV_URL ?? "https://caldav.icloud.com/", workerName, workerUrl: process.env.WORKER_URL, saveSecret: wranglerSaver(workerName) });
  server.listen(0, "127.0.0.1", () => {
    const port = (server.address() as any).port;
    console.log(`\n  iCloud setup is ready. Open this link (it only works on this computer):\n\n    http://127.0.0.1:${port}/?k=${key}\n`);
  });
}
}
