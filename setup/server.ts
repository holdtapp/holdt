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
import { writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { newReviewerCode } from "./reviewer.js";
import { qrTerminal } from "../src/qr.js";
/** The exact wrangler pinned in package.json (never whatever npx would fetch today), since it runs with your Cloudflare login. */
const WRANGLER = fileURLToPath(new URL(`../node_modules/.bin/wrangler${process.platform === "win32" ? ".cmd" : ""}`, import.meta.url));

/** 8-digit owner recovery code (`npm run new-code`), never part of the normal flow. Only a salted PBKDF2 hash goes to Cloudflare (20,000 rounds keeps the Worker check near 4 ms of CPU). */
export const CODE_ROUNDS = 20_000;
export function newApprovalCode() { const c = String(randomInt(0, 100_000_000)).padStart(8, "0"); const salt = randomBytes(16).toString("base64url"); return { code: c, display: `${c.slice(0, 4)}-${c.slice(4)}`, hash: `pbkdf2$${CODE_ROUNDS}$${salt}$${pbkdf2Sync(c, Buffer.from(salt, "base64url"), CODE_ROUNDS, 32, "sha256").toString("hex")}` }; }

export interface SetupDeps { caldavUrl: string; saveSecret: (name: string, value: string) => Promise<void>; workerName: string; workerUrl?: string }

/** Opens a URL in this computer's default browser. Resolves false when there's no browser to open (a server, SSH). */
export function openInBrowser(url: string): Promise<boolean> {
  if (process.env.HOLDT_NO_OPEN === "1") return Promise.resolve(false);
  const [cmd, args] = process.platform === "darwin" ? ["open", [url]] : process.platform === "win32" ? ["cmd", ["/c", "start", "", url]] : ["xdg-open", [url]];
  return new Promise((resolve) => {
    try { const p = spawn(cmd, args as string[], { stdio: "ignore", detached: true }); p.on("error", () => resolve(false)); p.on("spawn", () => { p.unref(); resolve(true); }); } catch { resolve(false); }
  });
}
/** The one-time Face ID link: the token rides in the fragment, so it never reaches a server log, a Referer or a link preview. */
export const enrollLink = (base: string, token: string, fromSetup = false) => `${base.replace(/\/+$/, "")}/enroll${fromSetup ? "?from=setup" : ""}#${token}`;

export function wranglerSaver(workerName: string) {
  return (name: string, value: string) => new Promise<void>((resolve, reject) => {
    const p = spawn(WRANGLER, ["secret", "put", name, "--name", workerName], { stdio: ["pipe", "ignore", "pipe"] });
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
      const confirm = randomBytes(32).toString("base64url"); const epoch = randomBytes(24).toString("base64url"); const et = newEnrollToken();
      try {
        await deps.saveSecret("ICLOUD_EMAIL", lastGood.email);
        await deps.saveSecret("ICLOUD_APP_PASSWORD", lastGood.password);
        await deps.saveSecret("CONFIRM_SECRET", confirm);
        await deps.saveSecret("GRANT_EPOCH", epoch); // new epoch = every older connection is cut off
        await deps.saveSecret("TIMEZONE", lastGood.timezone);
        await deps.saveSecret("WRITES_ENABLED", body.allowChanges === true ? "true" : "false");
        // No approval code. Owner proof is a one-time Face ID link (only its hash goes to Cloudflare), opened next in this browser.
        await deps.saveSecret("ENROLL_TOKEN_HASH", et.hash);
        await deps.saveSecret("ENROLL_TOKEN_ISSUED", String(Date.now()));
      } catch (err) { console.error(redact(err)); return send(200, { ok: false, message: "Couldn't save to Cloudflare. Make sure you ran `npm run cf:login` and `npm run deploy` first, then press Save again." }); }
      lastGood = null; // forget the password in this process
      const mcpUrl = deps.workerUrl ? `${deps.workerUrl.replace(/\/+$/, "")}/mcp` : undefined;
      // The page goes straight to the link, where one click on Save passkey (Turn on Face ID on an iPhone) finishes setup.
      const enrollUrl = deps.workerUrl ? enrollLink(deps.workerUrl, et.token, true) : undefined;
      return send(200, { ok: true, mcpUrl, enrollUrl, writesEnabled: body.allowChanges === true });
    }
    return send(404, { error: "not found" });
  });
  return { server, key };
}

/** `npm run setup -- --new-code` (fresh approval code) and `--revoke-all` (cut off every connection). */
export function newEnrollToken() { const token = randomBytes(32).toString("base64url"); return { token, hash: createHash("sha256").update(token).digest("hex") }; }
/** `--add-device` (passkey enroll link) and `--reset-passkeys` (forget every passkey) too. */
export interface ReviewerCliOpts { workerName?: string; account?: string; codeFile?: string; now?: number }
export async function cliAction(flag: string, save: (n: string, v: string) => Promise<void>, out: (s: string) => void, workerUrl = process.env.WORKER_URL, rv: ReviewerCliOpts = {}, open: (url: string) => Promise<boolean> = openInBrowser, extra: string[] = []) {
  if (flag === "--new-reviewer-code" || flag === "--revoke-reviewer") {
    // Reviewer codes belong on a separate demo Worker on the test account, never on the owner's own Worker.
    const name = rv.workerName ?? process.env.WORKER_NAME ?? "holdt";
    if (name === "holdt") { out("\n  Reviewer codes only go on a separate demo Worker. Set WORKER_NAME to that Worker's name and try again.\n"); return true; }
    if (flag === "--revoke-reviewer") {
      await save("REVIEWER_CODE_HASH", "revoked");
      out(`\n  Done. The reviewer link for ${name} stopped working, and every reviewer connection is cut off on its next call. Your own connections keep working.\n`);
      return true;
    }
    const r = newReviewerCode(rv.account ?? process.env.HOLDT_REVIEWER_ACCOUNT ?? "", rv.now);
    await save("REVIEWER_CODE_HASH", r.hash); await save("REVIEWER_CODE_ISSUED", String(r.issued));
    // The code goes to a private file, not the terminal, so it never lands in a scrollback, a log or a chat transcript.
    // It is a one-tap link: the code rides in the fragment, so opening it changes nothing and only the reviewer's tap uses it.
    const file = rv.codeFile ?? join(homedir(), ".holdt", `reviewer-link-${name}.txt`);
    const link = `${(workerUrl ?? `https://${name}.<your-subdomain>.workers.dev`).replace(/\/(mcp)?$/, "")}/review#${r.display}`;
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 }); writeFileSync(file, `${link}\n`, { mode: 0o600 }); chmodSync(file, 0o600);
    const until = new Date(r.expiresAt).toLocaleString("en-US", { timeZone: process.env.TZ || "America/Denver", dateStyle: "medium", timeStyle: "short" });
    out(`\n  New reviewer link for ${name} saved to ${file} (readable only by you).\n  Put it in the testing instructions. It works for any number of reviewers until ${until}. Revoke it any time with npm run setup -- --revoke-reviewer.\n  The demo Worker also needs REVIEWER_MODE = "on" in its [vars].\n`);
    return true;
  }
  if (flag === "--new-code") {
    const ac = newApprovalCode();
    await save("APPROVAL_CODE_HASH", ac.hash); await save("APPROVAL_CODE_ISSUED", String(Date.now()));
    out(`\n  Recovery code (works once, for 15 minutes):  ${ac.display}\n  Only for when no device with your Holdt passkey is at hand. While it's live, the approval page shows a code field.\n  Type it there yourself. Never paste it into a chat.\n`);
    return true;
  }
  if (flag === "--add-device") {
    // A one-time Face ID link. Only the token's SHA-256 goes to Cloudflare. The token itself is in the link's fragment.
    // It opens in this computer's browser, where one click on Save passkey adds the device and iCloud Keychain
    // carries the passkey to the owner's other Apple devices. The QR code is only for a device without that sync.
    const t = newEnrollToken();
    await save("ENROLL_TOKEN_HASH", t.hash); await save("ENROLL_TOKEN_ISSUED", String(Date.now()));
    const base = (workerUrl ?? "https://<your-worker>.workers.dev").replace(/\/+$/, ""), link = enrollLink(base, t.token);
    const wantQr = extra.includes("--qr");
    const opened = !wantQr && !!workerUrl && (await open(link));
    if (opened) out(`\n  Opened the Face ID link in your browser. Click Save passkey there. That's the only step.\n  It works once, for 10 minutes. For a phone that doesn't sync with iCloud Keychain, run npm run add-device -- --qr.\n`);
    else out(`\n  Open this on the device you want to add (works once, for 10 minutes):\n\n    ${link}\n\n  Or point an iPhone's camera at this code:\n\n${workerUrl ? qrTerminal(link) : "  (Set WORKER_URL to print a full link and a QR code.)"}\n`);
    return true;
  }
  if (flag === "--reset-passkeys") {
    await save("PASSKEY_EPOCH", randomBytes(18).toString("base64url"));
    out("\n  Done. Every passkey for this server stopped working. Turn Face ID on again with npm run add-device.\n");
    return true;
  }
  if (flag === "--revoke-all") {
    await save("GRANT_EPOCH", randomBytes(24).toString("base64url"));
    out("\n  Done. Every existing connection to this server is cut off. Reconnect from Grok Bot and approve with Face ID.\n");
    return true;
  }
  return false;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const workerName = process.env.WORKER_NAME ?? "holdt";
  const flag = process.argv[2] ?? "";
  if (flag) { cliAction(flag, wranglerSaver(workerName), console.log, process.env.WORKER_URL, { workerName }, openInBrowser, process.argv.slice(3)).then((ok) => { if (!ok) { console.log("Unknown option. Use --new-code, --revoke-all, --add-device, --reset-passkeys, --new-reviewer-code or --revoke-reviewer."); process.exit(2); } }, (e) => { console.error(redact(e)); process.exit(1); }); }
  else {
  const { server, key } = createSetupServer({ caldavUrl: process.env.CALDAV_URL ?? "https://caldav.icloud.com/", workerName, workerUrl: process.env.WORKER_URL, saveSecret: wranglerSaver(workerName) });
  server.listen(0, "127.0.0.1", () => {
    const port = (server.address() as any).port;
    const local = `http://127.0.0.1:${port}/?k=${key}`;
    openInBrowser(local).then((ok) => console.log(ok ? `\n  iCloud setup opened in your browser. If it didn't, open this link (it only works on this computer):\n\n    ${local}\n` : `\n  iCloud setup is ready. Open this link (it only works on this computer):\n\n    ${local}\n`));
  });
}
}
