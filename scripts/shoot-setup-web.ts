// Dev-only: renders the no-terminal setup page (src/setup-web.ts) in every state, as Safari on a Mac in a 393 pt
// window (setup runs on the computer your Grok Bot installs from), light and dark, through the real Worker code.
// Run: PUPPETEER_CORE=... npx tsx --import ./test/register.mjs scripts/shoot-setup-web.ts <outDir> [ids]
import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { MockKV } from "../test/kv-mock.js";
import { MockGuardNS } from "../test/guard-mock.js";
import { MockCalDav } from "../test/mock-caldav.js";
import { handleRequest } from "../src/worker.js";
import { sealRecord, withSealed } from "../src/setup-web.js";
import { addPasskey } from "../src/passkey.js";
const { default: puppeteer }: any = await import(process.env.PUPPETEER_CORE ?? "puppeteer-core");
const out = process.argv[2] ?? "shots"; mkdirSync(out, { recursive: true });
const only = process.argv[3] ? new Set(process.argv[3].split(",")) : undefined;
const USER = "test@holdt.app", PASS = "abcd-efgh-ijkl-mnop";
const cal = new MockCalDav({ user: USER, pass: PASS }); await cal.start();
const ORIGIN = "https://holdt.example.workers.dev"; let LOCAL = "", env: any;
const tok = () => { const t = randomBytes(32).toString("base64url"); return { t, h: createHash("sha256").update(t).digest("hex") }; };
let TOKEN = "";
async function freshEnv(over: Record<string, unknown> = {}, sealed = false) {
  const k = tok(); TOKEN = k.t;
  env = { OAUTH_KV: new MockKV(), GUARD: new MockGuardNS(), CALDAV_URL: cal.base, PASSKEYS: "on", SEAL_KEY: randomBytes(32).toString("base64url"), SETUP_TOKEN_HASH: k.h, SETUP_TOKEN_ISSUED: String(Date.now()), ...over };
  if (sealed) await sealRecord(env, { email: USER, password: PASS, timezone: "America/Denver", writes: false, confirm: "c".repeat(43), epoch: "e".repeat(32), enrollHash: "0".repeat(64), enrollIssued: Date.now(), at: Date.now() });
}
const server = createServer(async (req, res) => {
  const chunks: Buffer[] = []; for await (const c of req) chunks.push(c as Buffer);
  const rq = new Request(ORIGIN + req.url, { method: req.method, headers: req.headers as any, body: req.method === "GET" || req.method === "HEAD" ? undefined : Buffer.concat(chunks), redirect: "manual" });
  const r = await handleRequest(rq, env, { waitUntil() {}, passThroughOnException() {}, props: undefined }, fetch);
  const h: Record<string, string[]> = {}; r.headers.forEach((v, k) => { (h[k] ??= []).push(v); }); if (r.headers.getSetCookie) h["set-cookie"] = r.headers.getSetCookie();
  res.writeHead(r.status, h); res.end(Buffer.from(await r.arrayBuffer()));
});
await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r())); LOCAL = `http://127.0.0.1:${(server.address() as any).port}`;
type P = any;
const settle = (ms = 700) => new Promise((r) => setTimeout(r, ms));
const link = () => `${ORIGIN}/setup#${TOKEN}`;
const fill = async (p: P, pw = PASS) => { await p.type("#email", USER); await p.type("#pw", pw); };
const holdSave = (p: P, body?: unknown) => p.evaluateOnNewDocument((b: unknown) => { const real = window.fetch; window.fetch = (u: any, o: any) => String(u).endsWith("/setup/save") ? (b ? Promise.resolve(new Response(JSON.stringify(b))) : new Promise(() => {})) : real(u, o); }, body);
const SCREENS: { id: string; name: string; go: (p: P) => Promise<void> }[] = [
  { id: "40-setup-ready", name: "Setup page opened from the one-time link, nothing entered yet", go: async (p) => { await freshEnv(); await p.goto(link()); } },
  { id: "41-setup-checking", name: "App password pasted: the page checks it with Apple on its own (no button)", go: async (p) => { await freshEnv(); await holdSave(p); await p.goto(link()); await settle(400); await fill(p); } },
  { id: "43-setup-wrong-password", name: "Apple refused the pasted password", go: async (p) => { await freshEnv(); await p.goto(link()); await settle(400); await fill(p, "zzzz-zzzz-zzzz-zzzz"); await settle(1500); } },
  { id: "44-setup-again", name: "Setting up again on a Worker that is already set up", go: async (p) => { await freshEnv({}, true); await p.goto(link()); } },
  { id: "45-setup-link-ended", name: "Setup link already used or past its 30 minutes", go: async (p) => { await freshEnv({ SETUP_TOKEN_ISSUED: String(Date.now() - 31 * 60_000) }); await p.goto(link()); } },
  { id: "46-setup-is-set", name: "Setup page opened without a link, Holdt set up with a passkey", go: async (p) => { await freshEnv({}, true); await addPasskey(await withSealed(env), { id: randomBytes(16).toString("base64url"), jwk: {}, alg: -7, signCount: 0, createdAt: Date.now(), label: "iPhone" } as any); await p.goto(`${ORIGIN}/setup`); } },
  { id: "47-setup-not-ready", name: "Server not finished installing (no seal key yet)", go: async (p) => { await freshEnv({ SEAL_KEY: undefined }); await p.goto(`${ORIGIN}/setup`); } },
  { id: "48-setup-retry", name: "No clear answer from the server when opening the link (Try again)", go: async (p) => { await freshEnv(); await p.evaluateOnNewDocument(() => { const real = window.fetch; window.fetch = (u: any, o: any) => String(u).endsWith("/setup/claim") ? Promise.reject(new TypeError("offline")) : real(u, o); }); await p.goto(link()); } },
  { id: "49-setup-no-link", name: "Setup address opened without a link on a server not set up yet", go: async (p) => { await freshEnv(); await p.goto(`${ORIGIN}/setup`); } },
  { id: "50-setup-unfinished", name: "Account saved, but the passkey step was never finished", go: async (p) => { await freshEnv({}, true); await p.goto(`${ORIGIN}/setup`); } },
  { id: "42-setup-passkey-ready", name: "Password pasted, Apple accepted it on its own, one button left: Save passkey", go: async (p) => { await freshEnv(); await p.goto(link()); await settle(400); await fill(p); await settle(1500); } },
  { id: "51-setup-done", name: "Passkey saved on the same page: Holdt is set up, last step is adding the address in Grok Bot", go: async (p) => { await freshEnv(); const c = await p.target().createCDPSession(); await c.send("WebAuthn.enable"); await c.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true } }); await p.goto(link()); await settle(400); await fill(p); await settle(2500); const t = await p.evaluate(() => document.title); process.stderr.write(`e2e no-tap ${t}\n`); } },
];
const browser = await puppeteer.launch({ executablePath: process.env.CHROME_PATH ?? "/usr/bin/google-chrome", args: ["--no-sandbox", "--font-render-hinting=none"], headless: true, protocolTimeout: 60_000 });
const index: any[] = [];
for (const s of SCREENS) {
  if (only && !only.has(s.id)) continue;
  for (const mode of ["light", "dark"] as const) {
    const p = await browser.newPage();
    await p.setRequestInterception(true);
    p.on("request", async (rq: any) => {
      if (!rq.url().startsWith(ORIGIN)) return rq.continue();
      const r = await fetch(LOCAL + rq.url().slice(ORIGIN.length), { method: rq.method(), headers: rq.headers(), body: rq.postData(), redirect: "manual" });
      const headers: Record<string, string> = {}; r.headers.forEach((v, k) => { headers[k] = v; }); if (r.headers.getSetCookie) { const c = r.headers.getSetCookie(); if (c.length) headers["set-cookie"] = c.join("\n"); }
      rq.respond({ status: r.status, headers, body: Buffer.from(await r.arrayBuffer()) });
    });
    await p.setUserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15");
    await p.setViewport({ width: 393, height: Number(process.env.SHOOT_H || 852), deviceScaleFactor: 3, isMobile: false, hasTouch: false });
    await p.emulateMediaFeatures([{ name: "prefers-color-scheme", value: mode }]);
    await s.go(p); await settle(s.id.startsWith("42") ? 300 : 700); await p.evaluate(() => { (document.activeElement as any)?.blur?.(); window.scrollTo(0, 0); });
    if (mode === "light") { const m = await p.evaluate(() => { const f = Array.from(document.querySelectorAll(".foot") as any).find((x: any) => x.offsetParent) as any; const g = document.getElementById("go") as any; return { foot: f ? Math.round(f.getBoundingClientRect().bottom) : 0, go: g && g.offsetParent ? Math.round(g.getBoundingClientRect().bottom) : 0, page: document.documentElement.scrollHeight }; }); console.log(`fold ${s.id} foot=${m.foot} go=${m.go} page=${m.page}`); }
    const file = `${out}/${s.id}-${mode}.png`; await p.screenshot({ path: file });
    if (mode === "light") writeFileSync(`${out}/${s.id}.html`, await p.content());
    index.push({ id: s.id, name: s.name, mode, file });
    await p.close();
  }
}
const prev: any[] = only ? (() => { try { return JSON.parse(readFileSync(`${out}/index.json`, "utf8")); } catch { return []; } })() : [];
const merged = [...prev.filter((x) => !index.some((y) => y.id === x.id)), ...index].sort((a, b) => a.id.localeCompare(b.id) || a.mode.localeCompare(b.mode));
writeFileSync(`${out}/index.json`, JSON.stringify(merged, null, 1));
await browser.close(); server.close(); await cal.stop(); console.log(`shots ok: ${index.length}`);
