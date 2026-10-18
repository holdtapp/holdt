// Dev-only: renders every connect-flow screen (consent, approve on iPhone, Face ID set up, pairing, errors) at iPhone 15 size,
// light and dark, through the real Worker code. Run: npx tsx --import ./test/register.mjs scripts/shoot-connect.ts <outDir>
// puppeteer-core isn't a dependency. Point PUPPETEER_CORE at an install, and CHROME_PATH at Chrome.
import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { MockKV } from "../test/kv-mock.js";
import { providerFor } from "../src/worker.js";
import { sha256Hex, messageBody } from "../src/authorize.js";
import { addPasskey } from "../src/passkey.js";
import { documentHtml } from "../src/ui.js";
const { default: puppeteer }: any = await import(process.env.PUPPETEER_CORE ?? "puppeteer-core");
const out = process.argv[2] ?? "shots"; mkdirSync(out, { recursive: true });
const only = process.argv[3] ? new Set(process.argv[3].split(",")) : undefined;
const CODE = "48291376", ENROLL = "enroll-token-" + "t".repeat(30), GROK = "https://www.cursor.com/agents/mcp/oauth/callback";
let env: any, ORIGIN = "";
async function freshEnv(over: Record<string, unknown> = {}) {
  env = { ICLOUD_EMAIL: "test@holdt.app", ICLOUD_APP_PASSWORD: "x", CONFIRM_SECRET: "k".repeat(43), GRANT_EPOCH: "epoch-" + "e".repeat(30), TIMEZONE: "America/Denver", WRITES_ENABLED: "false", OAUTH_KV: new MockKV(),
    PASSKEYS: "on",
    ENROLL_TOKEN_HASH: createHash("sha256").update(ENROLL).digest("hex"), ENROLL_TOKEN_ISSUED: String(Date.now()), ...over };
}
// The new-device fixture is frozen at 8:00 PM MT on Oct 17 so light and dark show the same minute.
const pk = (daysAgo: number, label = "iPhone") => addPasskey(env, { id: randomBytes(16).toString("base64url"), jwk: {}, alg: -7, signCount: 0, createdAt: daysAgo < 1 ? Date.UTC(2026, 9, 18, 2, 0) : Date.now() - daysAgo * 86400_000, label, rpId: new URL(ORIGIN).hostname } as any);
const server = createServer(async (req, res) => {
  const chunks: Buffer[] = []; for await (const c of req) chunks.push(c as Buffer);
  if (req.url?.startsWith("/__msg/")) { const [t, x, o] = JSON.parse(decodeURIComponent(req.url.slice(7))); res.writeHead(200, { "content-type": "text/html; charset=utf-8" }); res.end(documentHtml(`Holdt: ${t}`, messageBody(t, x, o))); return; }
  const rq = new Request(ORIGIN + req.url, { method: req.method, headers: req.headers as any, body: req.method === "GET" || req.method === "HEAD" ? undefined : Buffer.concat(chunks), redirect: "manual" });
  (rq as any).cf = { city: "Denver", regionCode: "CO" }; // what Cloudflare would attach
  const r = await providerFor(ORIGIN, fetch).fetch(rq, env, { waitUntil() {}, passThroughOnException() {}, props: undefined } as any);
  const h: Record<string, string[]> = {}; r.headers.forEach((v, k) => { (h[k] ??= []).push(v); }); if (r.headers.getSetCookie) h["set-cookie"] = r.headers.getSetCookie();
  res.writeHead(r.status, h); res.end(Buffer.from(await r.arrayBuffer()));
});
await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r())); ORIGIN = `http://localhost:${(server.address() as any).port}`;
async function authorizeUrl(client_name: string, redirect = GROK) {
  const reg: any = await (await fetch(ORIGIN + "/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name, redirect_uris: [redirect], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) })).json();
  const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: redirect, code_challenge: randomBytes(32).toString("base64url"), code_challenge_method: "S256", state: "s1", scope: "calendar", resource: `${ORIGIN}/mcp` });
  return `${ORIGIN}/authorize?${q}`;
}
type P = any;
const MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";
/** A consent page opened on the Mac, so the iPhone has a real request to approve. Returns its approve link. */
async function awayLink(client = "Cursor", redirect = GROK) { const h = await (await fetch(await authorizeUrl(client, redirect), { headers: { "User-Agent": MAC } })).text(); return h.match(/data-link="([^"]+)"/)![1]!.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n)); }
const stubCancel = (p: P) => p.evaluateOnNewDocument(() => { (navigator.credentials as any).get = () => Promise.reject(new DOMException("cancelled", "NotAllowedError")); (navigator.credentials as any).create = () => Promise.reject(new DOMException("cancelled", "NotAllowedError")); });
/** Answers chosen endpoints with fixed JSON, so a state that needs a real authenticator can be drawn. */
const stubFetch = (p: P, map: Record<string, unknown>) => p.evaluateOnNewDocument((m: Record<string, unknown>) => {
  const real = window.fetch; window.fetch = (u: any, o: any) => { const k = Object.keys(m).find((x) => String(u).endsWith(x)); return k ? Promise.resolve(new Response(JSON.stringify(m[k]))) : real(u, o); };
}, map);
const stubCreate = (p: P) => p.evaluateOnNewDocument(() => { const ab = new Uint8Array([1, 2, 3]).buffer; (navigator.credentials as any).create = async () => ({ id: "x", response: { clientDataJSON: ab, attestationObject: ab } }); });
const stubGet = (p: P) => p.evaluateOnNewDocument(() => { const ab = new Uint8Array([1, 2, 3]).buffer; (navigator.credentials as any).get = async () => ({ id: "x", response: { clientDataJSON: ab, authenticatorData: ab, signature: ab } }); });
const holdSubmit = (p: P) => p.evaluateOnNewDocument(() => { HTMLFormElement.prototype.submit = function () { /* hold on the approving frame */ }; });
const FAKE_OPTS = { challenge_token: "x", publicKey: { rp: { id: "localhost", name: "Holdt" }, user: { id: "AAAA", name: "iCloud Calendar", displayName: "iCloud Calendar" }, challenge: "AAAA", pubKeyCredParams: [], excludeCredentials: [] } };
const settle = (ms = 700) => new Promise((r) => setTimeout(r, ms));
// id, title, how to reach it
const SCREENS: { id: string; name: string; mac?: boolean; go: (p: P) => Promise<void> }[] = [
  { id: "01-consent-faceid", name: "Consent, Face ID ready, read-only (Grok Bot). The one click", go: async (p) => { await freshEnv(); await pk(30); await p.goto(await authorizeUrl("Cursor")); } },
  { id: "02-consent-faceid-changes", name: "Consent, Face ID ready, changes on", go: async (p) => { await freshEnv({ WRITES_ENABLED: "true" }); await pk(30); await p.goto(await authorizeUrl("Cursor")); } },
  { id: "03-consent-approving", name: "Face ID accepted, piece drops home, page moves on", go: async (p) => { await freshEnv(); await pk(30); await stubGet(p); await holdSubmit(p); await p.goto(await authorizeUrl("Cursor")); await p.click("#pk"); } },
  { id: "04-consent-faceid-cancelled", name: "Face ID cancelled or no passkey on this device", go: async (p) => { await freshEnv(); await pk(30); await stubCancel(p); await p.goto(await authorizeUrl("Cursor")); await p.click("#pk"); } },
  { id: "05-consent-approve-on-iphone", mac: true, name: "On a Mac: Approve on your iPhone instead, opened (QR code, waiting)", go: async (p) => { await freshEnv(); await pk(30); await p.goto(await authorizeUrl("Cursor")); await p.click("#mode"); } },
  { id: "06-consent-new-device", name: "Consent with the new-device notice", go: async (p) => { await freshEnv(); await pk(0.02); await p.goto(await authorizeUrl("Cursor")); } },
  { id: "07-consent-approved-on-iphone", mac: true, name: "On a Mac: the iPhone said yes, the Mac finishes by itself", go: async (p) => { await freshEnv(); await pk(30); await holdSubmit(p); await stubFetch(p, { "/authorize/away": { ok: true, status: "approved" } }); await p.goto(await authorizeUrl("Cursor")); await p.click("#mode"); await settle(2600); } },
  { id: "08-consent-no-device", name: "Consent before any device has Face ID (waits, then continues)", go: async (p) => { await freshEnv(); await p.goto(await authorizeUrl("Cursor")); } },
  { id: "11-consent-unknown-app", name: "Consent for an app Holdt can't verify", go: async (p) => { await freshEnv(); await pk(30); await p.goto(await authorizeUrl("Calendar Helper", "https://app.example/oauth/callback")); } },
  { id: "13-not-allowed", name: "App not allowed to connect", go: async (p) => { await freshEnv({ REDIRECT_ALLOWLIST: GROK }); await p.goto(await authorizeUrl("Calendar Helper", "https://app.example/oauth/callback")); } },
  { id: "14-page-expired", name: "Approval page expired", go: async (p) => { await freshEnv(); await p.goto(ORIGIN + "/__msg/" + encodeURIComponent(JSON.stringify(["This page expired", "Nothing was shared. Ask your assistant to connect again for a fresh page.", {}]))); } },
  { id: "15-error", name: "Holdt couldn’t finish (server error)", go: async (p) => { await freshEnv(); await p.goto(ORIGIN + "/__msg/" + encodeURIComponent(JSON.stringify(["Holdt couldn’t finish connecting", "Nothing was shared. Ask your assistant to connect again.", { owner: "In the Cloudflare dashboard, open Workers, then your Holdt Worker, then Logs, and search for <span class=\"ref\">7F3A2C</span>." }]))); } },
  { id: "16-enroll", name: "Turn on Face ID from the setup link. The one click", go: async (p) => { await freshEnv(); await p.goto(`${ORIGIN}/enroll#${ENROLL}`); } },
  { id: "17-enroll-cancelled", name: "Setup link, Face ID cancelled", go: async (p) => { await freshEnv(); await stubCancel(p); await p.goto(`${ORIGIN}/enroll#${ENROLL}`); await settle(300); await p.click("#go"); await settle(900); } },
  { id: "19-enroll-link-expired", name: "Setup link expired (shown as the page opens)", go: async (p) => { await freshEnv({ ENROLL_TOKEN_ISSUED: String(Date.now() - 20 * 60_000) }); await p.goto(`${ORIGIN}/enroll#${ENROLL}`); } },
  { id: "20-enroll-done", mac: true, name: "On a Mac: Touch ID is on, first setup (the last step: tell Grok Bot the address)", go: async (p) => { await freshEnv(); await stubCreate(p); await stubFetch(p, { "/enroll/finish": { ok: true, count: 1 } }); await p.goto(`${ORIGIN}/enroll?from=setup#${ENROLL}`); await settle(300); await p.click("#go"); } },
  { id: "21-faceid-off", name: "Face ID off on this server", go: async (p) => { await freshEnv({ PASSKEYS: "off" }); await p.goto(`${ORIGIN}/enroll`); } },
  { id: "22-iphone-approve", name: "iPhone: approve a connection the Mac started (opened from the QR code)", go: async (p) => { await freshEnv(); await pk(30); await p.goto(await awayLink()); } },
  { id: "23-iphone-approved", name: "iPhone: approved", go: async (p) => { await freshEnv(); await pk(30); await stubGet(p); await stubFetch(p, { "/ok/approve": { ok: true, status: "approved", kind: "consent" } }); await p.goto(await awayLink()); await settle(400); await p.click("#yes"); } },
  { id: "24-iphone-expired", name: "iPhone: request expired", go: async (p) => { await freshEnv(); await pk(30); const l = await awayLink(); const real = Date.now; Date.now = () => real() + 6 * 60_000; try { await p.goto(l); await settle(600); } finally { Date.now = real; } } },
  { id: "25-pair-new-device", name: "Add this device: QR code for the iPhone to approve", go: async (p) => { await freshEnv(); await pk(30); await p.goto(`${ORIGIN}/pair`); } },
  { id: "26-iphone-approve-device", name: "iPhone: approve adding a new device", go: async (p) => { await freshEnv(); await pk(30); const r: any = await (await fetch(`${ORIGIN}/pair/new`, { method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN, "User-Agent": "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X)" }, body: "{}" })).json(); await p.goto(r.link); } },
  { id: "27-pair-ready", name: "New device approved: one click turns on Face ID here", go: async (p) => { await freshEnv(); await pk(30); await stubFetch(p, { "/pair/status": { ok: true, status: "approved", ...FAKE_OPTS } }); await p.goto(`${ORIGIN}/pair`); await settle(2600); } },
];
const browser = await puppeteer.launch({ executablePath: process.env.CHROME_PATH ?? "/usr/bin/google-chrome", args: ["--no-sandbox", "--font-render-hinting=none"], headless: true });
const index: any[] = [];
for (const s of SCREENS) {
  if (only && !only.has(s.id)) continue;
  for (const mode of ["light", "dark"] as const) {
    const p = await browser.newPage();
    // Computer-side screens (the QR fallback, the end of setup) render as Safari on a Mac in a 393 pt wide window.
    const mac = (s as any).mac === true;
    await p.setUserAgent(mac ? "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15" : "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1");
    await p.setViewport({ width: 393, height: 852, deviceScaleFactor: 3, isMobile: !mac, hasTouch: !mac });
    await p.emulateMediaFeatures([{ name: "prefers-color-scheme", value: mode }]);
    await s.go(p); await settle();
    const file = `${out}/${s.id}-${mode}.png`; await p.screenshot({ path: file });
    if (mode === "light") writeFileSync(`${out}/${s.id}.html`, await p.content());
    index.push({ id: s.id, name: s.name, mode, file });
    await p.close();
  }
}
const prev: any[] = only ? (() => { try { return JSON.parse(readFileSync(`${out}/index.json`, "utf8")); } catch { return []; } })() : [];
const merged = [...prev.filter((x) => !index.some((y) => y.id === x.id)), ...index].sort((a, b) => a.id.localeCompare(b.id) || a.mode.localeCompare(b.mode));
writeFileSync(`${out}/index.json`, JSON.stringify(merged, null, 1));
await browser.close(); server.close(); console.log(`shots ok: ${index.length}`);
