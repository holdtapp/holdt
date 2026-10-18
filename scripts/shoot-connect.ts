// Dev-only: renders every connect-flow screen (consent, approval code, Face ID set up, errors) at iPhone 15 size,
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
    APPROVAL_CODE_HASH: await sha256Hex(`icloud-mcp-approval:${CODE}`), APPROVAL_CODE_ISSUED: String(Date.now()), PASSKEYS: "on",
    ENROLL_TOKEN_HASH: createHash("sha256").update(ENROLL).digest("hex"), ENROLL_TOKEN_ISSUED: String(Date.now()), ...over };
}
// The new-device fixture is frozen at 8:00 PM MT on Oct 17 so light and dark show the same minute.
const pk = (daysAgo: number, label = "iPhone") => addPasskey(env, { id: randomBytes(16).toString("base64url"), jwk: {}, alg: -7, signCount: 0, createdAt: daysAgo < 1 ? Date.UTC(2026, 9, 18, 2, 0) : Date.now() - daysAgo * 86400_000, label, rpId: new URL(ORIGIN).hostname } as any);
const server = createServer(async (req, res) => {
  const chunks: Buffer[] = []; for await (const c of req) chunks.push(c as Buffer);
  if (req.url?.startsWith("/__msg/")) { const [t, x, o] = JSON.parse(decodeURIComponent(req.url.slice(7))); res.writeHead(200, { "content-type": "text/html; charset=utf-8" }); res.end(documentHtml(`Holdt: ${t}`, messageBody(t, x, o))); return; }
  const r = await providerFor(ORIGIN, fetch).fetch(new Request(ORIGIN + req.url, { method: req.method, headers: req.headers as any, body: req.method === "GET" || req.method === "HEAD" ? undefined : Buffer.concat(chunks), redirect: "manual" }), env, { waitUntil() {}, passThroughOnException() {}, props: undefined } as any);
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
const stubCancel = (p: P) => p.evaluateOnNewDocument(() => { (navigator.credentials as any).get = () => Promise.reject(new DOMException("cancelled", "NotAllowedError")); (navigator.credentials as any).create = () => Promise.reject(new DOMException("cancelled", "NotAllowedError")); });
const stubEnrollOk = (p: P) => p.evaluateOnNewDocument(() => {
  const ab = new Uint8Array([1, 2, 3]).buffer; (navigator.credentials as any).create = async () => ({ id: "x", response: { clientDataJSON: ab, attestationObject: ab } });
  const real = window.fetch; window.fetch = (u: any, o: any) => String(u).includes("/enroll/finish") ? Promise.resolve(new Response(JSON.stringify({ ok: true, count: 1 }))) : real(u, o);
});
const stubApprove = (p: P) => p.evaluateOnNewDocument(() => {
  const ab = new Uint8Array([1, 2, 3]).buffer; (navigator.credentials as any).get = async () => ({ id: "x", response: { clientDataJSON: ab, authenticatorData: ab, signature: ab } });
  HTMLFormElement.prototype.submit = function () { /* hold on the approving frame */ };
});
const settle = (ms = 700) => new Promise((r) => setTimeout(r, ms));
// id, title, how to reach it
const SCREENS: { id: string; name: string; go: (p: P) => Promise<void> }[] = [
  { id: "01-consent-faceid", name: "Consent, Face ID ready, read-only (Grok Bot)", go: async (p) => { await freshEnv(); await pk(30); await p.goto(await authorizeUrl("Cursor")); } },
  { id: "02-consent-faceid-changes", name: "Consent, Face ID ready, changes on", go: async (p) => { await freshEnv({ WRITES_ENABLED: "true" }); await pk(30); await p.goto(await authorizeUrl("Cursor")); } },
  { id: "03-consent-approving", name: "Face ID accepted, piece drops home, page moves on", go: async (p) => { await freshEnv(); await pk(30); await stubApprove(p); await p.goto(await authorizeUrl("Cursor")); await p.click("#pk"); } },
  { id: "04-consent-faceid-cancelled", name: "Face ID cancelled or no passkey on this device", go: async (p) => { await freshEnv(); await pk(30); await stubCancel(p); await p.goto(await authorizeUrl("Cursor")); await p.click("#pk"); } },
  { id: "05-consent-code-disclosure", name: "Use an approval code instead, opened", go: async (p) => { await freshEnv(); await pk(30); await p.goto(await authorizeUrl("Cursor")); await p.click("#mode"); } },
  { id: "06-consent-new-device", name: "Consent with the new-device notice", go: async (p) => { await freshEnv(); await pk(0.02); await p.goto(await authorizeUrl("Cursor")); } },
  { id: "07-consent-code-only", name: "Consent, approval code only (no Face ID set up)", go: async (p) => { await freshEnv(); await p.goto(await authorizeUrl("Cursor")); } },
  { id: "08-consent-code-typed", name: "Approval code typed", go: async (p) => { await freshEnv(); await p.goto(await authorizeUrl("Cursor")); await p.type("#code", "48291376"); } },
  { id: "09-consent-wrong-code", name: "Wrong approval code", go: async (p) => { await freshEnv(); await p.goto(await authorizeUrl("Cursor")); await p.type("#code", "11112222"); await Promise.all([p.waitForNavigation(), p.click("button[value=approve]")]); } },
  { id: "10-consent-code-expired", name: "Expired approval code", go: async (p) => { await freshEnv({ APPROVAL_CODE_ISSUED: String(Date.now() - 20 * 60_000) }); await p.goto(await authorizeUrl("Cursor")); await p.type("#code", "48291376"); await Promise.all([p.waitForNavigation(), p.click("button[value=approve]")]); } },
  { id: "11-consent-unknown-app", name: "Consent for an app Holdt can't verify", go: async (p) => { await freshEnv(); await p.goto(await authorizeUrl("Calendar Helper", "https://app.example/oauth/callback")); } },
  { id: "12-already-connected", name: "Code already used (already connected)", go: async (p) => { await freshEnv(); await env.OAUTH_KV.put(`approval-used:${env.APPROVAL_CODE_HASH}`, "1"); await p.goto(await authorizeUrl("Cursor")); await p.type("#code", "48291376"); await Promise.all([p.waitForNavigation(), p.click("button[value=approve]")]); } },
  { id: "13-not-allowed", name: "App not allowed to connect", go: async (p) => { await freshEnv({ REDIRECT_ALLOWLIST: GROK }); await p.goto(await authorizeUrl("Calendar Helper", "https://app.example/oauth/callback")); } },
  { id: "14-page-expired", name: "Approval page expired", go: async (p) => { await freshEnv(); await p.goto(ORIGIN + "/__msg/" + encodeURIComponent(JSON.stringify(["This page expired", "Nothing was shared. Ask your assistant to connect again for a fresh page.", {}]))); } },
  { id: "15-error", name: "Holdt couldn’t finish (server error)", go: async (p) => { await freshEnv(); await p.goto(ORIGIN + "/__msg/" + encodeURIComponent(JSON.stringify(["Holdt couldn’t finish connecting", "Nothing was shared. Ask your assistant to connect again.", { owner: "In the Cloudflare dashboard, open Workers, then your Holdt Worker, then Logs, and search for <span class=\"ref\">7F3A2C</span>." }]))); } },
  { id: "16-enroll", name: "Turn on Face ID (enroll)", go: async (p) => { await freshEnv(); await p.goto(`${ORIGIN}/enroll#${ENROLL}`); } },
  { id: "17-enroll-cancelled", name: "Enroll, Face ID cancelled", go: async (p) => { await freshEnv(); await stubCancel(p); await p.goto(`${ORIGIN}/enroll#${ENROLL}`); await p.type("#code", "4829 1376"); await p.click("#go"); await settle(1400); } },
  { id: "18-enroll-wrong-code", name: "Enroll, wrong code", go: async (p) => { await freshEnv(); await p.evaluateOnNewDocument(() => { const ab = new Uint8Array([1]).buffer; (navigator.credentials as any).create = async () => ({ id: "x", response: { clientDataJSON: ab, attestationObject: ab } }); const real = window.fetch; window.fetch = (u: any, o: any) => String(u).includes("/enroll/finish") ? Promise.resolve(new Response(JSON.stringify({ ok: false, field: "code", message: "That code doesn't match. 4 tries left." }))) : real(u, o); }); await p.goto(`${ORIGIN}/enroll#${ENROLL}`); await p.type("#code", "1111 2222"); await p.click("#go"); } },
  { id: "19-enroll-link-expired", name: "Enroll link expired", go: async (p) => { await freshEnv({ ENROLL_TOKEN_ISSUED: String(Date.now() - 20 * 60_000) }); await p.goto(`${ORIGIN}/enroll#${ENROLL}`); await p.type("#code", "4829 1376"); await p.click("#go"); } },
  { id: "20-enroll-done", name: "Face ID is on (you can close this)", go: async (p) => { await freshEnv(); await stubEnrollOk(p); await p.goto(`${ORIGIN}/enroll#${ENROLL}`); await p.type("#code", "4829 1376"); await p.click("#go"); } },
  { id: "21-faceid-off", name: "Face ID sign-in turned off", go: async (p) => { await freshEnv({ PASSKEYS: "off" }); await p.goto(`${ORIGIN}/enroll`); } },
];
const browser = await puppeteer.launch({ executablePath: process.env.CHROME_PATH ?? "/usr/bin/google-chrome", args: ["--no-sandbox", "--font-render-hinting=none"], headless: true });
const index: any[] = [];
for (const s of SCREENS) {
  if (only && !only.has(s.id)) continue;
  for (const mode of ["light", "dark"] as const) {
    const p = await browser.newPage();
    await p.setUserAgent("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1");
    await p.setViewport({ width: 393, height: 852, deviceScaleFactor: 3, isMobile: true, hasTouch: true });
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
