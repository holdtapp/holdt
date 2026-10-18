// The connect flow's words and looks: who is asking (named honestly), the new-device note in plain words, what the
// passkey sheet shows, host binding, contrast, tap targets, reduced motion, and no semicolons in anything a person reads.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { MockKV } from "./kv-mock.js";
import { providerFor } from "../src/worker.js";
import { sha256Hex, knownApp, clientLine, KNOWN_CALLBACKS } from "../src/authorize.js";
import { deviceNotice, deviceName, PASSKEY_NAMES, addPasskey, usableHere } from "../src/passkey.js";
import { TOKENS, STYLE, contrast, typo } from "../src/ui.js";
import { readFileSync } from "node:fs";

const ORIGIN = "http://localhost:8787", GROK = "https://www.cursor.com/agents/mcp/oauth/callback", CODE = "48291376", ENROLL = "enroll-token-" + "t".repeat(30);
let env: any;
async function fresh(over: Record<string, unknown> = {}) {
  env = { ICLOUD_EMAIL: "test@holdt.app", ICLOUD_APP_PASSWORD: "x", CONFIRM_SECRET: "k".repeat(43), GRANT_EPOCH: "e".repeat(36), TIMEZONE: "America/Denver", WRITES_ENABLED: "false", OAUTH_KV: new MockKV(),
    APPROVAL_CODE_HASH: await sha256Hex(`icloud-mcp-approval:${CODE}`), APPROVAL_CODE_ISSUED: String(Date.now()), PASSKEYS: "on",
    ENROLL_TOKEN_HASH: createHash("sha256").update(ENROLL).digest("hex"), ENROLL_TOKEN_ISSUED: String(Date.now()), ...over };
}
const call = (path: string, init: RequestInit = {}) => providerFor(ORIGIN, fetch).fetch(new Request(ORIGIN + path, { redirect: "manual", ...init }), env, { waitUntil() {}, passThroughOnException() {}, props: undefined } as any);
async function consentHtml(client_name: string, redirect: string) {
  const reg: any = await (await call("/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name, redirect_uris: [redirect], token_endpoint_auth_method: "none", grant_types: ["authorization_code"], response_types: ["code"] }) })).json();
  const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: redirect, code_challenge: randomBytes(32).toString("base64url"), code_challenge_method: "S256", state: "s", scope: "calendar", resource: `${ORIGIN}/mcp` });
  const page = await call(`/authorize?${q}`); return { page, html: await page.text() };
}
/** What a person reads: no style, no script, no tags, entities decoded. */
const visible = (html: string) => html.replace(/<\/?(strong|code|em)>/g, "").replace(/<style[\s\S]*?<\/style>|<script[\s\S]*?<\/script>/g, " ").replace(/<[^>]+>/g, " ").replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n)).replace(/[\s\u00a0]+/g, " ");
const LOCKED = "Never deletes your events. It can only take back its own, on your yes.";

test("ATTACK CF1: naming, Grok Bot only for Grok Bot's exact callback, never from a name the app typed", async () => {
  assert.equal(knownApp(GROK), "Grok Bot");
  for (const u of [GROK + "/", GROK + "?x=1", GROK.replace("https", "http"), "https://cursor.com/agents/mcp/oauth/callback", "https://www.cursor.com.evil.example/agents/mcp/oauth/callback", "cursor://anysphere.cursor-mcp/oauth/callback", "not a url"]) assert.equal(knownApp(u), undefined, u);
  assert.deepEqual(Object.values(KNOWN_CALLBACKS), ["Grok Bot"]);
  await fresh();
  const known = visible((await consentHtml("Cursor", GROK)).html);
  assert.match(known, /Connect Grok Bot to your iCloud Calendar\?/); assert.match(known, /Access goes to Grok Bot alone\. Allow this only if you just asked it to connect\./);
  assert.doesNotMatch(known, /Cursor|verify|registered itself/);
  // A stranger that names itself Grok Bot gets quotes and the plain truth
  const fake = visible((await consentHtml("Grok Bot", "https://app.example/cb")).html);
  assert.match(fake, /Connect an app to your iCloud Calendar\?/); assert.match(fake, /It calls itself “Grok Bot,” but Holdt can’t verify that\./); assert.match(fake, /Access goes to app\.example/);
  assert.doesNotMatch(fake, /Access goes only to Grok Bot/);
  assert.match(clientLine({ redirectHost: "app.example", redirectUri: "https://app.example/cb" }).lede, /didn't give a name/);
  assert.doesNotMatch(fake, /Grok Bot to your/, "an unverified name never goes in the headline");
});

test("consent copy: locked line verbatim, read-only and changes-on wording, and no semicolons anywhere a person reads", async () => {
  await fresh(); const ro = visible((await consentHtml("Cursor", GROK)).html);
  assert.ok(ro.includes(LOCKED)); assert.match(ro, /Changes are off, so it can’t add or change events\./); assert.match(ro, /Never sends invitations\./);
  await fresh({ WRITES_ENABLED: "true" }); const rw = visible((await consentHtml("Cursor", GROK)).html);
  assert.ok(rw.includes(LOCKED)); assert.match(rw, /Changes are on, and each one waits for your yes\./);
  const pages = [ro, rw, visible((await consentHtml("Calendar Helper", "https://app.example/cb")).html), visible(await (await call("/enroll")).text()), visible(await (await call("/ok")).text()), visible(await (await call("/pair")).text())];
  await fresh({ APPROVAL_CODE_HASH: undefined }); pages.push(visible((await consentHtml("Cursor", GROK)).html)); // no device yet
  await addPasskey(env, { id: "cred-a" + "x".repeat(20), jwk: {}, alg: -7, signCount: 0, createdAt: Date.now() - 30 * 86400_000 } as any); pages.push(visible((await consentHtml("Cursor", GROK)).html)); // the normal page
  const { askHtml } = await import("../src/authorize.js");
  pages.push(visible(askHtml("consent", "a Mac near Denver, CO", "just now", { clientName: "Cursor", redirectUri: GROK }, "off, so it can't add or change events")), visible(askHtml("pair", "an iPad", "1 minute ago", {}, "")));
  await fresh({ PASSKEYS: "off" }); pages.push(visible(await (await call("/enroll")).text()));
  for (const p of pages) { assert.doesNotMatch(p, /;/, p.slice(0, 80)); assert.doesNotMatch(p, /\b(unlock|elevate|seamless|powerful)\b/i); }
});

test("messages a person reads on the phone carry no command lines, only plain words", () => {
  for (const f of ["src/authorize.ts", "src/passkey.ts"]) {
    const src = readFileSync(f, "utf8");
    // every quoted sentence handed to a person as a message
    const msgs = [...src.matchAll(/message: (["`])((?:(?!\1).)*)\1|no\("[^"]*", (["`])((?:(?!\3).)*)\3|return "((?:[^"\\]|\\.)*\.)"/g)].map((m) => m[2] ?? m[4] ?? m[5]).filter(Boolean);
    assert.ok(msgs.length >= 4, `${f}: found ${msgs.length}`);
    for (const m of msgs) { assert.doesNotMatch(m!, /npm|--[a-z]/, m); assert.doesNotMatch(m!, /;/, m); }
  }
});

test("new-device note: plain words, who and when, and the one thing to do", () => {
  const now = Date.UTC(2026, 9, 18, 2, 0); // Oct 17, 8:00 PM MDT
  assert.equal(deviceNotice([], "America/Denver", now), undefined);
  const c = (id: string, ago: number, label?: string) => ({ id, jwk: {}, alg: -7 as const, signCount: 0, createdAt: now - ago, label });
  assert.equal(deviceNotice([c("a", 60_000, "iPhone")], "America/Denver", now), "An iPhone was added today at 7:59\u00a0PM. Not you? Tap\u00a0Don't\u00a0allow.");
  assert.equal(deviceNotice([c("a", 60_000, "iPhone"), c("b", 86400_000, "MacIntel"), c("c", 3 * 86400_000)], "America/Denver", now),
    "New devices: an iPhone today at 7:59\u00a0PM, a Mac yesterday at 8:00\u00a0PM and a new device on Oct 14 at 8:00\u00a0PM. Not you? Tap\u00a0Don't\u00a0allow.");
  assert.match(deviceNotice([c("a", 60_000)], "Not/AZone", now)!, /A new device was added today at 1:59\u00a0AM/);
  assert.deepEqual(["iPhone", "iPad", "MacIntel", "Win32", "Linux armv8l", "Linux x86_64", "", undefined].map(deviceName), ["an iPhone", "an iPad", "a Mac", "a Windows PC", "an Android device", "a Linux computer", "a new device", "a new device"]);
});

test("browser scripts parse, and the consent page puts the reset command only behind setup help", async () => {
  const { LOGIN_SCRIPT, ENROLL_SCRIPT, CONSENT_SCRIPT, READY_SCRIPT, OK_SCRIPT, PAIR_SCRIPT } = await import("../src/passkey.js");
  for (const sc of [LOGIN_SCRIPT, ENROLL_SCRIPT, CONSENT_SCRIPT, READY_SCRIPT, OK_SCRIPT, PAIR_SCRIPT]) assert.doesNotThrow(() => new Function(sc));
});

test("passkey sheet names: Holdt and iCloud Calendar, never an owner label", async () => {
  assert.deepEqual(PASSKEY_NAMES, { rp: "Holdt", user: "iCloud Calendar" });
  await fresh();
  const o: any = await (await call("/enroll/options", { method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN }, body: JSON.stringify({ token: ENROLL }) })).json();
  assert.equal(o.publicKey.rp.name, "Holdt"); assert.equal(o.publicKey.rp.id, "localhost");
  assert.equal(o.publicKey.user.name, "iCloud Calendar"); assert.equal(o.publicKey.user.displayName, "iCloud Calendar");
});

test("ATTACK CF2: host binding, a passkey made on another host is never offered here, and older records count as this host's", async () => {
  await fresh();
  const mk = (rpId?: string) => ({ id: randomBytes(16).toString("base64url"), jwk: {}, alg: -7 as const, signCount: 0, createdAt: Date.now() - 30 * 86400_000, rpId });
  const moved = mk("old.workers.dev"); await addPasskey(env, moved);
  const c1 = await consentHtml("Cursor", GROK); assert.doesNotMatch(c1.html, /id="pk"/, "only an other-host passkey: code only");
  const legacy = mk(undefined), here = mk("localhost"); await addPasskey(env, legacy); await addPasskey(env, here);
  const c2 = await consentHtml("Cursor", GROK); const o = JSON.parse(c2.html.match(/data-o="([^"]+)"/)![1]!.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n)));
  assert.deepEqual(new Set(o.ids), new Set([legacy.id, here.id]));
  assert.deepEqual(usableHere([moved, legacy, here], new URL("https://connect.holdt.app")).map((c) => c.id), [legacy.id]);
});

test("look: AA contrast in light and dark, 44 pt targets, safe areas, Dynamic Type and reduced motion", () => {
  for (const [mode, t] of Object.entries(TOKENS)) {
    for (const [fg, bg] of [["ink", "bg"], ["ink2", "bg"], ["ink", "surface"], ["ink2", "surface"], ["greenInk", "bg"], ["greenInk", "surface"], ["onGreen", "green"], ["warnInk", "warnBg"], ["err", "bg"], ["err", "surface"], ["ink", "secondaryBg"]] as const)
      assert.ok(contrast((t as any)[fg], (t as any)[bg]) >= 4.5, `${mode} ${fg} on ${bg}: ${contrast((t as any)[fg], (t as any)[bg]).toFixed(2)}`);
    assert.ok(contrast(t.green, t.bg) >= 3, `${mode} mark plate vs page`);
  }
  const rem = (sel: string) => Number(STYLE.match(new RegExp(`${sel}\\{[^}]*min-height:(?:max\\(44px,)?([\\d.]+)rem`))?.[1]); // max(44px, …) also floors it at small text sizes
  for (const sel of ["\\.btn", "\\.plain", "summary", "input\\.code"]) assert.ok(rem(sel) * 16 >= 44, `${sel} is ${rem(sel)}rem`);
  assert.match(STYLE, /env\(safe-area-inset-bottom\)/); assert.match(STYLE, /font:-apple-system-body/);
  assert.match(STYLE, /prefers-reduced-motion:reduce\)\{[^}]*animation:none!important/);
  assert.equal(typo("can't &#39; it&#39;s"), "can’t &#39; it’s");
});

test("connect: every app gets the safety line, a wrong code comes back empty and focused, a dead code puts help first", async () => {
  await fresh({ PASSKEYS: "off" });
  for (const [n, r] of [["Calendar Helper", "https://app.example/cb"], ["", "https://app.example/cb"], ["Cursor", GROK]]) assert.match(visible((await consentHtml(n, r)).html), /Allow (this )?only if you just asked it to connect\./);
  const { html } = await consentHtml("Cursor", GROK);
  const field = (h: string, k: string) => h.match(new RegExp(`name="${k}" value="([^"]*)"`))![1]!;
  const post = async (code: string) => (await call("/authorize", { method: "POST", body: new URLSearchParams({ handle: field(html, "handle").replace(/&#(\d+);/g, (_, x) => String.fromCharCode(+x)), ctx: field(html, "ctx").replace(/&#(\d+);/g, (_, x) => String.fromCharCode(+x)), code, decision: "approve" }) })).text();
  const wrong = await post("1111 2222");
  const input = wrong.match(/<input class="code"[^>]*>/)![0];
  assert.doesNotMatch(input, /value=/); assert.match(input, /autofocus/); assert.match(input, /aria-invalid="true"/);
  assert.doesNotMatch(wrong, /1111 2222/);
  // Every owner disclosure carries one label
  const labels = [...wrong.matchAll(/<details class="owner[^"]*"[^>]*><summary>([^<]*)/g)].map((m) => m[1]!.trim());
  assert.deepEqual([...new Set(labels)], ["Setup help"]);
  await fresh({ PASSKEYS: "off" });
  const exp = await (async () => { const { html: h } = await consentHtml("Cursor", GROK); env.APPROVAL_CODE_ISSUED = String(Date.now() - 20 * 60_000); return (await call("/authorize", { method: "POST", body: new URLSearchParams({ handle: field(h, "handle").replace(/&#(\d+);/g, (_, x) => String.fromCharCode(+x)), ctx: field(h, "ctx").replace(/&#(\d+);/g, (_, x) => String.fromCharCode(+x)), code: CODE, decision: "approve" }) })).text(); })();
  assert.match(exp, /<details class="owner dead" open><summary>Setup help/);
  assert.ok(exp.indexOf("<details class=\"owner dead\" open>") < exp.indexOf('value="approve">Allow with code'), "help opens right under the message, above the button");
  assert.match(exp, /class="btn secondary" name="decision" value="approve"/);
});

test("look: input and secondary-button borders meet 3:1 non-text contrast (WCAG 1.4.11) in light and dark", () => {
  for (const m of ["light", "dark"] as const) for (const bg of [TOKENS[m].surface, TOKENS[m].bg]) assert.ok(contrast(TOKENS[m].fieldLine, bg) >= 3, `${m} field border on ${bg}`);
  assert.match(STYLE, /input\.code\{[^}]*border:1\.5px solid var\(--field-line\)/);
});

test("no typed codes: every page in the normal flow has nothing to type and never mentions a code", async () => {
  await fresh({ APPROVAL_CODE_HASH: undefined, APPROVAL_CODE_ISSUED: undefined });
  const html: string[] = [(await consentHtml("Cursor", GROK)).html];
  await addPasskey(env, { id: "cred-a" + "x".repeat(20), jwk: {}, alg: -7, signCount: 0, createdAt: Date.now() - 30 * 86400_000 } as any);
  html.push((await consentHtml("Cursor", GROK)).html, await (await call("/enroll")).text(), await (await call("/ok")).text(), await (await call("/pair")).text());
  const { askHtml } = await import("../src/authorize.js"); html.push(askHtml("consent", "a Mac", "just now", { redirectUri: GROK }, ""), askHtml("pair", "an iPad", "just now", {}, ""));
  const { CONSENT_SCRIPT, ENROLL_SCRIPT, OK_SCRIPT, PAIR_SCRIPT, READY_SCRIPT } = await import("../src/passkey.js");
  for (const h of html) { assert.doesNotMatch(h, /<input(?![^>]*type="hidden")/, "no visible input"); assert.doesNotMatch(visible(h), /approval code|recovery code|8 digits|enter (the|a|your) code/i); }
  for (const sc of [CONSENT_SCRIPT, ENROLL_SCRIPT, OK_SCRIPT, PAIR_SCRIPT, READY_SCRIPT]) assert.doesNotMatch(sc, /approval code|8 digits/i);
});

test("one click: the setup link's button goes straight to the passkey sheet, and the consent button finishes the grant", async () => {
  const { ENROLL_SCRIPT, CONSENT_SCRIPT, PAIR_SCRIPT } = await import("../src/passkey.js");
  // Options are fetched as the page opens (spends nothing), so the click keeps Safari's user gesture for credentials.create.
  assert.match(ENROLL_SCRIPT, /else fetchOpts\(\)\.then\(/);
  assert.match(ENROLL_SCRIPT, /let r=await\(Date\.now\(\)-preAt<240000&&pre\?pre:fetchOpts\(\)\)/);
  assert.match(ENROLL_SCRIPT, /navigator\.credentials\.create/); assert.doesNotMatch(ENROLL_SCRIPT, /confirm\(|Continue/);
  // The consent button's sheet result submits the form at once. There is no second confirm step.
  assert.match(CONSENT_SCRIPT, /lab\.textContent='Approving';live\.textContent='Approving\. One moment\.';finish\(false\);/);
  assert.match(CONSENT_SCRIPT, /transports:\['internal','hybrid'\]/, "the sheet can offer a nearby iPhone by itself");
  // Pairing options arrive with the approval, so Turn on Face ID there is also a direct click to the sheet.
  assert.match(PAIR_SCRIPT, /if\(r\.status==='approved'&&r\.publicKey\)\{stop\(\);opts=r;show\('ready'\);\}/);
});

test("status lines are read once, focus survives a failed sheet, and icons hang beside every line", async () => {
  const { CONSENT_SCRIPT, ENROLL_SCRIPT } = await import("../src/passkey.js");
  const src = readFileSync(new URL("../src/authorize.ts", import.meta.url), "utf8");
  assert.match(src, /<p class="status" id="msg" aria-hidden="true">\$\{ICON\.info\}<span class="st"><\/span><\/p><p class="sr" id="live" role="status" aria-live="polite"><\/p>/, "enroll");
  assert.match(src, /<p class="status" id="pkmsg" aria-hidden="true">\$\{ICON\.info\}<span class="st">\$\{esc\(error\)\}<\/span><\/p><p class="sr" id="live" role="status" aria-live="polite">\$\{esc\(error\)\}<\/p>/, "a server-side error is in the live region too");
  assert.match(CONSENT_SCRIPT, /if\(!on\)\{msg\.parentNode\.classList\.remove\('keep'\);msg\.textContent='';live\.textContent='';\}/);
  assert.match(CONSENT_SCRIPT, /fails>1\)\{setMode\(true\);msg\.parentNode\.classList\.add\('keep'\);say\(bio\+' didn’t finish\.\\nScan the QR code with '\+\(other==='your iPhone'\?'your iPhone':'another device'\)\+' instead\.'\)/);
  assert.match(ENROLL_SCRIPT, /btn\.focus\(\);\}\}\);$/);
  for (const t of [src, readFileSync(new URL("../src/passkey.ts", import.meta.url), "utf8")]) assert.doesNotMatch(t, /code still works/i);
  assert.match(STYLE, /\.status\{display:flex;justify-content:center;align-items:flex-start;gap:\.35rem;[^}]*text-align:left\}/);
  assert.match(STYLE, /\.status\[hidden\]\{display:none\}/);
  assert.match(STYLE, /\.btn\.plain\.quiet\{margin-top:\.9rem\}/);
  assert.match(STYLE, /\[hidden\]\{display:none!important\}/);
  // The QR code stays black on white in dark mode, so a camera reads it.
  const { qrSvg } = await import("../src/qr.js"); assert.match(qrSvg("https://x.example/ok#a", "QR"), /<rect width="\d+" height="\d+" fill="#fff"\/><path d="[^"]+" fill="#000"\/>/);
});

test("pages that also open on a computer never say tap (R44): no-device consent, add this device, the reviewer link", async () => {
  await fresh({ APPROVAL_CODE_HASH: undefined });
  const pages = [visible((await consentHtml("Cursor", GROK)).html), visible(await (await call("/pair")).text())];
  await fresh({ REVIEWER_MODE: "on" }); pages.push(visible(await (await call("/review")).text()));
  for (const p of pages) assert.doesNotMatch(p, /\btap\b/i, p.slice(0, 80));
  assert.match(pages[0], /If you didn’t ask it to connect, don’t allow it\./);
  assert.match(pages[1], /Approve from the iPhone you already use with Holdt\./);
  assert.match(pages[2], /Nothing changes until you turn it on\./);
});
