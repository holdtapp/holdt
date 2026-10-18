// The add-this-device page (/pair) and the reviewer link page (/review), run in a tiny fake DOM: what each failure
// actually shows, what a screen reader hears, and what the button says on a computer.
import { test } from "node:test";
import assert from "node:assert/strict";
import { MockKV } from "./kv-mock.js";
import { providerFor } from "../src/worker.js";
import { checkReviewerCode } from "../src/reviewer.js";
import { ICON } from "../src/ui.js";

const ORIGIN = "http://localhost:8787";
const MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15";
const IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1";
let env: any;
const fresh = (over: Record<string, unknown> = {}) => { env = { ICLOUD_EMAIL: "test@holdt.app", ICLOUD_APP_PASSWORD: "x", CONFIRM_SECRET: "k".repeat(43), GRANT_EPOCH: "e".repeat(36), TIMEZONE: "UTC", OAUTH_KV: new MockKV(), PASSKEYS: "on", ...over }; };
const call = (path: string, ua = MAC) => providerFor(ORIGIN, fetch).fetch(new Request(ORIGIN + path, { headers: { "User-Agent": ua } }), env, { waitUntil() {}, passThroughOnException() {}, props: undefined } as any);
const scriptOf = (html: string) => html.match(/<script nonce="[^"]+">([\s\S]*)<\/script>/)![1]!;

/** Just enough DOM for these two scripts. Elements appear on first use, and each keeps its own h1, .lede and last child. */
class El {
  hidden = false; textContent = ""; innerHTML = ""; attrs: Record<string, string> = {}; cls = new Set<string>(); kids = new Map<string, El>(); on: Record<string, Function> = {}; removed = false;
  classList = { add: (c: string) => this.cls.add(c), remove: (c: string) => this.cls.delete(c), contains: (c: string) => this.cls.has(c), toggle: (c: string, v: boolean) => (v ? this.cls.add(c) : this.cls.delete(c)) };
  constructor(hidden = false) { this.hidden = hidden; }
  kid(k: string) { if (!this.kids.has(k)) this.kids.set(k, new El()); return this.kids.get(k)!; }
  querySelector(s: string) { const k = this.kid(s); return k.removed ? null : k; }
  get lastElementChild() { return this.kid("last"); }
  setAttribute(k: string, v: string) { this.attrs[k] = v; } removeAttribute(k: string) { delete this.attrs[k]; } hasAttribute(k: string) { return k in this.attrs; }
  remove() { this.removed = true; } focus() {} scrollIntoView() {} addEventListener(e: string, f: Function) { this.on[e] = f; }
}
function run(script: string, o: { ua?: string; fetch: (path: string, body: any) => any; hash?: string; ids?: Record<string, El>; create?: () => Promise<any>; touch?: boolean; screen?: { width: number; height: number }; store?: Map<string, string> }) {
  const els: Record<string, El> = { ...o.ids }, doc: any = { title: "", body: new El(), documentElement: new El(), getElementById: (id: string) => (els[id] ??= new El()), querySelectorAll: () => [], createTreeWalker: () => ({ nextNode: () => null }) };
  if (o.touch) doc.ontouchend = null;
  const intervals: Function[] = [], store = o.store ?? new Map<string, string>();
  const fakeFetch = async (path: string, init: any) => { const r = await o.fetch(path, JSON.parse(init.body)); if (r === "net") throw new TypeError("offline"); return { json: async () => r }; };
  const names = ["document", "navigator", "screen", "fetch", "location", "history", "sessionStorage", "setInterval", "clearInterval", "setTimeout", "requestAnimationFrame", "getSelection", "window"];
  const vals = [doc, { userAgent: o.ua ?? MAC, platform: "MacIntel", credentials: { create: () => o.create!() } }, o.screen ?? { width: 1440, height: 900 }, fakeFetch, { hash: o.hash ?? "", pathname: "/x", search: "", origin: ORIGIN }, { replaceState() {} },
    { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => store.set(k, v), removeItem: (k: string) => store.delete(k) },
    (f: Function) => intervals.push(f), () => {}, () => 0, () => 0, () => null, { PublicKeyCredential: function () {} }];
  new Function(...names, script)(...vals);
  return { store, $: (id: string) => doc.getElementById(id) as El, tick: async () => { for (const f of intervals) await f(); await settle(); } };
}
const settle = () => new Promise((r) => setTimeout(r, 5));
// The views start hidden except the first, as on the real page.
const views = (ids: string[]) => Object.fromEntries(ids.map((id, i) => [id, new El(i > 0)]));
const qrwait = () => { const e = new El(); e.classList.add("qrwait"); return e; };
const PAIR_VIEWS = () => ({ ...views(["ask", "ready", "done", "no", "skip", "dead", "nopk"]), scanstep: new El(true), qrwrap: qrwait() });
const NEW = { ok: true, claim: "c", qr: "<svg></svg>" }, APPROVED = { ok: true, status: "approved", challenge_token: "t", publicKey: { challenge: "AA", user: { id: "AA" }, excludeCredentials: [] } };
const SAVED = async () => ({ response: { clientDataJSON: new ArrayBuffer(1), attestationObject: new ArrayBuffer(1) } });
const shown = (p:{ $: (id: string) => El }, ids: string[]) => ids.filter((id) => !p.$(id).hidden);

test("pair page HTML: no scan step or waiting line before the QR code, and Setup help matches the device", async () => {
  fresh();
  const mac = await (await call("/pair")).text();
  assert.match(mac, /<ol class="steps one" id="scanstep" data-nobio hidden>/, "the scan step waits for the QR code");
  assert.match(mac, /id="awaymsg" aria-hidden="true">[\s\S]*?<span class="st">One moment\.<\/span>/);
  assert.doesNotMatch(mac.replace(/<script[\s\S]*<\/script>/, ""), /Waiting for/, "not before the QR code exists");
  const nopk = (h: string) => h.match(/<div id="nopk"[\s\S]*?<\/details>/)![0];
  assert.match(nopk(mac), /<code>npm run add-device<\/code>/); assert.doesNotMatch(nopk(mac), /--qr/);
  assert.match(nopk(await (await call("/pair", IPHONE)).text()), /<code>npm run add-device -- --qr<\/code>/);
});

test("pair page: the QR code brings the scan step and the waiting line, and a screen reader hears both", async () => {
  fresh(); const s = scriptOf(await (await call("/pair")).text());
  const p = run(s, { ids: PAIR_VIEWS(), fetch: (path) => path === "/pair/new" ? { ok: true, claim: "c", qr: "<svg class=\"qr\"></svg>" } : { ok: true, status: "pending" } });
  assert.equal(p.$("scanstep").hidden, true); await settle();
  assert.equal(p.$("scanstep").hidden, false); assert.match(p.$("qrwrap").innerHTML, /svg/);
  assert.equal(p.$("awaymsg").lastElementChild.textContent, "Waiting for that iPhone.");
  assert.equal(p.$("live").textContent, "QR code shown. Scan it with that iPhone’s camera. Waiting for that iPhone.");
  assert.equal(p.$("qrwrap").hidden, false);
});

test("pair page: a single dropped poll keeps polling, so a later approval is still picked up", async () => {
  fresh(); const s = scriptOf(await (await call("/pair")).text()); let reply: any = "net";
  const p = run(s, { ids: PAIR_VIEWS(), fetch: (path) => path === "/pair/new" ? NEW : reply });
  await settle(); await p.tick();
  assert.equal(p.$("awaymsg").lastElementChild.textContent, "Reconnecting…"); assert.equal(p.$("live").textContent, "Reconnecting…");
  assert.equal(p.$("qrwrap").hidden, false);
  reply = { ok: true, status: "pending" }; await p.tick(); assert.equal(p.$("awaymsg").lastElementChild.textContent, "Waiting for that iPhone.");
  reply = "net"; await p.tick(); await p.tick(); reply = { ok: true, status: "pending" }; await p.tick();
  reply = "net"; await p.tick(); assert.equal(p.$("awaymsg").lastElementChild.textContent, "Reconnecting…", "a success reset the count");
  reply = APPROVED; await p.tick(); assert.deepEqual(shown(p, ["ask", "ready", "done", "no", "skip", "dead", "nopk"]), ["ready"]);
});

test("pair page: three dropped polls in a row say so, stop the spinner and hide the QR code", async () => {
  fresh(); const s = scriptOf(await (await call("/pair")).text()); let net = false;
  const p = run(s, { ids: PAIR_VIEWS(), fetch: (path) => path === "/pair/new" ? NEW : net ? "net" : { ok: true, status: "pending" } });
  await settle(); await p.tick(); assert.equal(p.$("awaymsg").lastElementChild.textContent, "Waiting for that iPhone.");
  net = true; await p.tick(); await p.tick(); assert.equal(p.$("qrwrap").hidden, false); await p.tick();
  const t = "Holdt couldn’t reach your server. Check your connection, then reload this page.";
  assert.equal(p.$("awaymsg").lastElementChild.textContent, t); assert.equal(p.$("live").textContent, t);
  assert.equal(p.$("awaymsg").classList.contains("wait"), false); assert.equal(p.$("awaymsg").querySelector(".spin"), null);
  assert.equal(p.$("qrwrap").hidden, true, "no code to scan once the page has given up");
  assert.deepEqual(shown(p, ["ask", "ready", "done", "no", "skip", "dead", "nopk"]), ["ask"]);
  await p.tick(); assert.equal(p.$("awaymsg").lastElementChild.textContent, t, "polling stopped, so nothing overwrites it");
});

test("pair page: a device cap or a rate limit shows the server's sentence, never 'This request expired'", async () => {
  fresh(); const s = scriptOf(await (await call("/pair")).text());
  for (const [r, want] of [
    [{ ok: false, message: "Holdt already has 10 passkeys, the most it allows." }, "Holdt already has 10 passkeys, the most it allows."],
    [{ error: "rate_limited", error_description: "Too many requests. Wait a minute and try again." }, "Too many requests. Wait a minute and try again."],
  ] as const) {
    const p = run(s, { ids: PAIR_VIEWS(), fetch: () => r }); await settle();
    assert.deepEqual(shown(p, ["ask", "ready", "done", "no", "skip", "dead", "nopk"]), ["ask"], want);
    assert.equal(p.$("awaymsg").lastElementChild.textContent, want); assert.equal(p.$("live").textContent, want);
    assert.equal(p.$("awaymsg").querySelector(".spin"), null); assert.equal(p.$("scanstep").hidden, true);
    assert.equal(p.$("qrwrap").hidden, true, "no empty QR tile left on screen");
  }
  const y = run(s, { ids: PAIR_VIEWS(), fetch: () => ({ ok: false, message: "No device has Face ID for Holdt yet. Set it up from your computer first." }) }); await settle();
  assert.deepEqual(shown(y, ["ask", "nopk", "dead"]), ["nopk"]);
});

test("pair page: an approval already used says so, a real expiry keeps the expired view", async () => {
  fresh(); const s = scriptOf(await (await call("/pair")).text());
  for (const [finish, h1] of [["This approval was already used. Start again on this device.", "This approval was already used"], ["This request expired. Start again on this device.", ""]] as const) {
    const p = run(s, { ids: PAIR_VIEWS(), create: SAVED, fetch: (path) => path === "/pair/new" ? NEW : path === "/pair/status" ? APPROVED : { ok: false, message: finish } });
    await settle(); await p.tick(); assert.equal(p.$("ready").hidden, false);
    await p.$("go").on.click!(); await settle();
    assert.equal(p.$("dead").hidden, false);
    assert.equal(p.$("dead").querySelector("h1")!.textContent, h1, "a real expiry keeps the page's own 'This request expired' title");
    if (h1) assert.equal(p.$("dead").querySelector(".lede")!.textContent, "Start again on this device.");
  }
});

test("pair page on a computer: a cancelled sheet leaves Save passkey, never 'Turn on Touch ID or password'", async () => {
  fresh(); const s = scriptOf(await (await call("/pair")).text());
  for (const [ua, idle, busy] of [[MAC, "Save passkey", "Saving passkey"], ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Save passkey", "Saving passkey"], [IPHONE, "Turn on Face ID", "Turning on"]] as const) {
    let sheet: () => Promise<any> = async () => { throw Object.assign(new Error("no"), { name: "NotAllowedError" }); };
    const p = run(s, { ua, ids: PAIR_VIEWS(), create: () => sheet(), fetch: (path) => path === "/pair/new" ? NEW : path === "/pair/status" ? APPROVED : new Promise(() => {}) });
    await settle(); await p.tick();
    await p.$("go").on.click!(); assert.equal(p.$("go").lastElementChild.textContent, idle, ua);
    sheet = SAVED;
    void p.$("go").on.click!(); await settle(); assert.equal(p.$("go").lastElementChild.textContent, busy, ua);
  }
});

test("pair page HTML: the wait is in #live on first paint, an info icon waits behind the spinner, and the nopk lede names no biometric", async () => {
  fresh(); const html = await (await call("/pair")).text();
  assert.match(html, /<p class="sr" id="live" role="status" aria-live="polite">One moment\.<\/p>/);
  const away = html.match(/<p class="status wait" id="awaymsg"[\s\S]*?<\/p>/)![0];
  assert.ok(away.includes(ICON.info) && away.includes(ICON.spinner), "fail() removes the spinner and leaves the info icon");
  assert.match(html, /\.status\.wait \.ico:not\(\.spin\)\{display:none\}/, "only the spinner shows while waiting");
  const lede = html.match(/<div id="nopk"[\s\S]*?class="lede[^"]*">([^<]*)</)![1]!;
  assert.equal(lede, "No device can approve Holdt connections yet. Set one up first with Setup help below.");
  assert.doesNotMatch(lede, /Face/, "BIO_WALK has nothing to rewrite into 'Touch ID or password'");
});

test("pair page: a failed save on a computer says Couldn’t save the passkey, a phone keeps the server's Face ID sentence", async () => {
  fresh(); const s = scriptOf(await (await call("/pair")).text());
  for (const [ua, want] of [[MAC, "Couldn’t save the passkey. Reload this page and try again."], ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Couldn’t save the passkey. Reload this page and try again."], [IPHONE, "Face ID wasn’t saved. Reload this page and try again."]] as const) {
    const p = run(s, { ua, ids: PAIR_VIEWS(), create: SAVED, fetch: (path) => path === "/pair/new" ? NEW : path === "/pair/status" ? APPROVED : { ok: false, message: "Face ID wasn't saved. Reload this page and try again." } });
    await settle(); await p.tick(); await p.$("go").on.click!(); await settle();
    assert.equal(p.$("msg").lastElementChild.textContent, want, ua); assert.equal(p.$("live2").textContent, want, ua);
    assert.deepEqual(shown(p, ["ask", "ready", "done", "no", "skip", "dead", "nopk"]), ["ready"]);
  }
});

test("pair page: Not now during One moment. wins over a late /pair/new, so no poll starts and Device not added stays", async () => {
  fresh(); const s = scriptOf(await (await call("/pair")).text()); let late!: (v: any) => void, polls = 0;
  const p = run(s, { ids: PAIR_VIEWS(), fetch: (path) => path === "/pair/new" ? new Promise((r) => { late = r; }) : (polls++, { ok: true, status: "gone" }) });
  await settle(); p.$("later").on.click!(); late(NEW); await settle(); await p.tick();
  assert.equal(polls, 0, "no 2 s poll after Not now");
  assert.deepEqual(shown(p, ["ask", "ready", "done", "no", "skip", "dead", "nopk"]), ["skip"]);
  assert.equal(p.$("qrwrap").innerHTML, "", "the late QR code isn't drawn");
});

test("pair and enroll pages: a failed save names the biometric the button showed on a Home-button iPhone and an iPad", async () => {
  fresh(); const pair = scriptOf(await (await call("/pair")).text()), enroll = scriptOf(await (await call("/enroll")).text());
  const IPAD = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15";
  const BAD = { ok: false, message: "Face ID wasn't saved. Reload this page and try again." }, OPTS = { ok: true, challenge_token: "t", publicKey: APPROVED.publicKey };
  for (const [ua, screen, bio] of [[IPHONE, { width: 375, height: 667 }, "Touch ID"], [IPAD, { width: 1024, height: 1366 }, "Touch ID or Face ID"], [IPHONE, { width: 393, height: 852 }, "Face ID"]] as const) {
    const want = `${bio} wasn’t saved. Reload this page and try again.`;
    const p = run(pair, { ua, screen, touch: true, ids: PAIR_VIEWS(), create: SAVED, fetch: (path) => path === "/pair/new" ? NEW : path === "/pair/status" ? APPROVED : BAD });
    await settle(); await p.tick(); await p.$("go").on.click!(); await settle();
    assert.equal(p.$("go").lastElementChild.textContent, `Turn on ${bio}`, ua); assert.equal(p.$("msg").lastElementChild.textContent, want, ua); assert.equal(p.$("live2").textContent, want, ua);
    const e = run(enroll, { ua, screen, touch: true, hash: "#tok", ids: views(["setup", "done", "skip", "dead"]), create: SAVED, fetch: (path) => path === "/enroll/options" ? OPTS : BAD });
    await settle(); await e.$("go").on.click!(); await settle();
    assert.equal(e.$("msg").lastElementChild.textContent, want, ua);
  }
});

test("enroll page: each device hears its own words, a phone is told to tap and a computer to click", async () => {
  fresh(); const s = scriptOf(await (await call("/enroll")).text());
  const WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36", AND = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36";
  const OPTS = { ok: true, challenge_token: "t", publicKey: { challenge: "AA", user: { id: "AA" }, excludeCredentials: [] } };
  const page = (ua: string, finish: any, create: () => Promise<any>, touch = false) => run(s, { ua, touch, hash: "#tok", ids: views(["setup", "done", "skip", "dead"]), create, fetch: (path) => path === "/enroll/options" ? OPTS : finish });
  const NO = async () => { throw Object.assign(new Error("no"), { name: "NotAllowedError" }); }, DUP = async () => { throw Object.assign(new Error("dup"), { name: "InvalidStateError" }); };
  for (const [ua, touch, lede] of [[WIN, false, "Next time, click Allow on this device."], [AND, true, "Next time, tap Allow on this device."]] as const) {
    const ok = page(ua, { ok: true, count: 1 }, SAVED, touch); await settle(); await ok.$("go").on.click!(); await settle();
    assert.equal(ok.$("done").querySelector("h1")!.textContent, "Passkey saved", ua); assert.equal(ok.$("done").querySelector(".lede")!.textContent, lede, ua);
    const no = page(ua, {}, NO, touch); await settle(); await no.$("go").on.click!(); await settle();
    assert.equal(no.$("msg").lastElementChild.textContent, "Couldn’t save the passkey.\nTry again when you’re ready.", ua); assert.equal(no.$("go").lastElementChild.textContent, "Save passkey", ua);
    const bad = page(ua, { ok: false, message: "Face ID wasn't saved. Reload this page and try again." }, SAVED, touch); await settle(); await bad.$("go").on.click!(); await settle();
    assert.equal(bad.$("msg").lastElementChild.textContent, "Couldn’t save the passkey. Reload this page and try again.", ua);
    const dup = page(ua, {}, DUP, touch); await settle(); await dup.$("go").on.click!(); await settle();
    assert.equal(dup.$("msg").lastElementChild.textContent, "This device already has a passkey for Holdt.", ua);
  }
  const mac = page(MAC, {}, NO); await settle(); await mac.$("go").on.click!(); await settle();
  assert.equal(mac.$("go").lastElementChild.textContent, "Save passkey", "a cancelled sheet on a Mac never reads Turn on Touch ID or password");
  assert.equal(mac.$("msg").lastElementChild.textContent, "Touch ID or password didn’t finish.\nTry again when you’re ready.");
  const macOk = page(MAC, { ok: true, count: 1 }, SAVED); await settle(); await macOk.$("go").on.click!(); await settle();
  assert.match(macOk.$("done").querySelector(".lede")!.textContent, /^Next time, click Allow on this Mac\./);
  const phone = page(IPHONE, { ok: false, message: "This device already uses Face ID with Holdt." }, SAVED, true); await settle(); await phone.$("go").on.click!(); await settle();
  assert.equal(phone.$("msg").lastElementChild.textContent, "This device already uses Face ID with Holdt.", "an iPhone keeps Face ID");
});

test("device cap messages name passkeys, never Face ID, because the server can't know the device", async () => {
  const src = (await import("node:fs")).readFileSync(new URL("../src/passkey.ts", import.meta.url), "utf8") + (await import("node:fs")).readFileSync(new URL("../src/away.ts", import.meta.url), "utf8");
  for (const m of src.match(/Holdt already has \$\{MAX_PASSKEYS\}[^`]*/g)!) { assert.match(m, /passkeys, the most it allows/); assert.doesNotMatch(m, /Face|Touch/); }
});

test("reviewer page: Turning on is spoken, and an ended claim with no message says the server needs a look and keeps the code", async () => {
  fresh({ REVIEWER_MODE: "on" }); const s = scriptOf(await (await call("/review")).text());
  const wait = run(s, { hash: "#RVW-CODE", ids: views(["ask", "done", "dead"]), fetch: () => new Promise(() => {}) });
  void wait.$("go").on.click!(); assert.equal(wait.$("go").lastElementChild.textContent, "Turning on"); assert.equal(wait.$("live").textContent, "Turning on reviewer access.");
  const p = run(s, { hash: "#RVW-CODE", ids: views(["ask", "done", "dead"]), fetch: () => ({ ok: false, ended: true }) });
  await p.$("go").on.click!(); assert.equal(p.$("dead").hidden, false);
  assert.equal(p.$("dead").querySelector("h1")!.textContent, "Couldn’t turn on reviewer access");
  assert.equal(p.$("dead").querySelector(".lede")!.textContent, "Ask the developer to check this demo server."); assert.equal(p.$("dead").querySelector(".lede")!.hidden, false);
  assert.equal(p.store.get("holdt-review"), "RVW-CODE", "the link didn’t end, so a reload can try again");
});

test("reviewer page: no code says the link isn't complete, a server sentence shows as is, only an ended code says ended", async () => {
  fresh({ REVIEWER_MODE: "on" }); const s = scriptOf(await (await call("/review")).text());
  const none = run(s, { ids: views(["ask", "done", "dead"]), fetch: () => ({}) });
  assert.equal(none.$("dead").hidden, false);
  assert.equal(none.$("dead").querySelector("h1")!.textContent, "This reviewer link isn’t complete");
  assert.equal(none.$("dead").querySelector(".lede")!.textContent, "Open it again from the testing instructions.");
  const off = run(s, { hash: "#RVW-CODE", ids: views(["ask", "done", "dead"]), fetch: () => ({ ok: false, ended: true, message: "Reviewer links don’t work on this server." }) });
  assert.equal(off.$("dead").hidden, true); await off.$("go").on.click!();
  assert.equal(off.$("dead").hidden, false); assert.equal(off.$("dead").querySelector("h1")!.textContent, "Reviewer links don’t work on this server");
  assert.equal(off.$("dead").querySelector(".lede")!.hidden, true);
  const ended = run(s, { hash: "#RVW-CODE", ids: views(["ask", "done", "dead"]), fetch: () => ({ ok: false, ended: true, message: "This reviewer link has ended. Ask the developer for a new one." }) });
  await ended.$("go").on.click!(); assert.equal(ended.$("dead").hidden, false);
  assert.equal(ended.$("dead").querySelector("h1")!.textContent, "", "the page's own 'This reviewer link has ended' title stays");
  const html = await (await call("/review")).text(); assert.match(html, /This reviewer link has ended/);
});

test("reviewer page: a reload after success claims again and shows the done view, never 'isn’t complete'", async () => {
  fresh({ REVIEWER_MODE: "on" }); const s = scriptOf(await (await call("/review")).text());
  const store = new Map<string, string>(), claims: string[] = [], OK = { ok: true, until: Date.UTC(2026, 9, 31) };
  const first = run(s, { hash: "#RVW-CODE", store, ids: views(["ask", "done", "dead"]), fetch: (_p, b) => (claims.push(b.code), OK) });
  await first.$("go").on.click!(); assert.equal(first.$("done").hidden, false);
  const again = run(s, { store, ids: views(["ask", "done", "dead"]), fetch: (_p, b) => (claims.push(b.code), OK) }); await settle();
  assert.notEqual(again.$("dead").querySelector("h1")!.textContent, "This reviewer link isn’t complete");
  assert.deepEqual(shown(again, ["ask", "done", "dead"]), ["done"]); assert.deepEqual(claims, ["RVW-CODE", "RVW-CODE"]);
  const ended = run(s, { store, ids: views(["ask", "done", "dead"]), fetch: () => ({ ok: false, ended: true, message: "This reviewer link has ended. Ask the developer for a new one." }) }); await settle();
  assert.deepEqual(shown(ended, ["ask", "done", "dead"]), ["dead"]); assert.equal(store.size, 0, "an ended code is forgotten");
  const opened = run(s, { hash: "#RVW-CODE", ids: views(["ask", "done", "dead"]), fetch: () => { throw new Error("no claim before the tap"); } }); await settle();
  assert.deepEqual(shown(opened, ["ask", "done", "dead"]), ["ask"], "a first visit still waits for the tap");
});

test("reviewer error messages use typographic apostrophes", async () => {
  fresh({ REVIEWER_MODE: "off" }); assert.equal((await checkReviewerCode(env, "x") as any).message, "Reviewer links don’t work on this server.");
  const src = (await import("node:fs")).readFileSync(new URL("../src/reviewer.ts", import.meta.url), "utf8");
  assert.match(src, /That reviewer link isn’t complete\./); assert.match(src, /That reviewer link doesn’t match\./);
  for (const m of src.match(/message: [^\n]*/g)!) assert.doesNotMatch(m, /"[^"\n]*\w'\w[^"\n]*"/, m);
});
