// The add-this-device page (/pair) and the reviewer link page (/review), run in a tiny fake DOM: what each failure
// actually shows, what a screen reader hears, and what the button says on a computer.
import { test } from "node:test";
import assert from "node:assert/strict";
import { MockKV } from "./kv-mock.js";
import { providerFor } from "../src/worker.js";
import { checkReviewerCode } from "../src/reviewer.js";

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
function run(script: string, o: { ua?: string; fetch: (path: string, body: any) => any; hash?: string; ids?: Record<string, El>; create?: () => Promise<any> }) {
  const els: Record<string, El> = { ...o.ids }, doc: any = { title: "", body: new El(), documentElement: new El(), getElementById: (id: string) => (els[id] ??= new El()), querySelectorAll: () => [], createTreeWalker: () => ({ nextNode: () => null }) };
  const intervals: Function[] = [], store = new Map<string, string>();
  const fakeFetch = async (path: string, init: any) => { const r = await o.fetch(path, JSON.parse(init.body)); if (r === "net") throw new TypeError("offline"); return { json: async () => r }; };
  const names = ["document", "navigator", "screen", "fetch", "location", "history", "sessionStorage", "setInterval", "clearInterval", "setTimeout", "requestAnimationFrame", "getSelection"];
  const vals = [doc, { userAgent: o.ua ?? MAC, platform: "MacIntel", credentials: { create: () => o.create!() } }, { width: 1440, height: 900 }, fakeFetch, { hash: o.hash ?? "", pathname: "/x", search: "", origin: ORIGIN }, { replaceState() {} },
    { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => store.set(k, v), removeItem: (k: string) => store.delete(k) },
    (f: Function) => intervals.push(f), () => {}, () => 0, () => 0, () => null];
  new Function(...names, script)(...vals);
  return { $: (id: string) => doc.getElementById(id) as El, tick: async () => { for (const f of intervals) await f(); await settle(); } };
}
const settle = () => new Promise((r) => setTimeout(r, 5));
// The views start hidden except the first, as on the real page.
const views = (ids: string[]) => Object.fromEntries(ids.map((id, i) => [id, new El(i > 0)]));
const PAIR_VIEWS = () => ({ ...views(["ask", "ready", "done", "no", "skip", "dead", "nopk"]), scanstep: new El(true) });
const NEW = { ok: true, claim: "c", qr: "<svg></svg>" }, APPROVED = { ok: true, status: "approved", challenge_token: "t", publicKey: { challenge: "AA", user: { id: "AA" }, excludeCredentials: [] } };
const SAVED = async () => ({ response: { clientDataJSON: new ArrayBuffer(1), attestationObject: new ArrayBuffer(1) } });
const shown = (p:{ $: (id: string) => El }, ids: string[]) => ids.filter((id) => !p.$(id).hidden);

test("pair page HTML: no scan step or waiting line before the QR code, and Setup help matches the device", async () => {
  fresh();
  const mac = await (await call("/pair")).text();
  assert.match(mac, /<ol class="steps one" id="scanstep" data-nobio hidden>/, "the scan step waits for the QR code");
  assert.match(mac, /id="awaymsg" aria-hidden="true">[\s\S]*?<span class="st">One moment\.<\/span>/);
  assert.doesNotMatch(mac.replace(/<script[\s\S]*<\/script>/, ""), /Waiting for your iPhone/, "not before the QR code exists");
  const nopk = (h: string) => h.match(/<div id="nopk"[\s\S]*?<\/details>/)![0];
  assert.match(nopk(mac), /<code>npm run add-device<\/code>/); assert.doesNotMatch(nopk(mac), /--qr/);
  assert.match(nopk(await (await call("/pair", IPHONE)).text()), /<code>npm run add-device -- --qr<\/code>/);
});

test("pair page: the QR code brings the scan step and the waiting line, and a screen reader hears both", async () => {
  fresh(); const s = scriptOf(await (await call("/pair")).text());
  const p = run(s, { ids: PAIR_VIEWS(), fetch: (path) => path === "/pair/new" ? { ok: true, claim: "c", qr: "<svg class=\"qr\"></svg>" } : { ok: true, status: "pending" } });
  assert.equal(p.$("scanstep").hidden, true); await settle();
  assert.equal(p.$("scanstep").hidden, false); assert.match(p.$("qrwrap").innerHTML, /svg/);
  assert.equal(p.$("awaymsg").lastElementChild.textContent, "Waiting for your iPhone.");
  assert.equal(p.$("live").textContent, "QR code shown. Scan it with that iPhone’s camera. Waiting for your iPhone.");
});

test("pair page: a later poll that can't reach the server says so and stops the spinner", async () => {
  fresh(); const s = scriptOf(await (await call("/pair")).text()); let net = false;
  const p = run(s, { ids: PAIR_VIEWS(), fetch: (path) => path === "/pair/new" ? { ok: true, claim: "c", qr: "<svg></svg>" } : net ? "net" : { ok: true, status: "pending" } });
  await settle(); await p.tick(); assert.equal(p.$("awaymsg").lastElementChild.textContent, "Waiting for your iPhone.");
  net = true; await p.tick();
  const t = "Holdt couldn’t reach your server. Check your connection, then reload this page.";
  assert.equal(p.$("awaymsg").lastElementChild.textContent, t); assert.equal(p.$("live").textContent, t);
  assert.equal(p.$("awaymsg").classList.contains("wait"), false); assert.equal(p.$("awaymsg").querySelector(".spin"), null);
  assert.deepEqual(shown(p, ["ask", "ready", "done", "no", "skip", "dead", "nopk"]), ["ask"]);
});

test("pair page: a device cap or a rate limit shows the server's sentence, never 'This request expired'", async () => {
  fresh(); const s = scriptOf(await (await call("/pair")).text());
  for (const [r, want] of [
    [{ ok: false, message: "Holdt already has 10 Face ID devices, the most it allows." }, "Holdt already has 10 Face ID devices, the most it allows."],
    [{ error: "rate_limited", error_description: "Too many requests. Wait a minute and try again." }, "Too many requests. Wait a minute and try again."],
  ] as const) {
    const p = run(s, { ids: PAIR_VIEWS(), fetch: () => r }); await settle();
    assert.deepEqual(shown(p, ["ask", "ready", "done", "no", "skip", "dead", "nopk"]), ["ask"], want);
    assert.equal(p.$("awaymsg").lastElementChild.textContent, want); assert.equal(p.$("live").textContent, want);
    assert.equal(p.$("awaymsg").querySelector(".spin"), null); assert.equal(p.$("scanstep").hidden, true);
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

test("reviewer error messages use typographic apostrophes", async () => {
  fresh({ REVIEWER_MODE: "off" }); assert.equal((await checkReviewerCode(env, "x") as any).message, "Reviewer links don’t work on this server.");
  const src = (await import("node:fs")).readFileSync(new URL("../src/reviewer.ts", import.meta.url), "utf8");
  assert.match(src, /That reviewer link isn’t complete\./); assert.match(src, /That reviewer link doesn’t match\./);
  for (const m of src.match(/message: [^\n]*/g)!) assert.doesNotMatch(m, /"[^"\n]*\w'\w[^"\n]*"/, m);
});
