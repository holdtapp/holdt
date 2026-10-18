// A Mac may have no Touch ID sensor (a Mac mini or iMac without a Touch ID keyboard asks for the login password),
// so no page ever promises Touch ID on a Mac. It says "Allow on this Mac" and "Touch ID or password", which is what
// the system's own passkey sheet offers there. An iPhone with a Home button still says Touch ID, others Face ID.
import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { BIO_SWAP, LOGIN_SCRIPT, ENROLL_SCRIPT, CONSENT_SCRIPT, OK_SCRIPT, PAIR_SCRIPT } from "../src/passkey.js";

const MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";
const IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";

function swap(ua: string, touchDevice: boolean, h: number, texts: string[], title: string) {
  const nodes = texts.map((t) => ({ nodeValue: t, parentElement: { closest: () => null } }));
  const cls = new Set<string>();
  const el = {};
  const document: any = {
    title, documentElement: { classList: { add: (c: string) => cls.add(c) } },
    querySelectorAll: () => [el],
    createTreeWalker: () => { let i = 0; return { nextNode: () => nodes[i++] ?? null }; },
  };
  if (touchDevice) document.ontouchend = null;
  vm.runInNewContext(BIO_SWAP, { document, navigator: { userAgent: ua }, screen: { width: 390, height: h } });
  return { texts: nodes.map((n) => n.nodeValue), cls, title: document.title };
}

test("HONESTY: a Mac is never promised Touch ID, it gets Touch ID or password and the key glyph", () => {
  const r = swap(MAC, false, 900, ["Waiting for you to turn on Face\u00a0ID.", "Face ID is off"], "Holdt: Face ID is off");
  for (const t of [...r.texts, r.title]) {
    assert.doesNotMatch(t, /Face.ID/, t);
    assert.doesNotMatch(t.replace(/Touch.ID or password/g, ""), /Touch.ID/, `bare Touch ID promised on a Mac: ${t}`);
  }
  assert.ok(r.cls.has("mac") && !r.cls.has("touch"), "Mac shows the key glyph, not the fingerprint");
});

test("an iPhone with a Home button still says Touch ID, a Face ID iPhone keeps Face ID", () => {
  const se = swap(IPHONE, true, 667, ["Face ID is off"], "Holdt: Face ID is off");
  assert.equal(se.texts[0], "Touch ID is off"); assert.ok(se.cls.has("touch"));
  const x = swap(IPHONE, true, 852, ["Face ID is off"], "Holdt: Face ID is off");
  assert.equal(x.texts[0], "Face ID is off"); assert.ok(!x.cls.has("touch") && !x.cls.has("mac"));
});

test("HONESTY: no page script sets a Mac-only Touch ID promise", () => {
  for (const s of [LOGIN_SCRIPT, ENROLL_SCRIPT, CONSENT_SCRIPT, OK_SCRIPT, PAIR_SCRIPT]) {
    assert.doesNotMatch(s, /Allow with Touch ID|Turn on Touch ID|Touch ID is on|Use Touch ID|Touch ID not turned on|fingerprint stays on your Mac/);
  }
  assert.match(CONSENT_SCRIPT, /'Allow on '\+here/); assert.match(ENROLL_SCRIPT, /'Save a passkey on '\+here/); assert.match(CONSENT_SCRIPT, /here=touch\?'this Mac'/); assert.match(ENROLL_SCRIPT, /Touch ID or its password/);
});

test("HONESTY: biometric data never syncs, only the passkey does, and VoiceOver names the real button", async () => {
  const { readFileSync } = await import("node:fs");
  const src = readFileSync(new URL("../src/authorize.ts", import.meta.url), "utf8");
  assert.doesNotMatch(src, /(Face|Touch).ID syncs/); assert.match(src, /Your passkey syncs to your Apple devices with iCloud Keychain/); assert.match(src, /a device that already has your Holdt passkey\./, "Setup help names the passkey, so no device rewrite can garble it");
  for (const s of [LOGIN_SCRIPT, CONSENT_SCRIPT]) assert.doesNotMatch(s, /bio\+' shown'/);
});

test("HONESTY: Windows, Android and Linux browsers are never promised Touch ID or Face ID", () => {
  const WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";
  const AND = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36";
  for (const [ua, t] of [[WIN, false], [AND, true]] as const) {
    const r = swap(ua, t, 900, ["Waiting for you to turn on Face\u00a0ID.", "Face ID is off", "Your face stays on your device. Holdt never sees it."], "Holdt: Face ID is off");
    for (const x of [...r.texts, r.title]) assert.doesNotMatch(x, /Face.ID|Touch.ID|face stays/, x);
    assert.equal(r.texts[1], "Passkey is off"); assert.equal(r.texts[2], "Your passkey stays on your device. Holdt never sees it."); assert.ok(r.cls.has("key") && !r.cls.has("touch") && !r.cls.has("mac"));
  }
  const ipad = swap("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15", true, 1180, ["Face ID is off"], "x");
  assert.equal(ipad.texts[0], "Touch ID or Face ID is off", "an iPad has one of the two");
  for (const s of [ENROLL_SCRIPT, PAIR_SCRIPT, CONSENT_SCRIPT]) assert.match(s, /if\(gen\)/);
});

test("HONESTY (R45): computer-side Setup help never promises Face ID or Touch ID, it names a one-time setup link", async () => {
  const src = (await import("node:fs")).readFileSync(new URL("../src/authorize.ts", import.meta.url), "utf8");
  const line = /const ADD_DEVICE = "([^"]+)"/.exec(src)![1]!;
  assert.match(line, /one-time setup link/); assert.doesNotMatch(line, /Face|Touch/);
});

test("turning Face ID on or off reads as a passkey on a computer, and each iPhone and iPad keeps its own sensor", () => {
  const WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";
  const IPAD = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";
  const texts = ["Turn on Face ID first", "Didn’t add a device? Turn Face ID off everywhere, then set it up again.", "It doesn’t have Face ID for Holdt. Scan the code with the device where you turned it on.", "This device isn't set up for Face ID with Holdt."];
  for (const ua of [MAC, WIN]) {
    const r = swap(ua, false, 900, texts, "Holdt: Turn on Face ID");
    assert.deepEqual(r.texts, ["Save a passkey first", "Didn’t add a device? Turn passkeys off everywhere, then set it up again.", "It doesn’t have a passkey for Holdt. Scan the code with the device where you turned it on.", "This device isn't set up with Holdt."], ua);
    assert.equal(r.title, "Holdt: Save a passkey", ua);
  }
  assert.equal(swap(WIN, false, 900, ["x"], "Holdt: Face ID is off").title, "Holdt: Passkey is off");
  assert.equal(swap(MAC, false, 900, ["x"], "Holdt: Face ID is off").title, "Holdt: Touch ID or password is off");
  assert.equal(swap(IPHONE, true, 852, texts, "x").texts[0], "Turn on Face ID first");
  assert.equal(swap(IPHONE, true, 667, texts, "x").texts[0], "Turn on Touch ID first");
  // iPhone 6/7/8 Plus (414x736) have a Home button and Touch ID. No Face ID iPhone has a 736-pt screen.
  assert.equal(swap(IPHONE, true, 736, texts, "x").texts[0], "Turn on Touch ID first");
  assert.equal(swap(IPHONE, true, 812, texts, "x").texts[0], "Turn on Face ID first");
  assert.equal(swap(IPAD, true, 1180, texts, "x").texts[0], "Turn on Touch ID or Face ID first");
});

test("HONESTY (R45): a Mac or other computer waiting for its first passkey is told to save one, not to turn on a screen lock", () => {
  const WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";
  for (const ua of [MAC, WIN]) assert.equal(swap(ua, false, 900, ["Waiting for you to turn on Face\u00a0ID."], "x").texts[0], "Waiting for you to save a passkey.");
});
