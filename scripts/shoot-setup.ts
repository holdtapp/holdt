// Dev-only: renders the setup screen states against the mock CalDAV server for UX review.
import { MockCalDav } from "../test/mock-caldav.js";
import { createSetupServer } from "../setup/server.js";
import { fileURLToPath } from "node:url";
// puppeteer-core isn't a dependency. Install it anywhere and point PUPPETEER_CORE at it, or install it in this folder.
const { default: puppeteer }: any = await import(process.env.PUPPETEER_CORE ?? "puppeteer-core");
const out = process.argv[2] ?? fileURLToPath(new URL("../docs/shots", import.meta.url));
const mock = new MockCalDav({ user: "you@icloud.com", pass: "abcd-efgh-ijkl-mnop" }); await mock.start();
const { server, key } = createSetupServer({ caldavUrl: mock.base, workerName: "w", workerUrl: "https://holdt.you.workers.dev", saveSecret: async () => {} });
await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r())); const port = (server.address() as any).port;
const browser = await puppeteer.launch({ executablePath: process.env.CHROME_PATH ?? "/usr/bin/google-chrome", args: ["--no-sandbox"], headless: true });
for (const [label, w, h, dark] of [["desktop", 1100, 900, false], ["mobile", 390, 1000, false], ["dark", 1100, 900, true]] as const) {
  const p = await browser.newPage(); await p.setViewport({ width: w, height: h, deviceScaleFactor: 1 });
  await p.emulateMediaFeatures([{ name: "prefers-color-scheme", value: dark ? "dark" : "light" }, { name: "prefers-reduced-motion", value: "reduce" }]);
  await p.goto(`http://127.0.0.1:${port}/?k=${key}`); await p.screenshot({ path: `${out}/${label}-1-empty.png` });
  if (label === "dark") { await p.close(); continue; }
  await p.type("#pw", "MyDog2024!"); await p.screenshot({ path: `${out}/${label}-2-main-password.png` });
  await p.$eval("#pw", (e: any) => (e.value = "")); await p.type("#pw", "abcdefghijklmnop"); await p.type("#email", "you@icloud.com");
  await p.screenshot({ path: `${out}/${label}-3-ready.png` });
  await p.click("#test"); await p.waitForSelector("#save"); await new Promise((r) => setTimeout(r, 600)); await p.screenshot({ path: `${out}/${label}-4-found.png` });
  await p.click("#save"); await p.waitForSelector("#copy"); await p.screenshot({ path: `${out}/${label}-5-done.png` });
  await p.close();
}
const p = await browser.newPage(); await p.setViewport({ width: 1100, height: 900 });
await p.goto(`http://127.0.0.1:${port}/?k=${key}`); await p.type("#pw", "zzzzzzzzzzzzzzzz"); await p.type("#email", "you@icloud.com"); await p.click("#test");
await new Promise((r) => setTimeout(r, 1500)); await p.screenshot({ path: `${out}/desktop-6-wrong.png` });
await browser.close(); server.close(); await mock.stop(); console.log("shots ok");
