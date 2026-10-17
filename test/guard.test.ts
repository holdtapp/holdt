import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { MockGuardNS } from "./guard-mock.js";
import { guardUsedStore } from "../src/worker.js";
import { checkCode, sha256Hex } from "../src/authorize.js";
import { MockKV } from "./kv-mock.js";
import { makeMock, seed, makeTools } from "./helpers.js";

const mock = makeMock(); before(() => mock.start()); after(() => mock.stop()); beforeEach(() => seed(mock));

test("ATTACK G1: spend one token 10 times at once against the Durable Object", async () => {
  const ns = new MockGuardNS(); const g = ns.get("owner");
  const r = await Promise.all(Array.from({ length: 10 }, () => g.spend("n1", Date.now() + 60_000)));
  assert.equal(r.filter(Boolean).length, 1);
  assert.equal(await g.spend("n1", Date.now() + 60_000), false);
  assert.equal(await g.spend("n2", Date.now() + 60_000), true);
});

test("ATTACK G2: 31 simultaneous approval-code guesses, then the right code, against the Durable Object", async () => {
  const g = new MockGuardNS().get("owner");
  const wrong = await Promise.all(Array.from({ length: 31 }, () => g.codeTry("h", false, 5)));
  assert.equal(wrong.filter((v) => !v.ok && v.reason === "wrong").length, 5);
  assert.deepEqual(await g.codeTry("h", true, 5), { ok: false, reason: "locked", left: 0 });
});

test("the Durable Object makes one approval code connect exactly once", async () => {
  const g = new MockGuardNS().get("owner");
  const r = await Promise.all(Array.from({ length: 5 }, () => g.codeTry("h2", true, 5)));
  assert.equal(r.filter((v) => v.ok).length, 1); assert.ok(r.filter((v) => !v.ok).every((v: any) => v.reason === "used"));
});

test("checkCode goes through the Durable Object when GUARD is bound", async () => {
  const ns = new MockGuardNS(); const CODE = "55512345";
  const env: any = { GUARD: ns, OAUTH_KV: new MockKV(), APPROVAL_CODE_HASH: await sha256Hex(`icloud-mcp-approval:${CODE}`), APPROVAL_CODE_ISSUED: String(Date.now()) };
  const w: any = await checkCode(env, "00000000"); assert.equal(w.reason, "wrong"); assert.match(w.message, /4 tries left/);
  assert.equal((await checkCode(env, CODE)).ok, true);
  assert.equal(((await checkCode(env, CODE)) as any).reason, "used");
  assert.equal(((await checkCode({ ...env, APPROVAL_CODE_ISSUED: String(Date.now() - 16 * 60_000) }, CODE)) as any).reason, "expired");
});

test("confirm tokens are single use through the Durable Object, across separate Tools instances", async () => {
  const store = guardUsedStore({ GUARD: new MockGuardNS() })!;
  const p: any = await makeTools(mock, { usedStore: store }).call("prepare_create_event", { calendar_id: "home", title: "Once", start: "2026-11-03T12:00" });
  const r = await Promise.allSettled([1, 2, 3].map(() => makeTools(mock, { usedStore: store }).call("commit_create_event", { confirm_token: p.confirm_token })));
  assert.equal(r.filter((x) => x.status === "fulfilled" && (x.value as any).event_id).length, 1);
  assert.equal(mock.requests.filter((x) => x.method === "PUT").length, 1);
});
