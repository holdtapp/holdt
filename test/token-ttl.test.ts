// G3 (launch gate): a connection used at least once every 90 days never needs reconnecting.
// The OAuth provider options are built inside worker.ts, so this pins the configured values in the source itself.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const src = readFileSync(new URL("../src/worker.ts", import.meta.url), "utf8");

test("refresh tokens last 90 days and slide on use (refreshTokenTTL and refreshTokenIdleTTL), access tokens 1 hour", () => {
  assert.match(src, /refreshTokenTTL:\s*90 \* 86400,/);
  assert.match(src, /refreshTokenIdleTTL:\s*90 \* 86400,/);
  assert.match(src, /accessTokenTTL:\s*3600,/);
});
