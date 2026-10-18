// Mints the reviewer code for a demo Worker (src/reviewer.ts). Node side of the same hash the Worker checks.
import { randomBytes, pbkdf2Sync, createHash } from "node:crypto";
import { REVIEWER_ALPHABET, REVIEWER_CHARS, REVIEWER_PREFIX, REVIEWER_TTL_MS, reviewerSecretInput } from "../src/reviewer.js";
/** Same cost as the owner approval code (setup/server.ts CODE_ROUNDS), about 4 ms of Worker CPU per check. */
const CODE_ROUNDS = 20_000;

const tagOf = (email: string) => createHash("sha256").update(`holdt-reviewer/v1\n${String(email).trim().toLowerCase()}`).digest("hex");

/** 80 random bits as 16 Crockford base32 characters, shown as RVW-XXXX-XXXX-XXXX-XXXX. Only a salted, account-bound hash leaves this machine. */
export function newReviewerCode(accountEmail: string, now = Date.now()) {
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(accountEmail ?? "").trim())) throw new Error("Set HOLDT_REVIEWER_ACCOUNT to the demo Worker's iCloud address (it is never printed).");
  const bytes = randomBytes(10); let bits = 0n; for (const b of bytes) bits = (bits << 8n) | BigInt(b);
  let body = ""; for (let i = REVIEWER_CHARS - 1; i >= 0; i--) body += REVIEWER_ALPHABET[Number((bits >> BigInt(i * 5)) & 31n)];
  const code = REVIEWER_PREFIX + body;
  const salt = randomBytes(16).toString("base64url");
  const hash = `pbkdf2$${CODE_ROUNDS}$${salt}$${pbkdf2Sync(reviewerSecretInput(tagOf(accountEmail), code), Buffer.from(salt, "base64url"), CODE_ROUNDS, 32, "sha256").toString("hex")}`;
  const display = `${REVIEWER_PREFIX}-${body.match(/.{4}/g)!.join("-")}`;
  return { code, display, hash, issued: now, expiresAt: now + REVIEWER_TTL_MS };
}
