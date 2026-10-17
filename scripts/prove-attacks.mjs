#!/usr/bin/env node
// Proof that each protection is load-bearing. For every row: copy the repo to a scratch dir, switch the
// protection off with an exact text patch, run the matching ATTACK tests, and expect them to FAIL
// (the attack now succeeds). "Layered" rows switch off one layer and expect the attack to still be refused.
// The real source is never modified. Writes docs/attack-proof.md.  Usage: npm run prove
import { cpSync, mkdtempSync, readFileSync, writeFileSync, symlinkSync, rmSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const M = (file, find, replace) => ({ file, find, replace });
const ROWS = [
  { id: "A1", attack: "Replay a used approval code", protection: "Single-use code marker (approval-used KV key)", patches: [M("src/authorize.ts", "if (await env.OAUTH_KV.get(`approval-used:${hash}`)) return", "if (false) return")], breaks: ["A1"] },
  { id: "A2", attack: "Brute-force the 8-digit code", protection: "Lockout after 5 wrong tries", patches: [M("src/authorize.ts", "if (fails >= MAX_TRIES) return", "if (false) return")], breaks: ["A2"] },
  { id: "A4/A5", attack: "Open-redirect variants and a custom-scheme (app hijack) redirect", protection: "redirectAllowed() scheme and userinfo allowlist", patches: [M("src/authorize.ts", "export function redirectAllowed(uri: string) {", "export function redirectAllowed(uri: string) { return true;")], breaks: ["A4", "A5"] },
  { id: "A6", attack: "Keep using a grant after the owner ran --revoke-all", protection: "GRANT_EPOCH check on every /mcp call", patches: [M("src/worker.ts", "if (!props || props.epoch !== env.GRANT_EPOCH) {", "if (!props) {")], breaks: ["A6"] },
  { id: "A7a", attack: "300 KB request body", protection: "256 KB body cap", patches: [M("src/worker.ts", "if (len > 256_000)", "if (false)")], breaks: ["A7"] },
  { id: "A7b", attack: "50-call batch fan-out to iCloud", protection: "20-message batch cap", patches: [M("src/worker.ts", "if (msgs.length > 20)", "if (false)")], breaks: ["A7"] },
  { id: "B1/B2", attack: "Commit without prepare (forged token), or tamper a real token", protection: "HMAC signature on confirm_token", patches: [M("src/confirm.ts", "if (!valid) return", "if (false) return")], breaks: ["B1", "B2"] },
  { id: "B3", attack: "Use an expired token", protection: "10-minute token expiry", patches: [M("src/confirm.ts", "if (t.e < now) return", "if (false) return")], breaks: ["B3"] },
  { id: "B4 layer 1", attack: "Commit the same update twice", protection: "Nonce store only (ETag still on)", layered: true, patches: [M("src/confirm.ts", "if (await used.has(t.n)) return", "if (false) return")], holds: ["B4", "B5"] },
  { id: "B4 layers 1+2", attack: "Commit the same update twice", protection: "Nonce store AND ETag precondition", patches: [M("src/confirm.ts", "if (await used.has(t.n)) return", "if (false) return"), M("src/tools.ts", "if (etag && r.etag && r.etag !== etag) throw new UserError(\"This event changed", "if (false) throw new UserError(\"This event changed")], breaks: ["B4"] },
  { id: "B6", attack: "Spend a create token on commit_update_event", protection: "Action binding inside the token", patches: [M("src/confirm.ts", "if (t.a !== action) return", "if (false) return")], breaks: ["B6"], note: "With the binding off the commit still crashes before any write (0 PUTs), so the clean refusal is the binding." },
  { id: "C1", attack: "Injected invite text gets the model to change the invite", protection: "Refuse edits to events with ATTENDEE or ORGANIZER", patches: [M("src/tools.ts", "if (ev.props.some((p) => p.name === \"ATTENDEE\" || p.name === \"ORGANIZER\")) throw", "if (false) throw")], breaks: ["C1"] },
  { id: "C2", attack: "Injected text reaches the model unmarked", protection: "text_warning flag + event_text_is_data note", patches: [M("src/tools.ts", "export const looksLikeInstructions = (...texts: (string | undefined)[]) =>", "export const looksLikeInstructions = (...texts: (string | undefined)[]) => false &&")], breaks: ["C2"] },
  { id: "C3", attack: "Hostile title forges extra lines in the approval preview", protection: "oneLine() on every preview field", patches: [M("src/tools.ts", "export const oneLine = (s: string, n = 120) => {", "export const oneLine = (s: string, n = 120) => { return String(s);")], breaks: ["C3"] },
  { id: "C4", attack: "Injected model writes on a read-only connection", protection: "WRITES_ENABLED gate", patches: [M("src/tools.ts", "  private requireWrites() {", "  private requireWrites() { return;")], breaks: ["C4"] },
  { id: "D1", attack: "Crafted event_id reads a calendar outside the allowlist", protection: "event_id path must sit inside its calendar", patches: [M("src/tools.ts", "try { ok = new URL(href).pathname.startsWith(new URL(c.href).pathname); }", "try { ok = true; }")], breaks: ["D1"] },
  { id: "D2 layer 1", attack: "Crafted event_id sends the iCloud password to another server", protection: "Path check only (origin pinning still on)", layered: true, patches: [M("src/tools.ts", "try { ok = new URL(href).pathname.startsWith(new URL(c.href).pathname); }", "try { ok = true; }")], holds: ["D2"] },
  { id: "D2 layers 1+2+3", attack: "Crafted event_id sends the iCloud password to another server", protection: "Path check AND origin pinning AND trusted-host check", patches: [M("src/tools.ts", "try { ok = new URL(href).pathname.startsWith(new URL(c.href).pathname); }", "try { ok = true; }"), M("src/caldav.ts", "private assertSameOrigin(href: string) {", "private assertSameOrigin(href: string) { return;"), M("src/caldav.ts", "private assertTrustedHost(url: string) {", "private assertTrustedHost(url: string) { return;")], breaks: ["D2"] },
  { id: "E1", attack: "Forge a revert token to undo a change", protection: "HMAC signature on revert_token", patches: [M("src/confirm.ts", "if (!valid) return", "if (false) return")], breaks: ["E1"] },
  { id: "E2 layer 1", attack: "Replay a used undo to write twice", protection: "Nonce store only (undone flag and ETag still on)", layered: true, patches: [M("src/confirm.ts", "if (await used.has(t.n)) return", "if (false) return")], holds: ["E2"] },
  { id: "E2 layers 1+2+3", attack: "Replay a used undo to write twice", protection: "Nonce store AND undone flag AND ETag precondition", patches: [M("src/confirm.ts", "if (await used.has(t.n)) return", "if (false) return"), M("src/tools.ts", "if (ch.undone) throw new UserError(\"That change was already taken back. Nothing was done twice.\")", "if (false) throw new UserError(\"\")"), M("src/tools.ts", "if (r.etag !== v.payload.etag) throw", "if (false) throw")], breaks: ["E2"] },
  { id: "E3", attack: "Use a revert token after the 7-day window", protection: "Token expiry", patches: [M("src/confirm.ts", "if (t.e < now) return", "if (false) return")], breaks: ["E3"] },
  { id: "E4 layer 1", attack: "Another account spends this account's revert token", protection: "Owner check on the token only (log is still per-owner)", layered: true, patches: [M("src/tools.ts", "private assertOwner(tokenOwner: string, me: string) {", "private assertOwner(tokenOwner: string, me: string) { return;")], holds: ["E4"] },
  { id: "E4 layers 1+2", attack: "Another account spends this account's revert token", protection: "Owner check on the token AND per-owner change log", patches: [M("src/tools.ts", "private assertOwner(tokenOwner: string, me: string) {", "private assertOwner(tokenOwner: string, me: string) { return;"), M("src/journal.ts", "if (owner !== this.owner || ", "if (")], breaks: ["E4"] },
  { id: "E5", attack: "Aim undo at an event Holdt didn't add (corrupted or forged log entry)", protection: "Own-create check: Holdt's UID record from the last 24 hours", patches: [M("src/tools.ts", "if (uid !== ch.uid || !(await j.isOwnRecentCreate(ch.uid, this.now()))) throw", "if (false) throw")], breaks: ["E5"] },
];
const NOT_TOGGLED = [
  ["A3", "Replay an OAuth authorization code", "@cloudflare/workers-oauth-provider (single-use codes). Third-party code, not patched here. Attack refused."],
  ["A4 swap", "Swap redirect_uri to an unregistered URL", "Library exact-match on registered redirect URIs. Attack refused for 5 variants."],
  ["A6 none", "Call /mcp with no token or a made-up token", "Library bearer validation. 401 every time."],
  ["C5", "Call a delete or invite tool", "Architecture: no such tool exists, so there is nothing to switch off. The only removal path is commit_undo for an event Holdt added in the last 24 hours (rows E1 to E5)."],
];

function run(dir, pattern) {
  const r = spawnSync(process.execPath, ["--import", "./test/register.mjs", "--import", "tsx", "--test", `--test-name-pattern=${pattern}`, "test/attacks.test.ts"], { cwd: dir, encoding: "utf8" });
  const res = {}; for (const m of (r.stdout ?? "").matchAll(/^(not ok|ok) \d+ - ATTACK (\w+):/gm)) res[m[2]] = m[1] === "ok";
  return res;
}
function scratch() {
  const d = mkdtempSync(join(tmpdir(), "holdt-prove-"));
  for (const x of ["src", "test", "package.json", "tsconfig.json"]) cpSync(join(root, x), join(d, x), { recursive: true });
  symlinkSync(join(root, "node_modules"), join(d, "node_modules"));
  return d;
}
const out = []; let allOk = true;
const base = run(root, "ATTACK"); const baseOk = Object.keys(base).length > 0 && Object.values(base).every(Boolean);
if (!baseOk) { console.error("Baseline: some attacks are NOT refused with every protection on:", base); process.exit(1); }
console.log(`baseline: ${Object.keys(base).length} attacks, all refused`);
for (const row of ROWS) {
  const d = scratch();
  try {
    for (const p of row.patches) { const f = join(d, p.file); const s = readFileSync(f, "utf8"); if (!s.includes(p.find)) throw new Error(`${row.id}: patch target not found in ${p.file}: ${p.find}`); writeFileSync(f, s.replace(p.find, p.replace)); }
    const ids = [...(row.breaks ?? []), ...(row.holds ?? [])];
    const r = run(d, `ATTACK (${ids.join("|")}):`);
    const broke = (row.breaks ?? []).every((id) => r[id] === false), held = (row.holds ?? []).every((id) => r[id] === true);
    const proven = broke && held; allOk &&= proven;
    out.push({ ...row, proven, offResult: row.layered ? (held ? "still refused (next layer caught it)" : "SUCCEEDED") : broke ? "SUCCEEDED" : "still refused" });
    console.log(`${proven ? "PROVEN" : "NOT PROVEN"}  ${row.id}  ${row.protection}`);
  } finally { rmSync(d, { recursive: true, force: true }); }
}
const after = run(root, "ATTACK"); const afterOk = Object.values(after).every(Boolean);
const commit = (() => { try { return execFileSync("git", ["rev-parse", "--short", "HEAD"], { cwd: root, encoding: "utf8" }).trim(); } catch { return "unknown"; } })();
const when = new Date().toLocaleString("en-US", { timeZone: "America/Denver", dateStyle: "medium", timeStyle: "short" }) + " MT";
const md = [`# Holdt attack proof`, ``, `Generated by \`npm run prove\` (scripts/prove-attacks.mjs) at ${when}, on commit ${commit}${execFileSync("git", ["status", "--porcelain", "src"], { cwd: root, encoding: "utf8" }).trim() ? " plus uncommitted changes" : ""}.`,
  `Attacks live in test/attacks.test.ts and run against the same Worker code \`wrangler dev\` serves, with a mock iCloud and an attacker-controlled server on localhost.`, ``,
  `Method: every protection is switched off in a scratch copy (the real source is never edited), the matching attack is run, and it must now succeed. "Layered" rows switch off one layer and show the next one still stops the attack. Then every protection is back on and every attack is refused again.`, ``,
  `Baseline, all protections on: ${Object.keys(base).length} attacks, ${Object.values(base).filter(Boolean).length} refused.`, ``,
  `| Row | Attack | Protection switched off | Result with it off | Proven |`, `|---|---|---|---|---|`,
  ...out.map((r) => `| ${r.id} | ${r.attack} | ${r.protection} | ${r.offResult} | ${r.proven ? "yes" : "**no**"} |`), ``,
  `Re-enabled: ${Object.keys(after).length} attacks, ${Object.values(after).filter(Boolean).length} refused.`, ``,
  ...out.filter((r) => r.note).map((r) => `Note on ${r.id}: ${r.note}`), ``,
  `## Refused by structure or by the OAuth library (not switched off here)`, `| Row | Attack | Why it fails |`, `|---|---|---|`, ...NOT_TOGGLED.map((r) => `| ${r[0]} | ${r[1]} | ${r[2]} |`), ``,
  `## What the server cannot prove`, `The server can't see the conversation, so it can't prove the user said yes. A model that follows injected text could still prepare and commit a new event on a writable calendar. The design caps that damage: no delete or invite tools exist, events from other people can't be edited, every write is one exact previewed change, nothing leaves iCloud through Holdt, and read-only is one setting away. Event text is labelled as untrusted data in every result and in the server instructions.`, ``];
writeFileSync(join(root, "docs", "attack-proof.md"), md.join("\n"));
console.log(`\nre-enabled: ${afterOk ? "all attacks refused again" : "SOME ATTACK NOT REFUSED"}\nwrote docs/attack-proof.md`);
process.exit(allOk && afterOk ? 0 : 1);
