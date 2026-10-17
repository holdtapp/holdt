# Holdt security

Report a problem privately to the repository owner through GitHub (Security > Report a vulnerability). Please don't open a public issue. Supported version: the latest commit on the default branch.

## What Holdt promises, and what enforces it
Ordered by how much you can trust each layer: invariants in code first, then CI checks, then prose.

| Promise | Enforced by |
|---|---|
| Never deletes your events. It can only take back its own, on your yes. | No delete tool exists. The one removal path is `commit_undo` for an event with the UID Holdt gave it, added in the last 24 hours, unchanged since (If-Match). Attack rows C5, E1 to E5. |
| Never sends invitations. | No invite tool. Edits to events with any ORGANIZER or ATTENDEE (in any component) are refused. `assertSafeIcs()` refuses any ICS that adds an ATTENDEE or ORGANIZER line or carries a control character, as the last step before every write. Rows C1, R1, R2, R4, R7. |
| Every write is the exact change you saw. | HMAC confirm tokens bound to action, payload hash, expiry, GRANT_EPOCH and a single-use nonce held in a Durable Object. Previews show full values. Rows B1 to B6, R5, R6, R8, G1. |
| Nothing typed reaches iCloud unchecked. | Every tool schema is strict (bounded strings, ranged integers, closed objects), checked at module load and in CI (`strictSchemaProblems`). The validator checks the whole argument tree. `propLine` refuses CR/LF/controls. `test/fuzz.test.ts` sends CR, LF, NUL, U+2028, U+0085, bidi and smuggled iCalendar lines into every field of every tool and checks every byte sent to iCloud. |
| Only you can connect it. | A single-use 8-digit code (salted PBKDF2 hash, 15 minutes, 5 tries, decided atomically in a Durable Object), redirect URIs pinned with REDIRECT_ALLOWLIST, per-IP rate limits. Rows A1 to A9, G2. |

`npm run prove` switches each protection off in a scratch copy and shows its attack getting through, then back on. The table is in docs/attack-proof.md.

## Red-team items (REDTEAM-REPORT.md) and their status
| Item | Status |
|---|---|
| R1 to R16, N1 | Fixed (red-team patch, rebased), each with a test and a prove row. |
| T1 human gate | Open by design. The server can't see the conversation. Damage is capped as above, writes can be switched off, and every change can be taken back. MCP elicitation on commit is the next step where clients support it. |
| T2 cross-isolate races | Fixed. Durable Object `Guard` (one per owner) holds spent tokens, code tries and the used-code marker. KV plus in-isolate locks remain only as a fallback if the binding is missing. |
| T3 Version URLs | `preview_urls = false` in wrangler.toml. It applies on the next deploy. Older version URLs should also be checked in the dashboard. |
| T4 rate limits | Workers Rate Limiting: DCR 10/min per IP, approval submits 10/min per IP, /mcp 120/min per connection. Residual: someone can still burn the 5 code tries during a 15-minute window from 5 IPs. The fix is `npm run setup -- --new-code`. |
| T5 redirect allowlist | REDIRECT_ALLOWLIST holds the two callbacks the live Grok Bot client registered (read from KV client records on Oct 17, 2026). |
| T6 supply chain | wrangler pinned exactly (3.114.17) and run from node_modules. CI actions pinned by SHA. `npm audit signatures` in CI. Dependabot. |
| T7 config drift | The real wrangler.toml is committed (the KV id isn't secret). skip-worktree removed. |
| T8 crypto hygiene | Salted PBKDF2 code hash. Per-purpose derived keys. Zero-downtime rotation through CONFIRM_SECRET_PREVIOUS (docs/key-rotation.md). |
| T9 refresh tokens | 90-day sliding expiry (`refreshTokenIdleTTL`). The OAuth library keeps the previous refresh token valid until the new one is used, and has no reuse detection that revokes a grant. We accept this: refresh tokens are stored hashed, only reach Grok Bot's servers, and `npm run setup -- --revoke-all` cuts every grant at once. |
| T10 response size | Open. iCloud is a trusted, pinned host. |
| T11 to T13 | T11 fixed. T12 is a label, never claimed as a protection. T13 open (shared calendars sync edits to members). |

## Origin check rollout (MCP spec: servers MUST validate Origin)
The check refuses browser calls from other sites. Grok Bot calls from its servers, which normally send no Origin header, and those always pass. Before enforcing in production:
1. Deploy with `ORIGIN_CHECK = "report"` (the committed default). Nothing is refused. Every /mcp call that carries an Origin logs `origin seen: same-origin | allowed <origin> | foreign <origin>`.
2. Run `npm run tail` and use the connector from every surface you use (web, desktop, phone) for a few calls each.
3. If no `foreign` lines appear, set `ORIGIN_CHECK = "enforce"` and deploy. If a Grok Bot origin does appear, add it to `ALLOWED_ORIGINS` first.
4. Rollback is one line: set it back to `"report"` and deploy.
