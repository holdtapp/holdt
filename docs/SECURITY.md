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
| Only you can connect it. | With one-tap on: a passkey enrolled from a single-use link, checked for exact origin, RP ID, Face ID (user verification), signature and counter, against a 5-minute single-use challenge bound to that connect request. Rows P1 to P8. Always available: a single-use 8-digit code (salted PBKDF2 hash, 15 minutes, 5 tries, decided atomically in a Durable Object), redirect URIs pinned with REDIRECT_ALLOWLIST, per-IP rate limits. Rows A1 to A9, G2. |

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

## Client ID Metadata Documents: off by default
`clientIdMetadataDocumentEnabled` follows `CIMD = "on"` and is off otherwise (attack row M1). Reason: the live Grok Bot connection was made with Dynamic Client Registration (its client record is a DCR registration, Oct 17, 2026), so nothing needs CIMD today. With it on, anyone who opens /authorize makes the Worker fetch a URL they choose before any approval, which is SSRF surface (limited to public hosts by `global_fetch_strictly_public`) and a free way to make the consent page show a publisher name. Turn it on if Grok Bot or another client you use moves to CIMD.

## Origin check rollout (MCP spec: servers MUST validate Origin)
The check refuses browser calls from other sites. Grok Bot calls from its servers, which normally send no Origin header, and those always pass. Before enforcing in production:
1. Deploy with `ORIGIN_CHECK = "report"` (the committed default). Nothing is refused. Every /mcp call that carries an Origin logs `origin seen: same-origin | allowed <origin> | foreign <origin>`.
2. Run `npm run tail` and use the connector from every surface you use (web, desktop, phone) for a few calls each.
3. If no `foreign` lines appear, set `ORIGIN_CHECK = "enforce"` and deploy. If a Grok Bot origin does appear, add it to `ALLOWED_ORIGINS` first.
4. Rollback is one line: set it back to `"report"` and deploy.

## Passkey one-tap connect (PASSKEYS = "on")
Off by default. With it on and a device enrolled, the consent page shows **Allow with Face ID** and keeps the approval code under "No Face ID here? Use an approval code".
- **Enroll.** `npm run setup -- --add-device` prints `https://<worker>/enroll#<token>`. The token is 32 random bytes, single use, 15 minutes. Only its SHA-256 is a Worker secret, and it rides in the URL fragment, so it never reaches a server log or a Referer. The page removes it from the address bar as soon as it loads.
- **Verify.** Hand-written relying party in `src/webauthn.ts` (no new dependency): ES256 or RS256, attestation none, `userVerification: required`, exact origin, RP ID = the Worker host, `crossOrigin` refused, signature over authenticatorData and the client-data hash, and a counter that may never step back once it moves (iCloud Keychain passkeys report 0).
- **Challenge.** An HMAC-signed token from a key derived for this purpose only, 5 minutes, single use in the Durable Object, bound to the OAuth consent handle. Its binding is checked before it's spent, so pasting it into another request can't burn the real one.
- **Pages.** A script runs only on the enroll and consent pages, and only the one carrying that response's CSP nonce. `connect-src 'self'`, `frame-ancestors 'none'`, `form-action` still limited to self and the redirect origin.
- **Don't allow** always wins: the Face ID path is taken only when no button value came with the form.
- **Lost devices.** `npm run setup -- --reset-passkeys` rotates PASSKEY_EPOCH, which orphans every stored passkey at once. Codes keep working.
- **Not built yet:** remembered consent, the hosted multi-tenant variant, and enrolling from the setup page itself (the CLI flag does it for now).
