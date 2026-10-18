# Holdt security

Holdt is maintained by Terminus X Partners, LLC. Report a problem privately through GitHub (Security > Report a vulnerability on this repository). Please don't open a public issue. Supported version: the latest commit on the default branch.

## What Holdt promises, and what enforces it
Ordered by how much you can trust each layer: invariants in code first, then CI checks, then prose.

| Promise | Enforced by |
|---|---|
| Never deletes your events. It can only take back its own, on your yes. | No delete tool exists. The one removal path is `commit_undo` for an event with the UID Holdt gave it, added in the last 24 hours, unchanged since (If-Match). Attack rows C5, E1 to E5. |
| Never sends invitations. | No invite tool. Edits to events with any ORGANIZER or ATTENDEE (in any component) are refused. `assertSafeIcs()` refuses any ICS that adds an ATTENDEE or ORGANIZER line or carries a control character, as the last step before every write. Rows C1, R1, R2, R4, R7. |
| Every write is the exact change you saw. | HMAC confirm tokens bound to action, payload hash, expiry, GRANT_EPOCH and a single-use nonce held in a Durable Object. Previews show full values. Rows B1 to B6, R5, R6, R8, G1. |
| Nothing typed reaches iCloud unchecked. | Every tool schema is strict (bounded strings, ranged integers, closed objects), checked at module load and in CI (`strictSchemaProblems`). The validator checks the whole argument tree. `propLine` refuses CR/LF/controls. `test/fuzz.test.ts` sends CR, LF, NUL, U+2028, U+0085, bidi and smuggled iCalendar lines into every field of every tool and checks every byte sent to iCloud. |
| Only you can connect it. | With one-tap on: a passkey enrolled from a single-use link, checked for exact origin, RP ID, Face ID (user verification), signature and counter, against a 5-minute single-use challenge bound to that connect request. Rows P1 to P8. Owner recovery: a single-use 8-digit code (salted PBKDF2 hash, 15 minutes, 5 tries, decided atomically in a Durable Object), redirect URIs pinned with REDIRECT_ALLOWLIST, per-IP rate limits. Rows A1 to A9, G2. |

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

## Red-team round 2 (REDTEAM2-REPORT.md) and their status
| Item | Status |
|---|---|
| S1 to S6, S8 | Fixed (fixes2.patch), each with a test and a prove row. S8 removed the http://localhost callback from the production allowlist. The live grant uses the https callback, so it is unaffected. |
| S7 shared hosted callback | `CLIENT_ALLOWLIST` exists but stays **off**. On Oct 17, 2026, production KV held 5 client registrations. 4 were named "Cursor", carried identical metadata and were made within 6 minutes (Oct 16, 11:23 to 11:29 PM MDT). The live grant belongs to the last one. So Grok Bot registers a new client_id on every connect, and pinning one would lock the owner out on the next reconnect. The real defense is the human gate: approve only a connect you just started. |
| (a) enroll root of trust | Fixed: single-use fragment link from the owner's Worker secrets, or approval from an enrolled passkey, logged, visible notice. Rows P12, N5, N8. |
| (b) passkey store races, cap | Fixed: per-credential records in the Durable Object. Rows P9 to P11. |
| (c) PBKDF2 on dead codes | Fixed: Durable Object state checked first. Row K1. |
| (d) undo into a read-only calendar | Fixed at prepare and commit. Row E6. |
| (e) CIMD | Off unless `CIMD = "on"`. Row M1. |
| (f) batch amplification | 4 tool calls per request. Row A10. |
| Lax CBOR and DER details | Accepted. Each still has to pass a signature check under the enrolled key. |

## Origin check rollout (MCP spec: servers MUST validate Origin)
The check refuses browser calls from other sites. Grok Bot calls from its servers, which normally send no Origin header, and those always pass. Before enforcing in production:
1. Deploy with `ORIGIN_CHECK = "report"` (the committed default). Nothing is refused. Every /mcp call that carries an Origin logs `origin seen: same-origin | allowed <origin> | foreign <origin>`.
2. Run `npm run tail` and use the connector from every surface you use (web, desktop, phone) for a few calls each.
3. If no `foreign` lines appear, set `ORIGIN_CHECK = "enforce"` and deploy. If a Grok Bot origin does appear, add it to `ALLOWED_ORIGINS` first.
4. Rollback is one line: set it back to `"report"` and deploy.

## Passkey one-tap connect (PASSKEYS = "on")
On in wrangler.toml (`PASSKEYS = "on"`). No screen in the normal flow asks anyone to copy, paste or type a code. Full threat model, prove rows and click counts: docs/no-typed-codes.md.
- **Enroll.** Setup's Save, and `npm run add-device`, open `https://<worker>/enroll?from=setup#<token>` in this computer's browser. The token is 32 random bytes, single use, 10 minutes. Only its SHA-256 is a Worker secret, and it rides in the URL fragment, so it never reaches a server log, a Referer or a link preview. The page removes it from the address bar as it loads. Owner proof is that only the owner can write Worker secrets (setup needs the Cloudflare login), so the link by itself enrolls, which is also how a lost-phone recovery works. Every GET is the same static page. The page fetches options with a POST (spends nothing), and only /enroll/finish, after the click and Face ID, spends the token (rows P12, N8). `--qr` prints a terminal QR code when there's no browser.
- **Another device.** iCloud Keychain syncs the passkey to the owner's Apple devices. Otherwise /pair shows a QR code with a one-time approve link, the owner approves on an enrolled iPhone with Face ID, and the new device makes its passkey with a second secret (the claim) that never leaves its page (row N5).
- **Approve on your iPhone.** When this device has no passkey and the browser can't reach the phone itself, the consent page shows a QR code. The link carries a 5-minute single-use secret in its fragment, KV stores only its hash, and the iPhone page shows the app, where access goes, the device and city that asked, and an amber warning. Approving needs a Face ID signature from an enrolled passkey and a tap (rows N1 to N7).
- Each enroll logs `passkey enrolled: device "<name>" via setup link|approved on another device, N on this server` (visible in `npm run tail`), and for 7 days every consent page and `connection_status` note it ("Face ID was turned on for an iPhone today at 8:00 PM. Not you? Tap Don't allow."). `connection_status` adds the reset command for the owner.
- **Recovery code.** `npm run new-code` prints an 8-digit code (salted PBKDF2 hash, 15 minutes, 5 tries, decided in the Durable Object). The consent page shows a code field only while one is live, and on the demo Worker in reviewer mode.
- **Storage.** One record per credential: in the Durable Object in production (atomic 10-key cap, counter compared and stored in one step), KV per-key records as the fallback. A store over the cap turns one-tap off rather than trusting it (rows P9 to P11).
- **Verify.** Hand-written relying party in `src/webauthn.ts` (no new dependency): ES256 or RS256, attestation none, `userVerification: required`, exact origin, RP ID = the Worker host (each passkey records its host, and only passkeys made on the current host are offered, see docs/custom-domain.md), `crossOrigin` refused, signature over authenticatorData and the client-data hash, and a counter that may never step back once it moves (iCloud Keychain passkeys report 0).
- **Challenge.** An HMAC-signed token from a key derived for this purpose only, 5 minutes, single use in the Durable Object, bound to the OAuth consent handle. Its binding is checked before it's spent, so pasting it into another request can't burn the real one.
- **Pages.** A script runs only on the enroll and consent pages, and only the one carrying that response's CSP nonce. `connect-src 'self'`, `frame-ancestors 'none'`, `form-action` still limited to self and the redirect origin.
- **Don't allow** always wins: the Face ID path is taken only when no button value came with the form.
- **Names.** The passkey sheet shows relying party "Holdt" and account "iCloud Calendar". Holdt names the app "Grok Bot" only when access goes to Grok Bot's exact callback (`KNOWN_CALLBACKS` in src/authorize.ts). Any other app is shown in quotes as a name Holdt can't verify, with the host access goes to.
- **Lost devices, or a device you didn't add.** `npm run setup -- --reset-passkeys` rotates PASSKEY_EPOCH, which orphans every stored passkey at once. Run `npm run add-device` afterwards.
- **Not built yet:** remembered consent and the hosted multi-tenant variant.
