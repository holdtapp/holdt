# Secret-safe storage design

## Self-host (Phase 1, built)
- **Where the password lives (Terminal setup):** a Cloudflare Worker secret. Setup sends it to `wrangler secret put` on **stdin**, so it never appears on a command line, in shell history, in a file, or in `wrangler.toml`. The no-Terminal path seals it in Holdt's storage instead, see below.
- **Setup helper:**
  - Listens on 127.0.0.1 only and needs a one-time random key in the URL.
  - Checks the Host header (DNS-rebinding guard) and sends a strict CSP and `no-store`.
  - Forgets the password as soon as it's saved.
  - Allows at most 10 live tests per run, so Apple doesn't throttle the account.
- **Runtime:**
  - The password is held in memory per request and sent only as a Basic auth header, over HTTPS, to the configured CalDAV host or to `icloud.com` and `*.icloud.com`. A redirect is followed only when the next host passes the same check.
  - Every log line goes through `redact()`, which scrubs registered secrets (raw and base64), app-password-shaped strings, bearer and basic tokens, emails, iCloud principal paths and iCal bodies.
  - Errors shown to the bot are fixed plain-English strings, never raw HTTP or XML.
- **Revocation:**
  - The user removes the app-specific password at account.apple.com, and the connector gets a 401 and tells them how to reconnect.
  - Changing the Apple Account password revokes all app passwords (Apple: https://support.apple.com/en-us/102654).
  - `wrangler secret delete` or deleting the Worker removes our copy.
- **Proof (tests):**
  - `SECRET SAFETY` scans every log line emitted across the whole suite, including the auth failure, 503 and redirect paths, for the password, token, `base64(user:pass)` and email.
  - The setup test checks that no API response or stderr contains the password.
  - The probe test checks the same for its output.

## Self-host, no-Terminal setup (built, `src/setup-web.ts`)
When the owner sets up through `/setup` (docs/agent-setup.md), the Apple Account email and app-specific password never become Worker secrets. They are sealed with `src/vault.ts` (AES-256-GCM data key, wrapped with AES-KW by the `SEAL_KEY` Worker secret) and stored under `sealed:setup` in the Durable Object, KV as the fallback. `withSealed()` opens the record per request and overlays it on the environment. Only the Worker, holding SEAL_KEY, can open it. Cloudflare dashboard readers of KV or Durable Object storage see ciphertext. Details and prove rows: docs/SECURITY.md, "No-Terminal setup".

## Hosted mode (designed, `src/vault.ts` implemented and tested, wired up for no-Terminal setup only)
- **Envelope encryption:** a fresh AES-256-GCM data key per user encrypts the password, and the data key is wrapped (AES-KW) by a key-encryption key held only in the platform secret store or KMS.
- **Bound to the user:** associated data `icloud-mcp:v1:<userId>` binds each ciphertext to its user, so copying a row to another user fails (tested).
- **Key rotation:** a `kekId` is stored for rotation. Rotation means unwrapping with the old key and rewrapping with the new one. Holdt's change log keeps the previous version of an event it edited for 30 days, in your own KV, so undo can restore it.
- **Revocable from our side:** a Disconnect button deletes the row immediately, and rows are auto-wiped 30 days after a 401 or disconnect (proposed).
- Needs counsel review before launch, because the credential also opens iCloud Mail and Contacts.
