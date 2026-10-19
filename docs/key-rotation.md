# Key rotation

Holdt has three kinds of secret material. None of them is ever printed, logged or sent to the model.

| Secret | What it protects | How to rotate | What breaks |
|---|---|---|---|
| `CONFIRM_SECRET` | Confirm tokens, revert tokens, the consent-page context. Each purpose uses its own derived key (HMAC of the secret with a purpose label), and tokens are also bound to `GRANT_EPOCH`. | Zero-downtime, below. | Nothing, if you follow the steps. |
| `GRANT_EPOCH` | Every OAuth grant. | `npm run setup -- --revoke-all` | Every connection (by design), and any preview or revert token issued before it. Undo history stays, and `list_changes` hands out fresh revert tokens. |
| `APPROVAL_CODE_HASH` | The one-time approval code. Stored as `pbkdf2$20000$<random salt>$<hash>`, so it can't be reversed with a lookup table. It also expires after 15 minutes and is single use. | `npm run setup -- --new-code` | The old code. |
| `ICLOUD_APP_PASSWORD` | iCloud access. | Revoke it at account.apple.com, make a new one, then run setup again: `WORKER_URL=<your address> npm run setup`, or `npm run agent-setup -- --new-link` if you set up without Terminal. | Every connection, because a new setup saves a new `GRANT_EPOCH` and confirm key. Reconnect Grok Bot. `list_changes` hands out fresh revert tokens. |
| `SEAL_KEY` | The no-Terminal setup record, the setup session cookie, and the change log's titles and pre-edit events. Without it (Terminal setup) the change log is stored in plain text. | No rotation command. `agent-setup` makes it once and never replaces it (docs/agent-setup.md). | If it is replaced by hand, the sealed setup can't be opened, and undo of changes made before rotation is refused. Those change log entries show "(can't be read)" in `list_changes` and expire in 30 days. |

## Zero-downtime CONFIRM_SECRET rotation
This is for the Terminal path. If you set up without Terminal, the confirm key is sealed with your setup, and `npm run agent-setup -- --new-link` plus a save replaces it (and ends every connection).

1. Copy the current value into `CONFIRM_SECRET_PREVIOUS` with `npx --no-install wrangler secret put CONFIRM_SECRET_PREVIOUS`. You can't read a Cloudflare secret back, and `npm run setup` makes the value without showing it, so most owners don't have it. If you don't, do step 2 only: in-flight previews (10 minutes) and revert tokens (7 days) just stop working, and `list_changes` issues new revert tokens.
2. Put a new random value (32 bytes, base64url) in `CONFIRM_SECRET` without showing it on screen:
   `node -e "process.stdout.write(require('crypto').randomBytes(32).toString('base64url'))" | npx --no-install wrangler secret put CONFIRM_SECRET`
3. Wait 7 days, the longest token lifetime (revert tokens). New tokens are signed only with the new key. Old ones still verify.
4. Delete `CONFIRM_SECRET_PREVIOUS` with `npx --no-install wrangler secret delete CONFIRM_SECRET_PREVIOUS`.

Verification tries at most 3 keys, current first. Issuing only ever uses the current key.

## Why PBKDF2 at 20,000 rounds
An 8-digit code has only 10^8 values. A slow, salted hash makes a leaked hash expensive to brute-force, but the Worker must still check a guess within the free plan's 10 ms CPU budget. 20,000 rounds takes about 4 ms. The real limits are the 15-minute lifetime, single use and the 5-try lockout, which the Durable Object makes exact. The round count is stored in the hash, so a paid-plan deploy can raise it without changing code.
