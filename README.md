# Holdt for iCloud Calendar (self-hosted)

**Holdt, said holt.** Reads your calendar. Changes nothing until you say yes.

Holdt is a small MCP server that runs on **your own Cloudflare account** and lets Grok Bot read your iCloud calendars. **Calendar only: Apple Reminders is not included (see below).** It is read-only unless you turn changes on. With changes on, it still shows you every change first and waits for your yes. It can never delete anything or send invitations.

> Status: private beta. Reads were verified live against a real iCloud account on Oct 16, 2026 (calendar list, event detail, week view, search). Changes have only been tested against the mock iCloud server so far. 59 automated tests. Not submitted or published.

## Setup (about 5 minutes, ESTIMATE)
1. `npm install`
2. `npx wrangler login`, then `npx wrangler deploy`. Note your Worker address, e.g. `https://holdt.<you>.workers.dev`.
3. `WORKER_URL=https://holdt.<you>.workers.dev npm run setup`. A one-screen page opens on your computer:
   - **Open Apple's password page**, make an app-specific password, and paste it.
   - **Test connection** shows "Found N calendars".
   - Choose read-only or "changes with my yes", then **Save**.
4. Setup shows your connector address (`https://holdt.<you>.workers.dev/mcp`) and an 8-digit approval code. In Grok Bot, open **Connect Apps → Add custom MCP server**, paste the address, and enter the code on the approval page that opens. The code works once, for 15 minutes. Lost it? `npm run setup -- --new-code`.

Your password only goes to Apple and to your own Cloudflare secrets (via `wrangler secret put` on stdin). It is never written to disk, logged, or put on a command line. To disconnect, remove the password at account.apple.com → Sign-In and Security → App-Specific Passwords.

## Tools
| Tool | Kind |
|---|---|
| connection_status, list_calendars, list_events, search_events, get_event | read |
| prepare_create_event → commit_create_event | write, preview + yes |
| prepare_update_event → commit_update_event | write, preview + yes. Events with invitees, and the time of repeating events, are refused in v1 |

**Not included in v1:** Reminders, delete, invitations, single-occurrence edits of repeating events, Mail, Contacts, iMessage, Apple Health.

## Why Reminders isn't included
Apple's Reminders app (iOS 13 and later) keeps its lists in a private store that outside connectors can't reach over CalDAV. BusyCal and 2Do document this, and we confirmed it on a real account on Oct 16, 2026:
- CalDAV showed only a leftover "Reminders ⚠️" list holding 2 stale items.
- The iPhone's real "Reminders" list, with 1 item, was not visible.

Anything we built would read the wrong list, so v1 leaves Reminders out. You can ask your bot to put a timed calendar event with an alert on your calendar instead. The old CalDAV reminder code is kept behind `REMINDERS_EXPERIMENTAL=true` (off, unsupported) for a possible future version. To check an account yourself, see docs/reminders-probe.md.

## Safety design
- **Two-step writes.** `prepare_*` changes nothing and returns an HMAC-signed token bound to the exact change, valid for 10 minutes. `commit_*` only accepts that token.
- **No double writes.** Replays are blocked by token nonces, `If-None-Match: *` on creates and `If-Match` ETags on updates, so a change can't land twice and a stale preview can't overwrite newer edits.
- **Writes are attempted exactly once.** An ambiguous failure returns "re-check before retrying". Reads retry 429/5xx with backoff.
- **Credentials only go to trusted hosts:** the configured host or `*.icloud.com`, over HTTPS. Redirects elsewhere are refused (tested).
- **Logs are redacted:** passwords, tokens, Basic auth, emails, principal paths and iCal bodies. A test checks every log line from the whole suite.
- **OAuth 2.1 on `/mcp`** via @cloudflare/workers-oauth-provider: PKCE S256, RFC 9728 protected resource metadata, RFC 8707 audience-bound tokens, RFC 9207 `iss` on the redirect, refresh rotation and RFC 7009 revocation. Client ID Metadata Documents are on (the MCP 2026-07-28 default), with Dynamic Client Registration kept for older clients. Connecting needs a one-time 8-digit code from setup, so no key ever goes in chat. `npm run setup -- --revoke-all` cuts off every connection.
- **MCP 2026-07-28 and earlier.** Stateless requests (`server/discover`, per-request `_meta` version, `resultType`, cacheable `tools/list`) and the older `initialize` handshake (2025-11-25 back to 2024-11-05). Every tool has accurate `readOnlyHint` / `destructiveHint` / `idempotentHint` annotations, and every read tool has an `outputSchema`.

## Time rules
Times without an offset are in your time zone (set by setup). A date alone means that whole day in your zone, so "from 2026-10-17 to 2026-10-17" is all of Saturday Oct 17. All-day events stay on their date wherever you are. Repeating events are expanded per date, including "2nd Tuesday", "last Friday", "1st and 15th" and yearly rules like Thanksgiving. Rare rules (BYSETPOS, week numbers) show the first date with a note.

## Develop
`npm test` (59 tests) · `npm run typecheck` · `npx tsx scripts/shoot-setup.ts` (renders setup screenshots against the mock, dev only)

---
Holdt is an independent product. It is not made by, affiliated with or endorsed by Apple Inc. iCloud and Apple are trademarks of Apple Inc.
