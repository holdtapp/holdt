# Holdt for iCloud Calendar (self-hosted)

An AI shouldn't change your calendar without your yes.

**Holdt, said holt.** Reads your calendar. Writes only what it previewed first.

Holdt is a small MCP server, running on **your own Cloudflare account**, that lets Grok Bot read your iCloud calendars. With changes on, every change starts as a preview, and Grok Bot is told to show it and ask you first. Holdt can't see your answer, so it accepts only that previewed change, once, within 10 minutes. Never deletes your events. It can only take back its own, on your yes. It never sends invitations.

**Calendar only: Apple Reminders is not included (see below).** Events with invitees or an organizer can't be edited, and the time of a repeating event can't be changed yet.

> **Status:** v1.0.3, self-hosted.
> As of Oct 18, 2026: `npm test` runs 299 tests, all passing. `npm run prove` runs 110 attacks against a mock iCloud, all refused. It then switches off each of 112 protections in a scratch copy: for 101 the matching attack gets through, and for the 11 layered ones the next layer still refuses it. Table: [docs/attack-proof.md](docs/attack-proof.md).
> Verified live on an iCloud test account, Oct 17, 2026, on a pre-release build: adding, changing and undoing, a repeated commit refused, an undo after a later edit refused, and every other event left untouched (18 of 18 checks, [docs/live-test-2026-10-17.md](docs/live-test-2026-10-17.md)). Not covered yet: a conflict from an edit made on an iPhone, and an event across the Nov 1 DST change.

## Setup (no Terminal)
You need a free Cloudflare account, an Apple Account with two-factor authentication, and the Grok Bot desktop app. Send Grok Bot this link: **https://github.com/holdtapp/holdt/blob/main/docs/agent-setup.md**, and say "Set up Holdt for my iCloud Calendar." It installs Holdt on your Cloudflare account from your computer. Along the way you:

1. Click **Allow** on Cloudflare's page.
2. Apple's page opens in front of the Holdt setup page. Sign in, make an app-specific password named Holdt and copy it. Like every app-specific password, it reaches more of iCloud than calendars.
3. On the Holdt page, read-only is the default. Pick changes if you want them, then enter your Apple Account email and paste the password. Holdt checks it with Apple and seals it in your Cloudflare account.
4. Click **Save passkey** once (Touch ID or your password on a Mac, your screen lock on other computers). On a Mac, if iCloud Keychain is on, your iPhone gets the passkey too.
5. In Grok Bot, add the address from the last page under **Connect Apps → Add custom MCP server**.

When Grok Bot connects, the approval page's main button is **Allow with Face ID** on an iPhone (**Touch ID** on a Home-button iPhone, **Touch ID or Face ID** on an iPad), or **Allow on this Mac** on a Mac (Touch ID or your password). On a computer without your passkey, choose **Approve on your iPhone instead** and scan the code with it. Every path's steps and the threat model are in [docs/no-typed-codes.md](docs/no-typed-codes.md).

### For developers: Terminal setup
You need Node.js and a free Cloudflare account. A step-by-step version is in [docs/setup.md](docs/setup.md).

1. `npm install`
2. `npm run cf:login`
3. `npx --no-install wrangler kv namespace create OAUTH_KV`, and paste the id it prints over `REPLACE_WITH_YOUR_KV_ID` under `binding = "OAUTH_KV"` in wrangler.toml.
4. `npm run deploy`. Note your Worker address, e.g. `https://holdt.<you>.workers.dev`.
5. `WORKER_URL=https://holdt.<you>.workers.dev npm run setup`. A one-screen page opens. Make an app-specific password on Apple's page, paste it, enter your Apple Account email, **Test connection**, turn on **Let Grok Bot add and change events** if you want changes, then **Save and finish**.
6. Save opens a one-time passkey link in the same browser. Click **Save passkey** (on an iPhone it reads **Turn on Face ID**, **Turn on Touch ID** on a Home-button iPhone, or **Turn on Touch ID or Face ID** on an iPad). On a Mac, if iCloud Keychain is on, your iPhone gets the passkey too. The last screen shows your connector address with a Copy button.

Adding a device later: `WORKER_URL=https://holdt.<you>.workers.dev npm run add-device` opens a fresh link in your browser. Click **Save passkey** there. For a phone, `npm run add-device -- --qr` prints a QR code. Lost every device? `npm run new-code` prints a one-time recovery code, and the approval page shows a code field for 15 minutes.

Your password goes only to Apple and your own Cloudflare account. On the no-Terminal path it is sealed in Holdt's storage (AES-256-GCM, key in your Cloudflare secrets). On the Terminal path it goes to `wrangler secret put` on stdin. It is never written to disk on your computer, logged, or put on a command line. To cut Holdt off from iCloud, revoke the password at account.apple.com → Sign-In and Security → App-Specific Passwords.

## Tools
| Tool | Kind |
|---|---|
| connection_status, list_calendars, list_events, search_events, get_event | read |
| find_free_time | read. Open time across your calendars, optionally inside working hours |
| resolve_dates | read. Shows how a phrase like "next friday 3pm" will be read |
| prepare_create_event → commit_create_event | write, preview + yes. The preview warns about overlaps and offers 2 or 3 open times nearby |
| prepare_update_event → commit_update_event | write, preview + yes. Events with invitees, and the time of repeating events, are refused in v1 |
| list_changes, prepare_undo → commit_undo | the change log, and take back a change Holdt made, preview + yes |

**Not included in v1:** Reminders, deleting events Holdt didn't add, invitations, single-occurrence edits of repeating events, Mail, Contacts, iMessage, Apple Health.

## Why Reminders isn't included
Apple's Reminders app (iOS 13 and later) keeps its lists in a private store that outside connectors can't reach over CalDAV. BusyCal and 2Do document this, and we confirmed it on a real account on Oct 16, 2026:
- CalDAV showed only a leftover "Reminders ⚠️" list holding 2 stale items.
- The iPhone's real "Reminders" list, with 1 item, was not visible.

Anything we built would read the wrong list, so v1 leaves Reminders out. You can ask your bot to put a timed calendar event with an alert on your calendar instead. The old CalDAV reminder code is kept behind `REMINDERS_EXPERIMENTAL=true` (off, unsupported) for a possible future version. To check an account yourself, see docs/reminders-probe.md.

## Safety design
- **Undo, on your yes.** Every change Holdt makes is logged for 30 days and comes with a revert token that works for 7 days. Undoing an edit puts the old version back, but only if the event hasn't changed since. Undoing an add removes that event only if Holdt added it in the last 24 hours and it hasn't changed since, even by Holdt. Undo a later edit first, then the add. There is no other way for Holdt to remove anything.
- **Two-step writes.** `prepare_*` changes nothing and returns an HMAC-signed token bound to the exact change, valid for 10 minutes. `commit_*` only accepts that token.
- **No double writes.** Replays are blocked by token nonces, `If-None-Match: *` on creates and `If-Match` ETags on updates, so a change can't land twice and a stale preview can't overwrite newer edits.
- **Writes are attempted exactly once.** An ambiguous failure returns "re-check before retrying". Reads retry 429/5xx with backoff.
- **Credentials only go to trusted hosts:** the configured host or `*.icloud.com`, over HTTPS. Redirects elsewhere are refused (tested).
- **Prompt injection is contained.** Anyone can put an event on your calendar by inviting you, so event text is treated as untrusted. Every result labels it as data, text that reads like orders to an AI is flagged, events from other people's invitations can't be edited, and preview lines can't be forged by a hostile title. See docs/attack-proof.md.
- **Logs are redacted:** passwords, tokens, Basic auth, emails, principal paths and iCal bodies. A test checks every log line from the whole suite.
- **OAuth 2.1 on `/mcp`** via @cloudflare/workers-oauth-provider: PKCE S256, RFC 9728 protected resource metadata, RFC 8707 audience-bound tokens, RFC 9207 `iss` on the redirect, refresh rotation and RFC 7009 revocation. Grok Bot connects with Dynamic Client Registration. Client ID Metadata Documents (MCP 2026-07-28) are supported but off unless you set `CIMD = "on"`, because they make the Worker fetch a web address the caller picks. Connecting needs a passkey (Face ID, Touch ID or your device password) or a one-time 8-digit recovery code from `npm run new-code`, so no key ever goes in chat. Approvals, recovery codes and commit tokens are single use across every Cloudflare location (a revert token can be shown again for 7 days, and the undo it leads to is single use) (a Durable Object), sign-ups and approvals are rate limited, and only the callback addresses in REDIRECT_ALLOWLIST can receive access. See docs/SECURITY.md. `npm run setup -- --revoke-all` cuts off every connection. A separate demo server can also accept one shared reviewer code for marketplace review. It is off unless that server sets `REVIEWER_MODE = "on"`, lasts 14 days and can be revoked at any time. See docs/reviewer-testing.md.
- **MCP 2026-07-28 and earlier.** Stateless requests (`server/discover`, per-request `_meta` version, `resultType`, cacheable `tools/list`) and the older `initialize` handshake (2025-11-25 back to 2024-11-05). Every tool has accurate `readOnlyHint` / `destructiveHint` / `idempotentHint` annotations, and every read tool has an `outputSchema`.

## Time rules
Times without an offset are in your time zone (set by setup). Plain English works too: "tomorrow at 3pm", "next friday", "end of month", "the last friday of november", "in 2 weeks". "Next friday" means the Friday of next week. A clock time that falls in the spring-forward gap moves to the first valid time. Every preview spells out the date, so check it before saying yes. A date alone means that whole day in your zone, so "from 2026-10-17 to 2026-10-17" is all of Saturday Oct 17. All-day events stay on their date wherever you are. Repeating events are expanded per date, including "2nd Tuesday", "last Friday", "1st and 15th" and yearly rules like Thanksgiving. Rare rules (BYSETPOS, week numbers) show the first date with a note.

## Develop
`npm test` (299 tests) · `npm run prove` (switches each protection off and proves its attack then succeeds, or for layered rows that the next layer still stops it, see docs/attack-proof.md) · `npm run typecheck` · `npx tsx scripts/shoot-setup.ts` (renders setup screenshots against the mock, dev only)

## License, warranty and who makes Holdt
Holdt is made by Terminus X Partners, LLC and released under the MIT License (see LICENSE). It is provided as is, without warranty of any kind. You run it on your own accounts, and you are responsible for your Cloudflare deployment and your Apple Account, including the app-specific password you create for it. Read every preview before you say yes. Security reports: docs/SECURITY.md.

---
Holdt is an independent product. It is not made by, affiliated with, sponsored by or endorsed by Apple Inc. or xAI. iCloud, iPhone, Mac and Face ID are trademarks of Apple Inc., registered in the U.S. and other countries.
