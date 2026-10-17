# Quality loop: Phase 1 (Oct 16, 2026, MT)
Self-review passes, scored against the spec bar (9+). Scores are judgments, not measurements.

## Code
**Pass 1, found and fixed:**
1. SEQUENCE was not bumped on events that had none.
2. search_events' default window (395 days) broke its own 366-day limit.
3. Unbounded redirect loop. Now capped at 5, and every hop is host-checked.
4. Credentials could follow a redirect to any host. Now limited to `*.icloud.com` over HTTPS (tested).
5. A token replay from a fresh process could double-create. Now `If-None-Match: *` with a deterministic UID (tested).

**Pass 2, verified:**
- 30/30 tests pass.
- Strict TypeScript is clean.
- The Worker bundles with `--platform=neutral`, so there are no Node imports in runtime code.
- No delete or invite tools exist, and every tool's annotations match its kind.

**Score: 9/10 on mocked behaviour.** Not 10, because nothing has run against real iCloud yet. Remaining VERIFY items:
- (a) Real iCloud responses (partition redirect, the privilege set on subscribed calendars, the VTODO 404 propstat quirk). These are modelled on public notes, not observed.
- (b) Whether Cloudflare Workers `fetch` allows PROPFIND and REPORT to iCloud.
- (c) Whether Grok Bot's custom MCP connector sends a bearer header or needs the `?key=` link.
- (d) RRULE coverage: BYDAY with ordinals (e.g. "2nd Tuesday") isn't expanded. Those events show their first date with a note.

## Setup UX (screenshots in docs/shots/)
**Pass 1, found and fixed:**
1. Typing a regular password got auto-dashed into gibberish ("mydo-g2024!"). It now formats only a full 16-letter paste, or on blur.
2. The server's wrong-password message was wiped out by the client re-check.
3. "✓ Looks right" showed next to Apple's rejection.
4. The success panel looked disabled while animating.
5. The mobile button wrapped.
6. The finish screen said "your Worker URL" without giving it. It now shows one copyable connector link.
7. It told users to paste the key into chat. It now says Connect Apps, which keeps the key out of chat history.

**Pass 2, checked:**
- Desktop, mobile (390px) and dark mode.
- Reduced-motion honoured.
- Every error is one plain sentence with the fix.
- The live "Found N calendars" check names the calendars.
- An honest note when no reminder lists exist.

**Score: 9/10 for the screen itself.** The honest gap is the **self-host path around it**: a Cloudflare account plus `wrangler login`, `deploy` and `setup` in a terminal. That's fine for technical users and a real drop-off for everyone else. The hosted mode (vault designed) is what gets to true one-step setup.

## Not done in Phase 1, by design
Deploy, real-account test, marketplace submission, public repo, companion template.

---
# Pass 3 (Oct 16, 2026, MT): Calendar-only v1
**Change:** a real-account probe confirmed Reminders can't be reached. CalDAV showed only a legacy "Reminders ⚠️" list with 2 open items, while the phone's real list had 1 item. So:
- The 6 reminder tools are hidden from `tools/list` and refused with a plain reason unless `REMINDERS_EXPERIMENTAL=true`. That flag is off and unsupported.
- connection_status, the setup screen, the server instructions, the README and the listing draft now all say plainly that Reminders isn't included, and why.

**Tests:** 31/31 pass, including a new one that checks the v1 default exposes 9 tools with no reminder tool and refuses reminder calls. Strict typecheck is clean, and the screenshots were re-rendered.

**Code: 9/10.** The mocked behaviour is unchanged and green.

**Setup UX: 8/10, down from 9, because of one finding.**
- Grok Bot staff say custom connectors authenticate **only via OAuth**, and there is no safe way to enter a secret header (forum, Sep 17 2026). Custom servers are added by telling the bot in chat.
- So the current finish screen's `?key=` link would end up in a chat transcript where the model can see it.
- **Fix before deploy:** add an OAuth 2.1 layer to the Worker, so the user approves on our own page and no key ever enters chat. This is in the deploy plan, step A. Once it lands, re-score.

## Pass 4 (2026-10-16, step A: OAuth)
- Code 9/10. Uses @cloudflare/workers-oauth-provider 1.2.3 (DCR, PKCE, refresh rotation, RFC 7009 revoke, hashed tokens in KV). The legacy cursor:// callback is accepted. Consent needs a one-time 8-digit code (15 min, 5 tries, single use, only the hash is stored). GRANT_EPOCH rotation revokes everything. 41/41 tests. Bundle has no node: imports.
- Setup 9/10. No key ever goes in chat. The finish screen shows the URL sentence to paste and the code to type on the approval page. Adds `--new-code` and `--revoke-all`.
- Remaining (deploy-time only): create the KV namespace and set its id, then run a live check of the real Grok Bot connector against a deployed Worker.
