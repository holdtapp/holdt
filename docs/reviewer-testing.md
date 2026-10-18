# Testing Holdt as a reviewer

Holdt runs a demo server on a throwaway Apple Account made only for testing. You turn on reviewer access with one tap on a reviewer link. There is nothing to type. Nobody needs to be online for you to test.

## What you need

- Grok Bot on the web, Mac or iPhone
- The demo server address and the reviewer link from the submission's testing notes
- About 10 minutes

The demo account belongs to Holdt's test setup. Where an address has to appear in these notes it is shown as test@holdt.app. You never need to type it.

## Connect

1. Open the reviewer link in the browser you use for Grok Bot and tap Turn on reviewer access. The page shows the demo server address.
2. In Grok Bot, add a custom connector and paste the demo server address. It ends in /mcp.
3. Grok Bot opens Holdt's approval page. Check that it says "Connect Grok Bot to your iCloud Calendar?"
4. Tap Allow as reviewer. Grok Bot shows the connector as connected.

The reviewer link works for every reviewer, as many times as needed, for 14 days from when it was issued. Reviewer access lasts in that browser until the link ends. If a page says the link has ended, ask the developer for a new one. If the approval page shows no Allow as reviewer button, open the reviewer link again in that same browser.

## Five things to try

1. "What's on my calendar this week?" Holdt lists the demo week in Mountain Time.
2. "When am I free on Tuesday afternoon?" Holdt finds open time across both calendars.
3. "Add a 30 minute call called Reviewer check tomorrow at 2 PM." Holdt shows a preview first and changes nothing. Say yes and it adds the event.
4. "Move Reviewer check to 3 PM." You get a before and after preview. Say yes and it moves.
5. "Undo that, then remove Reviewer check." Holdt puts the time back, then removes the event it added. It can only remove events it added itself, within 24 hours.

Things Holdt refuses on purpose:

- Deleting any event it didn't add. There is no delete tool.
- Making a change without a yes in the chat.
- Running the same yes twice. A repeated commit returns "Nothing was done twice."

## Good to know

- Other reviewers share this demo calendar, so you may see their test events.
- Holdt never sends invitations and never shows the account's address.

---

## For the owner

Nothing here has been deployed. Each step that touches Cloudflare needs your go.

1. Use a separate demo Worker on the test Apple Account, for example a copy of the test config with its own name, KV namespace and rate-limit namespaces. Never the production Worker named holdt.
2. In that Worker's config, under [vars], set REVIEWER_MODE = "on". The production wrangler.toml never sets it, and a test checks that.
3. Deploy that Worker.
4. Mint the link: `WORKER_NAME=<demo-worker> WORKER_URL=<demo server address> HOLDT_REVIEWER_ACCOUNT=<test account address> npm run setup -- --new-reviewer-code`. Only a salted hash bound to that account goes to Cloudflare. The link, `https://<demo-worker>.../review#RVW-...`, goes to a private file in ~/.holdt and is not printed. The address is read from the environment and never printed or stored.
5. Put the link and the demo server address in the submission's testing notes. If a directory's submission form has a field that wants a credential, paste the link itself there. No form needs the bare code. (No click-budget exception was needed, see products/connect-standard section 10.)
6. Revoke at any time: `WORKER_NAME=<demo-worker> npm run setup -- --revoke-reviewer`. The link stops working, every browser's reviewer access ends and every reviewer connection is cut on its next call. Your own connections keep working. Minting a new link also retires the old one, its browser passes and its connections.

How it is locked down (src/reviewer.ts, tests in test/reviewer.test.ts):

- One tap, never on GET. The code lives in the link's fragment (#...), which browsers never send to a server, never put in a Referer and link previews never see. Opening /review sets nothing and changes nothing. The page strips the fragment from the address bar. Only the tap on Turn on reviewer access posts the code, and /review/claim takes same-origin JSON only, so another site can't post it for you.
- The tap earns a reviewer pass for that browser: an HttpOnly, Secure, host-only, SameSite=Lax cookie, HMAC-signed with a subkey of CONFIRM_SECRET. It names the link's id and the account, and expires with the link, never past 14 days. The consent page then shows one Allow as reviewer button. A forged, stale (revoked or rotated link) or expired pass connects nothing.
- Multi-use and 14 days. A future-dated issue time is refused.
- 80 random bits, so there is no lockout to grief. Per-IP rate limits on the approval page still apply. Wrong reviewer links never use up the owner's approval-code tries.
- Bound to the demo account. The hash includes a digest of the Worker's iCloud address, so the link matches on no other account. If the Worker's account changes, reviewer connections stop.
- Reviewer connections and passes carry the link's id. Revoke, expiry or a new link cuts them without touching the owner's connections.
- No reviewer-facing page, message or tool result contains the account's address. A test reads every page and read tool through a reviewer connection to check.
