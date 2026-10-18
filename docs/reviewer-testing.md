# Testing Holdt as a reviewer

Holdt runs a demo server on a throwaway Apple Account made only for testing. You connect to it with one reviewer code. Nobody needs to be online for you to test.

## What you need

- Grok Bot on the web, Mac or iPhone
- The demo server address and the reviewer code from the submission's testing notes
- About 10 minutes

The demo account belongs to Holdt's test setup. Where an address has to appear in these notes it is shown as test@holdt.app. You never need to type it.

## Connect

1. In Grok Bot, add a custom connector and paste the demo server address. It ends in /mcp.
2. Grok Bot opens Holdt's approval page. Check that it says "Connect Grok Bot to your iCloud Calendar?"
3. Type the reviewer code in the code box. It starts with RVW. Dashes and lower case are fine.
4. Press Allow. Grok Bot shows the connector as connected.

The reviewer code works for every reviewer, as many times as needed, for 14 days from when it was issued. If the page says the code has ended, ask the developer for a new one.

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
4. Mint the code: `WORKER_NAME=<demo-worker> HOLDT_REVIEWER_ACCOUNT=<test account address> npm run setup -- --new-reviewer-code`. Only a salted hash bound to that account goes to Cloudflare. The code itself goes to a private file in ~/.holdt and is not printed. The address is read from the environment and never printed or stored.
5. Put the code and the demo server address in the submission's testing notes.
6. Revoke at any time: `WORKER_NAME=<demo-worker> npm run setup -- --revoke-reviewer`. The code stops working and every reviewer connection is cut on its next call. Your own connections keep working. Minting a new code also retires the old one and its connections.

How it is locked down (src/reviewer.ts, tests in test/reviewer.test.ts):

- Multi-use and 14 days. A future-dated issue time is refused.
- 80 random bits, so there is no lockout to grief. Per-IP rate limits on the approval page still apply. Wrong reviewer codes never use up the owner's approval-code tries.
- Bound to the demo account. The hash includes a digest of the Worker's iCloud address, so the code matches on no other account. If the Worker's account changes, reviewer connections stop.
- Reviewer connections carry the code's id. Revoke, expiry or a new code cuts them without touching the owner's connections.
- No reviewer-facing page, message or tool result contains the account's address. A test reads every page and read tool through a reviewer connection to check.
