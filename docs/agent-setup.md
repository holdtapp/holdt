# Set up Holdt by sending this page to your Grok Bot

**For people:** send this page's link to your Grok Bot and say "Set up Holdt for my iCloud Calendar." Your Grok Bot does the install on your computer. You do three things: click **Allow** on Cloudflare's page, make one app-specific password on Apple's page and enter it on the Holdt page, then tap **Save passkey** once (Face ID on an iPhone, Touch ID or the device password on a Mac). You never open Terminal, and there's no Continue button.

You need a free Cloudflare account and an Apple Account with two-factor authentication on. Your Grok Bot needs access to your computer (the Grok Bot desktop app).

---

## For the Grok Bot doing the setup

Follow these steps on the user's own computer, in order. Report each "Step N of 4" line to the user in plain words.

### Rules (all of them, every time)
- Never ask the user for a password, a code, or a token in chat. The only password Holdt needs is typed by the user on the Holdt setup page in their own browser.
- Never print, paste, summarise or forward the setup link. `npm run agent-setup` opens it in the user's browser. If there is no browser, it saves it to a file only the user can read, and you tell the user where.
- Never run `wrangler secret put` yourself with a value in the command. Never read files under `~/.holdt/` aloud or into chat.
- Never change `SEAL_KEY`. Replacing it makes the sealed setup unreadable.
- Use only the user's own Cloudflare account, signed in on Cloudflare's own page by the user.

### Steps
1. Make sure Node.js 20 or later and git are installed. If not, ask the user before installing them.
2. Get Holdt and install it:
   ```
   git clone https://github.com/holdtapp/holdt.git && cd holdt && npm install
   ```
3. Run the install:
   ```
   HOLDT_APPLE_EMAIL=<their Apple Account email, if you know it> npm run agent-setup
   ```
   `HOLDT_APPLE_EMAIL` is optional. It rides only in the link's `#` fragment, so it reaches no server log, and the page fills the Email field from it. It is never printed.
   It signs in to Cloudflare (the user clicks **Allow** in the browser), makes Holdt's storage, deploys to the user's `workers.dev` address, saves Holdt's sealing key, opens the one-time setup page, then opens Apple's app-specific password page in front of it.
4. Tell the user: sign in on Apple's page, make an app-specific password named Holdt, copy it, switch to the Holdt page and paste it. The cursor is already in the field. Holdt checks it with Apple on its own as soon as all 16 letters are in. Read-only is chosen unless they pick changes-with-a-yes first. Then one tap on **Save passkey**. The passkey is made on the same page.
5. The last page says **Holdt is set up** and shows the server address with **Copy address**. Tell them to add it in Grok Bot under **Connect Apps → Add custom MCP server**. The address is `https://holdt.<their subdomain>.workers.dev/mcp`, and `npm run agent-setup` printed it as the last line.

### If something goes wrong
- The link has ended (used once, or older than 30 minutes): run `npm run agent-setup -- --new-link`. It opens a fresh link without redeploying.
- To change the iCloud account or the mode later: the same `--new-link` command. Saving a new setup ends existing connections, and the user connects Grok Bot again.
- "Deploy finished but no workers.dev address came back": the account has no `workers.dev` subdomain yet. Ask the user to open Workers in the Cloudflare dashboard once, then run `npm run agent-setup` again.
- The page says setup isn't finished (the account was saved but no passkey was made): run `npm run add-device`. It opens a passkey link in the user's browser.
- Apple refuses the password: the user makes a new app-specific password on Apple's page and enters it again. They get 8 tries per link.

Developers who prefer Terminal can still use the manual path in docs/setup.md.
