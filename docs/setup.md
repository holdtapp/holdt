# Set up Holdt for iCloud Calendar

This guide walks you through setup from start to finish. It takes about 10 minutes the first time (ESTIMATE). You need a computer for setup. After that, Holdt works from Grok Bot on any device.

Holdt runs on your own free Cloudflare account. Your Apple password goes only to Apple and to your own Cloudflare account. Nobody else ever holds it, including us.

## Before you start

- **A Mac, Windows or Linux computer.** You will type a few commands in Terminal (on a Mac, open Spotlight and type Terminal).
- **Node.js.** Download the LTS version from nodejs.org and install it.
- **A free Cloudflare account.** Sign up at dash.cloudflare.com.
- **Two-factor authentication on your Apple Account.** Apple needs it before it will make an app-specific password. Most accounts already have it.

## 1. Get Holdt

Download Holdt from its GitHub page (Code, then Download ZIP) and unzip it. Or, if you use git, clone it.

In Terminal, go into the Holdt folder. For example, if it unzipped to your Downloads folder:

```
cd ~/Downloads/holdt
```

## 2. Install and put Holdt on Cloudflare

Run these one at a time:

```
npm install
npm run cf:login
npm run deploy
```

- `npm run cf:login` opens your browser. Sign in to Cloudflare and press Allow.
- `npm run deploy` prints your Holdt address. It looks like `https://holdt.you.workers.dev`. Keep it handy.

## 3. Connect your iCloud Calendar

Run setup with your own address in place of the example:

```
WORKER_URL=https://holdt.you.workers.dev npm run setup
```

On Windows, in Command Prompt, run the two parts as two lines instead:

```
set WORKER_URL=https://holdt.you.workers.dev
npm run setup
```

Terminal prints a link. Open it in your browser. It only works on this computer. Then on that page:

1. Enter your Apple Account email, for example you@icloud.com.
2. Press **Open Apple's password page**. Sign in, go to Sign-In and Security, then App-Specific Passwords, and make one named Holdt. Apple shows 16 letters, like abcd-efgh-ijkl-mnop.
3. Paste it into **Paste it here**. Use the app-specific password, never your regular Apple password.
4. Press **Test connection**. You should see "Found 2 calendars" (or however many you have).
5. Choose **read-only** or **changes with my yes**. Read-only is the safe start. You can change it later.
6. Press **Save**.

The last screen shows your connector address (ending in `/mcp`) and an 8-digit approval code. The code works once, for 15 minutes.

## 4. Add Holdt to Grok Bot

1. In Grok Bot, open **Connect Apps**, then **Add custom MCP server**.
2. Paste your connector address, the one ending in `/mcp`.
3. An approval page opens. Check that it says "Connect Grok Bot to your iCloud Calendar?"
4. Type the 8-digit code and press **Allow**.

That's it. Try asking "What's on my calendar this week?"

## Good to know

- **Every change waits for your yes.** With changes on, Holdt shows a preview first and only makes the change after you agree. It never deletes your events and never sends invitations. It can take back its own changes, on your yes.
- **Code ran out?** Run `npm run setup -- --new-code` in the Holdt folder for a fresh one.
- **Turn changes on later.** In the Cloudflare dashboard, open Workers & Pages, then holdt, then Settings, then Variables and Secrets. Set WRITES_ENABLED to true and save.
- **Cut off every connection.** Run `npm run setup -- --revoke-all`.
- **Disconnect from Apple completely.** At account.apple.com, open Sign-In and Security, then App-Specific Passwords, and remove the Holdt password.

## If something goes wrong

- **"Apple didn't accept that."** Check the email is your Apple Account email and that you pasted the app-specific password. If you just made it, try making a new one.
- **"iCloud blocked the connection."** Work or school Apple Accounts may not allow app-specific passwords.
- **"That looks like your regular Apple Account password."** Make an app-specific password on Apple's page and paste that instead.
- **Reminders don't show up.** That's expected. Apple's current Reminders app can't be reached by calendar connectors, so Holdt covers your calendar only.

---
Holdt is an independent product. It is not made by, affiliated with or endorsed by Apple Inc. iCloud and Apple are trademarks of Apple Inc.
