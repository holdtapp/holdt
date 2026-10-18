# Set up Holdt for iCloud Calendar

This guide walks you through setup from start to finish. It takes about 10 minutes once Node.js and a Cloudflare account are ready (ESTIMATE). Allow about 5 more minutes if you still need to install Node.js or sign up for Cloudflare. You need a computer for setup. After that, Holdt works from Grok Bot on any device.

Holdt runs on your own free Cloudflare account. Your Apple password goes only to Apple and to your own Cloudflare account. Nobody else ever holds it, including us.

## Before you start

- **A Mac, Windows or Linux computer.** You will type a few commands in Terminal. On a Mac, open Spotlight and type Terminal. On Windows, use Command Prompt or PowerShell from the Start menu.
- **Node.js.** Download the LTS version from nodejs.org and install it.
- **A free Cloudflare account.** Sign up at dash.cloudflare.com.
- **Two-factor authentication on your Apple Account.** Apple needs it before it will make an app-specific password. Most accounts already have it.

## 1. Get Holdt

<!-- LINK GOES LIVE ONLY WHEN THE REPO IS PUBLIC. Owner and org still to be decided (launch plan decision 4). Update this link if the repo moves. -->
Download Holdt from its GitHub page at [github.com/dallintwatts/holdt](https://github.com/dallintwatts/holdt). Press Code, then Download ZIP, and unzip it. The folder is usually named holdt-main. Or, if you use git, clone it.

Then go into that folder. If it unzipped to your Downloads folder:

On a Mac or Linux, in Terminal:

```
cd ~/Downloads/holdt-main
```

On Windows, in Command Prompt:

```
cd %USERPROFILE%\Downloads\holdt-main
```

On Windows, in PowerShell:

```
cd $HOME\Downloads\holdt-main
```

If the folder has a different name, use that name instead.

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

On Windows, run the two parts as two lines instead. In Command Prompt:

```
set WORKER_URL=https://holdt.you.workers.dev
npm run setup
```

In PowerShell:

```
$env:WORKER_URL = "https://holdt.you.workers.dev"
npm run setup
```

Terminal prints a link. Open it in your browser. It only works on this computer. Then on that page:

1. Enter your Apple Account email, for example you@icloud.com.
2. Press **Open Apple's password page**. Sign in, go to Sign-In and Security, then App-Specific Passwords, and make one named Holdt. Apple shows 16 letters, like abcd-efgh-ijkl-mnop.
3. Paste it into **Paste it here**. Use the app-specific password, never your regular Apple password.
4. Press **Test connection**. You should see "Found 2 calendars" (or however many you have).
5. Choose **read-only** or **changes with my yes**. Read-only is the safe start. You can change it later.
6. Press **Save**.

Save opens a page called **Turn on Touch ID** (Face ID on an iPhone). Click the button and touch the sensor. That's the only step. Your iPhone gets it through iCloud Keychain. The next screen shows your connector address (ending in `/mcp`) with a Copy button.

## 4. Add Holdt to Grok Bot

1. In Grok Bot, open **Connect Apps**, then **Add custom MCP server**.
2. Paste your connector address, the one ending in `/mcp`.
3. An approval page opens. Check that it says "Connect Grok Bot to your iCloud Calendar?"
4. Click **Allow with Touch ID** (or Face ID). Nothing to type.

Not on a device with your passkey? Tap **Approve on your iPhone instead**, point your iPhone's camera at the code, tap the link and approve with Face ID. The computer finishes by itself.

That's it. Try asking "What's on my calendar this week?"

## Good to know

- **Every change waits for your yes.** With changes on, Holdt shows a preview first and only makes the change after you agree. It never deletes your events and never sends invitations. It can take back its own changes, on your yes.
- **Lost every device with Face ID?** Run `npm run new-code` in the Holdt folder. It prints a one-time recovery code, and for 15 minutes the approval page shows a field for it. Type it yourself, never paste it into a chat.
- **Turn changes on later.** In the Cloudflare dashboard, open Workers & Pages, then holdt, then Settings, then Variables and Secrets. Set WRITES_ENABLED to true and save.
- **Add a device.** Apple devices on the same Apple Account get Face ID for Holdt through iCloud Keychain. For another device, run `npm run add-device` (it opens the link in this computer's browser) or `npm run add-device -- --qr` and scan the code with that phone. Or open **Setup help** on the approval page, tap **add it**, and approve from your iPhone.
- **Reset Face ID.** If the approval page says a device you don't recognize was added, tap Don't allow. Then run `npm run reset-passkeys` in the Holdt folder. Every Face ID device stops working at once. Then run `npm run add-device` to add your own again.
- **Cut off every connection.** Run `npm run revoke-all`.
- **Disconnect from Apple completely.** At account.apple.com, open Sign-In and Security, then App-Specific Passwords, and remove the Holdt password.

## If something goes wrong

- **"Apple didn't accept that."** Check the email is your Apple Account email and that you pasted the app-specific password. If you just made it, try making a new one.
- **"iCloud blocked the connection."** Work or school Apple Accounts may not allow app-specific passwords.
- **"That looks like your regular Apple Account password."** Make an app-specific password on Apple's page and paste that instead.
- **Reminders don't show up.** That's expected. Apple's current Reminders app can't be reached by calendar connectors, so Holdt covers your calendar only.

---
Holdt is an independent product. It is not made by, affiliated with or endorsed by Apple Inc. iCloud and Apple are trademarks of Apple Inc.
