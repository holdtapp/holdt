# No typed codes: one click to set up, one click to connect

Holdt used to ask the owner to read an 8-digit approval code on the computer and type it on the phone. That step is gone.
Owner proof is now a passkey (Face ID or Touch ID), and the only thing the owner does in the normal flow is one click.

## Click counts (controllable actions per path)

"Controllable" means a tap or click on a Holdt page, or a Holdt command. Apple's own prompts are counted on their own line,
because we can't remove them: the passkey sheet's Face ID glance or Touch ID press, and on some systems a "Continue" in the
same sheet. Adding the server address to Grok Bot and pasting the Apple app-specific password are not owner proof (Grok Bot
and Apple need them), so they're listed separately too.

| Path | Holdt actions | Apple system prompts (not ours) | Also needed, not owner proof |
|---|---|---|---|
| First setup on a Mac: `npm run setup`, the page opens, paste password, Test, Save. The page then opens the one-time link | **1**: Turn on Touch ID | passkey sheet: Touch ID press (plus "Continue" on some macOS versions) | paste the app password, Test connection, Save (Apple requires the password). Then tell Grok Bot the address (Copy on the last screen) |
| Your iPhone after setup on the Mac | **0**: iCloud Keychain syncs the passkey | none | none |
| Connect from Grok Bot, device has the passkey | **1**: Allow with Face ID | passkey sheet: Face ID glance (or Touch ID) | none |
| Connect, passkey not on this device, browser offers "use a phone" (hybrid) | **1**: Allow with Face ID | Apple's QR in the sheet, scan with the iPhone, Face ID on the iPhone | none |
| Add a device later: `npm run add-device` opens the link on this computer | **1**: Turn on Touch ID | passkey sheet | running the command |
| Fallback A, connect: browser can't do hybrid | **3**: Approve on your iPhone instead, then on the iPhone: tap the camera's Holdt link, Allow with Face ID. The computer finishes by itself | Face ID on the iPhone | point the iPhone camera at the QR code |
| Fallback B, a device that doesn't sync (say an Android phone or a work Mac) | **3**: on the new device open Add this device (from Setup help), on the iPhone tap the camera's link and Allow with Face ID, then Turn on Face ID on the new device | Face ID on both | point the iPhone camera at the QR code |
| Fallback C, no browser on the setup machine (a server over SSH) | **2**: tap the camera's link, Turn on Face ID | passkey sheet | `npm run add-device -- --qr`, point the iPhone camera at the terminal QR code |

Why the fallbacks need more than one action:
- **A** exists only when the passkey isn't on this device and the browser's own sheet can't reach the phone. Approving needs the
  owner's enrolled passkey, and it lives on another device. That device has to be told which request to approve (the QR code)
  and has to show the request before the owner says yes. Opening a link must never approve by itself (link previews would),
  so the yes is a tap on the iPhone. The computer side is automatic.
- **B** adds a new passkey without a link from the owner's computer. An enrolled device must approve (one tap there), and the
  new device must make its own passkey, which browsers only allow from a click on that device. Those are two different devices,
  so two clicks is the floor.
- **C** has no browser where the command ran, so the link has to cross to the phone (scan) and the phone has to make the
  passkey from a click.

What we didn't do, and why:
- No auto-open of the passkey sheet on page load. Safari requires a click for `navigator.credentials.create`, and for the
  consent page the person should see what the app gets before the sheet covers it. The click is the consent.
- Conditional mediation (passkey autofill) needs a username field. Holdt has none, so it would add UI, not remove a step.
  Chrome's experimental "immediate" mediation isn't in Safari. The button stays the one action.
- No second "Approved, continue" screen after the sheet. The sheet's success submits the form at once.

How the one click keeps the user gesture: the setup page fetches the passkey options as it opens (a POST from its own script
that spends nothing), so the click goes straight to `navigator.credentials.create`. Only `/enroll/finish`, after the click and
Face ID, spends the link. Pairing gets its options with the approval, for the same reason.

## Threat model

| Threat | What stops it | Test | Prove row |
|---|---|---|---|
| Link leakage (chat history, screenshots, logs) | The secret is only in the URL fragment, which browsers never send to a server, a Referer or a link preview. KV and Worker secrets hold only its SHA-256. Setup links last 10 minutes, approve links 5. Each works once. The page removes the fragment from the address bar as it loads. | ATTACK N1, P6, P12 | N1 hash, N1 TTL, P6, P12 |
| Link prefetch by messaging apps | Every GET is the same static page. Reading a request is a POST from our own script. Approving needs a tap and Face ID. The setup link is spent only by `/enroll/finish`, after the click. | ATTACK N2, N8 | N2, N8 |
| CSRF | Every state-changing endpoint needs our exact Origin and `application/json`, which a cross-site form can't send. The consent form itself keeps the OAuth library's CSRF cookie. | ATTACK N3 | N3 origin, N3 JSON |
| Replay | Face ID challenges are HMAC-signed, single use and bound to one request. A request is decided once (approve or deny, not both) and used once. | ATTACK N4, P3, P4 | N4, P3, P4 |
| Unenrolled attacker race (someone who sees the QR code) | Approving needs a signature from an enrolled passkey. A pairing approval can only be claimed with a second secret that never leaves the new device's page, so seeing the QR code isn't enough to enroll. | ATTACK N5 | N5 passkey, N5 claim |
| Moving an approval to another request | Each approval is stored under the hash of its consent handle. | ATTACK N6 | (structural) |
| Phishing (someone sends the owner an approve link for their own connect request) | The approve page names the app (honestly, "Grok Bot" only for its exact callback), where access goes, the device and city the request came from, and an amber warning: "Approve only a request you just started yourself. Never one someone sent you." Requests die in 5 minutes. The passkey itself can't be phished (exact-origin check, row P1), and the hybrid path in Apple's sheet adds Bluetooth proximity. | ATTACK N7, P1 | N7, P1 |
| Leaked setup link used before the owner | Single use and 10 minutes. Any new device shows on every consent page for 7 days ("Not you? Tap Don't allow."), in `connection_status`, and in the Worker log. `npm run reset-passkeys` removes every device at once. | ATTACK P6, P12 and the 7-day notice test | P6, P12 |

Residual risk, in plain words: a person who is sent an approve link, ignores the warning, the device and the city, and approves
anyway within 5 minutes gives that connect request access. That's the same class of risk as reading out a code, and it's why
Allow with Face ID on the owner's own device (one click, origin-bound, not phishable) is the default path.

## Recovery
The approval code survives only as an owner tool. `npm run new-code` on the owner's computer prints an 8-digit code that works
once, for 15 minutes, and while it's live the consent page shows a code field. No screen in the normal flow mentions it.
The demo Worker's reviewer code (REVIEWER_MODE) uses the same field.
