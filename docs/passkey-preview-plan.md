# Passkey one-tap: preview plan for Dallin's 30-minute iPhone test

Status: plan only. Nothing here has been deployed. Every step that touches Cloudflare needs Dallin's go.

## What the test must answer
1. Does Grok Bot's connect sheet on iPhone allow WebAuthn for a third-party site? (Safari, SFSafariViewController and ASWebAuthenticationSession do. An embedded WKWebView does not.)
2. Is the full journey 2 taps plus Face ID, with no code typed?
3. When Face ID isn't available, does the page fall back to the code cleanly?

## Recommended: a separate preview Worker (production untouched)
The preview has its own name, host, KV, Durable Object and secrets, so the live `holdt` Worker and its connection are never touched. Passkeys bind to the host, so a passkey made for the preview never works on production (and that's what we want).

Setup, about 10 minutes (ESTIMATE):
1. `npx wrangler kv namespace create holdt-preview` and note the id.
2. Add to wrangler.toml (not committed until the test is approved):
   ```toml
   [env.preview]
   name = "holdt-preview"
   preview_urls = false
   kv_namespaces = [{ binding = "OAUTH_KV", id = "<preview kv id>" }]
   [env.preview.vars]
   PASSKEYS = "on"
   ORIGIN_CHECK = "report"
   REDIRECT_ALLOWLIST = "https://www.cursor.com/agents/mcp/oauth/callback,http://localhost:8787/callback"
   [[env.preview.durable_objects.bindings]]
   name = "GUARD"
   class_name = "Guard"
   [[env.preview.migrations]]
   tag = "v1-guard"
   new_sqlite_classes = ["Guard"]
   ```
   Rate-limit bindings are optional for a 30-minute test.
3. `npm run deploy -- --env preview`.
4. `WORKER_NAME=holdt-preview WORKER_URL=https://holdt-preview.<you>.workers.dev npm run setup`. Choose **read-only**. This writes the preview's own secrets, and a fresh app-specific password is better than reusing production's.

The test, about 15 minutes (ESTIMATE):
1. Run `npm run setup -- --add-device` (with the same WORKER_NAME and WORKER_URL). Open the link it prints in Safari on the iPhone, type the approval code it prints (typed, never pasted into a chat), tap Save a passkey, then Continue and Face ID. Expect "One-tap connect is on", then a "New device added" line on the next consent page and in connection_status.
2. In Grok Bot on the iPhone, add the custom connector `https://holdt-preview.<you>.workers.dev/mcp` and tap Connect.
3. On the consent page, tap **Allow with Face ID** and glance. Expect the sheet to close and Grok Bot to say Connected. Ask "what's on my calendar tomorrow".
4. Negative checks: tap Allow with Face ID, cancel the Face ID sheet, and expect the code field to open. Then enter a code from `npm run setup -- --new-code` and expect it to connect.
5. Watch `npx wrangler tail holdt-preview` throughout: expect `passkey enrolled`, `connection approved`, and no `passkey refused` lines on the happy path.

If step 3 shows "Face ID isn't available in this window", the sheet is a WKWebView. Then one-tap stays off for that surface and the design falls back to options C and D in docs/one-tap-design.md.

Teardown, 5 minutes: remove the connector in Grok Bot, `npx wrangler delete --name holdt-preview`, delete the preview KV namespace, revoke the preview's app-specific password at account.apple.com, and delete the passkey in iPhone Settings → Passwords.

## Alternative: flip the flag on production
Since the code path stays, `PASSKEYS = "on"` on the live Worker changes nothing until a device enrolls. It's faster (no new Worker) but it's a production deploy, and this v1 deploy also brings the Durable Object migration, rate limits and the new code-hash format. Do it only after the v1 deploy itself has been checked.
