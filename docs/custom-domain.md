# Running Holdt on your own domain

Holdt works on its `workers.dev` address. A domain you own reads better on the Face ID sheet and on the approval page.
iPhone shows the host on the passkey sheet, roughly "Sign in to yourdomain.com with your passkey for iCloud Calendar".

## Passkeys belong to one host

A passkey is made for exactly one host name. One made on `holdt.you.workers.dev` can't sign in on `connect.yourdomain.com`.

- Holdt remembers the host each passkey was made on and only offers the ones that fit the page you're on. After a move the approval page simply shows the code until you add Face ID again. Nothing breaks and nothing is weakened.
- Passkeys made before Holdt stored the host count as the current host's. After a move, clear them: `npm run setup -- --reset-passkeys`.
- Then add each device again from the new address: set `WORKER_URL` to it and run `npm run setup -- --add-device`.
- The old passkey stays in iCloud Keychain doing nothing. Remove it in Settings, Passwords, if you like.
- Keep one address. Once the domain works, set `workers_dev = false` in `wrangler.toml` and deploy, so nobody enrolls on the old host by mistake.

## Steps (Cloudflare)

1. The domain has to be a zone on the same Cloudflare account as the Worker. If it's registered elsewhere, add it in the Cloudflare dashboard (Add a domain, Free plan) and change the nameservers at your registrar to the two Cloudflare gives you. Wait until the zone shows Active.
2. In `wrangler.toml`, uncomment the `routes` line and put your host in it, for example `connect.yourdomain.com`. `custom_domain = true` makes Cloudflare create the DNS record and the certificate for you. Don't create the record by hand.
3. `npm run deploy`. Open `https://connect.yourdomain.com/.well-known/oauth-authorization-server` and check it answers.
4. In Grok Bot, remove the old connector and add the new address (`https://connect.yourdomain.com/mcp`). Approve with a fresh code.
5. Do the passkey steps above.
