// The owner's approval page. Grok Bot opens it during sign-in. The owner proves it's them with Face ID: on this device,
// or on their iPhone by scanning a QR code (src/away.ts). Nobody types a code in the normal flow (docs/no-typed-codes.md).
// The approval code survives only as an owner recovery tool: `npm run new-code` on the owner's computer turns on a
// one-time code field for 15 minutes (single use, 5 tries). The demo Worker's reviewer code uses the same field.
import { AuthorizationError } from "@cloudflare/workers-oauth-provider";
import type { Env } from "./worker.js";
import { registerEnvSecrets, SEC_HEADERS } from "./worker.js";
import { log } from "./redact.js";
import { guardFor } from "./guard.js";
import { reviewerState, checkReviewerCode, looksLikeReviewerCode } from "./reviewer.js";
import { loginOptions, checkPasskeyLogin, enrollApi, passkeysOn, loadPasskeys, deviceNotice, usableHere, json, sameOriginJson, readJson, LOGIN_SCRIPT, ENROLL_SCRIPT, CONSENT_SCRIPT, READY_SCRIPT, OK_SCRIPT, PAIR_SCRIPT, BIO_SWAP } from "./passkey.js";
import { awayApi, createConsentAway, takeConsentAway, whereFrom } from "./away.js";
import { qrSvg } from "./qr.js";
import { esc, screen, documentHtml, ICON, ownerNote, endScreen } from "./ui.js";

const CODE_TTL_MS = 15 * 60_000, MAX_TRIES = 5;
const hostOf = (u: string) => { try { return new URL(u).host || new URL(u).protocol; } catch { return "an unknown address"; } };
export async function sha256Hex(s: string) { return [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))].map((b) => b.toString(16).padStart(2, "0")).join(""); }
export const normalizeCode = (s: string) => String(s ?? "").replace(/\D/g, "");

/** Only https, loopback http, or the cursor: scheme Grok Bot uses may receive a code. Never userinfo (grok@evil) or a fragment. */
export function redirectAllowed(uri: string) {
  try { const u = new URL(uri); if (u.username || u.password || u.hash) return false; return u.protocol === "https:" || u.protocol === "cursor:" || (u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname)); } catch { return false; }
}

/** When REDIRECT_ALLOWLIST is set (comma-separated exact URIs), only those callbacks may receive a code. This stops codes
 * going to arbitrary sites. It does NOT stop a stranger using the same hosted app (same callback); see CLIENT_ALLOWLIST. */
/** When CLIENT_ALLOWLIST is set (comma-separated exact client_ids), only those registered clients may connect. A hosted
 * callback such as Cursor's is shared by every user of that app, so REDIRECT_ALLOWLIST alone can't tell the owner's
 * app from a stranger's app on the same platform. */
export function clientListed(env: Pick<Env, "CLIENT_ALLOWLIST">, clientId: string) {
  const list = (env.CLIENT_ALLOWLIST ?? "").split(",").map((x) => x.trim()).filter(Boolean);
  return !list.length || list.includes(clientId);
}
export function redirectListed(env: Pick<Env, "REDIRECT_ALLOWLIST">, uri: string) {
  const list = (env.REDIRECT_ALLOWLIST ?? "").split(",").map((x) => x.trim()).filter(Boolean);
  if (!list.length) return true;
  try { const u = new URL(uri).href; return list.some((x) => { try { return new URL(x).href === u; } catch { return false; } }); } catch { return false; }
}

export function formActionFor(uri: string) {
  try { const u = new URL(uri); if (u.username || u.password || u.hash) return false; return u.protocol === "https:" || u.protocol === "http:" ? u.origin : u.protocol; } catch { return ""; }
}
export function page(title: string, body: string, status = 200, headers?: Headers, redirectUri = "", script = "") {
  const h = headers ?? new Headers();
  h.set("Content-Type", "text/html; charset=utf-8"); for (const [k, v] of Object.entries(SEC_HEADERS)) h.set(k, v);
  // A script runs only on the passkey pages, and only the one carrying this response's nonce.
  // On a Mac, text marked data-bio says Touch ID (pages that have their own script do this in it).
  if (body.includes("data-bio")) script = BIO_SWAP + script;
  const nonce = script ? crypto.randomUUID().replace(/-/g, "") : "";
  h.set("Content-Security-Policy", `default-src 'none'; style-src 'unsafe-inline';${nonce ? ` script-src 'nonce-${nonce}'; connect-src 'self';` : ""} form-action 'self'${redirectUri && formActionFor(redirectUri) ? " " + formActionFor(redirectUri) : ""}; frame-ancestors 'none'; base-uri 'none'`);
  h.set("X-Frame-Options", "DENY");
  return new Response(documentHtml(title, body, nonce, script), { status, headers: h });
}
/** Callbacks that belong to Grok Bot. Holdt calls the app "Grok Bot" only when access will be delivered to one of these
 * exact URIs. The name follows where access goes, never the name an app typed into its own registration. A custom
 * scheme (cursor://) is left out on purpose: any app on a computer can claim a scheme, so it can't vouch for a name. */
export const KNOWN_CALLBACKS: Readonly<Record<string, string>> = { "https://www.cursor.com/agents/mcp/oauth/callback": "Grok Bot" };
export function knownApp(uri: string): string | undefined {
  try { const h = new URL(uri).href; for (const [k, v] of Object.entries(KNOWN_CALLBACKS)) if (new URL(k).href === h) return v; } catch { /* not a URL */ }
  return undefined;
}
/** Who is asking, in words a person can trust. Exported for the tests. */
export function clientLine(d: { clientName?: string; clientDomain?: string; redirectHost?: string; redirectUri?: string }) {
  const known = d.redirectUri ? knownApp(d.redirectUri) : undefined;
  if (known) return { known: true, title: `Connect ${known} to your iCloud Calendar?`, lede: `Access goes to ${esc(known)} alone. Allow this only if you just asked it to connect.` };
  if (d.clientDomain) return { known: false, title: `Connect ${d.clientName || d.clientDomain} to your iCloud Calendar?`, lede: `Published by <strong>${esc(d.clientDomain)}</strong>. Allow this only if you just asked it to connect.` };
  return { known: false, title: "Connect an app to your iCloud Calendar?", lede: d.clientName ? `It calls itself “${esc(d.clientName)},” but Holdt can't verify that. Allow this only if you just asked it to connect.` : "It didn't give a name, and Holdt can't verify where it's from. Allow this only if you just asked it to connect." };
}
const HINT = "8 digits, shown on the computer where you set up Holdt.";
/** A code that's spent, expired or blocked isn't a typing mistake: calm grey with the way forward, not red. */
const DEAD = new Set(["expired", "locked", "used", "none"]);
/** A wrong code comes back as an empty, focused field (like a wrong iPhone passcode): nothing to delete first. */
type FieldErr = { text: string; dead: boolean };
const FIELD_CODE = (o: { reviewer: boolean; error?: FieldErr }) => `<div class="field"><label class="lbl" for="code">${o.reviewer ? "Approval code or reviewer code" : "Approval code"}</label>
<input class="code" id="code" name="code" required ${o.reviewer ? 'inputmode="text" autocapitalize="characters" spellcheck="false" maxlength="40"' : 'inputmode="numeric" placeholder="8 digits" pattern="\\s*[0-9]{4}[ \\-]?[0-9]{4}\\s*" title="The 8 digits of your approval code" maxlength="12"'} autocomplete="one-time-code" enterkeyhint="go"${o.error ? " autofocus" : ""} aria-describedby="${o.error ? (o.error.dead ? "err" : "err codehint") : "codehint"}"${o.error && !o.error.dead ? ' aria-invalid="true"' : ""}>
${o.error ? `<span class="fielderr${o.error.dead ? " calm" : ""}" id="err" role="alert">${o.error.dead ? ICON.clock : ICON.alert}<span>${esc(o.error.text)}</span></span>` : ""}${o.error?.dead ? "" : `<span class="hint" id="codehint">${o.reviewer ? "The 8 digits from your computer, or the reviewer code that starts with RVW." : HINT}</span>`}</div>`;
const NEW_CODE_CMD = "On the computer where you set up Holdt, run this for a new approval code:<code>npm run new-code</code>";
const BOTH_CMDS = "On the computer where you set up Holdt:<ol><li>Turn Face ID off everywhere. Codes keep working.<code>npm run reset-passkeys</code></li><li>Get a new approval code.<code>npm run new-code</code></li></ol>";
/** One label for owner-only help on every screen. */
const HELP = "Setup help";
const REVIEWER_HINT = `<p class="foot">Reviewing Holdt? Enter the reviewer code from the testing instructions. It starts with RVW.</p>`;
/** The consent page. `errorFrom` says which control the error belongs to, so it shows beside that control. */
/** What the app gets, and the security notices that come before it. Shared by the consent page and the iPhone approve page. */
export function consentFacts(d: any, writes: string, notice?: string, extra = "", remote = false) {
  const who = clientLine(d);
  const facts = `<ul class="facts" role="list">

<li>${ICON.calendar}<p>Reads your calendars and events.</p></li>
<li class="${writes.startsWith("off") ? "off" : "on"}">${writes.startsWith("off") ? ICON.pencilOff : ICON.pencil}<p>Changes are ${esc(writes)}.</p></li>
<li class="lock">${ICON.guard}<p>Never deletes your events.<span class="sub keep"> It can only take back its own, on\u00a0your\u00a0yes.</span></p></li>
<li class="no">${ICON.mailOff}<p>Never sends invitations.</p></li></ul>`;
  // Security notices come first, before the summary of what the app gets.
  const dest = who.known ? "" : `<p class="factdest">${ICON.globe}<span>Access goes to <strong>${esc(d.redirectHost || "an unknown address")}</strong></span></p>`;
  const callouts = (d.redirectIsLoopback ? `<div class="callout">${ICON.alert}<p>${remote ? "This sends access to an app on the computer that asked. Approve only if you just started connecting from it." : "This sends access to an app on this computer. Continue only if you just started connecting from it."}</p></div>` : "")
    + (notice ? `<div class="callout">${ICON.device}<p><span class="sr">Security notice: </span>${esc(notice).replace(/ (Not you\?)/, "<br>$1")}</p></div>` : "") + extra;
  return { who, body: callouts + dest + facts };
}
function consentBody(d: any, handle: string, writes: string, error?: string, pk?: { token: string; challenge: string; rpId: string; ids: string[] }, notice?: string, reviewer = false, errorFrom: "code" | "pk" = "code", reason = "", typed = "") {
  const { who, body } = consentFacts(d, writes, notice);
  const dead = DEAD.has(reason);
  const codeErr: FieldErr | undefined = error && (!pk || errorFrom === "code") ? { text: reason === "expired" ? "That code expired. Get a new one on the computer where you set up Holdt." : error, dead } : undefined; // the open help carries where to get a new one
  const pkErr = error && pk && errorFrom === "pk" ? error : "";
  void typed;
  // A dead code: the way forward sits right under the message, open, and Allow with code steps back until a new code is in.
  // Setup help is the last thing on the page, collapsed. A dead code is the one exception: the fix opens right under it.
  const help = ownerNote(HELP, dead ? NEW_CODE_CMD : notice ? BOTH_CMDS : NEW_CODE_CMD, dead, dead ? "dead" : "");
  const allow = `<button class="btn ${dead ? "secondary" : "primary"}" name="decision" value="approve">Allow with code</button>`;
  const inPanel = dead ? help + allow : allow;
  const atEnd = dead ? "" : help;
  const hidden = `<input type="hidden" name="handle" value="${esc(handle)}"><input type="hidden" name="ctx" value="${esc(d.__ctx ?? "")}">`;
  const deny = `<button class="btn plain quiet" name="decision" value="deny" formnovalidate>Don’t allow</button>`;
  const actions = pk
    ? `<form method="post" autocomplete="off"${codeErr ? ' class="code"' : ""}>${hidden}<input type="hidden" name="pk_token" value="${esc(pk.token)}"><input type="hidden" name="pk_id"><input type="hidden" name="pk_cdj"><input type="hidden" name="pk_ad"><input type="hidden" name="pk_sig">
<button type="button" class="btn primary" id="pk" hidden data-o="${esc(JSON.stringify({ challenge: pk.challenge, rpId: pk.rpId, ids: pk.ids }))}">${ICON.faceId}${ICON.spinner}<span id="pklabel">Allow with Face ID</span></button>
<p class="status" id="pkmsg" aria-hidden="true">${ICON.info}<span class="st">${esc(pkErr)}</span></p><p class="sr" id="live" role="status" aria-live="polite">${esc(pkErr)}</p>
<div class="alt" id="altwrap"><div class="codebox" id="codepanel">
${FIELD_CODE({ reviewer, error: codeErr })}${inPanel}${reviewer ? REVIEWER_HINT : ""}</div>
<button type="button" class="btn plain" id="mode" aria-controls="codepanel" aria-expanded="${codeErr ? "true" : "false"}" hidden><span class="off">${ICON.keypad}Use an approval code instead</span><span class="on">${ICON.faceId}<span id="modeface">Use Face ID instead</span></span></button>
${deny}${atEnd}</div></form>`
    : `<form method="post" autocomplete="off">${hidden}${FIELD_CODE({ reviewer, error: codeErr })}
${dead ? help : ""}${allow}${deny}${reviewer ? REVIEWER_HINT : ""}${dead ? "" : help}</form>`;
  return screen({ title: who.title, lede: who.lede, markId: "mk", body, actions });
}
const PK_FIELDS = (pk: { token: string }) => `<input type="hidden" name="pk_token" value="${esc(pk.token)}"><input type="hidden" name="pk_id"><input type="hidden" name="pk_cdj"><input type="hidden" name="pk_ad"><input type="hidden" name="pk_sig">`;
const ADD_DEVICE = "On the computer where you set up Holdt, run this. It opens a one-time Face\u00a0ID link in that computer’s browser:<code>npm run add-device</code>";
const ADD_DEVICE_QR = "On the computer where you set up Holdt, run this, then scan the QR code it shows with this phone:<code>npm run add-device -- --qr</code>";
/** The normal consent page: Allow with Face ID, or scan a QR code and approve on the iPhone. Nothing to type. */
/** A phone can't scan its own screen, so on a phone the fallback names another device. */
export const isPhone = (req: Request) => /iPhone|iPad|Android/.test(req.headers.get("user-agent") ?? "");
function consentFaceBody(d: any, handle: string, writes: string, pk: { token: string; challenge: string; rpId: string; ids: string[] }, awayUrl: string, notice?: string, error = "", phone = false) {
  const { who, body } = consentFacts(d, writes, notice);
  const other = phone ? "another device" : "your iPhone", Other = other;
  const hidden = `<input type="hidden" name="handle" value="${esc(handle)}"><input type="hidden" name="ctx" value="${esc(d.__ctx ?? "")}"><input type="hidden" name="away">`;
  const panel = `<div class="awaybox" id="awaypanel" tabindex="-1" role="group" aria-labelledby="awayh" data-other="${other}"><p class="awayh" id="awayh">${ICON.device}<span>Approve on ${other}</span></p><div id="qrwrap" data-link="${esc(awayUrl)}">${qrSvg(awayUrl, phone ? "QR code. Scan it with another device’s camera to approve there." : "QR code. Scan it with your iPhone’s camera to approve there.")}</div>
<ol class="steps"><li>${phone ? "Scan this code with another\u00a0device." : "Scan this code with your\u00a0iPhone."}</li><li>Tap the Holdt link, then approve with Face\u00a0ID.</li></ol>
<p class="status wait" id="awaymsg" aria-hidden="true">${ICON.spinner}<span class="st">Waiting for ${Other}.</span></p>
<button class="btn secondary" id="awaygo" name="decision" value="away">I approved on ${phone ? "another device" : "my iPhone"}</button></div>`;
  const help = ownerNote(HELP, `<p>Face ID syncs to your Apple devices with iCloud Keychain, so most need nothing more.</p><p>For a device that doesn’t sync, <a href="/pair" target="_blank" rel="noopener">add it</a> and approve it from a device that already has Face\u00a0ID for Holdt.</p>${notice ? `<p>Didn’t add a device? Turn Face ID off everywhere, then set it up again.<code>npm run reset-passkeys</code></p>` : ""}`);
  const actions = `<form method="post" autocomplete="off"${error ? ' class="away"' : ""}>${hidden}${PK_FIELDS(pk)}
<button type="button" class="btn primary" id="pk" hidden data-o="${esc(JSON.stringify({ challenge: pk.challenge, rpId: pk.rpId, ids: pk.ids }))}">${ICON.faceId}${ICON.spinner}<span id="pklabel">Allow with Face ID</span></button>
<p class="status" id="pkmsg" aria-hidden="true">${ICON.info}<span class="st">${esc(error)}</span></p><p class="sr" id="live" role="status" aria-live="polite">${esc(error)}</p>
<p class="status ok" id="awayok" aria-hidden="true" hidden>${ICON.checkCircle}<span class="st">Approved on ${Other}. Finishing up.</span></p>
<div class="alt" id="altwrap">${panel}
<button type="button" class="btn plain" id="mode" aria-controls="awaypanel" aria-expanded="${error ? "true" : "false"}" hidden><span class="off">${ICON.device}Approve on ${other} instead</span><span class="on">${ICON.faceId}<span id="modeface">Use Face ID on this device</span></span></button>
<button class="btn plain quiet" name="decision" value="deny" formnovalidate>Don’t allow</button>${help}</div></form>`;
  return screen({ title: who.title, lede: who.lede, markId: "mk", body, actions });
}
/** Face ID isn't set up on any device yet. The page waits and carries on by itself once it is. */
function noDeviceBody(d: any, handle: string, writes: string, error = "", phone = false) {
  const { who, body } = consentFacts(d, writes);
  const actions = `<form method="post" autocomplete="off"><input type="hidden" name="handle" value="${esc(handle)}"><input type="hidden" name="ctx" value="${esc(d.__ctx ?? "")}">
<div class="awaybox setup" data-bio><p class="awayh">${ICON.faceId}<span>Turn on Face ID to approve</span></p><p>Holdt approves with Face\u00a0ID. Turn it on with Setup help below, and this page continues by\u00a0itself.</p>
<p class="status wait" id="readymsg" aria-hidden="true" hidden>${ICON.spinner}<span class="st">Waiting for Face\u00a0ID to be turned on.</span></p><p class="sr" id="readylive" role="status" aria-live="polite"></p></div>${error ? `<p class="status keep" role="alert">${ICON.info}<span class="st">${esc(error)}</span></p>` : ""}
<button class="btn plain quiet" name="decision" value="deny" formnovalidate>Don’t allow</button>${ownerNote(HELP, phone ? ADD_DEVICE_QR : ADD_DEVICE, true)}</form>`;
  return screen({ title: who.title, lede: who.lede, markId: "mk", body, actions });
}
/** Has the owner turned on a recovery code with `npm run new-code`, and is it still usable? Only then does a code field show. */
async function recoveryLive(env: Env, now = Date.now()) {
  if (!env.APPROVAL_CODE_HASH || !env.APPROVAL_CODE_ISSUED || now - Number(env.APPROVAL_CODE_ISSUED) > CODE_TTL_MS) return false;
  if (await env.OAUTH_KV.get(`approval-used:${env.APPROVAL_CODE_HASH}`)) return false;
  if (Number((await env.OAUTH_KV.get(`approval-fail:${env.APPROVAL_CODE_HASH}`)) ?? 0) >= MAX_TRIES) return false;
  const g = guardFor(env); if (g && (await g.codeState(env.APPROVAL_CODE_HASH, MAX_TRIES)) !== "open") return false;
  return true;
}
const CONSENT_TITLE = "Holdt: Connect your iCloud Calendar";
const writesFor = (env: Env) => env.WRITES_ENABLED === "true" ? "on, and each one waits for your yes" : "off, so it can't add or change events";
/** Picks the consent page for the server's state. `error` is shown beside the control it belongs to. */
async function renderConsent(env: Env, req: Request, url: URL, details: any, handle: string, o: { status?: number; headers?: Headers; redirectUri: string; error?: string; errorFrom?: "code" | "pk"; reason?: string; typed?: string } ) {
  const writes = writesFor(env), notice = await noticeFor(env), reviewer = (await reviewerState(env)).active;
  const pk = await loginOptions(env, url, handle);
  // Recovery (an owner-issued code is live) and the demo Worker's reviewer mode keep the code field.
  if (reviewer || (await recoveryLive(env)) || (o.error && o.errorFrom === "code"))
    return page(CONSENT_TITLE, consentBody(details, handle, writes, o.error, pk, notice, reviewer, o.errorFrom ?? "code", o.reason ?? "", o.typed ?? ""), o.status ?? 200, o.headers, o.redirectUri, pk ? LOGIN_SCRIPT : "");
  if (!passkeysOn(env)) return page("Holdt: Face ID is off", messageBody("Face ID is off", "Holdt can’t approve connections until Face ID is turned on. Nothing was shared.", { owner: '<ol><li>On the computer where you set up Holdt, set <code>PASSKEYS = "on"</code> in <code>wrangler.toml</code>.</li><li>Run this to deploy:<code>npm run deploy</code></li><li>Run this to turn on Face\u00a0ID:<code>npm run add-device</code></li></ol>' }), 400, o.headers);
  if (!pk) return page(CONSENT_TITLE, noDeviceBody(details, handle, writes, o.error ?? "", isPhone(req)), o.status ?? 200, o.headers, o.redirectUri, READY_SCRIPT);
  const from = whereFrom(req);
  const app = { clientName: details.clientName, clientDomain: details.clientDomain, redirectHost: details.redirectHost, redirectIsLoopback: details.redirectIsLoopback, redirectUri: details.redirectUri ?? o.redirectUri };
  const away = await createConsentAway(env, handle, from, app, writes);
  return page(CONSENT_TITLE, consentFaceBody(details, handle, writes, pk, `${url.origin}/ok#${away.secret}`, notice, o.error ?? "", isPhone(req)), o.status ?? 200, o.headers, o.redirectUri, CONSENT_SCRIPT);
}
/** A plain message screen for end states (see endScreen in ui.ts). */
export const messageBody = endScreen;

export async function authorizeHandler(req: Request, env: Env): Promise<Response> {
  registerEnvSecrets(env);
  const url = new URL(req.url);
  if (url.pathname === "/enroll" && req.method === "GET") return enrollPage(env, url, isPhone(req));
  if (url.pathname.startsWith("/enroll/")) return enrollApi(req, env);
  // GETs here are static pages: nothing is read, spent or decided until our own script POSTs after a tap.
  if (url.pathname === "/ok" && req.method === "GET") return okPage();
  if (url.pathname === "/pair" && req.method === "GET") return pairPage(env, url);
  if (url.pathname.startsWith("/ok/") || url.pathname.startsWith("/pair/") || url.pathname === "/authorize/away") return awayApi(req, env);
  if (url.pathname === "/authorize/away/new" || url.pathname === "/authorize/ready") return consentApi(req, env, url);
  if (url.pathname !== "/authorize") return new Response("Not found", { status: 404, headers: SEC_HEADERS });
  const oauth = (env as any).OAUTH_PROVIDER;
  try {
    if (req.method === "GET") {
      const request = await oauth.parseAuthRequest(req);
      if (!redirectAllowed(request.redirectUri) || !redirectListed(env, request.redirectUri) || !clientListed(env, request.clientId)) return page("Holdt: Can't connect", messageBody("This app can’t connect", `It wanted access sent to <strong>${esc(hostOf(request.redirectUri))}</strong>, which Holdt isn’t set up to allow. Nothing was shared.`, { html: true, owner: `If you trust this app, on the computer where you set up Holdt:<ol><li>Add this callback to <code>REDIRECT_ALLOWLIST</code> in <code>wrangler.toml</code>.<code>${esc(request.redirectUri.slice(0, 200))}</code></li><li>Run this to deploy.<code>npm run deploy</code></li></ol>` }), 400);
      const details = await oauth.describeConsent(request);
      const consent = await oauth.beginConsent(request);
      (details as any).__ctx = await signCtx(env, { clientName: details.clientName, clientDomain: details.clientDomain, redirectHost: details.redirectHost, redirectIsLoopback: details.redirectIsLoopback, redirectUri: request.redirectUri });
      (details as any).redirectUri = request.redirectUri;
      return renderConsent(env, req, url, details, consent.handle, { headers: consent.headers, redirectUri: request.redirectUri });
    }
    if (req.method !== "POST") return new Response(null, { status: 405, headers: SEC_HEADERS });
    const form = await req.formData();
    const handle = String(form.get("handle") ?? "");
    // The Face ID button and the iPhone approval submit from script, so no button value comes with them. A clicked Don't allow always wins.
    // Without script, "I approved on my iPhone" sends decision=away.
    const viaPasskey = !form.get("decision") && !!form.get("pk_sig");
    const viaAway = !viaPasskey && (form.get("decision") === "away" || (!form.get("decision") && form.get("away") === "1"));
    if (!viaPasskey && !viaAway && form.get("decision") !== "approve") {
      const denied = await oauth.denyConsent(req, handle);
      return new Response(null, { status: 302, headers: denied.headers });
    }
    const f = (k: string) => String(form.get(k) ?? "");
    // A reviewer code (RVW...) is checked on its own path: multi-use, and it never charges the owner's code tries.
    const viaReviewer = !viaPasskey && !viaAway && looksLikeReviewerCode(f("code"));
    const rv = viaReviewer ? await checkReviewerCode(env, f("code")) : undefined;
    const verdict = viaAway ? await takeConsentAway(env, handle) : viaPasskey ? await checkPasskeyLogin(env, url, handle, { token: f("pk_token"), id: f("pk_id"), clientDataJSON: f("pk_cdj"), authenticatorData: f("pk_ad"), signature: f("pk_sig") }) : rv ? (rv.ok ? { ok: true as const, hash: "" } : rv) : await checkCode(env, f("code"));
    if (!verdict.ok) {
      log.warn(`${viaAway ? "iPhone approval" : viaPasskey ? "passkey" : viaReviewer ? "reviewer code" : "approval code"} rejected: ${verdict.reason.slice(0, 80)}`);
      const ctxRaw = String(form.get("ctx") ?? "");
      const details: any = (await readCtx(env, ctxRaw)) ?? { clientName: "the app", redirectHost: "" };
      details.__ctx = ctxRaw;
      if (!viaPasskey && !viaAway && verdict.reason === "used") { const known = details.redirectUri ? knownApp(details.redirectUri) : undefined; return page("Holdt: Already connected", messageBody(known ? `${known} is already connected` : "You’re already connected", known ? `You said yes earlier. Close this page to go back to ${known}.` : "You said yes earlier. Close this page to go back to your assistant.", { mark: "closed", noClose: true }), 400); }
      // A fresh challenge (and a fresh QR code) for the retry: the old ones are spent, whether or not they verified.
      const pkError = viaAway ? (verdict.reason === "pending" ? "Not approved yet.\nScan the code with your iPhone, then approve with Face\u00a0ID." : verdict.reason === "denied" ? "Your iPhone said no.\nScan the new code to try again." : "That approval expired.\nScan the new code with your iPhone.") : verdict.message;
      return renderConsent(env, req, url, details, handle, { status: 400, redirectUri: details.redirectUri ?? "", error: pkError, errorFrom: viaPasskey || viaAway ? "pk" : "code", reason: verdict.reason, typed: f("code") });
    }
    const approved = await oauth.approveConsent(req, handle, { scope: ["calendar"] });
    if (!redirectAllowed(approved.request.redirectUri) || !redirectListed(env, approved.request.redirectUri) || !clientListed(env, approved.request.clientId)) return page("Holdt: Can't connect", messageBody("This app can’t connect", "Nothing was shared."), 400);
    const props = rv?.ok ? { epoch: env.GRANT_EPOCH, ...rv.props } : { epoch: env.GRANT_EPOCH };
    const { redirectTo } = await oauth.completeAuthorization({ request: approved.request, userId: rv?.ok ? "reviewer" : "owner", metadata: { label: rv?.ok ? "Grok Bot (reviewer)" : "Grok Bot" }, scope: approved.request.scope, props });
    log.info(rv?.ok ? "connection approved (reviewer code)" : viaAway ? "connection approved (on another device)" : "connection approved");
    approved.headers.set("Location", redirectTo);
    return new Response(null, { status: 302, headers: approved.headers });
  } catch (e) {
    if (e instanceof AuthorizationError && (e as any).redirectTo && redirectAllowed((e as any).redirectTo)) return Response.redirect((e as any).redirectTo, 302);
    if (e instanceof AuthorizationError) return page("Holdt: Page expired", messageBody("This page expired", "Nothing was shared. Ask your assistant to connect again for a fresh page."), 400);
    const ref = crypto.randomUUID().slice(0, 6).toUpperCase();
    log.error(`authorize failed (ref ${ref})`, e);
    return page("Holdt: Couldn’t finish", messageBody("Holdt couldn’t finish connecting", "Something went wrong on your Holdt server. Ask your assistant to connect again.", { owner: `In the Cloudflare dashboard, open Workers, then your Holdt Worker, then Logs, and search for <span class="ref">${esc(ref)}</span>.` }), 500);
  }
}

async function noticeFor(env: Env) { try { return passkeysOn(env) ? deviceNotice(await loadPasskeys(env), env.TIMEZONE || "UTC") : undefined; } catch { return undefined; } }
const ADD_DEVICE_HELP = "On the computer where you set up Holdt, run this for a new link. It opens in that computer’s browser:<code>npm run add-device</code>";
const ADD_DEVICE_HELP_QR = "On the computer where you set up Holdt, run this, then scan the QR code it shows with this device:<code>npm run add-device -- --qr</code>";
async function enrollPage(env: Env, url: URL, phone = false): Promise<Response> {
  const addHelp = phone ? ADD_DEVICE_HELP_QR : ADD_DEVICE_HELP;
  if (!passkeysOn(env)) return page("Holdt: Face ID is off", `<div data-bio>${messageBody("Face ID is off", "Face\u00a0ID setup is turned off on your Holdt server. Setup help shows how to turn it on.", { owner: '<ol><li>On the computer where you set up Holdt, set <code>PASSKEYS = "on"</code> in <code>wrangler.toml</code>.</li><li>Run this to deploy:<code>npm run deploy</code></li><li>Run this for a new link:<code>npm run add-device</code></li></ol>' })}</div>`, 404);
  const setup = screen({ title: "Turn on Face ID", lede: "Approve Holdt connections with a glance. There’s nothing to type.", markId: "mk",
    body: `<ul class="facts" role="list"><li>${ICON.faceId}<p id="face1">Your face stays on your device. Holdt never sees it.</p></li><li>${ICON.devices}<p>Syncs to your other Apple devices with iCloud\u00a0Keychain.</p></li><li>${ICON.link}<p>This link works once, for 10\u00a0minutes.</p></li></ul>`,
    actions: `<button type="button" class="btn primary" id="go">${ICON.faceId}${ICON.spinner}<span>Turn on Face ID</span></button><p class="status" id="msg" aria-hidden="true">${ICON.info}<span class="st"></span></p><p class="sr" id="live" role="status" aria-live="polite"></p>
<button type="button" class="btn plain quiet" id="later">Not now</button>` });
  return page("Holdt: Turn on Face ID", `<div id="setup">${setup}</div>
<div id="done" hidden>${screen({ title: "Face ID is on", titleId: "title-done", lede: "Next time, tap Allow with Face\u00a0ID. With iCloud Keychain on, your other Apple devices can use it too.", markState: "open", markId: "mkdone", centered: true, actions: `<div class="next" id="next" hidden><p>Last step. In Grok Bot, say:</p><p class="say" id="say"><span>Add the MCP server at</span> <span class="url">${esc(url.origin)}/mcp</span></p><button type="button" class="btn plain" id="copy" aria-label="Copy the message for Grok Bot">${ICON.copy}<span>Copy</span></button><p class="sr" id="copylive" role="status" aria-live="polite"></p></div><p class="foot" id="closeline">You can close this page.</p>` })}</div>
<div id="skip" hidden>${screen({ title: "Face ID not turned on", titleId: "title-skip", lede: "Holdt needs Face ID to approve connections. Turn it on whenever you’re ready.", markState: "muted", centered: true, actions: `<p class="foot">You can close this page.</p>${ownerNote(HELP, addHelp)}` })}</div>
<div id="dead" hidden>${screen({ title: "This link expired", titleId: "title-dead", lede: "Links last 10 minutes. Make a new one on the computer where you set up Holdt.", markState: "muted", centered: true, actions: `<p class="foot">You can close this page.</p>${ownerNote(HELP, addHelp)}` })}</div>`, 200, undefined, "", ENROLL_SCRIPT);
}

/** The approving device (an iPhone with Holdt's passkey) opens /ok#<secret>. The page is the same for everyone and
 * changes nothing: the script reads the request with a POST, and only a tap plus Face ID approves it. */
function okPage(): Response {
  const v = (id: string, o: Parameters<typeof screen>[0]) => `<div id="${id}" hidden>${screen(o)}</div>`;
  const close = `<p class="foot">You can close this page.</p>`;
  return page("Holdt: Approve", `<div id="load">${screen({ title: "Checking the request", titleId: "t-load", markState: "open", centered: true, actions: `<noscript><p class="foot">Turn on JavaScript in Safari settings to approve with Face\u00a0ID.</p></noscript>` })}</div>
<div id="ask" hidden></div>
${v("ok", { title: "Approved", titleId: "t-ok", lede: "The device that asked finishes on its own. There’s nothing more to do here.", markState: "open", markId: "mkok", centered: true, actions: close })}
${v("no", { title: "Not allowed", titleId: "t-no", lede: "Nothing was shared.", markState: "muted", centered: true, actions: close })}
${v("dead", { title: "This request expired", titleId: "t-dead", lede: "Requests last 5 minutes. Start again on the device that asked.", markState: "muted", centered: true, actions: close })}
${v("nopk", { title: "This device can’t approve yet", titleId: "t-nopk", lede: "It doesn’t have Face ID for Holdt. Scan the code with the device where you turned it on.", markState: "muted", centered: true, actions: close + ownerNote(HELP, ADD_DEVICE_HELP_QR) })}`, 200, undefined, "", OK_SCRIPT);
}
/** What the approving device shows, built on the server from the stored request (every value escaped). */
export function askHtml(kind: "consent" | "pair", from: string, when: string, app: any, writes: string) {
  const btns = `<button type="button" class="btn primary" id="yes">${ICON.faceId}${ICON.spinner}<span id="yeslabel">Allow with Face ID</span></button>
<p class="status" id="askmsg" aria-hidden="true">${ICON.info}<span class="st"></span></p><p class="sr" id="live" role="status" aria-live="polite"></p>
<button type="button" class="btn plain quiet" id="nope">Don’t allow</button>`;
  // Where the request came from leads, in the same words on both kinds, and never breaks across lines.
  const place = esc(from).replace(/ /g, "\u00a0");
  const asked = `From <strong>${place}</strong>, ${esc(when)}.`;
  if (kind === "pair") return screen({ title: "Add a new device?", lede: `${asked} It wants to approve Holdt connections with Face\u00a0ID.`, markId: "mk",
    body: `<div class="callout">${ICON.alert}<p>Allow this only for a device you’re holding right now. Never for one someone asked you to add.</p></div>`, actions: btns });
  const { who, body } = consentFacts(app ?? {}, writes || "off, so it can't add or change events", undefined, app?.redirectIsLoopback ? "" : `<div class="callout">${ICON.alert}<p>Approve only a request you just started yourself. Never one someone sent you.</p></div>`, true);
  // The name line keeps the same trust rule as the consent page: vouched for only on Grok Bot's exact callback.
  const trust = who.known ? `Access goes to ${esc(String(knownApp(app.redirectUri) ?? "")).replace(/ /g, "\u00a0")} alone.` : who.lede.replace(/ Allow this only if you just asked it to connect\.$/, "");
  return screen({ title: who.title, lede: `${asked} ${trust}`, markId: "mk", body, actions: btns });
}

/** A new device asks to be added. It shows a QR code for an enrolled device to approve, then makes its own passkey. */
function pairPage(env: Env, url: URL): Response {
  void url;
  if (!passkeysOn(env)) return page("Holdt: Face ID is off", messageBody("Face ID is off", "Face ID is turned off on this Holdt server, so a device can’t be added.", {}), 404);
  const close = `<p class="foot">You can close this page.</p>`;
  const v = (id: string, o: Parameters<typeof screen>[0]) => `<div id="${id}" hidden>${screen(o)}</div>`;
  return page("Holdt: Add this device", `<div id="ask">${screen({ title: "Add this device", lede: "Approve it from the iPhone where Face\u00a0ID for Holdt is already on.", markId: "mk",
    body: `<div class="awaybox lone" id="awaypanel"><div id="qrwrap" class="qrwait"></div>
<ol class="steps"><li>Scan this code with your\u00a0iPhone.</li><li>Tap the Holdt link, then approve with Face\u00a0ID.</li></ol>
<p class="status wait" id="awaymsg" aria-hidden="true">${ICON.spinner}<span class="st">Waiting for your iPhone.</span></p><noscript><p class="foot">Turn on JavaScript to add this device.</p></noscript></div>`,
    actions: `<p class="sr" id="live" role="status" aria-live="polite"></p><button type="button" class="btn plain quiet" id="later">Not now</button>` })}</div>
${v("ready", { title: "Turn on Face ID", titleId: "t-ready", lede: "Your iPhone approved this device. Finish here with a glance.", markId: "mkready",
    actions: `<button type="button" class="btn primary" id="go">${ICON.faceId}${ICON.spinner}<span>Turn on Face ID</span></button><p class="status" id="msg" aria-hidden="true">${ICON.info}<span class="st"></span></p><p class="sr" id="live2" role="status" aria-live="polite"></p><button type="button" class="btn plain quiet" id="later2">Not now</button>` })}
${v("done", { title: "Face ID is on", titleId: "t-done", lede: "Next time, tap Allow with Face ID on this device.", markState: "open", markId: "mkdone", centered: true, actions: close })}
${v("no", { title: "Device not added", titleId: "t-no", lede: "Your iPhone said no. Nothing changed.", markState: "muted", centered: true, actions: close })}
${v("skip", { title: "Device not added", titleId: "t-skip", lede: "You can add it anytime from this page.", markState: "muted", centered: true, actions: close })}
${v("dead", { title: "This request expired", titleId: "t-dead", lede: "Requests last 5 minutes. Reload this page to start again.", markState: "muted", centered: true, actions: close })}
${v("nopk", { title: "Turn on Face ID first", titleId: "t-nopk", lede: "No device has Face ID for Holdt yet. Turn it on first with Setup help below.", markState: "muted", centered: true, actions: close + ownerNote(HELP, ADD_DEVICE_HELP_QR, true) })}`, 200, undefined, "", PAIR_SCRIPT);
}

/** The consent page's own calls: a fresh QR code when the old one ran out, and "is Face ID on yet". Same-origin JSON only. */
async function consentApi(req: Request, env: Env, url: URL): Promise<Response> {
  const bad = sameOriginJson(req, url); if (bad) return bad;
  let b: any; try { b = await readJson(req); } catch { return json({ ok: false }, 400); }
  if (url.pathname === "/authorize/ready") { let ready = false; try { ready = passkeysOn(env) && usableHere(await loadPasskeys(env), url).length > 0; } catch { /* not yet */ } return json({ ok: true, ready }); }
  const handle = String(b?.handle ?? ""), d = await readCtx(env, String(b?.ctx ?? ""));
  if (!handle || !d || !passkeysOn(env)) return json({ ok: false }, 400);
  const away = await createConsentAway(env, handle, whereFrom(req), d, writesFor(env));
  const link = `${url.origin}/ok#${away.secret}`;
  return json({ ok: true, link, qr: qrSvg(link, "QR code. Scan it with your iPhone’s camera to approve there.") });
}

type Verdict = { ok: true; hash: string } | { ok: false; reason: string; message: string };
// Code checks run one at a time per isolate, and each try is charged and the code is spent inside that turn,
// so simultaneous guesses can't read a stale counter and one code can't approve two connections.
let codeQueue: Promise<unknown> = Promise.resolve();
export function checkCode(env: Env, raw: string, now = Date.now()): Promise<Verdict> {
  const run = codeQueue.then(() => checkCodeOnce(env, raw, now));
  codeQueue = run.catch(() => undefined);
  return run;
}
export const CODE_SALT = "icloud-mcp-approval:";
/** APPROVAL_CODE_HASH is "pbkdf2$<iterations>$<salt>$<hex>" (setup writes this: a random salt per code and PBKDF2-SHA256,
 * so a leaked hash can't be reversed with a lookup table) or, from older setups, a bare SHA-256 hex. Constant-time compare. */
/** Counts PBKDF2 runs, for the test that a dead code costs none. */
export const codeStats = { pbkdf2: 0 };
export async function codeMatches(stored: string, code: string): Promise<boolean> {
  let given: string, want: string;
  const m = stored.match(/^pbkdf2\$(\d{4,6})\$([A-Za-z0-9_-]{16,64})\$([0-9a-f]{64})$/);
  if (m) {
    codeStats.pbkdf2++;
    const it = Math.min(Number(m[1]), 100_000); const salt = Uint8Array.from(atob(m[2]!.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(code), "PBKDF2", false, ["deriveBits"]);
    given = [...new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: it }, k, 256))].map((b) => b.toString(16).padStart(2, "0")).join(""); want = m[3]!;
  } else { given = await sha256Hex(`${CODE_SALT}${code}`); want = stored; }
  let diff = given.length ^ want.length; for (let i = 0; i < Math.min(given.length, want.length); i++) diff |= given.charCodeAt(i) ^ want.charCodeAt(i);
  return diff === 0;
}
async function checkCodeOnce(env: Env, raw: string, now: number): Promise<Verdict> {
  const g = guardFor(env);
  if (g && env.APPROVAL_CODE_HASH && env.APPROVAL_CODE_ISSUED) {
    // Atomic across isolates: the Durable Object decides used / locked / spent / charged in one step.
    const hash = env.APPROVAL_CODE_HASH;
    if (now - Number(env.APPROVAL_CODE_ISSUED) > CODE_TTL_MS) return { ok: false, reason: "expired", message: "That code expired. Get a new one on the computer where you set up Holdt." };
    // Refuse a used or locked code before PBKDF2, so a flood of tries against a dead code costs no hashing CPU.
    const state = await g.codeState(hash, MAX_TRIES);
    if (state === "locked") return { ok: false, reason: "locked", message: "Too many wrong tries, so this code is now blocked. Get a new one on the computer where you set up Holdt." };
    if (state === "used") return { ok: false, reason: "used", message: "That code was already used. Get a new one on the computer where you set up Holdt." };
    const code = normalizeCode(raw);
    const v = await g.codeTry(hash, code.length === 8 && (await codeMatches(hash, code)), MAX_TRIES);
    if (v.ok) { await env.OAUTH_KV.put(`approval-used:${hash}`, "1", { expirationTtl: 86400 }); return { ok: true, hash }; }
    if (v.reason === "locked") return { ok: false, reason: "locked", message: "Too many wrong tries, so this code is now blocked. Get a new one on the computer where you set up Holdt." };
    if (v.reason === "used") return { ok: false, reason: "used", message: "That code was already used. Get a new one on the computer where you set up Holdt." };
    return { ok: false, reason: "wrong", message: v.left > 0 ? (v.left === 1 ? "That code doesn't match. 1 try left, then you'll need a new code." : `That code doesn't match. ${v.left} tries left.`) : "That code doesn't match, so it's now blocked. Get a new one on the computer where you set up Holdt." };
  }
  if (!env.APPROVAL_CODE_HASH || !env.APPROVAL_CODE_ISSUED) return { ok: false, reason: "none", message: "No approval code is set yet. Get one on the computer where you set up Holdt." };
  const hash = env.APPROVAL_CODE_HASH;
  const failKey = `approval-fail:${hash}`;
  const fails = Number((await env.OAUTH_KV.get(failKey)) ?? 0);
  if (fails >= MAX_TRIES) return { ok: false, reason: "locked", message: "Too many wrong tries, so this code is now blocked. Get a new one on the computer where you set up Holdt." };
  if (await env.OAUTH_KV.get(`approval-used:${hash}`)) return { ok: false, reason: "used", message: "That code was already used. Get a new one on the computer where you set up Holdt." };
  if (now - Number(env.APPROVAL_CODE_ISSUED) > CODE_TTL_MS) return { ok: false, reason: "expired", message: "That code expired. Get a new one on the computer where you set up Holdt." };
  const code = normalizeCode(raw);
  if (code.length === 8 && (await codeMatches(hash, code))) { await env.OAUTH_KV.put(`approval-used:${hash}`, "1", { expirationTtl: 86400 }); return { ok: true, hash }; }
  {
    await env.OAUTH_KV.put(failKey, String(fails + 1), { expirationTtl: 86400 });
    const left = MAX_TRIES - fails - 1;
    return { ok: false, reason: "wrong", message: left > 0 ? (left === 1 ? "That code doesn't match. 1 try left, then you'll need a new code." : `That code doesn't match. ${left} tries left.`) : "That code doesn't match, so it's now blocked. Get a new one on the computer where you set up Holdt." };
  }
}

// The re-shown page (after a wrong code) needs the client's name. Carry it in an HMAC-signed field
// so a forged form can't make the page lie about who is asking.
async function mac(env: Env, data: string) {
  const k = await crypto.subtle.importKey("raw", await subkey(env.CONFIRM_SECRET, "holdt/consent-ctx/v1"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return [...new Uint8Array(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(data)))].map((b) => b.toString(16).padStart(2, "0")).join("");
}
const safeEq = (a: string, b: string) => { let d = a.length ^ b.length; for (let i = 0; i < Math.min(a.length, b.length); i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
async function signCtx(env: Env, o: object) { const d = btoa(unescape(encodeURIComponent(JSON.stringify(o)))); return `${d}.${await mac(env, d)}`; }
async function readCtx(env: Env, s: string) { const [d, m] = s.split("."); if (!d || !m || !safeEq(m, await mac(env, d))) return undefined; try { return JSON.parse(decodeURIComponent(escape(atob(d)))); } catch { return undefined; } }

/** A separate key per purpose, derived from CONFIRM_SECRET (HMAC as a KDF), so a token for one purpose can never verify as another. */
export async function subkey(secret: string, label: string): Promise<ArrayBuffer> {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", k, new TextEncoder().encode(label));
}
