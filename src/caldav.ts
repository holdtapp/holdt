import { parseXml, all, first, kids, textOf, escapeXml, XNode } from "./xml.js";
import { log } from "./redact.js";

export type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body?: string; redirect?: "manual" | "follow" }) => Promise<{ status: number; headers: { get(n: string): string | null }; text(): Promise<string> }>;

export class CalDavError extends Error {
  constructor(public code: "authentication" | "not_found" | "conflict" | "rate_limited" | "unavailable" | "outcome_unknown" | "bad_response" | "forbidden" | "network", message: string, public retryAfter?: number) { super(message); }
}

export interface Collection { id: string; href: string; name: string; color?: string; components: string[]; writable: boolean; ctag?: string }
export interface Resource { href: string; etag: string; ics: string }

export interface CalDavOptions { baseUrl: string; username: string; password: string; fetch?: FetchLike; maxRetries?: number; sleep?: (ms: number) => Promise<void>; timeoutMs?: number }

/** Discovered calendar homes, per isolate. Saves two PROPFIND round trips on every tool call. Holds URLs only, never credentials. */
const HOMES = new Map<string, { home: string; exp: number }>();
const HOME_TTL_MS = 30 * 60_000;
export const USER_AGENT = "Holdt/0.1.0";

export class CalDavClient {
  static clearDiscoveryCache() { HOMES.clear(); }
  private auth: string; private f: FetchLike; private home?: string; private origin?: string;
  constructor(private o: CalDavOptions) {
    this.auth = "Basic " + btoa(unescape(encodeURIComponent(`${o.username}:${o.password}`)));
    this.f = o.fetch ?? (((u: string, i: any) => globalThis.fetch(u, i)) as unknown as FetchLike);
  }
  private abs(href: string, base: string) { return new URL(href, base).toString(); }

  private async req(method: string, url: string, body?: string, headers: Record<string, string> = {}, safe = true): Promise<{ status: number; text: string; headers: { get(n: string): string | null }; url: string }> {
    const max = safe ? (this.o.maxRetries ?? 3) : 1; const sleep = this.o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    let lastErr: CalDavError | undefined; let redirects = 0;
    this.assertTrustedHost(url);
    for (let attempt = 0; attempt < max; attempt++) {
      let res;
      try {
        res = await withTimeout(this.f(url, { method, redirect: "manual", headers: { Authorization: this.auth, "Content-Type": "application/xml; charset=utf-8", "User-Agent": USER_AGENT, ...headers }, body }), this.o.timeoutMs ?? 25000);
      } catch (e) {
        log.warn(`caldav ${method} fetch failed: ${(e as any)?.name ?? "error"}: ${String((e as any)?.message ?? "").slice(0, 120)}`);
        if (!safe) throw new CalDavError("outcome_unknown", "The change may or may not have been saved (network problem). Re-check before retrying.");
        lastErr = new CalDavError("network", "Couldn't reach iCloud."); await sleep(backoff(attempt)); continue;
      }
      if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
        if (++redirects > 5) throw new CalDavError("bad_response", "iCloud redirected too many times.");
        url = this.abs(res.headers.get("location")!, url); this.assertTrustedHost(url); attempt--; continue;
      }
      if (res.status === 401) throw new CalDavError("authentication", "iCloud refused the sign-in. The app-specific password may be wrong or revoked.");
      if (res.status === 403) throw new CalDavError("forbidden", "iCloud says this calendar can't be changed.");
      if (res.status === 404) throw new CalDavError("not_found", "That item no longer exists in iCloud.");
      if (res.status === 412) throw new CalDavError("conflict", "The event changed in iCloud since it was read. Read it again and retry.");
      if (res.status === 429 || res.status === 503 || res.status === 502 || res.status === 504) {
        const ra = Number(res.headers.get("retry-after")) || undefined;
        if (!safe) throw res.status === 429 ? new CalDavError("rate_limited", "iCloud is rate limiting. Nothing was changed.", ra ?? 5) : new CalDavError("outcome_unknown", "iCloud had a hiccup during the save. Re-check before retrying.");
        lastErr = new CalDavError(res.status === 429 ? "rate_limited" : "unavailable", "iCloud is busy right now. Try again shortly.", ra ?? 5);
        log.warn(`caldav ${method} status ${res.status} attempt ${attempt + 1}`);
        await sleep(Math.min((ra ?? 0) * 1000 || backoff(attempt), 8000)); continue;
      }
      if (res.status >= 400) throw new CalDavError("bad_response", `iCloud returned an unexpected error (${res.status}).`);
      return { status: res.status, text: await res.text(), headers: res.headers, url };
    }
    throw lastErr ?? new CalDavError("unavailable", "iCloud is unavailable.");
  }

  /** RFC 6764 discovery: well-known -> current-user-principal -> calendar-home-set (follows partition redirects). */
  private get cacheKey() { return `${this.o.baseUrl}\n${this.o.username}`; }
  async discover(): Promise<string> {
    if (this.home) return this.home;
    const hit = HOMES.get(this.cacheKey);
    if (hit && hit.exp > Date.now()) { this.home = hit.home; this.origin = new URL(hit.home).origin; return this.home; }
    const pf = `<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>`;
    let start = this.abs("/.well-known/caldav", this.o.baseUrl);
    let r = await this.req("PROPFIND", start, pf, { Depth: "0" });
    const principalHref = textOf(first(first(parseXml(r.text), "current-user-principal") ?? ({} as XNode), "href") as XNode);
    if (!principalHref) throw new CalDavError("bad_response", "iCloud didn't return an account principal.");
    const principal = this.abs(principalHref, r.url);
    const hs = `<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-home-set/></d:prop></d:propfind>`;
    r = await this.req("PROPFIND", principal, hs, { Depth: "0" });
    const homeHref = textOf(first(first(parseXml(r.text), "calendar-home-set") ?? ({} as XNode), "href") as XNode);
    if (!homeHref) throw new CalDavError("bad_response", "iCloud didn't return a calendar home.");
    this.home = this.abs(homeHref, r.url); this.origin = new URL(this.home).origin;
    HOMES.set(this.cacheKey, { home: this.home, exp: Date.now() + HOME_TTL_MS });
    return this.home;
  }

  async listCollections(): Promise<Collection[]> {
    const cached = !this.home && HOMES.has(this.cacheKey);
    try { return await this.listAt(await this.discover()); }
    catch (e) {
      // A cached home can go stale (Apple moved the account to another partition). Rediscover once.
      if (!cached || !(e instanceof CalDavError) || e.code === "authentication") throw e;
      HOMES.delete(this.cacheKey); this.home = undefined; this.origin = undefined;
      return this.listAt(await this.discover());
    }
  }
  private async listAt(home: string): Promise<Collection[]> {
    const body = `<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/" xmlns:ic="http://apple.com/ns/ical/"><d:prop><d:resourcetype/><d:displayname/><ic:calendar-color/><c:supported-calendar-component-set/><cs:getctag/><d:current-user-privilege-set/></d:prop></d:propfind>`;
    const r = await this.req("PROPFIND", home, body, { Depth: "1" });
    const out: Collection[] = [];
    for (const resp of all(parseXml(r.text), "response")) {
      const href = textOf(first(resp, "href"));
      const ok = okProps(resp); if (!ok) continue;
      const rt = first(ok, "resourcetype"); if (!rt || !first(rt, "calendar")) continue;
      const comps = all(ok, "comp").map((c) => (c.attrs.name ?? "").toUpperCase()).filter(Boolean);
      const privs = all(ok, "privilege").flatMap((p) => p.children.map((c) => c.name));
      const writable = privs.length === 0 ? true : privs.some((p) => p === "write" || p === "write-content" || p === "all");
      out.push({ id: idFromHref(href), href: this.abs(href, home), name: textOf(first(ok, "displayname")) || "Untitled", color: textOf(first(ok, "calendar-color")) || undefined, components: comps.length ? comps : ["VEVENT"], writable, ctag: textOf(first(ok, "getctag")) || undefined });
    }
    return out;
  }

  /** calendar-query REPORT. Skips non-200 propstats (iCloud returns a 404 propstat for the collection itself). */
  async query(collectionHref: string, comp: "VEVENT" | "VTODO", range?: { from: number; to: number }, extraFilter = ""): Promise<Resource[]> {
    const tr = range ? `<c:time-range start="${fmt(range.from)}" end="${fmt(range.to)}"/>` : "";
    const body = `<?xml version="1.0"?><c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/><c:calendar-data/></d:prop><c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="${comp}">${tr}${extraFilter}</c:comp-filter></c:comp-filter></c:filter></c:calendar-query>`;
    const r = await this.req("REPORT", collectionHref, body, { Depth: "1" });
    const out: Resource[] = [];
    for (const resp of all(parseXml(r.text), "response")) {
      const ok = okProps(resp); if (!ok) continue;
      const ics = textOf(first(ok, "calendar-data")); if (!ics) continue;
      out.push({ href: this.abs(textOf(first(resp, "href")), collectionHref), etag: textOf(first(ok, "getetag")), ics });
    }
    return out;
  }

  async get(href: string): Promise<Resource> {
    this.assertSameOrigin(href);
    const r = await this.req("GET", href, undefined, { Accept: "text/calendar" });
    return { href, etag: r.headers.get("etag") ?? "", ics: r.text };
  }
  /** Create (If-None-Match:*) or update (If-Match). Never retried: a write is attempted exactly once. */
  async put(href: string, ics: string, mode: { create: true } | { etag: string }): Promise<{ etag: string }> {
    this.assertSameOrigin(href);
    const h: Record<string, string> = { "Content-Type": "text/calendar; charset=utf-8" };
    if ("create" in mode) h["If-None-Match"] = "*"; else h["If-Match"] = mode.etag;
    const r = await this.req("PUT", href, ics, h, false);
    return { etag: r.headers.get("etag") ?? "" };
  }
  /** Remove one resource, only if it is still exactly the version we checked (If-Match). Never retried.
   * Only Holdt's undo calls this, for an event Holdt itself added in the last 24 hours. No tool exposes a general delete. */
  async deleteIfMatch(href: string, etag: string): Promise<void> {
    this.assertSameOrigin(href);
    if (!etag) throw new CalDavError("conflict", "Can't confirm the event is unchanged, so nothing was removed.");
    await this.req("DELETE", href, undefined, { "If-Match": etag }, false);
  }
  /** Credentials only ever go to the configured host or Apple's *.icloud.com partition hosts, over HTTPS (http allowed only for localhost tests). */
  private assertTrustedHost(url: string) {
    const u = new URL(url), b = new URL(this.o.baseUrl);
    const local = ["localhost", "127.0.0.1"].includes(u.hostname);
    const trusted = u.host === b.host || u.hostname === "icloud.com" || u.hostname.endsWith(".icloud.com");
    if (!trusted || (u.protocol !== "https:" && !local)) throw new CalDavError("forbidden", "Refusing to send your iCloud sign-in to an untrusted server.");
  }
  /** Refuse to send credentials anywhere except the discovered iCloud origin. */
  private assertSameOrigin(href: string) {
    const o = new URL(href).origin;
    if (this.origin && o !== this.origin) throw new CalDavError("forbidden", "Refusing to contact a server outside your iCloud calendar host.");
  }
}

function okProps(resp: XNode): XNode | undefined {
  for (const ps of kids(resp, "propstat")) { if (/\s200\s/.test(" " + textOf(first(ps, "status")) + " ")) return first(ps, "prop"); }
  return undefined;
}
const fmt = (ms: number) => new Date(ms).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
export const idFromHref = (href: string) => href.replace(/\/+$/, "").split("/").pop()!;
const backoff = (a: number) => Math.min(250 * 2 ** a + Math.floor(Math.random() * 100), 4000);
function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> { return new Promise((res, rej) => { const t = setTimeout(() => rej(new Error("timeout")), ms); p.then((v) => { clearTimeout(t); res(v); }, (e) => { clearTimeout(t); rej(e); }); }); }
export { escapeXml };
