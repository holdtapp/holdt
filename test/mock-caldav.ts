// In-memory mock of iCloud CalDAV, including the quirks we know about:
// well-known redirect, numeric principal path, Depth:1 REPORT returning a 404 propstat
// for the collection itself, read-only subscribed calendars, ETags, If-Match/If-None-Match.
import http from "node:http";

export interface Item { ics: string; etag: number }
export interface MockOpts { user: string; pass: string }
export class MockCalDav {
  server!: http.Server; port = 0; requests: { method: string; url: string; headers: http.IncomingHttpHeaders; body: string }[] = [];
  fail: { status: number; times: number; methods?: string[]; retryAfter?: string } | null = null;
  items = new Map<string, Item>(); etagSeq = 1;
  /** Simulates iCloud: what it stores is a rewrite of what was PUT, under a newer ETag than the PUT response named. */
  onPut: ((ics: string) => string) | null = null;
  cols: Record<string, { name: string; comps: string[]; readOnly?: boolean; color?: string }> = {
    "home": { name: "Home", comps: ["VEVENT"], color: "#34AADC" },
    "work": { name: "Work", comps: ["VEVENT"], color: "#FF2968" },
    "holidays": { name: "US Holidays", comps: ["VEVENT"], readOnly: true },
    "tasks": { name: "Groceries", comps: ["VTODO"] },
  };
  constructor(public o: MockOpts) {}
  get base() { return `http://127.0.0.1:${this.port}/`; }
  add(col: string, name: string, ics: string) { this.items.set(`/123456789/calendars/${col}/${name}`, { ics, etag: this.etagSeq++ }); }
  async start() {
    this.server = http.createServer((req, res) => {
      let body = ""; req.on("data", (c) => (body += c)); req.on("end", () => this.handle(req, res, body));
    });
    await new Promise<void>((r) => this.server.listen(0, "127.0.0.1", () => r()));
    this.port = (this.server.address() as any).port;
  }
  stop() { return new Promise<void>((r) => this.server.close(() => r())); }
  private handle(req: http.IncomingMessage, res: http.ServerResponse, body: string) {
    this.requests.push({ method: req.method!, url: req.url!, headers: req.headers, body });
    const send = (s: number, b = "", h: Record<string, string> = {}) => { res.writeHead(s, h); res.end(b); };
    if (this.fail && this.fail.times > 0 && (!this.fail.methods || this.fail.methods.includes(req.method!))) { this.fail.times--; return send(this.fail.status, "", this.fail.retryAfter ? { "Retry-After": this.fail.retryAfter } : {}); }
    const want = "Basic " + Buffer.from(`${this.o.user}:${this.o.pass}`).toString("base64");
    if (req.headers.authorization !== want) return send(401, "", { "WWW-Authenticate": 'Basic realm="iCloud"' });
    const url = new URL(req.url!, this.base); const p = decodeURIComponent(url.pathname);
    const ms = (inner: string) => send(207, `<?xml version="1.0" encoding="UTF-8"?><multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CS="http://calendarserver.org/ns/" xmlns:ICAL="http://apple.com/ns/ical/">${inner}</multistatus>`, { "Content-Type": "text/xml; charset=utf-8" });
    if (p === "/.well-known/caldav") return send(301, "", { Location: "/" });
    if (req.method === "PROPFIND" && (p === "/" || p === "")) return ms(`<response><href>/</href><propstat><prop><current-user-principal><href>/123456789/principal/</href></current-user-principal></prop><status>HTTP/1.1 200 OK</status></propstat></response>`);
    if (req.method === "PROPFIND" && p === "/123456789/principal/") return ms(`<response><href>/123456789/principal/</href><propstat><prop><C:calendar-home-set><href xmlns="DAV:">${this.base}123456789/calendars/</href></C:calendar-home-set></prop><status>HTTP/1.1 200 OK</status></propstat></response>`);
    if (req.method === "PROPFIND" && p === "/123456789/calendars/") {
      let out = `<response><href>/123456789/calendars/</href><propstat><prop><resourcetype><collection/></resourcetype></prop><status>HTTP/1.1 200 OK</status></propstat></response>`;
      out += `<response><href>/123456789/calendars/inbox/</href><propstat><prop><resourcetype><collection/><C:schedule-inbox/></resourcetype></prop><status>HTTP/1.1 200 OK</status></propstat></response>`;
      for (const [id, c] of Object.entries(this.cols)) {
        const priv = c.readOnly ? `<privilege><read/></privilege>` : `<privilege><read/></privilege><privilege><write/></privilege>`;
        out += `<response><href>/123456789/calendars/${id}/</href><propstat><prop><resourcetype><collection/><C:calendar/></resourcetype><displayname>${c.name.replace(/&/g, "&amp;")}</displayname>${c.color ? `<ICAL:calendar-color>${c.color}</ICAL:calendar-color>` : ""}<C:supported-calendar-component-set>${c.comps.map((x) => `<C:comp name="${x}"/>`).join("")}</C:supported-calendar-component-set><CS:getctag>1</CS:getctag><current-user-privilege-set>${priv}</current-user-privilege-set></prop><status>HTTP/1.1 200 OK</status></propstat><propstat><prop><x/></prop><status>HTTP/1.1 404 Not Found</status></propstat></response>`;
      }
      return ms(out);
    }
    const colM = p.match(/^\/123456789\/calendars\/([^/]+)\/$/);
    if (req.method === "REPORT" && colM) {
      const comp = /comp-filter name="(VEVENT|VTODO)"/.exec(body)?.[1];
      // iCloud quirk: the collection itself comes back with a 404 calendar-data propstat
      let out = `<response><href>${p}</href><propstat><prop><C:calendar-data/></prop><status>HTTP/1.1 404 Not Found</status></propstat></response>`;
      for (const [k, v] of this.items) if (k.startsWith(p) && v.ics.includes(`BEGIN:${comp}`)) out += `<response><href>${k}</href><propstat><prop><getetag>"${v.etag}"</getetag><C:calendar-data>${v.ics.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</C:calendar-data></prop><status>HTTP/1.1 200 OK</status></propstat></response>`;
      return ms(out);
    }
    const it = this.items.get(p);
    if (req.method === "GET") return it ? send(200, it.ics, { ETag: `"${it.etag}"`, "Content-Type": "text/calendar" }) : send(404);
    if (req.method === "PUT") {
      const col = p.split("/")[3]!; if (!this.cols[col]) return send(404); if (this.cols[col]!.readOnly) return send(403);
      if (req.headers["if-none-match"] === "*" && it) return send(412);
      if (req.headers["if-match"] && (!it || req.headers["if-match"] !== `"${it.etag}"`)) return send(412);
      const n = { ics: body, etag: this.etagSeq++ }; this.items.set(p, n);
      if (this.onPut) this.items.set(p, { ics: this.onPut(body), etag: this.etagSeq++ });
      return send(it ? 204 : 201, "", { ETag: `"${n.etag}"` });
    }
    if (req.method === "DELETE") { if (!it) return send(404); if (!req.headers["if-match"] || req.headers["if-match"] !== `"${it.etag}"`) return send(412); this.items.delete(p); return send(204); }
    return send(405);
  }
}
