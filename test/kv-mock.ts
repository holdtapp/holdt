// Minimal Workers KV mock: get (text/json), put (expirationTtl, metadata), delete, list (prefix, cursor, limit).
export class MockKV {
  m = new Map<string, { v: string; exp?: number; meta?: unknown }>();
  now = () => Date.now();
  private live(k: string) { const e = this.m.get(k); if (e && e.exp && e.exp <= this.now()) { this.m.delete(k); return undefined; } return e; }
  async get(k: string, o?: { type?: string } | string) { const e = this.live(k); if (!e) return null; const t = typeof o === "string" ? o : o?.type; return t === "json" ? JSON.parse(e.v) : e.v; }
  async getWithMetadata(k: string, o?: any) { const e = this.live(k); return { value: e ? await this.get(k, o) : null, metadata: e?.meta ?? null }; }
  async put(k: string, v: string, o: { expirationTtl?: number; expiration?: number; metadata?: unknown } = {}) {
    const exp = o.expirationTtl ? this.now() + o.expirationTtl * 1000 : o.expiration ? o.expiration * 1000 : undefined;
    this.m.set(k, { v: typeof v === "string" ? v : JSON.stringify(v), exp, meta: o.metadata });
  }
  async delete(k: string) { this.m.delete(k); }
  async list(o: { prefix?: string; cursor?: string; limit?: number } = {}) {
    const keys = [...this.m.keys()].filter((k) => this.live(k) && k.startsWith(o.prefix ?? "")).sort();
    const start = o.cursor ? Number(o.cursor) : 0, lim = o.limit ?? 1000; const page = keys.slice(start, start + lim);
    const done = start + lim >= keys.length;
    return { keys: page.map((name) => ({ name, metadata: this.m.get(name)?.meta, expiration: this.m.get(name)?.exp ? Math.floor(this.m.get(name)!.exp! / 1000) : undefined })), list_complete: done, cursor: done ? undefined : String(start + lim) };
  }
}
