// Holdt's change log. Every commit records what it did, and for an edit, the exact event as it was before.
// That is what undo restores. Holdt never deletes an event, except one it added itself in the last 24 hours,
// and only through prepare_undo then commit_undo after the user's yes.
export interface KVLike { get(k: string): Promise<string | null>; put(k: string, v: string, o?: { expirationTtl?: number }): Promise<unknown>; list(o: { prefix: string; limit?: number; cursor?: string }): Promise<{ keys: { name: string }[]; list_complete?: boolean; cursor?: string }> }
export interface Change { id: string; at: number; action: "create" | "update" | "undo"; cid: string; href: string; uid: string; title: string; before?: string; afterEtag: string; /** eventFingerprint of the event as iCloud stored it right after Holdt's write. Undo compares this, not the ETag. */ afterFp?: string; undone?: number; of?: string }

export const CHANGE_TTL_S = 30 * 86400, OWN_CREATE_TTL_S = 24 * 3600, REVERT_TTL_MS = 7 * 86400_000, MAX_BEFORE = 200_000;
const pad = (n: number) => String(n).padStart(13, "0");

export async function ownerKey(owner: string) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`holdt-owner:${owner.trim().toLowerCase()}`)));
  return [...h.slice(0, 12)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
/** Newest first: ids sort by inverted time, so a KV prefix list is already in order. */
export const newId = (now: number) => `${pad(9_999_999_999_999 - now)}-${crypto.randomUUID().slice(0, 8)}`;
const key = (o: string, id: string) => `chg:${o}:${id}`;
const ownKey = (o: string, uid: string) => `made:${o}:${uid}`;

export class Journal {
  constructor(private kv: KVLike, private owner: string) {}
  async record(c: Change) { await this.kv.put(key(this.owner, c.id), JSON.stringify(c), { expirationTtl: CHANGE_TTL_S }); if (c.action === "create") await this.kv.put(ownKey(this.owner, c.uid), String(c.at), { expirationTtl: OWN_CREATE_TTL_S }); }
  async get(owner: string, id: string): Promise<Change | undefined> { if (owner !== this.owner || !/^[0-9]{13}-[0-9a-f]{8}$/.test(id)) return undefined; const v = await this.kv.get(key(owner, id)); return v ? (JSON.parse(v) as Change) : undefined; }
  async markUndone(c: Change, now: number) { await this.kv.put(key(this.owner, c.id), JSON.stringify({ ...c, undone: now }), { expirationTtl: CHANGE_TTL_S }); }
  /** True only if Holdt itself added this event (same owner, same UID) within the last 24 hours. */
  async isOwnRecentCreate(uid: string, now: number) { const at = Number(await this.kv.get(ownKey(this.owner, uid))); return at > 0 && now - at <= OWN_CREATE_TTL_S * 1000; }
  async recent(limit: number): Promise<Change[]> {
    const { keys } = await this.kv.list({ prefix: `chg:${this.owner}:`, limit });
    return (await Promise.all(keys.map(async (k) => { const v = await this.kv.get(k.name); return v ? (JSON.parse(v) as Change) : undefined; }))).filter((x): x is Change => !!x);
  }
}
