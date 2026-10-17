// A Durable Object namespace for tests: one Guard instance per name, with in-memory storage that, like the real
// thing, is async (so a missing serialization would show up as a race).
import { Guard } from "../src/guard.js";
class MemStorage {
  m = new Map<string, unknown>();
  private tick = () => new Promise((r) => setTimeout(r, 1));
  async get(k: string) { await this.tick(); return this.m.get(k); }
  async put(k: string, v: unknown) { await this.tick(); this.m.set(k, v); }
  async delete(k: string | string[]) { await this.tick(); for (const x of Array.isArray(k) ? k : [k]) this.m.delete(x); }
  async list(o: { prefix?: string } = {}) { await this.tick(); return new Map([...this.m].filter(([k]) => k.startsWith(o.prefix ?? ""))); }
}
export class MockGuardNS {
  objs = new Map<string, Guard>();
  idFromName(n: string) { return n; }
  get(id: string) { let g = this.objs.get(id); if (!g) { g = new Guard({ storage: new MemStorage() }, {}); this.objs.set(id, g); } return g; }
}
