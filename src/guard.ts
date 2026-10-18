// One Durable Object per owner holds every "only once" fact: spent confirm and undo tokens, approval-code tries,
// and the used-code marker. A Durable Object runs one request at a time with strongly consistent storage, so these
// checks are truly atomic across every isolate and region (KV can't compare-and-set). Operations are also queued
// in-instance, so the guarantee doesn't lean on the runtime's input gates.
import { DurableObject } from "cloudflare:workers";

export type CodeVerdict = { ok: true } | { ok: false; reason: "used" | "locked" | "wrong"; left: number };

export class Guard extends DurableObject {
  private q: Promise<unknown> = Promise.resolve();
  private ops = 0;
  constructor(ctx: any, env: unknown) { super(ctx, env); this.ctx = ctx; }
  private serial<T>(f: () => Promise<T>): Promise<T> { const r = this.q.then(f); this.q = r.catch(() => undefined); return r; }

  /** True exactly once per key (until expiry). */
  spend(key: string, expiresAt: number): Promise<boolean> {
    return this.serial(async () => {
      const now = Date.now(); const k = `spent:${String(key).slice(0, 200)}`;
      const exp = (await this.ctx.storage.get(k)) as number | undefined;
      if (exp !== undefined && exp > now) return false;
      await this.ctx.storage.put(k, Math.max(expiresAt, now + 60_000));
      if (++this.ops % 200 === 0) await this.sweep(now);
      return true;
    });
  }
  /** A cheap look before the expensive hash: a used or locked code is refused without running PBKDF2. codeTry still decides. */
  codeState(codeHash: string, maxTries: number): Promise<"open" | "used" | "locked"> {
    return this.serial(async () => {
      const n = ((await this.ctx.storage.get(`code-fails:${codeHash}`)) as number | undefined) ?? 0;
      if (n >= maxTries) return "locked";
      return (await this.ctx.storage.get(`code-used:${codeHash}`)) ? "used" : "open";
    });
  }
  /** One approval-code try, decided atomically: refused if used or locked, else spent on a match, else charged. */
  codeTry(codeHash: string, matches: boolean, maxTries: number): Promise<CodeVerdict> {
    return this.serial(async () => {
      const used = `code-used:${codeHash}`, fails = `code-fails:${codeHash}`;
      const n = ((await this.ctx.storage.get(fails)) as number | undefined) ?? 0;
      if (n >= maxTries) return { ok: false, reason: "locked", left: 0 };
      if (await this.ctx.storage.get(used)) return { ok: false, reason: "used", left: maxTries - n };
      if (matches) { await this.ctx.storage.put(used, Date.now()); return { ok: true }; }
      await this.ctx.storage.put(fails, n + 1);
      return { ok: false, reason: "wrong", left: maxTries - n - 1 };
    });
  }
  // ---- passkeys: one record per credential, so a counter update can never be lost to another login's write ----
  pkList(ns: string): Promise<unknown[]> {
    return this.serial(async () => [...((await this.ctx.storage.list({ prefix: `pk:${ns}:` })) as Map<string, unknown>).values()]);
  }
  /** Adds a credential unless it's already there or the cap is reached, in one atomic step. */
  pkAdd(ns: string, key: string, cred: { signCount: number }, max: number): Promise<"ok" | "dup" | "full"> {
    return this.serial(async () => {
      const all = (await this.ctx.storage.list({ prefix: `pk:${ns}:` })) as Map<string, unknown>;
      if (all.has(`pk:${ns}:${key}`)) return "dup";
      if (all.size >= max) return "full";
      await this.ctx.storage.put(`pk:${ns}:${key}`, cred); return "ok";
    });
  }
  /** Records a sign-in's counter. Refused (false) if the credential is gone or the counter didn't move forward once it had. */
  pkBump(ns: string, key: string, count: number): Promise<boolean> {
    return this.serial(async () => {
      const k = `pk:${ns}:${key}`; const c = (await this.ctx.storage.get(k)) as { signCount: number } | undefined;
      if (!c) return false;
      if ((count !== 0 || c.signCount !== 0) && count <= c.signCount) return false;
      if (count !== c.signCount) await this.ctx.storage.put(k, { ...c, signCount: count });
      return true;
    });
  }
  // ---- no-terminal setup (src/setup-web.ts): the sealed record and setup sessions. Values are ciphertext or opaque ids ----
  sealedGet(key: string): Promise<unknown> { return this.serial(async () => this.ctx.storage.get(`sealed:${String(key).slice(0, 120)}`)); }
  sealedPut(key: string, value: unknown): Promise<void> { return this.serial(async () => { await this.ctx.storage.put(`sealed:${String(key).slice(0, 120)}`, value); }); }
  private async sweep(now: number) {
    const all = (await this.ctx.storage.list({ prefix: "spent:" })) as Map<string, number>;
    const dead = [...all].filter(([, e]) => e <= now).map(([k]) => k);
    for (let i = 0; i < dead.length; i += 128) await this.ctx.storage.delete(dead.slice(i, i + 128));
  }
}
/** The owner's Guard stub, or undefined when the binding isn't configured (tests, older deployments). */
export function guardFor(env: { GUARD?: any }): Guard | undefined { return env.GUARD ? (env.GUARD.get(env.GUARD.idFromName("owner")) as Guard) : undefined; }
