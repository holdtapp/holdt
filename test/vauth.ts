// A software passkey for tests: builds clientDataJSON, authenticatorData and attestation by hand, signs with WebCrypto.
import { createHash, randomBytes } from "node:crypto";
const b64u = (b: Uint8Array | ArrayBuffer) => Buffer.from(b instanceof Uint8Array ? b : new Uint8Array(b)).toString("base64url");
const sha = (b: Uint8Array | string) => new Uint8Array(createHash("sha256").update(b).digest());
function head(major: number, n: number) { return n < 24 ? [major << 5 | n] : n < 256 ? [major << 5 | 24, n] : [major << 5 | 25, n >> 8, n & 255]; }
export function enc(v: any): number[] {
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") { const b = [...Buffer.from(v)]; return [...head(3, b.length), ...b]; }
  if (v instanceof Uint8Array) return [...head(2, v.length), ...v];
  if (v instanceof Map) { const o = [...head(5, v.size)]; for (const [k, x] of v) o.push(...enc(k), ...enc(x)); return o; }
  throw new Error("cbor: unsupported");
}
function der(raw: Uint8Array) {
  const int = (x: Uint8Array) => { let i = 0; while (i < x.length - 1 && x[i] === 0) i++; let y = [...x.slice(i)]; if (y[0]! & 0x80) y = [0, ...y]; return [0x02, y.length, ...y]; };
  const body = [...int(raw.slice(0, 32)), ...int(raw.slice(32))]; return new Uint8Array([0x30, body.length, ...body]);
}
export class VirtualAuthenticator {
  id = new Uint8Array(randomBytes(32)); count = 0; uv = true; keys!: CryptoKeyPair;
  constructor(public origin: string, public rpId = new URL(origin).hostname) {}
  async init() { this.keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair; return this; }
  get credId() { return b64u(this.id); }
  private auth(flags: number, extra: number[] = [], rpId = this.rpId) { const c = this.count; return new Uint8Array([...sha(rpId), flags | (this.uv ? 0x04 : 0), c >>> 24, (c >> 16) & 255, (c >> 8) & 255, c & 255, ...extra]); }
  private cd(type: string, challenge: string, o: { origin?: string; crossOrigin?: boolean } = {}) { return new Uint8Array(Buffer.from(JSON.stringify({ type, challenge, origin: o.origin ?? this.origin, crossOrigin: o.crossOrigin ?? false }))); }
  async create(challenge: string, o: { origin?: string; rpId?: string; type?: string } = {}) {
    const j = await crypto.subtle.exportKey("jwk", this.keys.publicKey);
    const cose = new Map<number, any>([[1, 2], [3, -7], [-1, 1], [-2, new Uint8Array(Buffer.from(j.x!, "base64url"))], [-3, new Uint8Array(Buffer.from(j.y!, "base64url"))]]);
    const ad = this.auth(0x41, [...new Uint8Array(16), this.id.length >> 8, this.id.length & 255, ...this.id, ...enc(cose)], o.rpId);
    const att = new Uint8Array(enc(new Map<string, any>([["fmt", "none"], ["attStmt", new Map()], ["authData", ad]])));
    return { clientDataJSON: b64u(this.cd(o.type ?? "webauthn.create", challenge, o)), attestationObject: b64u(att) };
  }
  async get(challenge: string, o: { origin?: string; rpId?: string; type?: string; crossOrigin?: boolean; bump?: number } = {}) {
    this.count += o.bump ?? 0;
    const ad = this.auth(0x01, [], o.rpId); const cdj = this.cd(o.type ?? "webauthn.get", challenge, o);
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.keys.privateKey, new Uint8Array([...ad, ...sha(cdj)])));
    return { id: this.credId, clientDataJSON: b64u(cdj), authenticatorData: b64u(ad), signature: b64u(der(raw)) };
  }
}
