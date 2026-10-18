// Minimal WebAuthn relying party for one owner (passkey one-tap connect, docs/SECURITY.md).
// Attestation "none": we trust the authenticator the owner enrolled with an enroll token, not its make.
// Checked on every ceremony: type, challenge, exact origin, not cross-origin, RP ID hash, user present AND
// user verified (Face ID / Touch ID / device PIN), and for sign-in the signature and a non-decreasing counter.
const enc = new TextEncoder();
export const b64u = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b instanceof Uint8Array ? b : new Uint8Array(b)))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const fromB64u = (s: string) => { if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s) || s.length > 20000) throw new WebAuthnError("bad encoding"); return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)); };
export class WebAuthnError extends Error {}
const sha256 = async (b: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", b as BufferSource));
const eq = (a: Uint8Array, b: Uint8Array) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!; return d === 0; };

/** Just enough CBOR (RFC 8949) for attestationObject and COSE keys: ints, byte/text strings, arrays, maps. */
export function cbor(buf: Uint8Array): { value: any; end: number } {
  let p = 0, depth = 0;
  const need = (n: number) => { if (p + n > buf.length) throw new WebAuthnError("truncated CBOR"); };
  const len = (info: number): number => {
    if (info < 24) return info;
    const n = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : 0; if (!n) throw new WebAuthnError("unsupported CBOR length");
    need(n); let v = 0; for (let i = 0; i < n; i++) v = v * 256 + buf[p++]!; return v;
  };
  const item = (): any => {
    if (++depth > 8) throw new WebAuthnError("CBOR too deep");
    need(1); const b = buf[p++]!, major = b >> 5, info = b & 31;
    let out: any;
    if (major === 0) out = len(info);
    else if (major === 1) out = -1 - len(info);
    else if (major === 2) { const n = len(info); need(n); out = buf.slice(p, p + n); p += n; }
    else if (major === 3) { const n = len(info); need(n); out = new TextDecoder().decode(buf.slice(p, p + n)); p += n; }
    else if (major === 4) { const n = len(info); if (n > 64) throw new WebAuthnError("CBOR array too long"); out = []; for (let i = 0; i < n; i++) out.push(item()); }
    else if (major === 5) { const n = len(info); if (n > 64) throw new WebAuthnError("CBOR map too long"); out = new Map(); for (let i = 0; i < n; i++) { const k = item(); out.set(k, item()); } }
    else if (b === 0xf4 || b === 0xf5) out = b === 0xf5;
    else throw new WebAuthnError("unsupported CBOR item");
    depth--; return out;
  };
  const value = item(); return { value, end: p };
}

export interface StoredCredential { id: string; jwk: JsonWebKey; alg: -7 | -257; signCount: number; createdAt: number; label?: string; via?: string; /** The host it was made on. */ rpId?: string }
export interface Expect { challenge: Uint8Array; origin: string; rpId: string }
type Flags = { up: boolean; uv: boolean; at: boolean };
function parseAuthData(ad: Uint8Array) {
  if (ad.length < 37) throw new WebAuthnError("authenticator data too short");
  const f = ad[32]!; const flags: Flags = { up: !!(f & 0x01), uv: !!(f & 0x04), at: !!(f & 0x40) };
  const signCount = ((ad[33]! << 24) >>> 0) + (ad[34]! << 16) + (ad[35]! << 8) + ad[36]!;
  return { rpIdHash: ad.slice(0, 32), flags, signCount, rest: ad.slice(37) };
}
async function checkClientData(cdjB: Uint8Array, type: string, ex: Expect) {
  let cd: any; try { cd = JSON.parse(new TextDecoder().decode(cdjB)); } catch { throw new WebAuthnError("client data isn't JSON"); }
  if (cd?.type !== type) throw new WebAuthnError("wrong ceremony type");
  if (typeof cd.challenge !== "string" || !eq(fromB64u(cd.challenge), ex.challenge)) throw new WebAuthnError("challenge mismatch");
  if (cd.origin !== ex.origin) throw new WebAuthnError("wrong origin");
  if (cd.crossOrigin === true) throw new WebAuthnError("cross-origin ceremony");
}
async function checkAuthData(ad: ReturnType<typeof parseAuthData>, ex: Expect) {
  if (!eq(ad.rpIdHash, await sha256(enc.encode(ex.rpId)))) throw new WebAuthnError("wrong RP ID");
  if (!ad.flags.up) throw new WebAuthnError("user not present");
  if (!ad.flags.uv) throw new WebAuthnError("user not verified");
}
function coseToJwk(m: Map<number, any>): { jwk: JsonWebKey; alg: -7 | -257 } {
  const b = (k: number) => { const v = m.get(k); if (!(v instanceof Uint8Array)) throw new WebAuthnError("bad COSE key"); return b64u(v); };
  if (m.get(1) === 2 && m.get(3) === -7 && m.get(-1) === 1) { const x = m.get(-2), y = m.get(-3); if (x?.length !== 32 || y?.length !== 32) throw new WebAuthnError("bad P-256 key"); return { alg: -7, jwk: { kty: "EC", crv: "P-256", x: b(-2), y: b(-3) } }; }
  if (m.get(1) === 3 && m.get(3) === -257) { const n = m.get(-1); if (!(n instanceof Uint8Array) || n.length < 256) throw new WebAuthnError("RSA key too short"); return { alg: -257, jwk: { kty: "RSA", n: b(-1), e: b(-2) } }; }
  throw new WebAuthnError("unsupported key type (need ES256 or RS256)");
}
const importKey = (c: Pick<StoredCredential, "jwk" | "alg">) => c.alg === -7
  ? crypto.subtle.importKey("jwk", c.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"])
  : crypto.subtle.importKey("jwk", c.jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);

/** Registration (navigator.credentials.create). Returns the credential to store. */
export async function verifyRegistration(r: { clientDataJSON: string; attestationObject: string }, ex: Expect, now = Date.now()): Promise<StoredCredential> {
  await checkClientData(fromB64u(r.clientDataJSON), "webauthn.create", ex);
  const att = cbor(fromB64u(r.attestationObject)).value;
  if (!(att instanceof Map) || !(att.get("authData") instanceof Uint8Array)) throw new WebAuthnError("bad attestation object");
  const ad = parseAuthData(att.get("authData")); await checkAuthData(ad, ex);
  if (!ad.flags.at || ad.rest.length < 18) throw new WebAuthnError("no credential in attestation");
  const idLen = (ad.rest[16]! << 8) + ad.rest[17]!; if (idLen < 16 || idLen > 1023 || 18 + idLen > ad.rest.length) throw new WebAuthnError("bad credential id");
  const id = ad.rest.slice(18, 18 + idLen);
  const key = cbor(ad.rest.slice(18 + idLen)).value; if (!(key instanceof Map)) throw new WebAuthnError("bad COSE key");
  const { jwk, alg } = coseToJwk(key); await importKey({ jwk, alg }); // refuses a key WebCrypto can't use
  return { id: b64u(id), jwk, alg, signCount: ad.signCount, createdAt: now };
}

/** ECDSA signatures arrive DER-encoded. WebCrypto wants r||s, 32 bytes each. */
export function derToRaw(der: Uint8Array): Uint8Array {
  let p = 0; const bad = () => new WebAuthnError("bad signature encoding");
  if (der[p++] !== 0x30) throw bad(); let L = der[p++]!; if (L & 0x80) { if (L !== 0x81) throw bad(); L = der[p++]!; } if (p + L !== der.length) throw bad();
  const out = new Uint8Array(64);
  for (const off of [0, 32]) {
    if (der[p++] !== 0x02) throw bad(); const n = der[p++]!; if (n < 1 || n > 33 || p + n > der.length) throw bad();
    let v = der.slice(p, p + n); p += n; while (v.length > 32 && v[0] === 0) v = v.slice(1); if (v.length > 32) throw bad();
    out.set(v, off + 32 - v.length);
  }
  if (p !== der.length) throw bad(); return out;
}

/** Sign-in (navigator.credentials.get). Returns the new counter to store. */
export async function verifyAssertion(r: { clientDataJSON: string; authenticatorData: string; signature: string }, cred: StoredCredential, ex: Expect): Promise<{ signCount: number }> {
  const cdj = fromB64u(r.clientDataJSON), adB = fromB64u(r.authenticatorData);
  await checkClientData(cdj, "webauthn.get", ex);
  const ad = parseAuthData(adB); await checkAuthData(ad, ex);
  // Synced passkeys (iCloud Keychain) always report 0. A counter that once moved must keep moving: a clone shows up as a step back.
  if ((ad.signCount !== 0 || cred.signCount !== 0) && ad.signCount <= cred.signCount) throw new WebAuthnError("signature counter went backwards");
  const data = new Uint8Array(adB.length + 32); data.set(adB); data.set(await sha256(cdj), adB.length);
  const sig = fromB64u(r.signature);
  const ok = cred.alg === -7
    ? await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, await importKey(cred), derToRaw(sig) as BufferSource, data as BufferSource)
    : await crypto.subtle.verify("RSASSA-PKCS1-v1_5", await importKey(cred), sig as BufferSource, data as BufferSource);
  if (!ok) throw new WebAuthnError("bad signature");
  return { signCount: ad.signCount };
}
