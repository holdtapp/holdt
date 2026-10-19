// Envelope encryption. Used by no-Terminal setup (src/setup-web.ts) and by the hosted-mode design.
// Envelope encryption: per-user random data key (AES-256-GCM) encrypts the app password;
// the data key is wrapped by a key-encryption key (KEK) that lives only in the platform's
// secret store / KMS. Associated data binds a ciphertext to its user, so rows can't be swapped.
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
export const unb64u = (s: string) => unb64(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));

export interface Sealed { v: 1; kekId: string; wrappedKey: string; iv: string; ct: string }
export async function importKek(raw32: Uint8Array) { if (raw32.length !== 32) throw new Error("KEK must be 32 bytes"); return crypto.subtle.importKey("raw", raw32 as BufferSource, "AES-KW", false, ["wrapKey", "unwrapKey"]); }
export async function seal(kek: CryptoKey, kekId: string, userId: string, secret: string): Promise<Sealed> {
  const dk = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(`icloud-mcp:v1:${userId}`) }, dk, enc.encode(secret));
  const wrapped = await crypto.subtle.wrapKey("raw", dk, kek, "AES-KW");
  return { v: 1, kekId, wrappedKey: b64(wrapped), iv: b64(iv), ct: b64(ct) };
}
export async function open(kek: CryptoKey, userId: string, s: Sealed): Promise<string> {
  const dk = await crypto.subtle.unwrapKey("raw", unb64(s.wrappedKey), kek, "AES-KW", { name: "AES-GCM" }, false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(s.iv), additionalData: enc.encode(`icloud-mcp:v1:${userId}`) }, dk, unb64(s.ct));
  return dec.decode(pt);
}
