// Secret-safe logging. Every log line passes through redact(). Secrets are registered
// at startup so even an accidental interpolation is scrubbed.
const secrets = new Set<string>();
export function registerSecret(s: string | undefined) { if (s && s.length >= 4) secrets.add(s); }
export function clearSecrets() { secrets.clear(); }

const PATTERNS: [RegExp, string][] = [
  [/\b[a-z]{4}-[a-z]{4}-[a-z]{4}-[a-z]{4}\b/gi, "[app-password]"],
  [/(authorization\s*[:=]\s*)(basic|bearer)\s+[A-Za-z0-9+/=._~-]+/gi, "$1[redacted]"],
  [/\b(basic|bearer)\s+[A-Za-z0-9+/=._~-]{8,}/gi, "$1 [redacted]"],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "[email]"],
  [/\/\d{6,}\/calendars\/[^\s"'<]*/g, "/[principal]/calendars/[path]"],
  [/BEGIN:VCALENDAR[\s\S]*?(END:VCALENDAR|$)/g, "[ical-body]"],
];
export function redact(input: unknown): string {
  let s = typeof input === "string" ? input : safeJson(input);
  for (const sec of secrets) {
    s = s.split(sec).join("[secret]");
    try { const b = btoa(sec); s = s.split(b).join("[secret]"); } catch { /* non-latin1 */ }
  }
  for (const [re, rep] of PATTERNS) s = s.replace(re, rep);
  return s;
}
function safeJson(v: unknown) { try { return v instanceof Error ? `${v.name}: ${v.message}` : JSON.stringify(v); } catch { return String(v); } }

export type Sink = (line: string) => void;
let sink: Sink = (l) => console.log(l);
export function setLogSink(s: Sink) { sink = s; }
export const log = {
  info: (msg: string, meta?: unknown) => sink(redact(`[info] ${msg}${meta === undefined ? "" : " " + redact(meta)}`)),
  warn: (msg: string, meta?: unknown) => sink(redact(`[warn] ${msg}${meta === undefined ? "" : " " + redact(meta)}`)),
  error: (msg: string, meta?: unknown) => sink(redact(`[error] ${msg}${meta === undefined ? "" : " " + redact(meta)}`)),
};
