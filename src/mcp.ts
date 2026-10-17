import { toolsFor, Tools, UserError } from "./tools.js";
import { CalDavError } from "./caldav.js";
import { log } from "./redact.js";

export const SERVER_INFO = { name: "holdt", title: "Holdt for iCloud Calendar", version: "0.1.0" };
const SUPPORTED = ["2025-06-18", "2025-03-26", "2024-11-05"];
const INSTRUCTIONS = "Reads the user's iCloud calendars (Calendar only: Apple Reminders is not available through this connector). Every change is two steps: call prepare_* to get a preview, show it to the user, and call commit_* only after they clearly say yes to that exact preview. Never commit on your own initiative. This server cannot delete anything or send invitations.";

type Rpc = { jsonrpc: "2.0"; id?: string | number | null; method: string; params?: any };

export async function handleRpc(msg: Rpc, makeTools: () => Tools, opts: { remindersExperimental?: boolean } = {}): Promise<object | null> {
  const TOOLS = toolsFor(opts);
  const id = msg.id ?? null; const isNote = msg.id === undefined;
  const ok = (result: unknown) => ({ jsonrpc: "2.0", id, result });
  const err = (code: number, message: string) => ({ jsonrpc: "2.0", id, error: { code, message } });
  if (msg?.jsonrpc !== "2.0" || typeof msg.method !== "string") return err(-32600, "Invalid request");
  switch (msg.method) {
    case "initialize": {
      const v = SUPPORTED.includes(msg.params?.protocolVersion) ? msg.params.protocolVersion : SUPPORTED[0];
      return ok({ protocolVersion: v, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO, instructions: INSTRUCTIONS });
    }
    case "notifications/initialized": case "notifications/cancelled": return null;
    case "ping": return ok({});
    case "tools/list": return ok({ tools: TOOLS });
    case "tools/call": {
      const name = msg.params?.name; const args = msg.params?.arguments ?? {};
      if (!TOOLS.some((t) => t.name === name)) return err(-32602, `Unknown tool: ${String(name).slice(0, 60)}`);
      if (typeof args !== "object" || Array.isArray(args)) return err(-32602, "arguments must be an object");
      try {
        const res = await makeTools().call(name, args);
        return ok({ content: [{ type: "text", text: JSON.stringify(res, null, 1) }], structuredContent: res, isError: false });
      } catch (e) {
        return ok({ content: [{ type: "text", text: friendly(e) }], isError: true });
      }
    }
    default: return isNote ? null : err(-32601, `Method not found: ${msg.method.slice(0, 60)}`);
  }
}

export function friendly(e: unknown): string {
  if (e instanceof UserError) return e.message;
  if (e instanceof CalDavError) {
    log.warn(`caldav error ${e.code}`);
    const fix: Record<string, string> = {
      authentication: " To fix: make a new app-specific password at account.apple.com (Sign-In and Security > App-Specific Passwords) and run setup again. This also happens after you change your Apple Account password, because Apple then cancels all app passwords.",
      rate_limited: ` Wait about ${e.retryAfter ?? 5} seconds and try again.`,
      unavailable: " Try again in a minute.",
      outcome_unknown: " Read the item again to see whether the change landed before trying again.",
    };
    return e.message + (fix[e.code] ?? "");
  }
  log.error("unexpected error", e);
  return "Something went wrong on the connector. Nothing was changed. Try again, and if it keeps happening check the Worker logs.";
}
