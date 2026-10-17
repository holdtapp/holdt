// Minimal, namespace-tolerant XML reader for WebDAV multistatus bodies.
// Runs in Workers and Node (no DOM). Element names are matched by local name.

export interface XNode { name: string; attrs: Record<string, string>; children: XNode[]; text: string }

const ENT: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };
export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|lt|gt|amp|quot|apos);/gi, (_, e: string) => {
    if (e[0] === "#") { const n = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return n > 0 && n <= 0x10ffff && !(n >= 0xd800 && n <= 0xdfff) ? String.fromCodePoint(n) : "\ufffd"; }
    return ENT[e.toLowerCase()] ?? _;
  });
}
export function escapeXml(s: string): string {
  return s.replace(/[<>&"']/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&apos;" })[c]!);
}

export function parseXml(src: string): XNode {
  const root: XNode = { name: "#root", attrs: {}, children: [], text: "" };
  const stack: XNode[] = [root];
  const re = /<!\[CDATA\[([\s\S]*?)\]\]>|<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!DOCTYPE[^>]*>|<\/([^\s><]+)\s*>|<([^\s/><]+)((?:\s+[^\s=/><]+\s*=\s*(?:"[^"<]*"|'[^'<]*'))*)\s*(\/?)>|([^<]+)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src))) {
    const top = stack[stack.length - 1]!;
    if (m[1] !== undefined) top.text += m[1];
    else if (m[2]) { if (stack.length > 1) stack.pop(); }
    else if (m[3]) {
      const attrs: Record<string, string> = {};
      const ar = /([^\s=]+)\s*=\s*("([^"]*)"|'([^']*)')/g; let a;
      while ((a = ar.exec(m[4] ?? ""))) attrs[a[1]!] = decodeEntities(a[3] ?? a[4] ?? "");
      const node: XNode = { name: local(m[3]), attrs, children: [], text: "" };
      top.children.push(node);
      if (!m[5]) stack.push(node);
    } else if (m[6] !== undefined) top.text += decodeEntities(m[6]);
  }
  return root;
}
const local = (n: string) => (n.includes(":") ? n.slice(n.indexOf(":") + 1) : n).toLowerCase();

export function all(n: XNode, name: string): XNode[] {
  const out: XNode[] = []; const want = name.toLowerCase();
  const walk = (x: XNode) => { for (const c of x.children) { if (c.name === want) out.push(c); walk(c); } };
  walk(n); return out;
}
export const first = (n: XNode, name: string) => all(n, name)[0];
export const kids = (n: XNode, name: string) => n.children.filter((c) => c.name === name.toLowerCase());
export const textOf = (n: XNode | undefined): string => (n ? (n.text + n.children.map(textOf).join("")).trim() : "");
