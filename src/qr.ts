// QR codes for the no-typing flows: the setup link (terminal and the local setup page), the consent page's
// "approve on your iPhone" link and a new device's "add this device" link. qrcode-generator is pinned and has no deps.
import qrcode from "qrcode-generator";

function matrix(text: string) {
  const q = qrcode(0, "M"); q.addData(text); q.make();
  const n = q.getModuleCount();
  return { n, dark: (r: number, c: number) => r >= 0 && c >= 0 && r < n && c < n && q.isDark(r, c) };
}
/** Inline SVG, black on white with a 4-module quiet zone (cameras need the contrast in dark mode too). */
export function qrSvg(text: string, label: string) {
  const { n, dark } = matrix(text); let d = "";
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) {
    if (!dark(r, c) || dark(r, c - 1)) continue;
    let w = 1; while (dark(r, c + w)) w++;
    d += `M${c + 4} ${r + 4}h${w}v1h-${w}z`;
  }
  const s = n + 8;
  return `<svg class="qr" viewBox="0 0 ${s} ${s}" role="img" aria-label="${label.replace(/[<>"&]/g, "")}" shape-rendering="crispEdges"><rect width="${s}" height="${s}" fill="#fff"/><path d="${d}" fill="#000"/></svg>`;
}
/** Terminal QR with half blocks, two rows per line. Dark modules print as spaces on a white block background,
 * so it scans in dark and light terminals alike. */
export function qrTerminal(text: string) {
  const { n, dark } = matrix(text); const lines: string[] = [];
  for (let r = -2; r < n + 2; r += 2) {
    let line = "  ";
    for (let c = -2; c < n + 2; c++) {
      const t = dark(r, c), b = dark(r + 1, c);
      line += t && b ? " " : t ? "\u2584" : b ? "\u2580" : "\u2588";
    }
    lines.push(line);
  }
  return lines.join("\n");
}
