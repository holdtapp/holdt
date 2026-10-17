// Shared input checks for the setup screen (used by the page script and the server).
export type Check = { ok: true; value: string } | { ok: false; message: string };

export function normalizeAppPassword(raw: string): Check {
  const s = (raw ?? "").trim();
  const letters = s.replace(/[\s-]/g, "");
  if (!s) return { ok: false, message: "Paste the app-specific password from Apple's page." };
  if (/^[a-z]{16}$/i.test(letters)) return { ok: true, value: letters.toLowerCase().match(/.{4}/g)!.join("-") };
  if (letters.length >= 6 && /[0-9!@#$%^&*()_+=.,?]/.test(letters)) return { ok: false, message: "That looks like your regular Apple Account password. Don't use that here. Use the 16-letter app-specific password Apple shows you (like abcd-efgh-ijkl-mnop)." };
  if (/^[a-z]+$/i.test(letters) && letters.length < 16) return { ok: false, message: `That's ${letters.length} letters. An app-specific password has 16. Copy it again from Apple's page.` };
  if (/^[a-z]+$/i.test(letters) && letters.length > 16) return { ok: false, message: "That's longer than an app-specific password (16 letters). Copy just the password, nothing around it." };
  return { ok: false, message: "That doesn't look like an app-specific password. It should be 16 letters in four groups, like abcd-efgh-ijkl-mnop." };
}
export function normalizeEmail(raw: string): Check {
  const s = (raw ?? "").trim().toLowerCase();
  if (!s) return { ok: false, message: "Enter the email you use to sign in to iCloud (your Apple Account)." };
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) return { ok: false, message: "That doesn't look like an email address." };
  return { ok: true, value: s };
}
/** Map a live-test failure to one plain-English sentence plus the fix. */
export function explainFailure(code: string): string {
  switch (code) {
    case "authentication": return "Apple didn't accept that. Check the email is your Apple Account email, and that you pasted the app-specific password (not your regular password). If you just made it, try making a new one.";
    case "rate_limited": case "unavailable": return "iCloud is busy right now. Wait a minute and press Test again.";
    case "network": return "Couldn't reach iCloud. Check your internet connection and try again.";
    case "forbidden": return "iCloud blocked the connection. If this is a work or school (Managed) Apple Account, it may not allow app-specific passwords.";
    default: return "Something unexpected happened while talking to iCloud. Press Test again. If it keeps failing, the details are in the terminal.";
  }
}
