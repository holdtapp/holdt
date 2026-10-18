// The look of every page Holdt shows a person: consent, the approval code, Face ID set up, and the errors.
// One shell for all of them, so the brand, the safe areas, Dynamic Type, dark mode and reduced motion are right everywhere.
//   Type:   iOS Dynamic Type through `font: -apple-system-body`, everything else in rem, so text follows the reader's size.
//   Colour: Guard Green #0F7B53 with a white glyph. Every text pair meets WCAG AA in light and dark (test/ui.test.ts).
//   Motion: the mark's lifted piece drops home on a yes (anticipation, ease-in drop, squash, settle). Nothing moves
//           when the reader asks for reduced motion.
/** The product name shown under the mark on every screen, so a person always sees who is asking. */
export const PRODUCT = "Holdt";
export const esc = (v: string) => String(v).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/** Colour tokens. Exported so the contrast test checks the exact values the CSS uses. */
export const TOKENS = {
  // iOS grouped materials: systemGroupedBackground, secondarySystemGroupedBackground, label, and a secondary label kept at AA.
  light: { bg: "#F2F2F7", surface: "#FFFFFF", ink: "#000000", ink2: "#5B5B60", line: "#D1D1D6", green: "#0F7B53", greenInk: "#0B6A47", onGreen: "#FFFFFF", warnBg: "#FFF4E0", warnInk: "#6E4700", err: "#C4281C", secondaryBg: "#E5E5EA", mute: "#36383C", fieldLine: "#8A8A8E" },
  dark: { bg: "#000000", surface: "#1C1C1E", ink: "#FFFFFF", ink2: "#AEAEB2", line: "#38383A", green: "#0F7B53", greenInk: "#5FCF9C", onGreen: "#FFFFFF", warnBg: "#2E2410", warnInk: "#FFD27A", err: "#FF8A80", secondaryBg: "#2C2C2E", mute: "#3A3C40", fieldLine: "#6C6C70" },
} as const;
const vars = (t: Record<string, string>) => Object.entries(t).map(([k, v]) => `--${k.replace(/[A-Z]/g, (c) => "-" + c.toLowerCase())}:${v}`).join(";");

// The code panel is a mode switch: open it and the passkey button steps aside, so one primary button shows at a time.
export const STYLE = `:root{${vars(TOKENS.light)};color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{${vars(TOKENS.dark)}}}
*{box-sizing:border-box}
html{--spring:linear(0,.083,.258,.454,.63,.771,.873,.942,.984,1.007,1.018,1.02,1.018,1.015,1.011,1.007,1.004,1.002,1.001,1);font-size:17px;font-family:-apple-system,BlinkMacSystemFont,system-ui,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;-webkit-text-size-adjust:100%;text-size-adjust:100%}
@supports (font:-apple-system-body){html{font:-apple-system-body}}
body{margin:0;background:var(--bg);color:var(--ink);line-height:1.29;letter-spacing:-.024em;-webkit-font-smoothing:antialiased}
.screen{display:flex;flex-direction:column;min-height:100vh;min-height:100dvh;max-width:430px;margin:0 auto;
 padding:calc(env(safe-area-inset-top) + 2.6rem) max(1.18rem,env(safe-area-inset-right)) calc(env(safe-area-inset-bottom) + 1.1rem) max(1.18rem,env(safe-area-inset-left))}
@media (min-height:900px) and (min-width:600px){.screen{min-height:0;margin:9vh auto}}
.head{text-align:center}
.msg .head{margin:0}.msg .actions{margin-top:0;padding-top:1.25rem}.msg .foot{margin-top:0}
.mark{display:block;width:min(3.9rem,72px);height:min(3.9rem,72px);margin:0 auto .4rem;border-radius:22%;overflow:visible}
.mark .plate{fill:var(--green)}.mark .glyph{fill:#fff}.mark .whole{opacity:0}
.brand{margin:0 0 .9rem;color:var(--ink2);font-size:.765rem;font-weight:600;letter-spacing:-.005em}
.mark.muted .piece{opacity:.45}
h1{font-size:2rem;line-height:1.2;font-weight:700;letter-spacing:.011em;margin:0 0 .55rem;text-wrap:balance}h1.long{font-size:1.65rem;line-height:1.21;letter-spacing:.013em}
.lede{color:var(--ink2);margin:0 auto;max-width:21rem;text-wrap:balance}
.lede strong{color:var(--ink);font-weight:600}
.facts{list-style:none;margin:1.6rem 0 0;padding:0;background:var(--surface);border-radius:.62rem}
.facts li{display:flex;gap:.85rem;align-items:flex-start;padding:.66rem 1rem;min-height:2.6rem}
.facts li{position:relative}.facts li+li::before{content:"";position:absolute;top:0;left:3.1rem;right:0;border-top:.5px solid var(--line)}
.ico{flex:none;width:1.25rem;height:1.25rem;margin-top:.08rem;color:var(--green-ink)}
.facts p{margin:0;text-wrap:pretty}.facts .dest{padding-bottom:.85rem}.facts .dest .ico{color:var(--ink2)}.facts .dest p{font-weight:600}.facts .dest strong{font-weight:700}
.facts .lock p{text-wrap:pretty}.facts .lock .sub.keep{display:block}.facts .sub.keep{display:inline;color:var(--ink);font-size:1rem;margin:0}.facts .on .ico{color:var(--green-ink)}.facts .off .ico,.facts .no .ico{color:var(--ink2)}.facts .sub{display:block;text-wrap:wrap;color:var(--ink2);font-size:.9rem;margin-top:.1rem}
.callout{display:flex;gap:.65rem;margin:1rem 0 0;padding:.7rem .9rem;border-radius:.62rem;background:var(--warn-bg);color:var(--warn-ink);font-size:.88rem;line-height:1.33;letter-spacing:-.01em}
.callout .ico{color:var(--warn-ink)}.callout+.callout,.callout+.facts,.callout+.owner+.facts{margin-top:.6rem}.callout+.owner{margin-top:.1rem}
.callout p{margin:0;text-wrap:pretty}[hidden]{display:none!important}.callout strong{font-weight:650}
.actions{margin-top:auto;padding-top:1.6rem}
/* The one action sits in the thumb zone at the bottom of the screen, like a system sheet. Long content simply pushes it down. */
.gap{flex:1 0 1.4rem}.gap+.actions{margin-top:0;padding-top:0}.actions.near{margin-top:0}
form{margin:0}
.btn{display:flex;align-items:center;justify-content:center;gap:.5rem;width:100%;min-height:max(44px,2.95rem);padding:.7rem 1rem;border:0;border-radius:.82rem;
 font:inherit;font-weight:600;letter-spacing:-.024em;cursor:pointer;-webkit-tap-highlight-color:transparent;touch-action:manipulation;transition:transform .45s var(--spring),opacity .15s}
.btn:active{transform:scale(.97);transition-duration:.08s}
.btn[disabled]{opacity:.55;cursor:default}.btn[aria-busy=true]{opacity:1}
.btn .spin{display:none}.btn[aria-busy=true] .spin{display:block;animation:spin .8s linear infinite}.btn[aria-busy=true] .ico:not(.spin){display:none}
@keyframes spin{to{transform:rotate(360deg)}}
form.busy .alt{opacity:0;transition:opacity .2s}
form.code #pk,form.code #pkmsg:not(.keep){display:none}form.js:not(.code) #codepanel{display:none}
#mode .on,form.code #mode .off{display:none}form.code #mode .on{display:inline-flex}
#mode{font-weight:400;font-size:1rem;color:var(--green-ink)}#mode .ico{color:var(--green-ink)}#pkmsg,#msg,#askmsg{margin:0 0 .75rem}/* Failure lines sit above the button, so the button never moves under the thumb. */html.touch .ico.bio-face{display:none}html:not(.touch) .ico.bio-touch{display:none}html.key .ico.bio-face{display:none}html:not(.key) .ico.bio-key{display:none}#mode span{display:inline-flex;align-items:center;gap:.4rem}#mode .ico{width:1.1rem;height:1.1rem;margin:0}
form.code #codepanel .field{margin-top:0}#codepanel.codebox{margin-top:0}form.code #codepanel{animation:rise .28s cubic-bezier(.2,.8,.3,1) both}
.primary{background:var(--green);color:var(--on-green)}
.secondary{background:var(--surface);color:var(--ink);box-shadow:inset 0 0 0 1px var(--field-line)}
.plain{background:transparent;color:var(--green-ink);font-weight:400;min-height:max(44px,2.75rem);margin-top:.35rem}
.plain.quiet{color:var(--green-ink);font-weight:400}.btn.plain.quiet{margin-top:.9rem}
.btn .ico{color:currentColor;margin:0;width:1.35rem;height:1.35rem}
.btn+.btn{margin-top:.6rem}.btn.plain{margin-top:.15rem}
:focus-visible{outline:3px solid var(--green-ink);outline-offset:3px;border-radius:.6rem}h1[tabindex="-1"]:focus{outline:none}.status.ok .ico{color:var(--green-ink)}form.busy #awayok{opacity:1}
.status{display:flex;justify-content:center;align-items:flex-start;gap:.35rem;margin:.45rem 0 .1rem;font-size:.88rem;letter-spacing:-.01em;color:var(--ink2);text-align:left}.status .ico{flex:none;width:1.05rem;height:1.05rem;margin:.1em 0 0;color:var(--ink2)}.status:has(.st:empty){display:none}.status .st{white-space:pre-line;max-width:19rem}.status[hidden]{display:none}#codeok{margin:.2rem 0 .7rem}#codeok .ico{color:var(--green-ink)}
details{margin-top:.35rem}
summary{display:flex;align-items:center;justify-content:center;gap:.35rem;min-height:max(44px,2.75rem);color:var(--green-ink);font-weight:600;cursor:pointer;list-style:none;border-radius:.6rem;-webkit-tap-highlight-color:transparent}
summary::-webkit-details-marker{display:none}
summary .chev{width:.8rem;height:.8rem;transition:transform .2s cubic-bezier(.3,.7,.4,1)}
details[open]>summary .chev{transform:rotate(180deg)}
details[open] .codebox{animation:rise .28s cubic-bezier(.2,.8,.3,1) both}
.codebox{margin-top:.6rem}
.field{display:block;margin:0 0 .9rem}
.field .lbl{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.field .hint{display:block;color:var(--ink2);font-size:.82rem;margin:.45rem 0 0;text-align:center;text-wrap:balance}
input.code:focus::placeholder{color:transparent}input.code{display:block;width:100%;min-height:3.3rem;padding:.6rem 1rem;border-radius:.9rem;border:1.5px solid var(--field-line);background:var(--surface);color:var(--ink);
 font:600 1.45rem/1 -apple-system,"SF Pro Display",Inter,system-ui,sans-serif;letter-spacing:.1em;word-spacing:.2em;text-align:center;font-variant-numeric:tabular-nums}
input.code:focus{border-color:var(--green-ink);outline:none;box-shadow:0 0 0 3px color-mix(in srgb,var(--green) 28%,transparent)}
input.code::placeholder{color:var(--ink2);font-weight:400;font-size:1.05rem;letter-spacing:0;word-spacing:0;opacity:1}
input.code::selection{background:color-mix(in srgb,var(--green) 22%,transparent)}
input.code[aria-invalid=true]{border-color:var(--err)}input.code[aria-invalid=true]:focus{box-shadow:0 0 0 3px color-mix(in srgb,var(--err) 22%,transparent)}
.fielderr{display:flex;justify-content:center;align-items:flex-start;gap:.35rem;text-align:left;text-wrap:balance;color:var(--err);font-size:.9rem;font-weight:400;margin:.55rem 0 0}.fielderr[hidden]{display:none}.fielderr.calm:not([hidden])+.hint{display:none}
.fielderr.calm{color:var(--ink2);font-weight:500}.fielderr.calm .ico{color:var(--ink2)}
.fielderr .ico{flex:none;color:var(--err);width:1.05rem;height:1.05rem;margin:.1em 0 0}
.foot .refline{display:block;margin-top:.5rem}.ref{color:var(--ink);font-weight:600;font-variant-numeric:tabular-nums;user-select:all;-webkit-user-select:all}
.foot{color:var(--ink2);font-size:.765rem;letter-spacing:-.005em;text-align:center;margin:1rem auto 0;max-width:20rem;text-wrap:pretty}
.owner{margin-top:.5rem}.alt>.owner,form>.owner{margin-top:.5rem}.owner summary{color:var(--ink2);font-weight:400;font-size:.765rem;letter-spacing:-.005em}.owner .body{margin:.2rem 0 0;padding:.75rem;border-radius:.62rem;background:var(--secondary-bg);color:var(--ink2);font-size:.765rem;line-height:1.4;letter-spacing:-.005em}
.owner ol{margin:0;padding-left:1.2rem}.owner li+li{margin-top:.3rem}
.owner.dead .body{color:var(--ink)}.owner.dead+.btn{margin-top:1rem}.factdest{display:flex;gap:.6rem;align-items:center;justify-content:center;margin:1.1rem 0 0;font-size:.94rem}.factdest .ico{color:var(--ink2);margin:0}.factdest+.facts{margin-top:.7rem}
.owner code{background:var(--surface);box-shadow:inset 0 0 0 1px var(--line);display:block;width:max-content;max-width:100%;overflow-x:auto;white-space:nowrap;margin:.35rem 0;padding:.4rem .55rem}
code{font:.8rem ui-monospace,"SF Mono",Menlo,monospace;background:var(--secondary-bg);color:var(--ink);padding:.12rem .35rem;border-radius:.35rem;white-space:nowrap}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.in{animation:rise .55s var(--spring) both}.in.d1{animation-delay:.04s}.in.d2{animation-delay:.08s}.in.d3{animation-delay:.12s}
@keyframes rise{from{opacity:0;transform:translateY(.6rem)}40%{opacity:1}to{opacity:1;transform:none}}
.piece{transform-box:fill-box;transform-origin:50% 100%}
.closed .piece{transform:translateY(14px)}.closed .whole{opacity:1}
#done .drop~h1{animation:rise .3s .5s cubic-bezier(.2,.8,.3,1) both}
.drop .whole{animation:seal 0s .43s both}@keyframes seal{to{opacity:1}}
.drop .piece{animation:drop .43s both}
.drop .plate-g{animation:pulse .2s .39s cubic-bezier(.3,.7,.4,1) both;transform-box:fill-box;transform-origin:50% 50%}
@keyframes drop{0%{transform:translateY(0);animation-timing-function:cubic-bezier(.3,0,.6,1)}
 25%{transform:translateY(-1.2px);animation-timing-function:cubic-bezier(.55,0,1,.6)}
 72%{transform:translateY(14px) scale(.97,1.05)}
 84%{transform:translateY(14px) scale(1.05,.92);animation-timing-function:cubic-bezier(.3,.7,.4,1)}
 100%{transform:translateY(14px) scale(1,1)}}
@keyframes pulse{0%,100%{transform:scale(1)}45%{transform:scale(1.02)}}
/* Approve on your iPhone: a QR code card, the fallback when Face ID isn't on this device. Black on white in both modes so cameras read it. */
.awaybox{margin:0 0 .2rem;padding:.75rem 1rem;background:var(--surface);border-radius:.62rem;text-align:center}
.awaybox:focus{outline:none}.awaybox:focus-visible{outline:3px solid var(--green-ink);outline-offset:3px}
#qrwrap{display:flex;justify-content:center}.qr{display:block;width:min(7rem,40vw);height:auto;border-radius:.45rem}.qrwait{width:min(7rem,40vw);aspect-ratio:1;margin:0 auto;border-radius:.45rem;background:var(--secondary-bg)}
.stepsw{width:fit-content;max-width:100%;margin:.8rem auto 0;text-align:left}.stepsw .status{justify-content:flex-start;margin:.25rem 0 0 .1rem}.setupline{margin:1.2rem auto .4rem;max-width:21rem;text-align:center;color:var(--ink2);font-size:.94rem;line-height:1.4}.setupline+.status{margin:0 0 .4rem;justify-content:center}.setupline~.owner+.btn{margin-top:.6rem}.next .say{overflow-wrap:break-word}.setupwait{margin:1.2rem 0 .9rem}.copymsg:empty{display:none}.copymsg{margin:.6rem 0 0;text-align:center}.steps{text-align:left;margin:0;padding-left:1.3rem;max-width:100%;font-size:.94rem}.steps li+li{margin-top:.25rem}.screen:has(form.away) .gap{flex:0 0 .6rem}form.away #awaypanel{display:flex;gap:.7rem;align-items:center;text-align:left;padding-left:.85rem;padding-right:.85rem}form.away #awaypanel .stepsw{margin:0;text-align:left;flex:1}form.away #awaypanel .steps.one{text-align:left}form.away #awaypanel .stepsw .status{justify-content:flex-start}form.away #qrwrap{flex:none}.alt{container-type:inline-size}@container (max-width:19rem){form.away #awaypanel{flex-direction:column;text-align:center}form.away #awaypanel .stepsw,form.away #awaypanel .steps.one{text-align:center}form.away #awaypanel .stepsw .status{justify-content:center}}.steps li,.status .st{text-wrap:balance}.steps.one{list-style:none;padding-left:0;text-align:center}.stepsw:has(.one){text-align:center}.stepsw:has(.one) .status{justify-content:center;margin-left:0}
.awaybox .status{margin:.6rem 0 0}.status.wait .ico{animation:spin .9s linear infinite}.status.wait .ico.spin{display:block}
.awaybox.setup{text-align:left}.awaybox.setup p{margin:0}.awayh{display:flex;gap:.55rem;align-items:center;font-weight:600;font-size:1.06rem;margin-bottom:.35rem!important}.awayh .ico{margin:0}.awaybox.lone{margin-top:1.5rem}.awaybox.lone .qr,.awaybox.lone .qrwait{width:min(11rem,60vw)}.awaybox .stepsw .status{margin-top:.45rem}.in:has(>.awaybox.lone)+.gap{flex-basis:0}.awaybox:not(.setup) .awayh{justify-content:center;margin-bottom:.7rem!important}.awaybox.setup p:not(.awayh){color:var(--ink2);font-size:.94rem}.awaybox.setup .status{justify-content:flex-start;margin:.55rem 0 0}#awayok{color:var(--ink)}@media (prefers-color-scheme:dark){#qrwrap .qr{box-shadow:0 0 0 1px var(--line)}}
form.js:not(.away) #awaypanel{display:none}form.away #pk,form.away #pkmsg:not(.keep){display:none}form.js #awaygo{display:none}#awaygo{margin-top:.8rem}
form.away #mode .off{display:none}form.away #mode .on{display:inline-flex}form.away #awaypanel{animation:rise .28s cubic-bezier(.2,.8,.3,1) both}
.next{margin:1.2rem 0 0;text-align:center}.next p{margin:0;color:var(--ink2)}.next .say{margin:.6rem 0 0;padding:.8rem 1rem;border-radius:.62rem;background:var(--surface);color:var(--ink);font-weight:500;overflow-wrap:anywhere;user-select:all;-webkit-user-select:all}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}.drop .piece{transform:translateY(14px)}.drop .whole{opacity:1}}
/* Continuous (squircle) corners where the engine draws them, at the radius iOS uses for the same element. */
@supports (corner-shape:squircle){.btn,.facts,.awaybox,.callout,.owner .body,.next .say{corner-shape:squircle}.btn{border-radius:1.5rem}.facts,.awaybox,.callout,.owner .body,.next .say{border-radius:1.15rem}}
@media (prefers-contrast:more){:root{--ink2:var(--ink);--line:var(--ink2)}}`;

/** The Holdt lift mark, inline. Open = waiting for your yes. `closed` draws the piece home (approved). */
export function mark(state: "open" | "closed" | "muted" = "open", id = "") {
  return `<svg class="mark${state === "open" ? "" : " " + state}"${id ? ` id="${id}"` : ""} viewBox="0 0 64 64" aria-hidden="true"><g class="plate-g"><rect class="plate" width="64" height="64" rx="14"/><g class="glyphs"><path class="glyph" d="M20 27H32V39H44V51H20Z"/><rect class="glyph piece" x="32" y="13" width="12" height="12"/><rect class="glyph whole" x="20" y="27" width="24" height="24"/></g></g></svg>`;
}

const I = (d: string, extra = "") => `<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"${extra}>${d}</svg>`;
export const ICON = {
  calendar: I(`<rect x="3.5" y="5" width="17" height="15.5" rx="3"/><path d="M3.5 9.8h17M8 3v4M16 3v4"/>`),
  pencil: I(`<path d="M14.5 5.5l4 4M4 20l1-4.5L15.8 4.7a1.8 1.8 0 012.5 0l1 1a1.8 1.8 0 010 2.5L8.5 19z"/>`),
  lock: I(`<rect x="5" y="10.5" width="14" height="10" rx="2.5"/><path d="M8.5 10.5V8a3.5 3.5 0 017 0v2.5"/>`),
  trashOff: I(`<path d="M4.5 7h15M9.5 7V4.8h5V7M6.5 7l.9 12.2a1.5 1.5 0 001.5 1.3h6.2a1.5 1.5 0 001.5-1.3L17.5 7M3 3l18 18"/>`),
  copy: I(`<rect x="8.5" y="8.5" width="11.5" height="11.5" rx="2.5"/><path d="M15.5 8.5V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7.5a2 2 0 002 2h2.5"/>`),
  info: I(`<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 8h.01"/>`),
  checkCircle: I(`<circle cx="12" cy="12" r="8.6"/><path d="M8.2 12.3l2.6 2.6 5-5.4"/>`),
  guard: I(`<path d="M12 3.5l7 2.6v5.3c0 4.4-3 7.9-7 9.1-4-1.2-7-4.7-7-9.1V6.1z"/><path d="M8.8 12.2l2.2 2.2 4.2-4.4"/>`),
  undo: I(`<path d="M9 14L4.5 9.5 9 5"/><path d="M4.5 9.5H14a5.5 5.5 0 010 11h-3"/>`),
  mailOff: I(`<rect x="3.5" y="5.5" width="17" height="13" rx="2.5"/><path d="M4 7l8 6 8-6M3 3l18 18"/>`),
  // Face ID, Touch ID and passkey glyphs travel together. An iPhone with a Home button (html.touch) shows the fingerprint,
  // a Mac or a non-Apple device (html.key) shows a key, since it may have no Touch ID sensor.
  faceId: I(`<path d="M4 8.5V6.5A2.5 2.5 0 016.5 4h2M15.5 4h2A2.5 2.5 0 0120 6.5v2M20 15.5v2a2.5 2.5 0 01-2.5 2.5h-2M8.5 20h-2A2.5 2.5 0 014 17.5v-2M9 9.5v1.2M15 9.5v1.2M12 9.5v3.6h-1M9.5 16a4 4 0 005 0"/>`).replace('class="ico"', 'class="ico bio-face"')
    + I(`<path d="M12 11v3.5c0 2-.6 3.8-1.6 5.3M8.6 12.3V11a3.4 3.4 0 016.8 0v2.2c0 2.4-.5 4.6-1.4 6.6M5.6 15.5c.2-1.3.3-2.8.3-4.5a6.1 6.1 0 0110.2-4.5M18.1 9.4c.1.5.1 1 .1 1.6 0 2.6-.3 5-1 7.2M4.8 7.6A8.7 8.7 0 0112 3.2c1.6 0 3.1.4 4.4 1.2"/>`).replace('class="ico"', 'class="ico bio-touch"')
    + I(`<circle cx="8" cy="12" r="3.6"/><path d="M11.6 12H20.5M17.5 12v3M20.5 12v2.4"/>`).replace('class="ico"', 'class="ico bio-key"'),
  device: I(`<rect x="7" y="2.8" width="10" height="18.4" rx="2.6"/><path d="M11 18h2"/>`),
  alert: I(`<circle cx="12" cy="12" r="8.6"/><path d="M12 7.6v5.2M12 16.3v.1"/>`),
  globe: I(`<circle cx="12" cy="12" r="8.6"/><path d="M3.6 12h16.8M12 3.4c2.4 2.4 3.6 5.3 3.6 8.6s-1.2 6.2-3.6 8.6c-2.4-2.4-3.6-5.3-3.6-8.6S9.6 5.8 12 3.4z"/>`),
  pencilOff: I(`<path d="M14.5 5.5l4 4M4 20l1-4.5L15.8 4.7a1.8 1.8 0 012.5 0l1 1a1.8 1.8 0 010 2.5L8.5 19zM3 3l18 18"/>`),
  tablet: I(`<rect x="5" y="2.8" width="14" height="18.4" rx="2.4"/><path d="M11 18.2h2"/>`),
  laptop: I(`<rect x="4.5" y="5" width="15" height="10" rx="1.6"/><path d="M2.5 18.5h19"/>`),
  devices: I(`<rect x="2.8" y="5" width="12.5" height="9" rx="1.6"/><path d="M1.8 17h14.5"/><rect x="16.5" y="8" width="5" height="10.5" rx="1.4"/>`),
  spinner: `<svg class="ico spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M12 3.5a8.5 8.5 0 108.5 8.5" /></svg>`,
  clock: I(`<circle cx="12" cy="12" r="8.6"/><path d="M12 7.5V12l3 2"/>`),
  keypad: I(`<circle cx="7" cy="6" r="1.2"/><circle cx="12" cy="6" r="1.2"/><circle cx="17" cy="6" r="1.2"/><circle cx="7" cy="11" r="1.2"/><circle cx="12" cy="11" r="1.2"/><circle cx="17" cy="11" r="1.2"/><circle cx="7" cy="16" r="1.2"/><circle cx="12" cy="16" r="1.2"/><circle cx="17" cy="16" r="1.2"/><circle cx="12" cy="20.5" r="1.2"/>`),
  link: I(`<path d="M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1"/>`),
  chev: `<svg class="chev" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2.5 4.5L6 8l3.5-3.5"/></svg>`,
};

/** A full screen: mark, headline, lede, then whatever follows. `lede` is trusted HTML (callers escape). */
/** Typographic apostrophes in copy. Safe on finished markup: every dynamic value went through esc(), so a raw ' only
 * appears in our own text, and an escaped one (&#39;) only ever sits between letters in words. */
export const typo = (html: string) => html.replace(/(\w)(?:'|&#39;)(\w)/g, "$1’$2");
export function screen(o: { title: string; titleId?: string; lede?: string; markState?: "open" | "closed" | "muted"; markId?: string; body?: string; actions?: string; centered?: boolean }) {
  return typo(`<main class="screen${o.centered ? " msg" : ""}"><div class="head">${mark(o.markState, o.markId)}<p class="brand">${PRODUCT}</p><h1 class="in${/^Connect /.test(o.title) && o.title.length > 24 ? " long" : ""}" id="${o.titleId ?? "title"}">${esc(o.title)}</h1>${o.lede ? `<p class="lede in d1">${o.lede}</p>` : ""}</div>${o.body ? `<div class="in d2">${o.body}</div>` : ""}${o.actions && !o.centered ? `<div class="gap"></div>` : ""}${o.actions ? `<div class="actions in d3">${o.actions}</div>` : ""}</main>`);
}

/** Owner-only help (commands, settings) lives behind this, never in the main copy: on a phone it means nothing to most people. */
export const ownerNote = (summary: string, html: string, open = false, cls = "") => `<details class="owner${cls ? " " + cls : ""}"${open ? " open" : ""}><summary>${esc(summary)} ${ICON.chev}</summary><div class="body">${html}</div></details>`;

/** End states (done, expired, error, not allowed). Mark: closed = a finished yes, muted = nothing happened.
 * One exit line: "You can close this page." unless the text already says where to go (noClose), then setup help, if any. `text` is plain (escaped here) unless html is set, when the caller escapes. */
export function endScreen(title: string, text: string, o: { owner?: string; ownerSummary?: string; ownerOpen?: boolean; mark?: "open" | "closed" | "muted"; extra?: string; ref?: string; noClose?: boolean; html?: boolean } = {}) {
  const foot = [o.noClose ? "" : "You can close this page.", o.extra ? esc(o.extra) : "", ""].filter(Boolean).join("<br>") + (o.ref ? `<span class="refline">Reference <span class="ref">${esc(o.ref)}</span></span>` : "");
  return screen({ title, lede: o.html ? text : esc(text), markState: o.mark ?? "muted", centered: true, actions: `${foot ? `<p class="foot">${foot}</p>` : ""}${o.owner ? ownerNote(o.ownerSummary ?? "Setup help", o.owner, o.ownerOpen) : ""}` });
}

/** The shared document. Every Holdt page goes through here. */
export function documentHtml(title: string, body: string, nonce = "", script = "") {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="light dark"><meta name="theme-color" content="${TOKENS.light.bg}" media="(prefers-color-scheme: light)"><meta name="theme-color" content="${TOKENS.dark.bg}" media="(prefers-color-scheme: dark)"><meta name="referrer" content="no-referrer"><meta name="format-detection" content="telephone=no"><title>${esc(title)}</title><style>${STYLE}</style></head><body>${body}${nonce ? `<script nonce="${nonce}">${script}</script>` : ""}</body></html>`;
}

/** Contrast ratio per WCAG 2.x, for the test. */
export function contrast(a: string, b: string) {
  const lum = (h: string) => { const n = parseInt(h.slice(1), 16); return [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((c) => { const s = c / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4; }).reduce((acc, v, i) => acc + v * [0.2126, 0.7152, 0.0722][i]!, 0); };
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x! + 0.05) / (y! + 0.05);
}
