#!/usr/bin/env python3
"""
Render the README banner and the GitHub social-preview image.

    python3 scripts/make-banner.py

The pixel logo, the block digits and every colour are read from tinfoil.py, so
the artwork cannot drift from what the tool actually prints. Rendering goes
through headless Chrome - it is already installed on most machines, and it
draws type exactly as GitHub's viewers will see it.

Outputs:
    assets/banner.png           2560x640, README header (rounded, transparent corners)
    assets/social-preview.png   1280x640, upload under Settings > Social preview
"""

import html
import os
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import tinfoil as t  # noqa: E402

# The same run `tinfoil --demo` renders, so the banner and the recording agree.
SCORE = 50
COUNTS = (7, 3, 8)
REPO = "github.com/gorkemguler/tinfoil"


def xterm(n):
    """xterm-256 index -> hex, matching what a terminal draws for the tool's colours."""
    if n >= 232:
        v = 8 + 10 * (n - 232)
        return "#%02x%02x%02x" % (v, v, v)
    n -= 16
    levels = (0, 95, 135, 175, 215, 255)
    return "#%02x%02x%02x" % (levels[n // 36], levels[(n // 6) % 6], levels[n % 6])


ACCENT = xterm(t.COLOR_ACCENT)
CRIT, HIGH, MED, OK = (xterm(t.COLOR_CRIT), xterm(t.COLOR_HIGH),
                       xterm(t.COLOR_MED), xterm(t.COLOR_OK))
GRADE, GRADE_COLOR = t.grade_of(SCORE)[0], xterm(t.grade_of(SCORE)[1])

BG = "#12131a"
TEXT = "#ececf2"
MUTED = "#8d8e9c"
FAINT = "#5c5d6b"


# --------------------------------------------------------------------------
# pixel art, generated from the tool's own glyphs
# --------------------------------------------------------------------------

FULL, UPPER, LOWER = "█", "▀", "▄"


def logo_svg(px, color=ACCENT):
    """The half-block TINFOIL wordmark: each character cell is two square pixels."""
    rows = t.LOGO
    cols = max(len(r.rstrip()) for r in rows)
    cells = []
    for r, row in enumerate(rows):
        for c, ch in enumerate(row):
            if ch in (FULL, UPPER):
                cells.append((c, 2 * r))
            if ch in (FULL, LOWER):
                cells.append((c, 2 * r + 1))
    w, h = cols * px, 4 * px
    rects = "".join('<rect x="%d" y="%d" width="%d" height="%d"/>' % (c * px, y * px, px, px)
                    for c, y in cells)
    return ('<svg width="%d" height="%d" viewBox="0 0 %d %d" fill="%s" '
            'shape-rendering="crispEdges">%s</svg>' % (w, h, w, h, color, rects))


def digits_svg(n, pw, ph, color):
    """Big score digits. Terminal cells are twice as tall as wide, so pixels are too."""
    rects, x = [], 0
    for i, ch in enumerate(str(n)):
        if i:
            x += 2 * pw
        for r, row in enumerate(t.DIGITS[ch]):
            for c, cell in enumerate(row):
                if cell != " ":
                    rects.append((x + c * pw, r * ph))
        x += 5 * pw
    w, h = x, 5 * ph
    body = "".join('<rect x="%d" y="%d" width="%d" height="%d"/>' % (rx, ry, pw, ph)
                   for rx, ry in rects)
    return ('<svg width="%d" height="%d" viewBox="0 0 %d %d" fill="%s" '
            'shape-rendering="crispEdges">%s</svg>' % (w, h, w, h, color, body))


def gauge_svg(score, cells, cw, h, color):
    filled = int(round(cells * score / 100.0))
    w = cells * cw
    return ('<svg width="%d" height="%d" viewBox="0 0 %d %d" shape-rendering="crispEdges">'
            '<rect width="%d" height="%d" fill="%s" opacity=".2"/>'
            '<rect width="%d" height="%d" fill="%s"/></svg>'
            % (w, h, w, h, w, h, color, filled * cw, h, color))


# --------------------------------------------------------------------------
# shared pieces
# --------------------------------------------------------------------------

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { width: %(w)dpx; height: %(h)dpx; background: transparent; overflow: hidden; }
body {
  font-family: -apple-system, "SF Pro Display", "Helvetica Neue", Arial, sans-serif;
  -webkit-font-smoothing: antialiased; color: %(text)s;
}
.mono { font-family: "SF Mono", ui-monospace, Menlo, Consolas, monospace; }
.frame {
  position: relative; width: 100%%; height: 100%%; overflow: hidden;
  background:
    radial-gradient(ellipse 70%% 90%% at 8%% 0%%, rgba(135,215,215,.13), transparent 60%%),
    radial-gradient(ellipse 45%% 70%% at 88%% 60%%, rgba(255,175,95,.10), transparent 65%%),
    %(bg)s;
}
.frame::before {           /* a faint terminal dot grid */
  content: ""; position: absolute; inset: 0; pointer-events: none;
  background-image: radial-gradient(rgba(255,255,255,.055) 1px, transparent 1.3px);
  background-size: 22px 22px;
  -webkit-mask-image: linear-gradient(100deg, #000 10%%, transparent 75%%);
}
.frame > * { position: relative; }
h1 { font-weight: 700; letter-spacing: -0.025em; line-height: 1.12; }
h1 span { color: %(accent)s; }
.pills { display: flex; gap: 8px; flex-wrap: wrap; }
.pills span {
  font-size: 13px; font-weight: 500; color: %(muted)s; white-space: nowrap;
  border: 1px solid rgba(255,255,255,.12); border-radius: 999px; padding: 6px 12px;
  background: rgba(255,255,255,.025);
}
.pills b { color: %(ok)s; font-weight: 600; }
.card {
  background: rgba(8,8,12,.6); border: 1px solid rgba(255,255,255,.09);
  border-radius: 14px; box-shadow: 0 24px 70px rgba(0,0,0,.45);
}
.cmd { color: %(faint)s; }
.cmd i { color: %(ok)s; font-style: normal; }
.score { display: flex; align-items: flex-start; }
.side { display: grid; align-items: center; white-space: nowrap; }
.dim { color: %(faint)s; }
.label { color: %(muted)s; letter-spacing: .08em; }
.grade { font-weight: 700; }
.gauge { display: flex; align-items: center; gap: 12px; }
"""


def css(w, h):
    return CSS % {"w": w, "h": h, "text": TEXT, "bg": BG, "accent": ACCENT,
                  "muted": MUTED, "faint": FAINT, "ok": OK}


def pills():
    items = ["<b>1</b> file", "<b>0</b> dependencies", "<b>0</b> network calls",
             "macOS &middot; Linux", "MIT"]
    return '<div class="pills mono">%s</div>' % "".join("<span>%s</span>" % i for i in items)


def score_card(pw, ph, font, gauge_cell, pad):
    fails, warns, passes = COUNTS
    side = [
        '<div class="label">PARANOIA SCORE</div>',
        '<div class="grade" style="color:%s">%s</div>' % (GRADE_COLOR, GRADE),
        '<div class="gauge">%s<span class="dim">%d/100</span></div>'
        % (gauge_svg(SCORE, 26, gauge_cell, int(ph * 0.55), GRADE_COLOR), SCORE),
        '<div><span style="color:%s">%d failed</span>&nbsp;&nbsp; '
        '<span style="color:%s">%d warnings</span>&nbsp;&nbsp; '
        '<span style="color:%s">%d passed</span></div>' % (CRIT, fails, MED, warns, OK, passes),
        '<div class="dim">18 checks in 2.4s</div>',
    ]
    return (
        '<div class="card mono" style="padding:%dpx %dpx">'
        '<div class="cmd" style="font-size:%dpx;margin-bottom:%dpx"><i>$</i> python3 tinfoil.py</div>'
        '<div class="score" style="gap:%dpx">%s'
        '<div class="side" style="grid-auto-rows:%dpx;font-size:%dpx">%s</div>'
        '</div></div>'
        % (pad, pad + 2, font, int(ph * 0.8), int(pw * 2.6),
           digits_svg(SCORE, pw, ph, GRADE_COLOR), ph, font, "".join(side))
    )


# --------------------------------------------------------------------------
# the two compositions
# --------------------------------------------------------------------------

def banner_html():
    w, h = 1280, 320
    return """<!doctype html><html><head><meta charset="utf-8"><style>%s
.frame { border-radius: 18px; border: 1px solid rgba(255,255,255,.08);
         display: flex; align-items: center; justify-content: space-between; padding: 0 58px; }
.left { display: flex; flex-direction: column; gap: 24px; }
h1 { font-size: 36px; }
</style></head><body><div class="frame">
  <div class="left">
    %s
    <h1>Your machine's attack surface,<br><span>in one command.</span></h1>
    %s
  </div>
  %s
</div></body></html>""" % (css(w, h), logo_svg(14), pills(),
                          score_card(pw=10, ph=20, font=13, gauge_cell=7, pad=22))


FINDINGS = [
    ("✗", "CRITICAL", CRIT, "2 .env files committed to git", ""),
    ("✗", "HIGH", HIGH, "postgres, redis open on 0.0.0.0", ""),
    ("✗", "HIGH", HIGH, "AWS key in shell history", "AKIA**********7Q"),
    ("!", "WARN", MED, "SSH key without a passphrase", ""),
]


def findings_panel():
    rows = []
    for glyph, sev, color, text, extra in FINDINGS:
        rows.append(
            '<div class="f"><b style="color:%s">%s</b><b style="color:%s">%s</b>'
            '<span>%s</span>%s</div>'
            % (color, glyph, color, sev, html.escape(text),
               ' <em class="dim">%s</em>' % extra if extra else ""))
    return '<div class="findings card mono">%s</div>' % "".join(rows)


def social_html():
    w, h = 1280, 640
    return """<!doctype html><html><head><meta charset="utf-8"><style>%s
.frame { padding: 58px 64px; display: flex; flex-direction: column; justify-content: space-between; }
header { display: flex; align-items: center; justify-content: space-between; }
.url { font-size: 18px; color: %s; }
h1 { font-size: 54px; margin-top: 30px; }
.row { display: flex; gap: 26px; align-items: stretch; margin-top: 34px; }
.findings { flex: 1; padding: 22px 26px; display: flex; flex-direction: column;
            justify-content: center; gap: 12px; font-size: 18px; }
.f { display: flex; align-items: baseline; white-space: nowrap; }
.f b { font-weight: 700; }
.f b:first-child { width: 1.6em; }
.f b:nth-child(2) { width: 6.2em; font-size: 15px; letter-spacing: .04em; }
.f em { font-style: normal; margin-left: .9em; }
.pills { margin-top: 30px; }
.pills span { font-size: 15px; padding: 7px 14px; }
</style></head><body><div class="frame">
  <div>
    <header>%s<div class="url mono">%s</div></header>
    <h1>Your machine's attack surface,<br><span>in one command.</span></h1>
    <div class="row">%s%s</div>
  </div>
  %s
</div></body></html>""" % (css(w, h), MUTED, logo_svg(18), REPO, findings_panel(),
                          score_card(pw=11, ph=22, font=14, gauge_cell=7, pad=20), pills())


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def find_chrome():
    for p in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
              "/Applications/Chromium.app/Contents/MacOS/Chromium"):
        if os.path.exists(p):
            return p
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return found
    sys.exit("make-banner: no Chrome or Chromium found - install one to render the artwork")


def png_size(path):
    with open(path, "rb") as fh:
        head = fh.read(24)
    return struct.unpack(">II", head[16:24])


def render(chrome, markup, out, w, h, scale):
    out = Path(out)
    out.unlink() if out.exists() else None
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp, "page.html")
        page.write_text(markup, encoding="utf-8")
        # A throwaway profile, so this never touches (or fights) a running Chrome.
        proc = subprocess.Popen([
            chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
            "--no-first-run", "--no-default-browser-check",
            "--user-data-dir=%s" % Path(tmp, "profile"),
            "--force-device-scale-factor=%s" % scale,
            "--window-size=%d,%d" % (w, h),
            "--default-background-color=00000000",
            "--screenshot=%s" % out.resolve(),
            page.as_uri(),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)

        # Headless Chrome on macOS writes the screenshot and then often lingers
        # instead of exiting. Wait for a complete file, then stop it ourselves.
        deadline, last, stable = time.time() + 60, -1, 0
        while time.time() < deadline and proc.poll() is None:
            size = out.stat().st_size if out.exists() else -1
            stable = stable + 1 if size > 0 and size == last else 0
            last = size
            if stable >= 3:
                break
            time.sleep(0.25)
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
    if not out.exists():
        sys.exit("make-banner: Chrome produced no image for %s" % out)
    got = png_size(out)
    want = (w * scale, h * scale)
    if got != want:
        sys.exit("make-banner: %s is %dx%d, expected %dx%d" % ((out,) + got + want))
    print("  %-26s %dx%d  %s" % (out.relative_to(ROOT), got[0], got[1],
                                  "%dK" % (out.stat().st_size // 1024)))


def main():
    chrome = find_chrome()
    (ROOT / "assets").mkdir(exist_ok=True)
    render(chrome, banner_html(), ROOT / "assets/banner.png", 1280, 320, 2)
    render(chrome, social_html(), ROOT / "assets/social-preview.png", 1280, 640, 1)


if __name__ == "__main__":
    main()
