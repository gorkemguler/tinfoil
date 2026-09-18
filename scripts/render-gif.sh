#!/usr/bin/env bash
#
# Render a VHS tape to a GIF.
#
# Why this exists instead of a bare `vhs <tape>`:
#
#   VHS captures the terminal frames correctly, then composites and encodes them
#   in a final step that fails silently on some setups - notably vhs 0.12 on
#   macOS, which exits 0, prints "Creating <file>.gif...", and writes nothing.
#   It also passes ffmpeg's `-vsync`, removed in ffmpeg 8.
#
#   So we ask VHS for the raw frames, which it produces reliably, and do the
#   encode ourselves. If a future VHS fixes this, `vhs assets/demo.tape` will
#   work on its own and this script becomes a thin wrapper around the same
#   result.
#
# Usage: scripts/render-gif.sh assets/demo.tape

set -euo pipefail

TAPE="${1:?usage: scripts/render-gif.sh <tape>}"
[ -f "$TAPE" ] || { echo "no such tape: $TAPE" >&2; exit 1; }

command -v vhs >/dev/null || {
    echo "vhs not found. Install it with: brew install vhs" >&2
    exit 1
}

# ffmpeg 8 removed -vsync, which older VHS builds still pass. We do not use it,
# but prefer a pinned ffmpeg when one is installed so both paths agree.
FFMPEG="$(command -v ffmpeg || true)"
for candidate in /opt/homebrew/opt/ffmpeg@7/bin/ffmpeg /usr/local/opt/ffmpeg@7/bin/ffmpeg; do
    [ -x "$candidate" ] && FFMPEG="$candidate" && break
done
[ -n "$FFMPEG" ] || { echo "ffmpeg not found. Install it with: brew install ffmpeg" >&2; exit 1; }

OUT="$(grep -m1 '^Output ' "$TAPE" | awk '{print $2}')"
[ -n "$OUT" ] || { echo "$TAPE declares no Output" >&2; exit 1; }
FPS="$(grep -m1 '^Set Framerate ' "$TAPE" | awk '{print $3}')"
FPS="${FPS:-30}"

FRAMES=".frames-$(basename "${TAPE%.tape}")"
TMP_TAPE="$(mktemp -t vhstape).tape"
trap 'rm -rf "$FRAMES" "$TMP_TAPE"' EXIT

# Ask for the frames alongside whatever the tape already declares.
awk -v frames="$FRAMES/" '
    { print }
    !done && /^Output / { print "Output " frames; done = 1 }
' "$TAPE" > "$TMP_TAPE"

rm -rf "$FRAMES"
echo "==> capturing frames for $TAPE"
vhs "$TMP_TAPE" > /dev/null 2>&1 || true

count=$(ls "$FRAMES"/frame-text-*.png 2>/dev/null | wc -l | tr -d ' ')
[ "$count" -gt 0 ] || { echo "VHS captured no frames - is ttyd working?" >&2; exit 1; }
echo "    $count frames"

# VHS numbers frames from wherever the recording starts, so hand ffmpeg a
# glob rather than a %05d pattern with an assumed start index.
mkdir -p "$(dirname "$OUT")"
echo "==> encoding $OUT"
# VHS exports two layers: frame-text carries the terminal contents and
# frame-cursor carries only the cursor, so the cursor goes on top of the text.
"$FFMPEG" -y \
    -framerate "$FPS" -pattern_type glob -i "$FRAMES/frame-text-*.png" \
    -framerate "$FPS" -pattern_type glob -i "$FRAMES/frame-cursor-*.png" \
    -filter_complex "[0:v][1:v] overlay=shortest=1 [v];[v] split [a][b];[a] palettegen=stats_mode=diff [p];[b][p] paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" \
    -loop 0 "$OUT" > /dev/null 2>&1

[ -s "$OUT" ] || { echo "encode produced nothing" >&2; exit 1; }
echo "    $(du -h "$OUT" | cut -f1)  $OUT"
