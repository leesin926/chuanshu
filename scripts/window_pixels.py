"""Pixel-side assertions shared by the two frozen-build gates.

Windows reaches them through `freeze_smoke.py`, Linux through `.probe/linux_smoke.sh`; neither gate can
import the other, and the failure they both have to catch - a pairing QR that is a clean white box -
looks like a healthy window to every other check. Nothing here may touch a platform API.
"""

from __future__ import annotations


def ink_and_paper(raw: bytes) -> tuple[int, float, float]:
    """(distinct colours, share of near-black, share of near-white) across a sampled scan of BGRA pixels.

    A window that will not repaint for a covered capture answers with the right size and one flat
    colour, which is the polite failure a screenshot gate mistakes for success.
    """
    step = 4 * max(1, len(raw) // 4 // 20000)
    seen: set[bytes] = set()
    dark = light = total = 0
    for i in range(0, len(raw) - 3, step):
        px = raw[i:i + 3]
        lum = (px[2] * 299 + px[1] * 587 + px[0] * 114) // 1000
        seen.add(px)
        total += 1
        if lum < 48:
            dark += 1
        elif lum > 208:
            light += 1
    return len(seen), dark / total, light / total


def runs(line: bytes) -> list[tuple[int, int, int]]:
    """(value, start, length) for every constant run in a one-byte-per-pixel line."""
    out: list[tuple[int, int, int]] = []
    start = 0
    for x in range(1, len(line)):
        if line[x] != line[start]:
            out.append((line[start], start, x - start))
            start = x
    out.append((line[start], start, len(line) - start))
    return out


def finder_row(line: bytes) -> list[int]:
    """Where a one-byte-per-pixel line crosses 1:1:3:1:1 - the bar at the corner of a QR finder pattern.

    The unit is the middle run divided by three and each of the five has to sit within 60 % of its
    share, which is loose enough for antialiasing and tight enough that a dashed drop-zone border
    (1:1, then nothing) never answers.
    """
    hits: list[int] = []
    seq = runs(line)
    for i in range(2, len(seq) - 2):
        value, start, length = seq[i]
        if not value or length < 5:
            continue
        unit = length / 3
        if all(abs(seq[i + k][2] - unit * (1 if k else 3)) <= 0.6 * unit * (1 if k else 3)
               for k in (-2, -1, 0, 1, 2)):
            hits.append(start + length // 2)
    return hits


def finder_patterns(raw: bytes, w: int, h: int) -> int:
    """How many scanlines cross a QR finder pattern, given BGRA pixels.

    ``_qr_pixmap`` paints the modules with QtSvg onto a white image, so a bundle that lost the SVG
    plugin shows a clean white box, a page that looks otherwise perfect, and an empty error log.
    Measured on the Windows build: a drawn QR gives 31-33 rows, a text-only page gives 0, and the
    same page with the box painted over by hand also gives 0.
    """
    dark = bytes(1 if v < 128 else 0 for v in raw[1::4])          # green channel, one byte per pixel
    hits = 0
    for y in range(0, h, 2):
        for cx in finder_row(dark[y * w:(y + 1) * w]):
            if any(abs(cy - y) < 40 for cy in finder_row(dark[cx::w])):
                hits += 1
                break
    return hits


if __name__ == "__main__":
    # `python window_pixels.py window.png window-receive.png` -> `colours=228 finder_rows=31`, for the
    # gates that can only reach a window through a screenshot tool (Linux: maim, see .probe/linux_smoke.sh).
    import sys

    from PySide6.QtGui import QImage

    def load(path: str) -> tuple[bytes, int, int]:
        img = QImage(path).convertToFormat(QImage.Format_ARGB32)
        w, h = img.width(), img.height()
        return bytes(img.constBits())[: w * h * 4], w, h

    argv = sys.argv[1:]
    if not argv:
        raise SystemExit("usage: window_pixels.py <window.png> [<window-receive.png>]")
    raw, _, _ = load(argv[0])
    report = [f"colours={ink_and_paper(raw)[0]}"]
    if len(argv) > 1:
        second, w2, h2 = load(argv[1])
        report.append(f"finder_rows={finder_patterns(second, w2, h2)}")
    print(" ".join(report))
