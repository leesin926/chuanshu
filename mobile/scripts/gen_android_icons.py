#!/usr/bin/env python3
"""Render the four Android launcher densities from the PC app mark.

manifest.json's app-android.distribute.icons are paths to PNGs, and DCloud ships its own logo for
any of the four left empty - so a release APK without these is a different app on the home screen.
The mark is vector upstream (assets/icons/logo.svg); the launcher needs padding and an opaque plate,
which is why the composition below is not that file verbatim.

    py -X utf8 mobile/scripts/gen_android_icons.py

Needs PySide6 (QtSvg) on the machine that packs, i.e. the PC side, not the phone project.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "mobile" / "chuanshu" / "static" / "icons" / "android"

# logo.svg's glyph box is x 5.1..17.4, y 7.1..16.9 on the 24 grid (stroke half-width included);
# scaled 25x and centred that leaves the mark at ~60% of the plate, which is what a legacy
# launcher icon can carry without being cropped by the round mask on Android 8+.
LAUNCHER_SVG = """<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="112" fill="#3b82f6"/>
  <g transform="translate(-25,-44) scale(25)" stroke="#ffffff" stroke-width="1.8"
     stroke-linecap="round" fill="none">
    <path d="M6 13.5v-2M9.5 16V8M13 14.5v-4M16.5 12.5v-1.5"/>
  </g>
</svg>"""

DENSITIES = {"hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}


def render(px: int) -> QImage:
    renderer = QSvgRenderer(QByteArray(LAUNCHER_SVG.encode()))
    if not renderer.isValid():
        raise SystemExit("launcher SVG failed to parse")
    image = QImage(px, px, QImage.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    renderer.render(painter)
    painter.end()
    return image


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, px in DENSITIES.items():
        target = OUT / f"{name}.png"
        image = render(px)
        if not image.save(str(target), "PNG"):
            print(f"FAIL  {target}: QImage.save returned False")
            return 1
        print(f"ok    {target.name}  {px}x{px}  {target.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
