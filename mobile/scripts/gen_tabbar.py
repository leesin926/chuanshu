"""Draw the six tabBar PNGs (three glyphs, each in its off and on colour).

pages.json wants 81x81 local files under 40 KB and Harmony accepts neither a font icon nor a
remote url, so the tabs need real pixels. They are generated rather than committed binary because
a glyph set has to stay editable and consistent with the palette the rest of the app uses.

    py -X utf8 mobile/scripts/gen_tabbar.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QColor, QGuiApplication, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtCore import Qt, QRectF, QPointF

SIZE = 81
OFF = QColor("#8a9099")
ON = QColor("#1456f0")
OUT = Path(__file__).resolve().parents[1] / "chuanshu" / "static" / "tabbar"


def canvas() -> QPixmap:
    pm = QPixmap(SIZE, SIZE)
    pm.fill(Qt.transparent)
    return pm


def painter(pm: QPixmap, color: QColor) -> QPainter:
    p = QPainter(pm)
    # A cosmetic pen would scale away to nothing on a 3x phone, so the stroke is a device
    # independent width chosen for an 81px icon and scaled with the size.
    pen = QPen(color)
    pen.setWidthF(SIZE / 20.0)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    p.setPen(pen)
    p.setRenderHint(QPainter.Antialiasing, True)
    return p


def norm(rect: float, x: float, y: float) -> QPointF:
    """Map a 0..1 glyph coordinate onto the canvas, inside a margin of `rect` of the icon size."""
    span = SIZE * (1.0 - 2 * rect)
    return QPointF(SIZE * rect + span * x, SIZE * rect + span * y)


def home(p: QPainter) -> None:
    m = 0.18
    a = norm(m, 0.02, 0.44)
    apex = norm(m, 0.5, 0.06)
    b = norm(m, 0.98, 0.44)
    p.drawLine(a, apex)
    p.drawLine(apex, b)
    wall_l = norm(m, 0.14, 0.40)
    wall_r = norm(m, 0.86, 0.40)
    floor_l = norm(m, 0.14, 0.92)
    floor_r = norm(m, 0.86, 0.92)
    p.drawLine(wall_l, floor_l)
    p.drawLine(wall_r, floor_r)
    p.drawLine(floor_l, floor_r)
    door_l = norm(m, 0.40, 0.92)
    door_r = norm(m, 0.60, 0.92)
    door_tl = norm(m, 0.40, 0.62)
    door_tr = norm(m, 0.60, 0.62)
    p.drawLine(door_l, door_tl)
    p.drawLine(door_tl, door_tr)
    p.drawLine(door_tr, door_r)


def files(p: QPainter) -> None:
    m = 0.16
    top_left = norm(m, 0.08, 0.04)
    fold_from = norm(m, 0.66, 0.04)
    top_right = norm(m, 0.92, 0.30)
    bottom_right = norm(m, 0.92, 0.96)
    bottom_left = norm(m, 0.08, 0.96)
    path = QPainterPath()
    path.moveTo(top_left)
    path.lineTo(fold_from)
    path.lineTo(top_right)
    path.lineTo(bottom_right)
    path.lineTo(bottom_left)
    path.closeSubpath()
    p.drawPath(path)
    corner = QPainterPath()
    corner.moveTo(fold_from)
    corner.lineTo(norm(m, 0.66, 0.30))
    corner.lineTo(top_right)
    p.drawPath(corner)
    for y in (0.50, 0.66, 0.82):
        p.drawLine(norm(m, 0.24, y), norm(m, 0.76, y))


def me(p: QPainter) -> None:
    m = 0.16
    head = QRectF(SIZE * 0.33, SIZE * 0.10, SIZE * 0.34, SIZE * 0.34)
    p.drawEllipse(head)
    body = QPainterPath()
    body.moveTo(norm(m, 0.06, 0.96))
    body.cubicTo(norm(m, 0.10, 0.60), norm(m, 0.36, 0.52), norm(m, 0.50, 0.52))
    body.cubicTo(norm(m, 0.64, 0.52), norm(m, 0.90, 0.60), norm(m, 0.94, 0.96))
    p.drawPath(body)


GLYPHS = {"home": home, "files": files, "me": me}


def main() -> int:
    # Without a QGuiApplication a QPixmap aborts the process on Windows, so the app object exists
    # even though nothing here opens a window.
    app = QGuiApplication(sys.argv)
    if not OUT.is_dir():
        OUT.mkdir(parents=True)
    for name, draw in GLYPHS.items():
        for color, suffix in ((OFF, ""), (ON, "-on")):
            pm = canvas()
            p = painter(pm, color)
            draw(p)
            p.end()
            out = OUT / (name + suffix + ".png")
            if not pm.save(str(out), "PNG"):
                print("FAILED to write " + str(out))
                app.quit()
                return 1
            print("%s  %d B" % (out, out.stat().st_size))
    app.quit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
