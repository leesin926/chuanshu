"""Draw the eight tabBar PNGs (four glyphs, each as a line icon and a solid icon).

The design set pairs an outlined glyph in #9CA3AF for the unselected tab with the same glyph
filled in #2F7CF6 for the selected one, so both states are drawn from one path definition and
cannot drift. pages.json wants 81x81 local files under 40 KB, and Harmony accepts neither a font
icon nor a remote url, so the tabs need real pixels.

    py -X utf8 mobile/scripts/gen_tabbar.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QColor, QBrush, QGuiApplication, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtCore import Qt, QRectF, QPointF, QSizeF

SIZE = 81
OFF = QColor("#9CA3AF")
ON = QColor("#2F7CF6")
KNOCK = QColor("#FFFFFF")
OUT = Path(__file__).resolve().parents[1] / "chuanshu" / "static" / "tabbar"


def norm(rect: float, x: float, y: float) -> QPointF:
    """Map a 0..1 glyph coordinate onto the canvas, inside a margin of `rect` of the icon size."""
    span = SIZE * (1.0 - 2 * rect)
    return QPointF(SIZE * rect + span * x, SIZE * rect + span * y)


def pen_for(p: QPainter, color: QColor, weight: float) -> None:
    # A cosmetic pen would scale away to nothing on a 3x phone, so the stroke is a device
    # independent width chosen for an 81px icon and scaled with the size.
    pen = QPen(color)
    pen.setWidthF(SIZE / weight)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(QBrush(Qt.transparent))


def arrow(p: QPainter, up: bool, base_y: float, tip_y: float) -> None:
    """A vertical shaft with a chevron head, both drawn in the current pen."""
    mid = norm(0.30, 0.5, 0.0)
    p.drawLine(QPointF(mid.x(), SIZE * base_y), QPointF(mid.x(), SIZE * tip_y))
    head = 0.26 if up else -0.26
    p.drawLine(norm(0.30, 0.5 - head, 1.0), norm(0.30, 0.5, 0.0))
    p.drawLine(norm(0.30, 0.5, 0.0), norm(0.30, 0.5 + head, 1.0))


def home(p: QPainter, on: bool, color: QColor) -> None:
    m = 0.18
    body = QPainterPath()
    body.moveTo(norm(m, 0.02, 0.46))
    body.lineTo(norm(m, 0.50, 0.04))
    body.lineTo(norm(m, 0.98, 0.46))
    body.lineTo(norm(m, 0.98, 0.96))
    body.lineTo(norm(m, 0.02, 0.96))
    body.closeSubpath()
    door = QRectF(SIZE * 0.40, SIZE * 0.62, SIZE * 0.20, SIZE * 0.34)
    if on:
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(color))
        p.drawPath(body)
        # The selected house keeps the door as a knockout, or a filled blob is not a house.
        p.setBrush(QBrush(KNOCK))
        p.drawRect(door)
    else:
        pen_for(p, color, 20.0)
        p.drawPath(body)
        p.drawRect(door)


def files(p: QPainter, on: bool, color: QColor) -> None:
    m = 0.16
    tab = QPainterPath()
    tab.moveTo(norm(m, 0.06, 0.30))
    tab.lineTo(norm(m, 0.36, 0.30))
    tab.lineTo(norm(m, 0.46, 0.12))
    tab.lineTo(norm(m, 0.06, 0.12))
    tab.closeSubpath()
    box = QRectF(SIZE * 0.06, SIZE * 0.32, SIZE * 0.88, SIZE * 0.56)
    if on:
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(color))
        p.drawPath(tab)
        p.drawRoundedRect(box, 6, 6)
    else:
        pen_for(p, color, 20.0)
        p.drawPath(tab)
        p.drawRoundedRect(box, 6, 6)


def transfer(p: QPainter, on: bool, color: QColor) -> None:
    """A rounded tray with an arrow down into it and an arrow back out - the tab holds both directions."""
    frame = QRectF(SIZE * 0.10, SIZE * 0.10, SIZE * 0.80, SIZE * 0.80)
    if on:
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(color))
        p.drawRoundedRect(frame, 14, 14)
        pen_for(p, KNOCK, 16.0)
    else:
        pen_for(p, color, 20.0)
        p.drawRoundedRect(frame, 14, 14)
    # Down arrow on the left half, up arrow on the right half.
    down_x = SIZE * 0.36
    up_x = SIZE * 0.64
    p.drawLine(QPointF(down_x, SIZE * 0.28), QPointF(down_x, SIZE * 0.68))
    p.drawLine(QPointF(down_x - SIZE * 0.09, SIZE * 0.56), QPointF(down_x, SIZE * 0.68))
    p.drawLine(QPointF(down_x, SIZE * 0.68), QPointF(down_x + SIZE * 0.09, SIZE * 0.56))
    p.drawLine(QPointF(up_x, SIZE * 0.72), QPointF(up_x, SIZE * 0.32))
    p.drawLine(QPointF(up_x - SIZE * 0.09, SIZE * 0.44), QPointF(up_x, SIZE * 0.32))
    p.drawLine(QPointF(up_x, SIZE * 0.32), QPointF(up_x + SIZE * 0.09, SIZE * 0.44))


def me(p: QPainter, on: bool, color: QColor) -> None:
    m = 0.16
    head = QRectF(SIZE * 0.33, SIZE * 0.10, SIZE * 0.34, SIZE * 0.34)
    body = QPainterPath()
    body.moveTo(norm(m, 0.06, 0.96))
    body.cubicTo(norm(m, 0.10, 0.60), norm(m, 0.36, 0.52), norm(m, 0.50, 0.52))
    body.cubicTo(norm(m, 0.64, 0.52), norm(m, 0.90, 0.60), norm(m, 0.94, 0.96))
    body.closeSubpath()
    if on:
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(color))
        p.drawEllipse(head)
        p.drawPath(body)
    else:
        pen_for(p, color, 20.0)
        p.drawEllipse(head)
        outline = QPainterPath()
        outline.moveTo(norm(m, 0.06, 0.96))
        outline.cubicTo(norm(m, 0.10, 0.60), norm(m, 0.36, 0.52), norm(m, 0.50, 0.52))
        outline.cubicTo(norm(m, 0.64, 0.52), norm(m, 0.90, 0.60), norm(m, 0.94, 0.96))
        p.drawPath(outline)


GLYPHS = {"home": home, "files": files, "transfer": transfer, "me": me}


def main() -> int:
    # Without a QGuiApplication a QPixmap aborts the process on Windows, so the app object exists
    # even though nothing here opens a window.
    app = QGuiApplication(sys.argv)
    if not OUT.is_dir():
        OUT.mkdir(parents=True)
    for name, draw in GLYPHS.items():
        for color, suffix, on in ((OFF, "", False), (ON, "-on", True)):
            pm = QPixmap(SIZE, SIZE)
            pm.fill(Qt.transparent)
            p = QPainter(pm)
            p.setRenderHint(QPainter.Antialiasing, True)
            draw(p, on, color)
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
