"""Launch the packaged build and prove it really runs: window on screen, QR painted,
log clean, and the terminal face beside it answering.

The window leg asks *that handle* for its own pixels instead of photographing a screen region: a build
sitting behind another app used to be judged from a picture of the app in front of it, and still print
its own rect's size while doing so.

The in-process UI selftest cannot cover what only a frozen build breaks (bundled data
files, native extensions, resource lookup under ``sys._MEIPASS``), so this drives the
actual exe. It writes into a scratch APPDATA and closes only the process it started.

Expect a Windows Firewall prompt per new exe path: the build is unsigned, so Windows asks
before it accepts inbound traffic. Answering cancel leaves permanent *block* rules for that
path - which is exactly what the installer's "firewall" task exists to avoid, and what
`ChuanShu-cli.exe firewall` then reads back as blocked. `--no-discover` does not dodge the
prompt: the CLI leg's plain TCP listener was enough to raise one on this machine, and this
gate leaves that prompt standing for the user to answer - it never clicks a system dialog.

    py -X utf8 scripts/freeze_smoke.py [dist/ChuanShu/ChuanShu.exe]
"""

from __future__ import annotations

import ctypes
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# The shipped folder, not a scratch copy: an older scratch build passes every check it was
# built for, which is how a two-executable spec can be smoke-tested while still shipping one.
EXE = ROOT / "dist/ChuanShu/ChuanShu.exe"
SHOTS = ROOT / ".probe/freeze"
CLI_PORT = 43915

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32


def decode(raw: bytes) -> str:
    """A frozen build writes the console codepage and ignores PYTHONIOENCODING - the
    bootloader configures the interpreter itself, so PEP 587 never reads the env."""
    for enc in ("utf-8", "gbk"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


class RECT(ctypes.Structure):
    _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                ("right", ctypes.c_long), ("bottom", ctypes.c_long)]


def window_of(pid: int) -> int | None:
    """First visible top-level window owned by ``pid``."""
    found: list[int] = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def probe(hwnd, _):
        owner = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and user32.IsWindowVisible(hwnd) and user32.GetWindowTextLengthW(hwnd):
            found.append(hwnd)
        return True

    user32.EnumWindows(probe, 0)
    return found[0] if found else None


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", ctypes.c_uint32), ("biWidth", ctypes.c_long),
                ("biHeight", ctypes.c_long), ("biPlanes", ctypes.c_uint16),
                ("biBitCount", ctypes.c_uint16), ("biCompression", ctypes.c_uint32),
                ("biSizeImage", ctypes.c_uint32), ("biXPelsPerMeter", ctypes.c_long),
                ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", ctypes.c_uint32),
                ("biClrImportant", ctypes.c_uint32)]


# Device contexts and bitmaps are pointers. Left at ctypes' default int return, an x64 HDC is silently
# truncated to 32 bits and every later GDI call gets a handle that never existed.
user32.GetDC.restype = ctypes.c_void_p
user32.GetDC.argtypes = [ctypes.c_void_p]
user32.ReleaseDC.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
user32.PrintWindow.restype = ctypes.c_int
user32.PrintWindow.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]
gdi32.CreateCompatibleDC.restype = ctypes.c_void_p
gdi32.CreateCompatibleDC.argtypes = [ctypes.c_void_p]
gdi32.CreateCompatibleBitmap.restype = ctypes.c_void_p
gdi32.CreateCompatibleBitmap.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
gdi32.SelectObject.restype = ctypes.c_void_p
gdi32.SelectObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
gdi32.DeleteObject.argtypes = [ctypes.c_void_p]
gdi32.DeleteDC.argtypes = [ctypes.c_void_p]
gdi32.GetDIBits.restype = ctypes.c_int
gdi32.GetDIBits.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint,
                            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]


def capture(hwnd: int, w: int, h: int) -> bytes | None:
    """The pixels of *this* window, asked of the window itself.

    ``screen.grabWindow(0, x, y, …)`` photographs a screen region, so when the window under test sits
    behind something else the gate saves that other app, prints its own rect's size, and calls the leg
    held. PrintWindow with PW_RENDERFULLCONTENT (2) is what makes a covered Qt window answer at all.
    """
    hdc_win = user32.GetDC(hwnd)
    if not hdc_win:
        return None
    try:
        mem = gdi32.CreateCompatibleDC(hdc_win)
        bmp = gdi32.CreateCompatibleBitmap(hdc_win, w, h)
        old = gdi32.SelectObject(mem, bmp)
        try:
            if not user32.PrintWindow(hwnd, mem, 2):
                return None
            info = BITMAPINFOHEADER()
            info.biSize = ctypes.sizeof(BITMAPINFOHEADER)
            info.biWidth, info.biHeight = w, -h          # negative height = top-down rows
            info.biPlanes, info.biBitCount = 1, 32
            buf = ctypes.create_string_buffer(w * h * 4)
            if not gdi32.GetDIBits(mem, bmp, 0, h, buf, ctypes.byref(info), 0):
                return None
            return buf.raw
        finally:
            gdi32.SelectObject(mem, old)
            gdi32.DeleteObject(bmp)
            gdi32.DeleteDC(mem)
    finally:
        user32.ReleaseDC(hwnd, hdc_win)


def ink_and_paper(raw: bytes) -> tuple[int, float, float]:
    """(distinct colours, share of near-black, share of near-white) across a sampled scan of *raw*.

    The one failure PrintWindow has here is the polite kind: a window that will not repaint for a
    covered capture answers with the right size and a single flat colour, and the leg passes. So the
    gate refuses a flat image instead of trusting that the handle was the right one.
    """
    stride = 4 * max(1, len(raw) // 4 // 20000)
    seen: set[bytes] = set()
    dark = light = total = 0
    for i in range(0, len(raw) - 3, stride):
        lum = (raw[i + 2] * 299 + raw[i + 1] * 587 + raw[i] * 114) // 1000
        seen.add(raw[i:i + 3])
        total += 1
        if lum < 48:
            dark += 1
        elif lum > 208:
            light += 1
    return len(seen), dark / total, light / total


class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


user32.PostMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_long]
user32.ScreenToClient.argtypes = [ctypes.c_void_p, ctypes.c_void_p]


def click(hwnd: int, x: int, y: int) -> None:
    """Post a left click at a *client*-area point, leaving the user's cursor where it is.

    Only the nav rail is ever clicked, so a wrong estimate can change which page shows and nothing
    else - none of the buttons that open a dialog live in that strip.
    """
    lp = (y << 16) | (x & 0xFFFF)
    user32.PostMessageW(hwnd, 0x0200, 0, lp)            # WM_MOUSEMOVE, so Qt has a position to press at
    time.sleep(0.2)
    user32.PostMessageW(hwnd, 0x0201, 1, lp)            # WM_LBUTTONDOWN, MK_LBUTTON
    time.sleep(0.1)
    user32.PostMessageW(hwnd, 0x0202, 0, lp)            # WM_LBUTTONUP


def _runs(line: bytes) -> list[tuple[int, int, int]]:
    """(value, start, length) for every constant run in a one-byte-per-pixel line."""
    out: list[tuple[int, int, int]] = []
    start = 0
    for x in range(1, len(line)):
        if line[x] != line[start]:
            out.append((line[start], start, x - start))
            start = x
    out.append((line[start], start, len(line) - start))
    return out


def _one_to_one_three(line: bytes) -> list[int]:
    """Where a line crosses 1:1:3:1:1 - the bar at the corner of every QR finder pattern.

    The unit is the middle run divided by three and each of the five has to sit within 60 % of its
    share, which is loose enough for antialiasing and tight enough that this UI's dashed drop-zone
    border (1:1, then nothing) never answers.
    """
    hits: list[int] = []
    seq = _runs(line)
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
    """How many scanlines cross a QR finder pattern - the corner mark nothing else here can draw.

    The pairing QR is the one promise a frozen build can break in silence: ``_qr_pixmap`` paints the
    modules with QtSvg onto a white image, so a bundle without the SVG plugin shows a clean white box,
    a page that looks otherwise perfect, and an empty error log. Measured on this build: a drawn QR
    gives 31-33 rows, a page of only text and dashed borders gives 0, and the same page with the box
    painted over by hand also gives 0 - which is the answer this leg exists to catch.
    """
    dark = bytes(1 if v < 128 else 0 for v in raw[1::4])          # green channel, one byte per pixel
    hits = 0
    for y in range(0, h, 2):
        for cx in _one_to_one_three(dark[y * w:(y + 1) * w]):
            column = dark[cx::w]
            if any(abs(cy - y) < 40 for cy in _one_to_one_three(column)):
                hits += 1
                break
    return hits


def cli_legs(exe: Path, env: dict[str, str]) -> tuple[list[str], int]:
    """Run the terminal face of the same build; returns the checks that did not hold and the legs run.

    Three things only a frozen CLI can prove: app/cli.py reached the bundle at all,
    protocol.json and the catalogues resolve under ``sys._MEIPASS`` from a Qt-free
    process, and a console exe has a stdout that carries the answer.
    """
    cli = exe.parent / (exe.stem + "-cli.exe")
    if not cli.is_file():
        return [f"{cli.name} is not next to {exe.name}"], 0
    problems: list[str] = []
    legs = 0

    def ask(*args: str) -> tuple[int, str]:
        nonlocal legs
        legs += 1
        got = subprocess.run([str(cli), *args], env=env, capture_output=True, timeout=90)
        return got.returncode, decode(got.stdout + got.stderr)

    rc, me = ask("self")
    if rc != 0:
        problems.append(f"`self` exited {rc}: {me[:300]}")
    if "协议版本" not in me:
        problems.append(f"`self` never read the bundled contract: {me[:300]}")
    if not re.search(r"配对码：\d{6}", me):
        problems.append(f"a first run showed no 6-digit pairing code: {me[:300]}")

    rc, en = ask("self", "--lang", "en")
    if rc != 0:
        problems.append(f"`self --lang en` exited {rc}: {en[:300]}")

    root = SHOTS / "cli-in"
    rc, listen = ask("receive", "--root", str(root), "--port", str(CLI_PORT), "--yes", "--seconds", "3", "--no-discover")
    if rc != 0 or f"监听：{CLI_PORT}" not in listen:
        problems.append(f"the frozen receiver did not serve {CLI_PORT}: rc={rc} {listen[:300]}")
    if "入站：" not in listen:
        problems.append(f"the frozen receiver promised the port without the inbound half: {listen[-300:]}")

    # Windows matches firewall rules by program path, so this is the one leg that asks about the
    # shipped binary rather than about python.exe - and the answer is whatever this machine was told
    # to do with *this* path, which is why the check is that the sentence and the number agree.
    rc, fw = ask("firewall")
    verdict = re.search(r"结论：(\w+)", fw)
    if not verdict:
        problems.append(f"`firewall` printed no verdict: rc={rc} {fw[:300]}")
    elif rc != {"open": 0, "unknown": 1, "no_allow": 2, "blocked": 3}[verdict.group(1)]:
        problems.append(f"`firewall` said {verdict.group(1)} but exited {rc}")
    else:
        print(f"  [firewall] {verdict.group(1)} -> rc={rc}")
    return problems, legs


def main() -> int:
    exe = Path(sys.argv[1] if len(sys.argv) > 1 else EXE).resolve()
    if not exe.is_file():
        print(f"not built yet: {exe}", file=sys.stderr)
        return 2
    SHOTS.mkdir(parents=True, exist_ok=True)
    appdata = SHOTS / "appdata"
    if appdata.exists():
        import shutil

        shutil.rmtree(appdata)
    env = {**os.environ, "APPDATA": str(appdata), "USERPROFILE": str(appdata)}

    problems, legs = cli_legs(exe, env)
    for line in problems:
        print("  CLI " + line, file=sys.stderr)

    started = time.time()
    child = subprocess.Popen([str(exe)], env=env)
    try:
        hwnd = None
        while time.time() - started < 25:
            if child.poll() is not None:
                print(f"exe exited with {child.returncode} before showing a window", file=sys.stderr)
                return 1
            hwnd = window_of(child.pid)
            if hwnd:
                break
            time.sleep(0.25)
        if not hwnd:
            print("no window within 25s", file=sys.stderr)
            return 1

        # Qt fixes the process's DPI awareness while the application object is built, and GetWindowRect
        # answers in that unit - read the rect before this and a scaled desktop hands back a virtualized
        # size, which crops the capture of its own window.
        from PySide6.QtGui import QGuiApplication, QImage

        app = QGuiApplication([])
        rect = RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        w, h = rect.right - rect.left, rect.bottom - rect.top
        # Give the window a moment to finish its first paint (identity keypair, first page).
        time.sleep(2.0)

        png = SHOTS / "window.png"
        visual: list[str] = []
        raw = capture(hwnd, w, h)
        if raw is None:
            visual.append(f"PrintWindow returned no pixels for hwnd={hwnd} at {w}x{h}")
        else:
            img = QImage(raw, w, h, w * 4, QImage.Format_ARGB32).copy()
            if not img.save(str(png)):
                visual.append(f"a {w}x{h} capture would not save to {png}")
            else:
                colours, ink, paper = ink_and_paper(raw)
                print(f"window {w}x{h} -> {png}  colours={colours} ink={ink:.3f} paper={paper:.3f}")
                if colours < 8:
                    visual.append(f"the capture is {colours}-colour flat: hwnd={hwnd} never repainted "
                                  f"itself for PrintWindow, so nothing here proves the UI was drawn")
        app.processEvents()

        # The pairing QR is the one promise in this build that can break without a sound - a bundle that
        # lost QtSvg paints a clean white box and logs nothing - and it lives on the 接收 page, so the
        # rail is clicked (third row) and the finder patterns are counted in the pixels.
        if not visual:
            origin = POINT(rect.left, rect.top)
            user32.ScreenToClient(hwnd, ctypes.byref(origin))
            # The design window is 1080x720 at 100 % scale and Qt scales the layout with the display,
            # so the rail point is carried proportionally rather than taken as a constant.
            click(hwnd, round(78 * w / 1080) - origin.x, round(202 * h / 720) - origin.y)
            time.sleep(1.5)
            png2 = SHOTS / "window-receive.png"
            raw2 = capture(hwnd, w, h)
            if raw2 is None:
                visual.append(f"the 接收 page gave no pixels for hwnd={hwnd}")
            elif not QImage(raw2, w, h, w * 4, QImage.Format_ARGB32).copy().save(str(png2)):
                visual.append(f"the 接收 capture would not save to {png2}")
            else:
                marks = finder_patterns(raw2, w, h)
                print(f"receive page -> {png2}  finder rows={marks}")
                if marks < 3:
                    visual.append(f"the 接收 page has {marks} scanline(s) crossing a finder pattern, and "
                                  f"a drawn QR gives dozens: the pairing box is blank, so QtSvg or "
                                  f"qrcode is out of the bundle (or the rail click missed the page)")

        log = appdata / "ChuanShu" / "ChuanShu" / "logs" / "app.log"
        text = log.read_text(encoding="utf-8", errors="replace") if log.is_file() else ""
        bad = [line for line in text.splitlines() if "ERROR" in line or "Traceback" in line]
        print(f"log {len(text.splitlines())} line(s), {len(bad)} error line(s)")
        for line in bad[:10]:
            print("  " + line)
        for marker in ("listening", "discovery", "mDNS", "zeroconf"):
            hits = [line for line in text.splitlines() if marker.lower() in line.lower()]
            if hits:
                print(f"  [{marker}] {hits[-1]}")
        print("cli legs: " + (f"{legs} checked, all held" if not problems
                              else f"{len(problems)} problem(s), listed above"))
        for line in visual:
            print("  visual " + line, file=sys.stderr)
        return 0 if not bad and not problems and not visual else 1
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=10)
        print(f"exe stopped after {time.time() - started:.1f}s")


if __name__ == "__main__":
    sys.exit(main())
