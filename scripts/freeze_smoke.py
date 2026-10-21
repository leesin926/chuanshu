"""Launch the packaged build and prove it really runs: window on screen, QR painted,
log clean.

The in-process UI selftest cannot cover what only a frozen build breaks (bundled data
files, native extensions, resource lookup under ``sys._MEIPASS``), so this drives the
actual exe. It writes into a scratch APPDATA and closes only the process it started.

Expect one Windows Firewall prompt per new exe path: the build is unsigned, so Windows
asks before it accepts inbound mDNS. Answering cancel leaves permanent *block* rules for
that path - which is exactly what the installer's "firewall" task exists to avoid.

    py -X utf8 scripts/freeze_smoke.py [.probe/dist-freeze/ChuanShu/ChuanShu.exe]
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / ".probe/dist-freeze/ChuanShu/ChuanShu.exe"
SHOTS = ROOT / ".probe/freeze"

user32 = ctypes.windll.user32


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

        rect = RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        # Give the window a moment to finish its first paint (identity keypair, QR).
        time.sleep(2.0)

        from PySide6.QtGui import QGuiApplication

        app = QGuiApplication([])
        screen = app.primaryScreen()
        shot = screen.grabWindow(0, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top)
        png = SHOTS / "window.png"
        if not shot.save(str(png)):
            print("screenshot failed to save", file=sys.stderr)
            return 1
        app.processEvents()
        print(f"window {rect.right - rect.left}x{rect.bottom - rect.top} -> {png}")

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
        return 0 if not bad else 1
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
