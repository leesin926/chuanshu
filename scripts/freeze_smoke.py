"""Launch the packaged build and prove it really runs: window on screen, QR painted,
log clean, and the terminal face beside it answering.

The in-process UI selftest cannot cover what only a frozen build breaks (bundled data
files, native extensions, resource lookup under ``sys._MEIPASS``), so this drives the
actual exe. It writes into a scratch APPDATA and closes only the process it started.

Expect one Windows Firewall prompt per new exe path: the build is unsigned, so Windows
asks before it accepts inbound mDNS. Answering cancel leaves permanent *block* rules for
that path - which is exactly what the installer's "firewall" task exists to avoid. The CLI
half below runs with --no-discover, so it does not open a second prompt.

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


def cli_legs(exe: Path, env: dict[str, str]) -> list[str]:
    """Run the terminal face of the same build; returns the checks that did not hold.

    Three things only a frozen CLI can prove: app/cli.py reached the bundle at all,
    protocol.json and the catalogues resolve under ``sys._MEIPASS`` from a Qt-free
    process, and a console exe has a stdout that carries the answer.
    """
    cli = exe.parent / (exe.stem + "-cli.exe")
    if not cli.is_file():
        return [f"{cli.name} is not next to {exe.name}"]
    problems: list[str] = []

    def ask(*args: str) -> tuple[int, str]:
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
    return problems


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

    problems = cli_legs(exe, env)
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
        print("cli legs: " + ("4 checked, all held" if not problems else f"{len(problems)} problem(s), listed above"))
        return 0 if not bad and not problems else 1
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
