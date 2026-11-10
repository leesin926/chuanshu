# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the Qt-free terminal face, on a Python that has no Qt to begin with.

Why this is a separate spec and not a flag on app.spec: 32-bit Windows is the one shipping
target with no PySide6 wheel at all (Qt6 publishes win_amd64 and win_arm64 only), so a
win32 build cannot carry the window no matter how the spec is written. What it can carry is
the CLI - app/cli.py imports no Qt, and app.spec's own a_cli Analysis already excludes
PySide6 to keep that promise. This spec is that half, alone.

    pyinstaller --noconfirm app-cli.spec

Output is dist/ChuanShu-cli/ - a different folder from dist/ChuanShu, so a 32-bit CLI build
never overwrites a 64-bit GUI build sitting in the same tree.
"""

import sys
from pathlib import Path

sys.path.insert(0, SPECPATH)
from app.meta import APP_NAME  # noqa: E402

_locale = Path(SPECPATH) / "locale"
datas = [
    (str(mo), "locale/" + str(mo.parent.relative_to(_locale)).replace("\\", "/"))
    for mo in _locale.rglob("*.mo")
]

# The wire contract: app/net/spec.py reads protocol.json at startup, so a build that
# leaves it out fails on the first request rather than at import time.
_protocol = Path(SPECPATH) / "protocol"
datas += [(str(f), "protocol") for f in sorted(_protocol.iterdir()) if f.is_file()]

a = Analysis(
    ["app/cli.py"],
    pathex=[SPECPATH],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=["PySide6"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=APP_NAME + "-cli",
    debug=False,
    optimize=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name=APP_NAME + "-cli",
)
