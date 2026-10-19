# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: one-folder build with the compiled catalogues bundled in.

One-folder keeps startup fast and lets the Inno script copy the whole tree;
switch to onefile only if you truly need a single exe.
"""

import sys
from pathlib import Path

sys.path.insert(0, SPECPATH)
from app.meta import APP_NAME  # noqa: E402

# Bundle compiled catalogues only; .po sources stay out of the shipped app.
_locale = Path(SPECPATH) / "locale"
datas = [
    (str(mo), "locale/" + str(mo.parent.relative_to(_locale)).replace("\\", "/"))
    for mo in _locale.rglob("*.mo")
]

# Icon config + glyph SVGs, read at runtime by app/icons.py.
_icons = Path(SPECPATH) / "assets" / "icons"
datas += [(str(f), "assets/icons") for f in sorted(_icons.iterdir()) if f.is_file()]

a = Analysis(
    ["app/main.py"],
    pathex=[SPECPATH],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=APP_NAME,
    debug=False,
    optimize=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name=APP_NAME,
)
