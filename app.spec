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

# The wire contract. app/net/spec.py reads protocol.json at startup, so a build that
# leaves it out fails on the first request rather than at import time.
_protocol = Path(SPECPATH) / "protocol"
datas += [(str(f), "protocol") for f in sorted(_protocol.iterdir()) if f.is_file()]

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

# The terminal face is a second executable rather than a flag on the first: a windowed
# (console=False) build has no stdout to write to, so `ChuanShu-cli self` could never show
# anything. Separate entry, separate bundle slot, one folder next to the window.
a_cli = Analysis(
    ["app/cli.py"],
    pathex=[SPECPATH],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    # The CLI must stay importable without Qt - that is what makes it usable on a headless
    # box. Excluding PySide6 turns an accidental `import PySide6` into a build failure
    # instead of a bundle that quietly carries 60 MB of GUI along.
    excludes=["PySide6"],
    noarchive=False,
)

pyz_cli = PYZ(a_cli.pure)

exe_cli = EXE(
    pyz_cli,
    a_cli.scripts,
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


def _merge(*tocs):
    """One TOC per name, first build wins.

    Both Analyses collect the same .mo/.svg/protocol.json and, on Windows, mostly the same
    DLLs. A duplicate basename in one COLLECT is a collision PyInstaller has to resolve by
    guesswork, so the first entry keeps its bytes and the rest are dropped.
    """
    seen = {}
    for toc in tocs:
        for item in toc:
            seen.setdefault(item[0], item)
    return list(seen.values())


coll = COLLECT(
    exe,
    exe_cli,
    _merge(a.binaries, a_cli.binaries),
    _merge(a.datas, a_cli.datas),
    strip=False,
    upx=False,
    name=APP_NAME,
)
