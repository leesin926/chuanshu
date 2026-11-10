#!/usr/bin/env bash
# build-linux.sh - translations -> PyInstaller -> tar.gz, the Linux half of build.ps1.
#
#   ./build-linux.sh              # build and pack
#   ./build-linux.sh --exe-only   # stop after PyInstaller (run dist/ChuanShu/ChuanShu yourself)
#   PY=python3.12 ./build-linux.sh
#
# Needs the runtime and build dependencies first:
#   python3 -m pip install -r requirements.txt -r requirements-dev.txt
#
# PY must point at an interpreter whose Babel matches the Windows side (2.18). On this machine
# that is the venv, not the distro python:
#   PY=/root/.venvs/cs/bin/python ./build-linux.sh
# Ubuntu's system Babel is 2.10, and its `update` rewrites locale/*.po into a shape that
# scripts/i18n_sync.py reads as 51 untranslated messages - a fake hole that stops the build
# and leaves the tracked catalogs damaged.
#
# The product is one folder holding two executables: ChuanShu (the window) and ChuanShu-cli
# (the terminal face). A tar.gz is what that shape ships as - the only format promised here.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$root"

py="${PY:-python3}"
exe_only=0
[[ "${1:-}" == "--exe-only" ]] && exe_only=1

name="$("$py" -c 'from app.meta import APP_NAME; print(APP_NAME)')"
version="$("$py" -c 'from app.meta import VERSION; print(VERSION)')"

# The archive says which CPU it was frozen for, and PyInstaller always freezes for the
# interpreter running it - so the honest source of that word is the machine doing the build,
# not a literal in this script. x86_64 keeps shipping as "x64" so the file name this project
# has published so far is unchanged; anything else is named after uname itself.
case "$(uname -m)" in
    x86_64) arch=x64 ;;
    aarch64) arch=arm64 ;;
    *) arch="$(uname -m)" ;;
esac

if [[ $exe_only -eq 0 ]]; then
    echo "==> translations"
    # The .mo files are read from _MEIPASS at runtime, so a stale catalogue ships as stale UI.
    "$py" -m babel.messages.frontend extract --project="$name" --version="$version" \
        -F babel.cfg -o locale/app.pot .
    # --ignore-pot-creation-date keeps a rebuild of unchanged source from rewriting all eight
    # .po and .mo with a fresh timestamp (4 bytes per .mo, measured) - the frozen bundle would
    # otherwise differ from the last build of the same tree, and so would its sha256.
    "$py" -m babel.messages.frontend update -D app -i locale/app.pot -d locale --ignore-pot-creation-date
    "$py" -X utf8 scripts/i18n_sync.py
    "$py" -m babel.messages.frontend compile -D app -d locale
fi

echo "==> PyInstaller"
"$py" -m PyInstaller --noconfirm --clean app.spec

archive="dist/${name}-${version}-linux-${arch}.tar.gz"
if [[ $exe_only -eq 1 ]]; then
    echo
    echo "  app       : dist/$name/$name"
    echo "  cli       : dist/$name/$name-cli"
    echo "  (skipped the tar.gz; re-run without --exe-only to pack it)"
else
    echo "==> packing $archive"
    tar -czf "$archive" -C dist "$name"
    echo
    echo "  app       : dist/$name/$name"
    echo "  cli       : dist/$name/$name-cli"
    echo "  archive   : $archive"
fi
echo "  run it    : extract anywhere, then ./ChuanShu/$name  (or ./ChuanShu/$name-cli --help)"
