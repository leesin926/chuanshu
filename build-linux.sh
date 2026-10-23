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

if [[ $exe_only -eq 0 ]]; then
    echo "==> translations"
    # The .mo files are read from _MEIPASS at runtime, so a stale catalogue ships as stale UI.
    "$py" -m babel.messages.frontend extract --project="$name" --version="$version" \
        -F babel.cfg -o locale/app.pot .
    "$py" -m babel.messages.frontend update -D app -i locale/app.pot -d locale
    "$py" -X utf8 scripts/i18n_sync.py
    "$py" -m babel.messages.frontend compile -D app -d locale
fi

echo "==> PyInstaller"
"$py" -m PyInstaller --noconfirm --clean app.spec

archive="dist/${name}-${version}-linux-x64.tar.gz"
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
