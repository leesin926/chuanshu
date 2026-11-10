#!/usr/bin/env python3
"""Print the CPU a built executable was frozen for, by reading its own header.

Why a script instead of a step in the workflow: "PyInstaller finished" is not evidence of the
architecture - PyInstaller always builds for whatever interpreter is running it, so a CI job
that silently fell back to an x64 Python would still report success and ship an x64 binary
labelled arm64. The machine field of the PE/ELF header is the only thing in the artifact that
answers that question, and this reads it without a disassembler.

    py -X utf8 scripts/arch_probe.py dist/ChuanShu/ChuanShu.exe
    py -X utf8 scripts/arch_probe.py --expect ARM64 dist/ChuanShu/ChuanShu.exe

Exit 0 when the architecture matches (or when --expect is absent), 1 when it does not,
2 when the file is neither PE nor ELF.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

PE_MACHINES = {
    0x014C: "I386",
    0x8664: "AMD64",
    0xAA64: "ARM64",
}

ELF_MACHINES = {
    0x3E: "x86_64",
    0xB7: "aarch64",
    0x28: "arm",
}


def probe(path: Path) -> tuple[str, str]:
    """Return (format, architecture) for one file.

    Only the first 512 bytes are read: the targets are a 40 MB installer and a folder of
    frozen DLLs, and the machine field lives in the header of both formats.
    """
    with path.open("rb") as handle:
        head = handle.read(0x200)
    if head[:2] == b"MZ":
        # e_lfanew at 0x3C points at the PE header; the machine word is the third field of it.
        # A truncated download can end before any of those offsets, and a half-written file
        # must read as "unknown" rather than raise out of the middle of a CI assertion.
        if len(head) < 0x40:
            return "PE", "unknown"
        (pe_off,) = struct.unpack_from("<I", head, 0x3C)
        if pe_off + 6 > len(head) or head[pe_off:pe_off + 4] != b"PE\0\0":
            return "PE", "unknown"
        (machine,) = struct.unpack_from("<H", head, pe_off + 4)
        return "PE", PE_MACHINES.get(machine, f"PE:0x{machine:04X}")
    if head[:4] == b"\x7fELF":
        if len(head) < 20 or head[5] not in (1, 2):
            return "ELF", "unknown"
        # EI_DATA says which way round e_machine is; reading it little-endian by default
        # would report a big-endian ELF as some other CPU entirely.
        (machine,) = struct.unpack_from(">H" if head[5] == 2 else "<H", head, 18)
        return "ELF", ELF_MACHINES.get(machine, f"ELF:0x{machine:02X}")
    return "unknown", "unknown"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--expect", help="fail unless every file reports this architecture")
    args = ap.parse_args(argv)

    mismatch = False
    unreadable = False
    for path in args.paths:
        if not path.is_file():
            print(f"{path}: MISSING")
            mismatch = True
            continue
        fmt, arch = probe(path)
        print(f"{path}: {fmt} {arch}")
        if fmt == "unknown":
            unreadable = True
        if args.expect and arch != args.expect:
            print(f"  expected {args.expect}, got {arch}", file=sys.stderr)
            mismatch = True
    return 1 if mismatch else 2 if unreadable else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
