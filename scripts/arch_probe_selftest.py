"""Unit tests for scripts/arch_probe.py - the assertion CI trusts to label a package.

    py -X utf8 scripts/arch_probe_selftest.py

The probe is the only thing standing between a CI job that silently fell back to an x64
interpreter and an artifact published as arm64, so its own failure modes are tested here
rather than discovered on a runner: every machine word it claims, both ELF byte orders,
truncated and non-executable inputs, and the exit codes its docstring promises.

Headers are built byte by byte instead of copied from a real binary so a case can be exact
about what is wrong with it (a signature that fits but a machine word that does not, an
e_lfanew pointing past the read window). The shipped exe is probed too, when it is there.
"""

from __future__ import annotations

import io
import struct
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import arch_probe  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
failures: list[str] = []


def check(label: str, ok: bool, seen="") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f": {seen}" if seen else ""))
    if not ok:
        failures.append(label)


def pe(machine: int, *, pe_off: int = 0x80, signature: bytes = b"PE\0\0", size: int = 0x200) -> bytes:
    buf = bytearray(size)
    buf[0:2] = b"MZ"
    if size >= 0x40:
        struct.pack_into("<I", buf, 0x3C, pe_off)
    if pe_off + 4 <= size:
        buf[pe_off:pe_off + 4] = signature[: size - pe_off]
    if pe_off + 6 <= size:
        struct.pack_into("<H", buf, pe_off + 4, machine)
    return bytes(buf)


def elf(machine: int, *, big: bool = False, cls: int = 2, data: int | None = None, size: int = 64) -> bytes:
    buf = bytearray(size)
    buf[0:4] = b"\x7fELF"
    if size >= 7:
        buf[4] = cls
        buf[5] = (2 if big else 1) if data is None else data
        buf[6] = 1
    if size >= 20:
        struct.pack_into(">H" if big else "<H", buf, 18, machine)
    return bytes(buf)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="arch-probe-") as tmp:
        root = Path(tmp)

        def put(name: str, data: bytes) -> Path:
            path = root / name
            path.write_bytes(data)
            return path

        # --- PE: the three Windows targets this project ships, and the ones it must not claim ---
        for machine, want in ((0x8664, "AMD64"), (0xAA64, "ARM64"), (0x014C, "I386")):
            path = put(f"pe-{want}.exe", pe(machine))
            check(f"PE {want} reads as {want}", arch_probe.probe(path) == ("PE", want), arch_probe.probe(path))
        path = put("pe-other.exe", pe(0x01C0))
        check("an unlisted PE machine is reported, not guessed", arch_probe.probe(path) == ("PE", "PE:0x01C0"), arch_probe.probe(path))

        # --- PE error paths: a partial download must not raise out of a CI assertion ---
        cases = {
            "pe-nosig.exe": (pe(0x8664, signature=b"XX\0\0"), ("PE", "unknown")),
            "pe-short.exe": (b"MZ" + b"\0" * 10, ("PE", "unknown")),
            "pe-far.exe": (pe(0x8664, pe_off=0x400), ("PE", "unknown")),
            "pe-cut.exe": (pe(0x8664, pe_off=0x80, size=0x85), ("PE", "unknown")),
        }
        for name, (data, want) in cases.items():
            path = put(name, data)
            try:
                seen = arch_probe.probe(path)
            except Exception as exc:  # a traceback here is the failure this test exists for
                seen = f"raised {type(exc).__name__}: {exc}"
            check(f"{name} degrades to {want[1]}", seen == want, seen)

        # --- ELF: both byte orders, both classes, and the 32-bit ARM floor ---
        for machine, want, big in ((0x3E, "x86_64", False), (0xB7, "aarch64", False),
                                   (0xB7, "aarch64", True), (0x28, "arm", False)):
            path = put(f"elf-{want}-{'be' if big else 'le'}", elf(machine, big=big))
            check(f"ELF {want} {'big' if big else 'little'}-endian", arch_probe.probe(path) == ("ELF", want), arch_probe.probe(path))
        # The endian fix has to be load-bearing: the same bytes read the wrong way round are a
        # different CPU, so a probe that ignored EI_DATA would pass the case above by luck.
        be = elf(0xB7, big=True)
        check("big-endian aarch64 is not what a little-endian read would say",
              struct.unpack_from("<H", be, 18)[0] != 0xB7, f"0x{struct.unpack_from('<H', be, 18)[0]:04X}")
        path = put("elf-32", elf(0x28, cls=1))
        check("ELF class 1 (32-bit) reads its machine too", arch_probe.probe(path) == ("ELF", "arm"), arch_probe.probe(path))
        path = put("elf-other", elf(0x15))
        check("an unlisted ELF machine is reported, not guessed", arch_probe.probe(path) == ("ELF", "ELF:0x15"), arch_probe.probe(path))
        for name, data in (("elf-short", b"\x7fELF\x02\x01"), ("elf-bad-data", elf(0xB7, data=0))):
            path = put(name, data)
            check(f"{name} degrades to unknown", arch_probe.probe(path) == ("ELF", "unknown"), arch_probe.probe(path))

        # --- neither format ---
        for name, data in (("text.txt", b"not an executable\n"), ("empty.bin", b"")):
            path = put(name, data)
            check(f"{name} is unknown", arch_probe.probe(path) == ("unknown", "unknown"), arch_probe.probe(path))

        # --- the read window: a 40 MB installer must not be slurped to read 512 bytes ---
        big = put("big.exe", pe(0x8664) + b"\0" * (4 * 1024 * 1024))
        requested: list[int] = []
        real_open = Path.open

        class Counting:
            def __init__(self, handle):
                self.handle = handle

            def read(self, n=-1):
                requested.append(n)
                return self.handle.read(n)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.handle.close()

        def counting_open(self, *args, **kwargs):
            return Counting(real_open(self, *args, **kwargs))

        Path.open = counting_open
        try:
            seen = arch_probe.probe(big)
        finally:
            Path.open = real_open
        check("a 4 MB file is read through a 512-byte window", seen == ("PE", "AMD64") and requested == [0x200],
              f"{seen} read={requested}")

        # --- main(): exit codes, and that argv is the argument list it actually parses ---
        def run_main(argv: list[str]) -> int:
            # The probe prints one line per file; keep that out of the PASS/FAIL ledger.
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                return arch_probe.main(argv)

        amd64 = put("ok-amd64.exe", pe(0x8664))
        arm64 = put("ok-arm64.exe", pe(0xAA64))
        i386 = put("ok-i386.exe", pe(0x014C))
        text = put("not-exe.txt", b"hello")
        missing = root / "absent.exe"
        check("no --expect on a readable binary is 0", run_main([str(amd64)]) == 0)
        check("--expect matching is 0", run_main(["--expect", "ARM64", str(arm64)]) == 0)
        check("--expect mismatching is 1", run_main(["--expect", "ARM64", str(amd64)]) == 1)
        check("one mismatch among several is 1", run_main(["--expect", "AMD64", str(amd64), str(i386)]) == 1)
        check("several expectations all holding is 0", run_main([str(amd64), str(arm64), str(i386)]) == 0)
        check("a missing file is 1", run_main([str(missing)]) == 1)
        check("a directory is 1, not a traceback", run_main([str(root)]) == 1)
        check("an unreadable format is 2, as the docstring promises", run_main([str(text)]) == 2)
        check("a mismatch outranks an unreadable format", run_main(["--expect", "AMD64", str(text)]) == 1)

    # --- the artifact this machine actually ships, when it is there ---
    for exe, want in ((REPO / "dist/ChuanShu/ChuanShu.exe", "PE"), (REPO / "dist/ChuanShu/ChuanShu-cli.exe", "PE")):
        if not exe.is_file():
            print(f"SKIP  {exe.name} (no frozen build in this tree)")
            continue
        fmt, arch = arch_probe.probe(exe)
        check(f"{exe.name} is a {want} with a named CPU", fmt == want and arch in arch_probe.PE_MACHINES.values(), f"{fmt} {arch}")

    print("RESULT " + (f"FAILED {len(failures)}: " + " / ".join(failures) if failures else "ALL PASS"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())