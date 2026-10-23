"""End-to-end proof that app/cli.py needs no Qt and no window: two CLI processes, each with
its own APPDATA identity directory, pairing and transferring in both directions.

Run: py -X utf8 scripts/cli_selftest.py
Everything it writes stays under .probe/cli/, which is git-ignored and rebuilt from scratch
each run, so "landed exactly once" means this run's arrival and not last week's.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = ROOT / ".probe" / "cli"
SAMPLE = SCRATCH / "sample.bin"
failures: list[str] = []


def check(label: str, ok: bool, seen="") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f": {seen}" if seen else ""))
    if not ok:
        failures.append(str(label))


def env_of(role: str) -> dict:
    (SCRATCH / role).mkdir(parents=True, exist_ok=True)
    return dict(os.environ, APPDATA=str(SCRATCH / role), PYTHONIOENCODING="utf-8")


def start(role: str, extra: list[str]) -> subprocess.Popen:
    cmd = [sys.executable, "-X", "utf8", "-m", "app.cli", *extra]
    return subprocess.Popen(cmd, cwd=str(ROOT), env=env_of(role), stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, encoding="utf-8", bufsize=1)


def read_until(proc: subprocess.Popen, pattern: str, seconds: float = 25.0) -> str:
    """Collect stdout until a line matches, so the banner is read before it is used."""
    deadline = time.monotonic() + seconds
    lines: list[str] = []
    assert proc.stdout is not None
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        lines.append(line.rstrip())
        print(f"    [serve] {line.rstrip()}")
        if re.search(pattern, line):
            break
    return "\n".join(lines)


def banner(text: str) -> tuple[int, str, str]:
    return (int(re.search(r"监听：(\d+)", text).group(1)),
            re.search(r"配对码：(\d+)", text).group(1),
            re.search(r"密码：(\S+)", text).group(1))


def send(role: str, extra: list[str]) -> subprocess.CompletedProcess:
    cmd = [sys.executable, "-X", "utf8", "-m", "app.cli", "send", *extra]
    return subprocess.run(cmd, cwd=str(ROOT), env=env_of(role), capture_output=True,
                          text=True, encoding="utf-8", timeout=120)


def cli(role: str, extra: list[str]) -> subprocess.CompletedProcess:
    cmd = [sys.executable, "-X", "utf8", "-m", "app.cli", *extra]
    return subprocess.run(cmd, cwd=str(ROOT), env=env_of(role), capture_output=True,
                          text=True, encoding="utf-8", timeout=60)


def stop(proc: subprocess.Popen) -> None:
    proc.kill()
    rest, _ = proc.communicate(timeout=10)
    for line in (rest or "").splitlines():
        print(f"    [serve] {line}")


def main() -> int:
    for stale in ("R", "S"):
        shutil.rmtree(SCRATCH / stale, ignore_errors=True)
    probe = subprocess.run([sys.executable, "-X", "utf8", "-c",
                            "import sys, app.cli;"
                            "print([m for m in sys.modules if m.split('.')[0] in ('PySide6','shiboken6')])"],
                           cwd=str(ROOT), capture_output=True, text=True, encoding="utf-8", timeout=60)
    check("importing app.cli pulls in no Qt", probe.stdout.strip() == "[]", probe.stdout.strip() or probe.stderr.strip())
    SAMPLE.write_bytes(os.urandom(3_000_000))
    digest = hashlib.sha256(SAMPLE.read_bytes()).hexdigest()
    print(f"sample: {SAMPLE.stat().st_size} bytes {digest[:12]}")

    # --- leg 1: R receives, S sends with R's code and passphrase
    r1 = start("R", ["receive", "--yes", "--root", str(SCRATCH / "R" / "in"), "--seconds", "150", "--no-discover"])
    port, code, secret = banner(read_until(r1, r"按 Ctrl-C|听 \d+"))
    check("receiver announced port, code and passphrase", port > 0 and len(code) == 6, f"{port} {code} {secret}")

    out1 = send("S", [f"127.0.0.1:{port}", "--code", code, "--secret", secret, str(SAMPLE), "--base", str(SCRATCH)])
    check("send S->R exited 0", out1.returncode == 0, (out1.stdout or out1.stderr)[-500:])
    landed = list((SCRATCH / "R" / "in").rglob("sample.bin"))
    check("the file landed exactly once", len(landed) == 1, [str(p) for p in landed])
    if landed:
        check("the landed bytes hash the same", hashlib.sha256(landed[0].read_bytes()).hexdigest() == digest)
    arrival = read_until(r1, r"校验通过", 25)
    check("the receiver said which files verified", "sample.bin" in arrival and "校验通过" in arrival, arrival.strip()[-200:])

    # --- leg 2: S receives, R sends back. Both ends pinned each other in leg 1, so no code.
    # A spare port rather than the contract one: leg 1's receiver is still standing, and this
    # leg has to reach the second process, not whichever of them the shared port answers for.
    r2 = start("S", ["receive", "--yes", "--root", str(SCRATCH / "S" / "in"), "--port", "43912",
                     "--seconds", "90", "--no-discover"])
    port2, _, _ = banner(read_until(r2, r"按 Ctrl-C|听 \d+"))
    out2 = send("R", [f"127.0.0.1:{port2}", str(SAMPLE), "--base", str(SCRATCH)])
    check("send R->S needed no pair code", out2.returncode == 0, (out2.stdout or out2.stderr)[-500:])
    back = list((SCRATCH / "S" / "in").rglob("sample.bin"))
    check("the reverse file landed", len(back) == 1, [str(p) for p in back])
    if back:
        check("the reverse bytes hash the same", hashlib.sha256(back[0].read_bytes()).hexdigest() == digest)

    # --- the read-only commands describe what those two legs left behind
    pins_r = cli("R", ["pins"])
    check("R lists the peer it pinned", "S" in pins_r.stdout or "DESKTOP" in pins_r.stdout, pins_r.stdout.strip())
    self_s = cli("S", ["self"])
    check("self prints identity and dirs", "指纹：" in self_s.stdout and "身份目录：" in self_s.stdout,
          self_s.stdout.strip()[-160:])
    peers = cli("S", ["peers", "--seconds", "2", "--no-verify"])
    check("peers runs and answers", peers.returncode == 0, peers.stdout.strip()[-200:])

    stop(r1)
    stop(r2)
    print("RESULT " + ("ALL PASS" if not failures else f"FAILURES: {failures}"))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
