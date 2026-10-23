"""Linux half of the story, run on a Linux machine with a scratch HOME.

    wsl -d Ubuntu-24.04 bash -lc 'cd /mnt/e/wowo3 && python3 scripts/linux_selftest.py'

It proves what can be proved without a display: that the CLI imports with neither Qt nor
PySide6 installed, that the identity directory lands on the XDG path and the private key on
0600, that a second receiver is kept off the contract port, that the XDG autostart entry
round-trips, and that a transfer works both ways. The GUI half - theme auto-detect, the
frameless shell, the no-tray degradation - needs PySide6, which is not installed here, so
those branches are only covered by scripts/ui_selftest.py under offscreen Windows.
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

REPO = Path(__file__).resolve().parents[1]
HOME = Path("/tmp/cs-linux-home")
failures: list[str] = []


def check(label: str, ok: bool, seen="") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f": {seen}" if seen else ""))
    if not ok:
        failures.append(str(label))


def fresh(role: str) -> Path:
    """One role's scratch HOME, rebuilt from nothing so a pass means this run did it."""
    home = HOME / role
    shutil.rmtree(home, ignore_errors=True)
    for sub in (".local/share", ".config/autostart", "work"):
        (home / sub).mkdir(parents=True, exist_ok=True)
    return home


def env_of(home: Path) -> dict:
    return dict(os.environ, HOME=str(home), XDG_DATA_HOME=str(home / ".local" / "share"),
                XDG_CONFIG_HOME=str(home / ".config"), PYTHONIOENCODING="utf-8")


def run(cmd_extra: list[str], home: Path, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "app.cli", *cmd_extra], cwd=str(REPO),
                          env=env_of(home), capture_output=True, text=True,
                          encoding="utf-8", timeout=timeout)


def tail(result: subprocess.CompletedProcess, n: int = 300) -> str:
    return (result.stdout + result.stderr)[-n:]


def start(cmd_extra: list[str], home: Path) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-m", "app.cli", *cmd_extra], cwd=str(REPO),
                            env=env_of(home), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", bufsize=1)


def read_until(proc: subprocess.Popen, pattern: str, seconds: float = 25.0) -> str:
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


def stop(proc: subprocess.Popen) -> None:
    proc.kill()
    rest, _ = proc.communicate(timeout=10)
    for line in (rest or "").splitlines():
        print(f"    [serve] {line}")


def main() -> int:
    HOME.mkdir(parents=True, exist_ok=True)
    bare = HOME / "bare"
    bare.mkdir(parents=True, exist_ok=True)
    h_r, h_s, h_a = fresh("R"), fresh("S"), fresh("A")
    sample = HOME / "sample.bin"
    sample.write_bytes(os.urandom(3_000_000))
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()

    # 1. PySide6 is not installed on this machine, so importing IS the Qt-free proof.
    probe = subprocess.run([sys.executable, "-c", "import app.cli; print('OK')"], cwd=str(REPO),
                           capture_output=True, text=True, encoding="utf-8", timeout=60)
    check("app.cli imports on Linux without PySide6", probe.stdout.strip().endswith("OK"),
          (probe.stdout + probe.stderr)[-300:])

    # 2. XDG data dir, and the key material readable only by its owner.
    info = run(["self"], h_r)
    check("self ran", info.returncode == 0, tail(info))
    id_dirs = list((h_r / ".local" / "share").glob("*/*/identity"))
    check("identity lives under $XDG_DATA_HOME/ORG/APP", bool(id_dirs), h_r / ".local" / "share")
    key = id_dirs[0] / "peer-key.pem" if id_dirs else Path("/nonexistent")
    mode = key.stat().st_mode & 0o777 if key.is_file() else -1
    check("a fresh private key is 0600", mode == 0o600, oct(mode))
    others = {p.name: oct(p.stat().st_mode & 0o777) for p in sorted(id_dirs[0].iterdir()) if p.is_file()}
    check("every identity file is owner-only", all(m == "0o600" for m in others.values()), others)
    if key.is_file():  # An older build left the key at the umask default; loading fixes that.
        key.chmod(0o644)
        run(["self"], h_r)
        check("a world-readable key is tightened on load", (key.stat().st_mode & 0o777) == 0o600,
              oct(key.stat().st_mode & 0o777))

    # 3. Autostart: an XDG entry, written where the spec says and matched on read-back.
    sys.path.insert(0, str(REPO))
    os.environ.update(env_of(h_a))
    from app import autostart
    from app.paths import autostart_desktop_path
    check("a source checkout does not offer autostart", not autostart.is_supported())
    autostart.is_frozen = lambda: True  # only a packaged build may register itself
    check("a packaged Linux build does", autostart.is_supported())
    path = autostart_desktop_path()
    check("the entry is $XDG_CONFIG_HOME/autostart/<name>.desktop",
          str(path).startswith(str(h_a / ".config" / "autostart")), path)
    check("set_enabled(True) writes it", autostart.set_enabled(True) and path.is_file(), path)
    check("is_enabled() reads it back", autostart.is_enabled())
    check("the Exec line points at the executable",
          f"Exec={autostart.launch_command()}" in path.read_text(encoding="utf-8"), path)
    check("set_enabled(False) removes it", autostart.set_enabled(False) and not path.is_file())

    # 4. A receiver on the contract port, and the identity material it wrote.
    first = start(["receive", "--yes", "--root", str(h_r / "work" / "in"),
                   "--seconds", "150", "--no-discover"], h_r)
    announced = read_until(first, r"按 Ctrl-C|听 \d+")
    port, code, secret = banner(announced)
    check("receiver bound the contract port", port == 43720, port)
    # The inbound half of the banner, on a machine with no firewall tool to ask: it has to say
    # something here too, because "监听：43720" is what a user reads as reachable.
    check("the receiver said the inbound half too", "入站：" in announced, announced.strip()[-160:])

    # 5. Transfer S->R with R's pairing material.
    out1 = run(["send", f"127.0.0.1:{port}", "--code", code, "--secret", secret,
                str(sample), "--base", str(HOME)], h_s)
    check("send S->R exited 0", out1.returncode == 0, tail(out1, 400))
    landed = list((h_r / "work" / "in").rglob("sample.bin"))
    check("the file landed exactly once", len(landed) == 1, [str(p) for p in landed])
    if landed:
        check("the landed bytes hash the same", hashlib.sha256(landed[0].read_bytes()).hexdigest() == digest)
    arrival = read_until(first, r"校验通过", 25)
    check("the receiver named the verified file", "sample.bin" in arrival, arrival.strip()[-160:])

    # 6. A second receiver on this machine while the first still holds the contract port.
    # This is the branch Windows can never show: there the bind succeeds and both processes
    # print 43720, so only the probe before it can tell them apart.
    second = start(["receive", "--yes", "--root", str(h_s / "work" / "in"),
                    "--seconds", "60", "--no-discover"], h_s)
    text2 = read_until(second, r"按 Ctrl-C|听 \d+")
    port2 = int(re.search(r"监听：(\d+)", text2).group(1))
    check("a second receiver moved off the taken port", port2 != 43720 and "端口" in text2,
          f"{port2} | {text2.splitlines()[0]}")

    # 7. Back the other way, now that both sides have pinned each other.
    out2 = run(["send", f"127.0.0.1:{port2}", str(sample), "--base", str(HOME)], h_r)
    check("the reverse send needed no pair code", out2.returncode == 0, tail(out2, 400))
    back = list((h_s / "work" / "in").rglob("sample.bin"))
    check("the reverse file landed", len(back) == 1, [str(p) for p in back])

    # 8. The catalogues compiled here read back in another language.
    en = run(["self", "--lang", "en"], h_s)
    check("self --lang en runs", en.returncode == 0, tail(en, 160))

    # 8b. zeroconf is not installed here, and discovery is supposed to say so per channel
    # rather than to fall over: the mDNS half reports unavailable, the UDP half still works.
    peers = run(["peers", "--seconds", "1", "--no-verify", "-v"], h_s)
    logged = peers.stdout + peers.stderr
    check("mDNS reports unavailable without zeroconf, UDP stays ok",
          "'mdns': 'unavailable'" in logged and "'udp': 'ok'" in logged,
          [line for line in logged.splitlines() if "channels" in line])

    # 9. A stranger - not a 传书 - holding a port: the probe has to name it and still come up.
    # This is also the case the EADDRINUSE branch would serve, and it never gets there,
    # because the probe answers first.
    stranger = start(["receive", "--yes", "--root", str(h_r / "work" / "in2"),
                      "--port", "43913", "--seconds", "12", "--no-discover"], h_r)
    text3 = read_until(stranger, r"按 Ctrl-C|听 \d+")
    holder = subprocess.Popen([sys.executable, "-c",
                               "import socket;"
                               "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
                               "s.bind(('0.0.0.0',43914));s.listen(8)\n"
                               "import time;time.sleep(12)"], cwd=str(REPO))
    time.sleep(1.0)
    squatter = start(["receive", "--yes", "--root", str(h_r / "work" / "in3"),
                      "--port", "43914", "--seconds", "8", "--no-discover"], h_r)
    text4 = read_until(squatter, r"按 Ctrl-C|听 \d+")
    port4 = int(re.search(r"监听：(\d+)", text4).group(1))
    port3 = int(re.search(r"监听：(\d+)", text3).group(1))
    check("a free port is taken as asked", port3 == 43913 and "端口" not in text3,
          f"{port3} | {text3.splitlines()[0]}")
    check("a stranger on the port is named, not guessed", port4 != 43914 and "不是传书" in text4,
          f"{port4} | {text4.splitlines()[0]}")
    stop(stranger)
    stop(squatter)
    holder.kill()
    holder.wait(timeout=10)

    # The firewall question on the machine that has neither firewalld nor ufw installed. This is the
    # Linux half of the reader the Windows gate checks against netsh, and WSL is what proves the
    # absent-tool branch: the honest answer about a firewall nobody can read is "unknown", never
    # "you are open" - a silent all-clear here is exactly the #87 bug on the other platform.
    fw = run(["firewall", "--port", str(port)], h_r)
    check("a machine with no firewall tool says unknown and exits 1",
          fw.returncode == 1 and "结论：unknown" in fw.stdout, tail(fw, 200))

    stop(first)
    stop(second)
    print("RESULT " + ("ALL PASS" if not failures else f"FAILURES: {failures}"))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
