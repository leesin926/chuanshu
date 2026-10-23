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
#: The transfer legs run `app.cli` in subprocesses and need no import; the firewall section reads
#: the machine through the same module the terminal does, so it imports it in-process.
sys.path.insert(0, str(ROOT))
SCRATCH = ROOT / ".probe" / "cli"
SAMPLE = SCRATCH / "sample.bin"
#: What netsh writes for one machine on one profile, in both OS languages: the labels are on the
#: same line as the value but separated from it by padding, which is why the reader prefix-matches.
ZH_PROFILE = """
公用配置文件 设置:
----------------------------------------------------------------------
状态                                  启用
防火墙策略                          BlockInbound,AllowOutbound
"""
EN_PROFILE = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
"""
#: Two rules in one chunk of a dump, with no blank line between the separator rules and no
#: program= line: the reader must still keep their fields apart and in their own rule.
RULES = """

规则名称:                             chuanshu
----------------------------------------------------------------------
已启用:                               是
方向:                                 入
配置文件:                             公用
协议:                                 TCP
操作:                                 允许

规则名称:                             chuanshu-cli
----------------------------------------------------------------------
已启用:                               是
方向:                                 入
配置文件:                             公用
协议:                                 TCP
操作:                                 阻止
"""
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


def firewall_checks(role: str) -> None:
    """`firewall` reads the machine, and the parsers behind it are checked against canned output.

    The verdict half is asked of the *real* platform: on Windows that is netsh answering about this
    very python.exe, which is worth more than a fixture. The states netsh cannot be made to show on
    demand - a block rule, firewalld, ufw, no tool at all - come from the fixtures below, because a
    gate that only passes on one machine's configuration proves nothing about the other's.
    """
    from app.net import firewall

    out = cli(role, ["firewall"])
    verdict = re.search(r"结论：(\w+)", out.stdout)
    check("firewall printed a verdict the machine can be read back from", verdict is not None, out.stdout.strip()[-300:])
    if verdict:
        check(f"and exited with the number for {verdict.group(1)}",
              out.returncode == {"open": 0, "unknown": 1, "no_allow": 2, "blocked": 3}[verdict.group(1)],
              f"rc={out.returncode} verdict={verdict.group(1)}")
    check("the reader answered for this process's own program", "问的是：" in out.stdout, out.stdout.splitlines()[:1])

    zh, en = firewall.parse_current_profile(ZH_PROFILE), firewall.parse_current_profile(EN_PROFILE)
    check("the profile reader takes both OS languages",
          zh == ("public", True, "block") and en == ("domain", True, "block"), f"{zh} / {en}")
    rules = firewall.parse_rules(RULES)
    check("a rule dump keeps each rule's own fields", len(rules) == 2 and rules[0].action == "allow"
          and rules[1].action == "block" and rules[0].profiles == ("public",), rules)
    both = firewall.Status(tool="netsh", profile="public", enabled=True, default_inbound="block",
                           rules=(rules[0], rules[1]))
    check("a block rule beats the allow rule beside it", both.verdict == "blocked", both.verdict)
    nothing = firewall.Status(tool="netsh", profile="public", enabled=True, default_inbound="block")
    check("no rule of any kind is not called open", nothing.verdict == "no_allow", nothing.verdict)
    off = firewall.Status(tool="netsh", profile="public", enabled=False)
    check("a machine with the firewall off is open, not unreadable", off.verdict == "open", off.verdict)
    check("an absent tool is reported as unknown, never as fine", firewall.Status(tool="none").verdict == "unknown")

    win = firewall.Status(tool="netsh", profile="public", enabled=True, default_inbound="block",
                          target=Path(sys.executable), port=43720)
    commands = firewall.fix_commands(win, "ChuanShu")
    joined = " ".join(commands)
    check("the Windows fix clears this program's rules before writing one",
          "delete rule name=all dir=in" in joined and "action=allow" in joined, commands)
    check("it admits only the LAN rather than the world, on any profile",
          "remoteip=LocalSubnet" in commands[1] and "profile=any" in commands[1], commands[1])
    check("and it names the program the rule is for, not a port that may have moved",
          str(win.target) in commands[1] and "43720" not in commands[1], commands[1])
    linux = firewall.fix_commands(firewall.Status(tool="firewalld", port=43720), "ChuanShu")
    check("the Linux fix has to name the port, since nothing else identifies the listener",
          "43720/tcp" in linux[0] and "43720/tcp" in linux[1], linux)

    calls: list[list[str]] = []

    def fake_run(argv: list[str]) -> tuple[int, str]:
        calls.append(argv)
        text = " ".join(argv)
        if "--state" in text:
            return 0, "running\n"
        if "--get-default-zone" in text:
            return 0, "public\n"
        if "--query-port" in text:
            return (0, "yes\n") if "/tcp" in text else (1, "no\n")
        if argv[0] == "ufw":
            return 0, "Status: active\n43720/tcp                   ALLOW IN    192.168.1.0/24\n"
        return 1, "not found\n"

    real_run = firewall._run
    firewall._run = fake_run
    try:
        fw = firewall._firewalld(43720)
        check("firewalld's zone and its one open port are both read",
              fw.tool == "firewalld" and fw.profile == "public" and fw.enabled and len(fw.rules) == 1, fw)
        ufw = firewall._ufw(43720)
        check("ufw's ALLOW line is read as a rule", ufw.rules and ufw.rules[0].action == "allow", ufw.rules)
        check("a port ufw never mentions is not called open", firewall._ufw(43999).verdict == "no_allow",
              firewall._ufw(43999).verdict)
        check("nothing in the reader ran a command that writes",
              not any("add" in " ".join(argv) or "--reload" in " ".join(argv) for argv in calls), calls)
    finally:
        firewall._run = real_run


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
    announced = read_until(r1, r"按 Ctrl-C|听 \d+")
    port, code, secret = banner(announced)
    check("receiver announced port, code and passphrase", port > 0 and len(code) == 6, f"{port} {code} {secret}")
    # "监听：43720" is only half the promise, and the other half is not the listener's own fact:
    # a machine can hold the port and still be unreachable. The banner says which of them it is.
    check("the receiver also said whether a peer can get in", "入站：" in announced, announced.strip()[-160:])

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
    firewall_checks("R")

    stop(r1)
    stop(r2)
    print("RESULT " + ("ALL PASS" if not failures else f"FAILURES: {failures}"))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
