"""What the platform's own firewall says about this program - read-only.

The failure this exists for: a receiver can be listening perfectly and still admit nobody. On
Windows, answering "don't allow" to the first-run prompt leaves *block* rules pinned to that exe
path, and a block rule wins over any allow rule for the same program; the log then shows inbound
connections that never arrive and the UI has nothing to say about it. Nothing in the application
layer can see that decision, so this asks the platform (netsh, firewall-cmd, ufw) and hands back
facts for the window and the terminal to render.

Deliberately read-only. Writing a rule needs elevation and belongs to the installer - a running
app that silently edits the firewall of the machine it was only asked to send files from is the
kind of surprise this product does not allow.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

#: netsh prints its own labels in the OS language, so both spellings are matched.
_PROFILE_WORDS = {
    "域": "domain", "domain": "domain",
    "专用": "private", "private": "private",
    "公用": "public", "public": "public",
}
_ACTION_WORDS = {
    "允许": "allow", "allow": "allow",
    "阻止": "block", "block": "block",
}
#: netsh says "是/否" for a rule's 已启用 and "启用/关闭" for a profile's 状态 - both are read here.
_ON = {"是", "yes", "true", "on", "启用", "已启用", "开启"}
_OFF = {"否", "no", "false", "off", "禁用", "关闭", "已禁用"}


def _decode(raw: bytes) -> str:
    """netsh output has been seen in both UTF-8 and the console codepage on one machine."""
    for encoding in ("utf-8", "gbk", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class Rule:
    name: str
    action: str  # allow | block
    direction: str  # in | out
    profiles: tuple[str, ...]
    enabled: bool
    program: str = ""

    def covers(self, profile: str) -> bool:
        return not self.profiles or not profile or profile in self.profiles


@dataclass(frozen=True)
class Status:
    """Facts only - every sentence about them is built by whoever shows them."""

    tool: str  # netsh | firewalld | ufw | none | error
    profile: str = ""
    enabled: bool | None = None
    default_inbound: str = ""  # block | allow | ""
    rules: tuple[Rule, ...] = ()
    notes: tuple[str, ...] = ()
    failed: tuple[str, ...] = field(default_factory=tuple)
    #: What these facts were read for: the program's path where rules are written per program
    #: (Windows), or the listener's number where they are written per port (Linux).
    target: Path | None = None
    port: int = 0

    @property
    def verdict(self) -> str:
        """blocked | no_allow | open | unknown - the four states the UI has sentences for."""
        if self.tool in {"none", "error"} or self.failed:
            return "unknown"
        mine = [rule for rule in self.rules if rule.enabled and rule.direction == "in"]
        if any(rule.action == "block" and rule.covers(self.profile) for rule in mine):
            return "blocked"
        if self.enabled is None:
            return "unknown"
        if self.enabled is False:
            return "open"
        if any(rule.action == "allow" and rule.covers(self.profile) for rule in mine):
            return "open"
        if self.default_inbound == "block" or self.tool in {"firewalld", "ufw"}:
            return "no_allow"
        return "unknown"


def _normalise_profile(word: str) -> str:
    return _PROFILE_WORDS.get(word.strip().lower(), word.strip().lower())


#: Reading the platform normalises its labels into these tokens; showing them turns them back
#: into the words the machine wrote them with. The window and the terminal share this table so
#: the two faces cannot start calling the same rule two different things.
WORDS = {
    "allow": "允许", "block": "阻止", "in": "入站", "out": "出站",
    "domain": "域", "private": "专用", "public": "公用",
}


def word(value: str) -> str:
    return WORDS.get(value, value)


def on_off(value: bool | None) -> str:
    return "开" if value else ("关" if value is False else "未知")


def _split_profiles(text: str) -> tuple[str, ...]:
    parts = [part for part in text.replace(";", ",").split(",") if part.strip()]
    return tuple(_normalise_profile(part) for part in parts)


def parse_current_profile(text: str) -> tuple[str, bool | None, str]:
    """From `netsh advfirewall show currentprofile`: profile, on/off, default inbound action.

    netsh writes this section with the label and the value *whitespace*-separated and only the
    header line carries a colon, so matching has to be on line prefixes rather than on `key:value`.
    """
    profile = ""
    enabled: bool | None = None
    inbound = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        head, _, rest = stripped.partition(" ")
        rest = stripped[len(head):].strip() if head else ""
        if stripped.startswith(("防火墙策略", "Firewall Policy")):
            inbound = "block" if "blockinbound" in stripped.lower().replace(" ", "") else "allow"
        elif stripped.startswith(("状态", "State ")):
            value = rest.lower()
            if value in _ON or value in _OFF:
                enabled = value in _ON
        elif "配置文件" in stripped or stripped.endswith("Profile Settings:"):
            name = stripped.split("配置文件")[0] if "配置文件" in stripped else stripped.split("Profile")[0]
            candidate = _normalise_profile(name.strip())
            if candidate in _PROFILE_WORDS.values():
                profile = candidate
    return profile, enabled, inbound


def parse_rules(text: str) -> tuple[Rule, ...]:
    """From `netsh advfirewall firewall show rule name=all dir=in`: every rule in the dump.

    A blank line is *not* a reliable separator - one chunk of the dump can carry a dozen rules - so
    this streams and starts a new rule at each 规则名称/Rule Name line.
    """
    rules: list[Rule] = []
    fields: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or set(stripped) == {"-"}:
            continue
        head, sep, rest = stripped.partition(":")
        if not sep:
            continue
        head, rest = head.strip(), rest.strip()
        if head in {"规则名称", "Rule Name"}:
            if fields:
                rules.append(_build(fields))
            fields = {"规则名称": rest}
            continue
        if fields:
            fields[head] = rest
    if fields:
        rules.append(_build(fields))
    return tuple(rules)


def _build(fields: dict[str, str]) -> Rule:
    def value(*keys: str) -> str:
        for key in keys:
            if key in fields:
                return fields[key].strip()
        return ""

    direction_raw = value("方向", "Direction").lower()
    direction = "in" if direction_raw in {"入", "in", "inbound"} else "out"
    action_raw = value("操作", "Action").lower()
    profiles_raw = value("配置文件", "Profiles")
    enabled_raw = value("已启用", "Enabled").lower()
    return Rule(
        name=value("规则名称", "Rule Name"),
        action=_ACTION_WORDS.get(action_raw, action_raw or "allow"),
        direction=direction,
        profiles=_split_profiles(profiles_raw) if profiles_raw else (),
        enabled=enabled_raw in _ON if enabled_raw else True,
        program=value("程序", "Program"),
    )


def _run(argv: list[str]) -> tuple[int, str]:
    """Run a read-only probe; never raise. An absent tool is a fact, not an exception."""
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, no user input
            argv, capture_output=True, timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as error:
        return -1, f"{type(error).__name__}: {error}"
    body = proc.stdout or proc.stderr
    return proc.returncode, _decode(body)


def _matches_program(fields_path: str, exe: Path) -> bool:
    if not fields_path:
        return False
    try:
        return Path(fields_path.split(";")[0].strip('"')).resolve() == exe.resolve()
    except OSError:
        return False


def _netsh(exe: Path, port: int) -> Status:
    """Two calls: the profile this machine is on, then the inbound rules pinned to this exe."""
    rc, current = _run(["netsh", "advfirewall", "show", "currentprofile"])
    if rc != 0:
        return Status(tool="error", notes=(current.strip(),), target=exe, port=port)
    profile, enabled, inbound = parse_current_profile(current)
    # `verbose` is not decoration: without it netsh omits the 程序/Program line entirely, and the
    # whole point is finding the rules pinned to *this* exe rather than to some name we guessed.
    rc, dump = _run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in", "verbose"])
    if rc != 0:
        return Status(tool="netsh", profile=profile, enabled=enabled, default_inbound=inbound,
                      failed=(dump.strip(),), target=exe, port=port)
    mine = tuple(rule for rule in parse_rules(dump) if _matches_program(rule.program, exe))
    return Status(tool="netsh", profile=profile, enabled=enabled, default_inbound=inbound,
                  rules=mine, target=exe, port=port)


def _firewalld(inspection_port: int) -> Status:
    rc, state = _run(["firewall-cmd", "--state"])
    if rc != 0:
        return Status(tool="none", notes=(state.strip(),), port=inspection_port)
    running = state.strip().lower() == "running"
    rc, zone_out = _run(["firewall-cmd", "--get-default-zone"])
    zone = zone_out.strip() if rc == 0 else ""
    rules: list[Rule] = []
    for proto in ("tcp", "udp"):
        rc, answer = _run(["firewall-cmd", f"--query-port={inspection_port}/{proto}"])
        # A closed port is not a rule written against us, so it is not reported as one: it simply
        # leaves no allow entry, which the verdict reads as "nothing lets this in".
        if rc == 0 and answer.strip().lower() == "yes":
            rules.append(Rule(name=f"port {inspection_port}/{proto}", action="allow", direction="in",
                              profiles=(zone,), enabled=True))
    return Status(tool="firewalld", profile=zone, enabled=running, default_inbound="block",
                  rules=tuple(rules), port=inspection_port)


def _ufw(inspection_port: int) -> Status:
    """`ufw status` needs root on Ubuntu, so a denial here is the normal answer for a user run."""
    rc, text = _run(["ufw", "status"])
    if rc != 0:
        return Status(tool="none", notes=(text.strip(),), port=inspection_port)
    rules = tuple(
        Rule(name=f"ufw line {index}", action="allow", direction="in", profiles=(), enabled=True)
        for index, line in enumerate(text.splitlines())
        if str(inspection_port) in line and "ALLOW IN" in line
    )
    return Status(tool="ufw", profile="", enabled="Status: active" in text, default_inbound="block",
                  rules=rules, port=inspection_port)


def fix_commands(status: Status, rule_name: str) -> list[str]:
    """What would settle this, as commands for someone with elevation to run.

    Nothing in this module runs them: writing a rule is the installer's or the user's decision, and
    a program that edited its own machine's firewall to make a transfer work is the kind of surprise
    this product does not allow. Windows gets the pair the installer writes - clear whatever this exe
    already has, then allow the LAN in. The port is deliberately not in them: 43720 falls back to an
    ephemeral number when it is taken, and a rule pinned to a port that moved is a false guarantee.
    Linux has no per-program rule to lean on, so there the number is the command and it has to be
    re-run if the listener moved.
    """
    if status.target is not None:
        quoted = f'"{status.target}"'
        return [
            f'netsh advfirewall firewall delete rule name=all dir=in program={quoted}',
            f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=allow'
            f" profile=any remoteip=LocalSubnet program={quoted}",
        ]
    return [
        f"firewall-cmd --permanent --add-port={status.port}/tcp && firewall-cmd --reload",
        f"ufw allow {status.port}/tcp",
    ]


def inspect(exe: Path | None = None, port: int = 0) -> Status:
    """Ask the platform. `exe` is the running binary on Windows, `port` the listener on Linux.

    Nothing here needs the UI: the facts come from the machine, and both faces render them.
    """
    if os.name == "nt":
        return _netsh(exe or Path(sys.executable), port)
    status = _firewalld(port)
    if status.tool == "none":
        status = _ufw(port)
    return status
