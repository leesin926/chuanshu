"""Verify the vendored protocol contract before trusting it.

Two repos drift silently the moment someone edits shared/protocol/ by hand, so this
checks the copy against its stamp *and* the contract against itself. stdlib only - the
mobile side has no reason to install anything to run it.

    python scripts/check_protocol.py
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
CONTRACT = HERE / "shared" / "protocol"
REQUIRED_KEYS = {
    "protocol_version",
    "brand",
    "ports",
    "discovery",
    "transport",
    "endpoints",
    "error_codes",
    "limits",
}


def fail(msg: str) -> None:
    print(f"FAIL  {msg}")
    raise SystemExit(1)


def check_uts_mirror(body: dict) -> None:
    """The UTS constants are a second copy of the same numbers, so check them against the contract.

    Nothing runs that file at build time, so a fork here would only surface as a pairing failure on
    a phone - which is exactly when it is expensive to diagnose.
    """
    src = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "cs-protocol.uts").read_text(encoding="utf-8")
    mirrored = {
        "PROTOCOL_VERSION": body["protocol_version"],
        "TRANSPORT_PORT": body["ports"]["transport_default"],
        "PREFIX_CHARS": body["discovery"]["fingerprint_prefix_chars"],
        "PAIR_CODE_TTL_S": body["transport"]["pair_code_ttl_s"],
        "PAIR_CODE_DIGITS": body["transport"]["pair_code_digits"],
        "PASSPHRASE_CHARS": body["transport"]["passphrase_chars"],
        "CHUNK_SIZE": body["transport"]["chunk_size"],
        "MAX_FILES_PER_OFFER": body["limits"]["max_files_per_offer"],
        "MAX_NAME_BYTES": body["limits"]["max_name_bytes"],
        "MAX_PATH_DEPTH": body["limits"]["max_path_depth"],
        # The two idle windows of spec §3/§4 are the receiver's own promise, so the phone that
        # keeps them has to agree with the PC that publishes them - a shorter window on a phone
        # would delete files the sender still believes are resumable.
        "SESSION_IDLE_S": body["transport"]["session_idle_timeout_s"],
        "OFFER_IDLE_S": body["transport"]["offer_idle_timeout_s"],
        # §4's third window. The sender keeps it (it re-posts the manifest until this runs out) and the
        # receiver keeps it too (an unanswered offer is dropped on it), so a phone that guessed would
        # either give up on a peer that is still waiting or keep a card alive past the sender's deadline.
        "OFFER_WAIT_S": body["transport"]["offer_wait_timeout_s"],
        # §3's throttle. Until round twenty-three these two lived only inside cs-receive.uts, where no
        # mirror check looked - the phone agreed with the PC by accident, not by measurement.
        "PAIR_CODE_MAX_FAILS": body["transport"]["pair_code_max_fails"],
        "PAIR_CODE_LOCK_S": body["transport"]["pair_code_lock_s"],
        # The discovery windows are the same story: a phone that expired a candidate on a different
        # clock, or broadcast on a different port, is a phone the PC cannot be found by.
        "DISCOVERY_PORT": body["ports"]["discovery_udp"],
        "ANNOUNCE_INTERVAL_S": body["discovery"]["announce_interval_s"],
        "PEER_EXPIRY_S": body["discovery"]["peer_expiry_s"],
    }
    for name, expected in mirrored.items():
        found = re.search(rf"export const {name}: number = (\d+)", src)
        if found is None:
            fail(f"cs-protocol.uts no longer declares {name}")
        if int(found.group(1)) != int(expected):
            fail(f"cs-protocol.uts {name} = {found.group(1)} but the contract says {expected}")
    transport = body["transport"]
    found = re.search(r"export const PAIR_CODE_STATIC: boolean = (true|false)", src)
    if found is None:
        fail("cs-protocol.uts no longer declares PAIR_CODE_STATIC")
    if (found.group(1) == "true") != bool(transport["pair_code_static"]):
        fail(f"cs-protocol.uts PAIR_CODE_STATIC = {found.group(1)} but the contract says {transport['pair_code_static']}")
    if re.search(rf"QR_SCHEME: string = '{re.escape(body['brand']['qr_scheme'])}'", src) is None:
        fail(f"cs-protocol.uts does not carry the pairing scheme {body['brand']['qr_scheme']!r}")

    # The signed bytes are specified by the contract and built in exactly one place here, because
    # three-versus-four fields is the whole compatibility story between an old and a new build.
    if re.search(r"export function pairMessage\(", src) is None:
        fail("cs-protocol.uts must build the pair signature message itself; spec §3 defines it")
    for key in ("['secret']", "['tls_fingerprint']"):
        if key not in src:
            fail(f"cs-protocol.uts no longer sends the optional pair body key {key}")

    check_discovery_mirror(body)
    check_chunk_escape()


def check_chunk_escape() -> None:
    """spec §4's zero-byte encoding is decided from the header's *value*, on every end that reads it.

    The value itself lives in the contract's prose, not in `protocol.json`, so nothing else would notice
    the day one receiver goes back to asking "did a header arrive?" instead of "is it the encoding I
    know?" - an unknown encoding then gets bytes thrown away before the length and digest checks can say
    what they are, which is the one thing §4 says a receiver must not do. The two native hosts cannot
    import the shared module, so each restates the value; this is the guard that keeps the restatements
    restating the same thing."""
    root = HERE.parent
    utssdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    desktop = (root / "app" / "net" / "spec.py").read_text(encoding="utf-8")
    found = re.search(r'^CHUNK_ESCAPE_VALUE = "([^"]+)"', desktop, re.M)
    if found is None:
        fail("app/net/spec.py no longer names the escape value spec §4 writes on the wire")
    value = found.group(1)
    shared = (utssdk / "cs-protocol.uts").read_text(encoding="utf-8")
    if f"CHUNK_ESCAPE_VALUE: string = '{value}'" not in shared:
        fail(f"cs-protocol.uts does not mirror the escape value {value!r}")
    for name, pattern in (
        ("app-android/CsServe.kt", rf'CHUNK_ESCAPE_STU = "{value}"'),
        ("app-harmony/index.uts", rf"CHUNK_ESCAPE_STU: string = '{value}'"),
    ):
        host = (utssdk / name).read_text(encoding="utf-8")
        if re.search(pattern, host) is None:
            fail(f"{name} does not carry the escape value {value!r} it compares against")
        if "== CHUNK_ESCAPE_STU" not in host:
            fail(f"{name} declares the escape value but never compares a header against it")
    for name, presence in (("app-android/CsServe.kt", 'escape.isNotEmpty() && method == "PUT"'),
                           ("app-harmony/index.uts", "escape != '' && method == 'PUT'")):
        if presence in (utssdk / name).read_text(encoding="utf-8"):
            fail(f"{name} decides the body's encoding from the header's presence, not its value (spec §4)")



def check_discovery_mirror(body: dict) -> None:
    """The roster is written once, so the announcement's own field names are checkable here too.

    A discovery packet that the other end cannot read is invisible rather than wrong: no dialog, no
    error, just an empty device list. That is the most expensive kind of protocol fork to find, so
    the mirror is guarded like every other number."""
    utssdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    constants = (utssdk / "cs-protocol.uts").read_text(encoding="utf-8")
    service_type = body["brand"]["mdns_service_type"]
    if f"MDNS_SERVICE_TYPE: string = '{service_type}'" not in constants:
        fail(f"cs-protocol.uts does not declare the mDNS service type {service_type!r}")
    short = service_type.removesuffix(".local.")
    if f"MDNS_SERVICE_SHORT: string = '{short}'" not in constants:
        fail(f"cs-protocol.uts must carry the Info.plist form {short!r} (spec §2)")

    src = (utssdk / "cs-discovery.uts").read_text(encoding="utf-8")
    discovery = body["discovery"]
    for field in discovery["udp_payload_fields"]:
        if f'"{field}"' not in src and f"'{field}'" not in src:
            fail(f"cs-discovery.uts no longer reads or writes the announce field {field!r}")
    for field in discovery["mdns_txt_fields"]:
        if f"{field}=" not in src and f"'{field}'" not in src:
            fail(f"cs-discovery.uts no longer reads or writes the TXT field {field!r}")

    # The ArkTS half cannot import cs-protocol.uts, so it restates three of its constants. That copy is
    # the one place a fork can hide: the phone would broadcast on a port nobody listens on and say
    # nothing about it, because discovery failures are silent by construction.
    harmony = (utssdk / "app-harmony" / "index.uts").read_text(encoding="utf-8")
    restated = {
        "DISCOVERY_PORT": str(body["ports"]["discovery_udp"]),
        "ANNOUNCE_INTERVAL_S": str(discovery["announce_interval_s"]),
        "MDNS_SERVICE_SHORT": short,
    }
    for name, expected in restated.items():
        quote = "'" if not expected.isdigit() else ""
        pattern = rf"const {name}: (?:number|string) = {quote}{re.escape(expected)}{quote}"
        if re.search(pattern, harmony) is None:
            fail(f"app-harmony/index.uts does not restate {name} = {expected!r} as the contract requires")


def check_limits_in_prose(body: dict) -> None:
    """Every number a receiver refuses a transfer with has to be named by the section that lists refusals.

    §5 is the page a reader comes to for "what will the other end turn down", and it is written as the
    floor the wire has to meet. A limit that lives only in `protocol.json` is invisible there: the sender
    gets a 400 for a reason nobody wrote down, and the mirror guard - which only compares numbers - stays
    green. That is how `max_path_depth` rode on both ends for eight inspection rounds with no sentence in
    §5 and no leg anywhere.
    """
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    marker = "## 5."
    if marker not in spec:
        fail("spec.md no longer has a §5 to read the refusal limits out of")
    section = spec.split(marker, 1)[1].split("\n## ", 1)[0]
    for name in ("max_name_bytes", "max_path_depth", "max_files_per_offer"):
        if name not in section:
            fail(f"§5 stays silent about {name}, but a receiver refuses transfers on it (protocol.json limits)")


def check_error_table(body: dict) -> None:
    """The phone restates the code table twice - the words in `errorText`, the number in `statusOf` - and
    neither copy is the contract.

    The PC reads its grid out of `protocol.json` at run time, so one selftest leg can compare all eleven
    cells. A phone cannot parse JSON at compile time, so `cs-receive.uts` spells the same numbers as an
    if-chain and `cs-protocol.uts` spells the same sentences as string returns. That restatement is where
    a fork hides quietly: until #176 every receive leg compared only the code *name*, so editing 403 to 400
    stayed green while the peer - which does read the number - started telling its user something else.
    The legs now read numbers; this guard is what keeps the copies honest between runs.
    """
    utssdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    words = (utssdk / "cs-protocol.uts").read_text(encoding="utf-8")
    states = (utssdk / "cs-receive.uts").read_text(encoding="utf-8")
    wire = (utssdk / "web" / "index.uts").read_text(encoding="utf-8")

    chain = re.search(r"function statusOf\(code: string\): number \{(.*?)\n\}", states, re.S)
    if chain is None:
        fail("cs-receive.uts no longer has a statusOf() to give the wire its number")
    table: dict[str, int] = {}
    for cond, num in re.findall(r"if \((.*?)\) \{\s*return (\d+)", chain.group(1), re.S):
        for named in re.findall(r"'([A-Z_]+)'", cond):
            table[named] = int(num)
    rest = re.sub(r"if \(.*?\) \{\s*return \d+\s*\}", "", chain.group(1), flags=re.S)
    fallback = re.findall(r"return (\d+)", rest)
    if len(fallback) != 1:
        fail(f"statusOf must end in exactly one fallback return, found {len(fallback)}")
    for code, entry in body["error_codes"].items():
        want_http = int(entry["http"])
        got_http = table.get(code, int(fallback[0]))
        if got_http != want_http:
            fail(f"cs-receive.uts answers {code} with {got_http}, but error_codes says {want_http}")
        spelled = re.search(rf"if \(code == '{code}'\) \{{\s*return '([^']*)'\s*\}}", words)
        if spelled is None:
            fail(f"cs-protocol.uts errorText() no longer names {code} - the screen shows 协议错误：{code} instead")
        if spelled.group(1) != entry["msgid"]:
            fail(f"errorText() says {spelled.group(1)!r} for {code}, the contract msgid is {entry['msgid']!r}")
        # The browser's stand-in PC is a fourth copy: it answers this end's own kernel's shapes, so a
        # number written there teaches the sender legs to expect the wrong one.
        for num in re.findall(rf"failure\('{code}',.*?, (\d+), cb\)", wire, re.S):
            if int(num) != want_http:
                fail(f"web/index.uts answers a {code} refusal with {num}, but the peer's own kernel says {want_http}")
        for num in re.findall(rf"cb\((\d+), JSON\.stringify\(\{{ code: '{code}'", wire):
            if int(num) != want_http:
                fail(f"web/index.uts parks a {code} reply at {num}, but the contract table says {want_http}")


def check_hello_features(body: dict) -> None:
    """§7 says hello's `features` is the contract's list, sent verbatim, deciding nothing in v1.

    A wire field with no named owner is how a second compatibility rule gets invented: each end retypes the
    three words, and the first person who wants to change behaviour on one end finds three lists to argue
    about instead of one to edit.
    """
    want = list(body["transport"]["hello_features"])
    utssdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    shared = (utssdk / "cs-protocol.uts").read_text(encoding="utf-8")
    declared = re.search(r"export const HELLO_FEATURES: string\[\] = \[([^\]]*)\]", shared)
    if declared is None:
        fail("cs-protocol.uts no longer declares HELLO_FEATURES, the one copy §7 points every end at")
    listed = [one.strip().strip("'") for one in declared.group(1).split(",")]
    if listed != want:
        fail(f"cs-protocol.uts HELLO_FEATURES = {listed} but transport.hello_features says {want}")
    for name in ("cs-receive.uts", "web/index.uts"):
        src = (utssdk / name).read_text(encoding="utf-8")
        if "features: HELLO_FEATURES," not in src:
            fail(f"{name} answers hello with a restated capability list instead of importing HELLO_FEATURES")
    desk = (HERE.parent / "app" / "net" / "receive.py").read_text(encoding="utf-8")
    if re.search(r'"features":\s*list\(self\.proto\.hello_features\)', desk) is None:
        fail("app/net/receive.py no longer answers hello from the list protocol.json carries")
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    if "## 7." not in spec:
        fail("spec.md no longer has a §7 to read the capability-list rule out of")
    section = spec.split("## 7.", 1)[1].split("\n## ", 1)[0]
    if "transport.hello_features" not in section:
        fail("§7 stays silent about transport.hello_features, but three ends send it on every hello")


def check_endpoint_count(body: dict) -> None:
    """§8 counts the endpoints for the relay branch, and that number is a restatement of `endpoints`.

    The cloud branch is specified on paper only - there is no code here to disagree with - so the prose *is*
    the integration note. Add an eighth endpoint and §8 keeps promising 七, which is exactly the shape #176
    found on the other side of the contract: a number copied by hand, with nothing checking the copy.
    """
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    if "## 8." not in spec:
        fail("spec.md no longer has a §8 to read the relay branch's endpoint count out of")
    section = spec.split("## 8.", 1)[1].split("\n## ", 1)[0]
    spelled = re.findall(r"([一二两三四五六七八九十])个端点", section)
    if not spelled:
        fail("§8 no longer names how many endpoints the relay branch has to cover")
    numerals = {"一": 1, "两": 2, "二": 2, "三": 3, "四": 4, "五": 5,
                "六": 6, "七": 7, "八": 8, "九": 9, "十": 10}
    want = len(body["endpoints"])
    for one in spelled:
        got = numerals.get(one)
        if got != want:
            fail(f"§8 counts {one}个端点, but protocol.json defines {want}")


def check_pair_code_digits(body: dict) -> None:
    """The contract says how long the pair code is out loud, in prose, and the field is the number ends mint from.

    #176 pinned §8's hand-copied endpoint count; §1's round found the same shape inside `protocol.json` itself -
    /v1/pair's purpose promised a "4-digit code" two keys below `pair_code_digits: 6`. A code is read off a screen
    and typed on a keypad by a person, so the sentence that tells them how many to expect is not free text.
    """
    want = int(body["transport"]["pair_code_digits"])
    for name in ("protocol.json", "spec.md"):
        text = (CONTRACT / name).read_text(encoding="utf-8-sig")
        said = [int(one) for one in re.findall(r"(\d+)\s*位(?:配对)?码", text)]
        said += [int(one) for one in re.findall(r"(\d+)[- ]digit", text)]
        for got in said:
            if got != want:
                fail(f"{name} says a {got}-digit pair code, but transport.pair_code_digits says {want}")


def check_identity_files() -> None:
    """§1's storage column names files - and for several rounds one of them existed nowhere.

    The table promised a `identity.json` no end ever wrote: the PC keeps `peer-key.pem` beside `peer-cert.pem`
    and reads `peer_id` back out of the certificate's CN, the phones keep a seed, an SPKI and an id file under
    their own names. A contract filename is a hook someone integrating a fourth platform reaches for, so §1 keeps
    to the ones this repo actually opens - the identity row now says what every end already conceded in the leaf
    row: 文件名不属协议.
    """
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    if "## 1." not in spec:
        fail("spec.md no longer has a §1 to read the identity storage out of")
    section = spec.split("## 1.", 1)[1].split("\n## ", 1)[0]
    named = sorted(set(re.findall(r"`([A-Za-z0-9_.-]+\.(?:json|pem|txt))`", section)))
    if not named:
        fail("§1 no longer names a single file - the storage column has to stay readable")
    roots = (HERE.parent / "app", HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk")
    corpus = "".join(path.read_text(encoding="utf-8", errors="ignore")
                     for root in roots for path in sorted(root.rglob("*"))
                     if path.suffix in (".py", ".uts", ".kt"))
    for name in named:
        if name not in corpus:
            fail(f"§1 names {name}, but no end opens a file by that name")


def check_peer_id_shape() -> None:
    """§1 gives `peer_id` one shape - sixteen random bytes, hex - and the four places that mint it have to keep it.

    The browser's stand-in labelled itself `android-web-` plus eight bytes. Nothing on the wire reads a peer_id as
    a label, so it worked - which is exactly how a fourth shape for a frozen identity field gets written down by
    accident: Harmony already refuses to load an id that is not 32 hex characters, and the first build to trust
    that shape is a build the demo peer cannot talk to.
    """
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    if "## 1." not in spec:
        fail("spec.md no longer has a §1 to read the peer_id shape out of")
    row = spec.split("## 1.", 1)[1].split("\n## ", 1)[0]
    found = re.search(r"随机 (\d+) 字节 hex", row)
    if found is None:
        fail("§1 no longer states the peer_id shape as N random bytes, hex")
    size = int(found.group(1))
    utssdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    minted = (
        ("app/net/identity.py", HERE.parent / "app" / "net" / "identity.py", rf"peer_id = secrets\.token_hex\({size}\)"),
        ("app-android/CsIdentity.kt", utssdk / "app-android" / "CsIdentity.kt",
         rf"fun newPeerId\(\): String \{{\s*val bytes = ByteArray\({size}\)"),
        ("app-harmony/index.uts", utssdk / "app-harmony" / "index.uts", rf"hexOf\(randomBytes\({size}\)\)"),
        ("web/index.uts", utssdk / "web" / "index.uts", rf"myPeerId = hexOf\(randomBytes\({size}\)\)"),
    )
    for label, path, pattern in minted:
        if re.search(pattern, path.read_text(encoding="utf-8")) is None:
            fail(f"{label} no longer mints a peer_id of {size} random bytes as §1's table says")
    harmony = (utssdk / "app-harmony" / "index.uts").read_text(encoding="utf-8")
    if f"id.length != {size * 2}" not in harmony:
        fail(f"app-harmony/index.uts no longer measures the id it loads against §1's {size}-byte shape")


def check_spki_head() -> None:
    """§1's fingerprint is a digest over twelve DER bytes plus the key - and three ends hand-type those twelve.

    No phone platform gives a bare Ed25519 key to a DER encoder, so each spells the SubjectPublicKeyInfo header as
    an array (#106). A byte off one copy is not a pairing failure: the signature is over the 32 key bytes, so the
    pair wire still verifies, and the fork surfaces only as a trust-store entry that never matches the number the
    peer prints on its screen. app/net/identity.py:_spki_der is the fourth copy of the same twelve, and the PC
    selftest's §1 leg is what ties it to these three.
    """
    utssdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    files = ("app-android/CsIdentity.kt", "app-harmony/index.uts", "web/index.uts")
    head: tuple[int, ...] | None = None
    for name in files:
        src = (utssdk / name).read_text(encoding="utf-8")
        found = re.search(r"SPKI_HEAD\s*(?::[^=\n]*)?=\s*[\w\s]*[\[\(]([^\]\)]*)[\]\)]", src)
        if found is None:
            fail(f"{name} no longer spells the SPKI header §1's fingerprint is taken over")
        spelled = tuple(int(one, 16) for one in re.findall(r"0x([0-9a-fA-F]{2})", found.group(1)))
        if len(spelled) != 12:
            fail(f"{name} spells {len(spelled)} bytes where an Ed25519 SubjectPublicKeyInfo header is 12")
        if head is not None and spelled != head:
            fail(f"{name} spells a different Ed25519 SPKI header than the other ends: {spelled} vs {head}")
        head = spelled


def check_freeze_gate() -> None:
    """§9 is the sentence that defines what "frozen" means - and three of its clauses pointed at nothing.

    Round twelve read it against the tree. It cited `.probe/protocol_report.txt` (a file the tool writes next
    run, under a directory the repo ignores, so no reader of the contract could open it), it named `py` -
    Windows' launcher - as the gate for a contract whose PC side now has a Linux port, and it promised a chain
    cell 「多文件含目录」 that only the PC had ever measured: the shared receiving kernel had a depth *gate*
    (5d) but had never finished an offer whose relpath carried a directory. The prose now says which artifact
    each clause is; this keeps them from drifting back into wishes.
    """
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    if "## 9." not in spec:
        fail("spec.md no longer has a §9 to read the freeze criterion out of")
    section = spec.split("## 9.", 1)[1].split("\n## ", 1)[0]
    root = HERE.parent
    selftest = (root / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    for cited in sorted(set(re.findall(r"[A-Za-z0-9_./-]*scripts/[A-Za-z0-9_.-]+\.py", section))):
        if not (root / cited).is_file():
            fail(f"§9 runs {cited}, which is not in the tree")
    run_lines = "\n".join(one for one in selftest.splitlines() if one.strip().startswith("Run:"))
    for launcher in ("py", "python3"):
        if f"`{launcher} " not in section:
            fail(f"§9's freeze command lost the {launcher} form - the gate has to read as runnable on both PC "
                 "platforms, not only on the one Windows' launcher exists for")
        if launcher not in run_lines:
            fail(f"§9 says `{launcher}`, but scripts/protocol_selftest.py's own Run: line does not offer it")
    for report in sorted(set(re.findall(r"`\.probe/([A-Za-z0-9_.-]+)`", section))):
        if report not in selftest:
            fail(f"§9 points at .probe/{report}, but no script in the tree writes that name")
    if re.search(r'check\("nested[^"]*"[^\n]*is_file\(\)', selftest) is None:
        fail('the PC gate no longer holds a check("nested…") leg that reads the landing off the disk - '
             '§9\'s 多文件含目录 is a statement about where bytes land, not about what a manifest says')
    harness = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "web" / "index.uts").read_text(encoding="utf-8")
    if harness.count("'§9 冻结链") < 3:
        fail("the shared receiving kernel has no §9 冻结链 legs - §9's 多文件含目录 cell is a PC-only measurement again")


def check_sender_limit() -> None:
    """§5 spends `max_files_per_offer` on the sender too, and a sentence about "both ends" needs a body each.

    Round nine (#174) measured that a manifest over the limit can only come back as
    `UNSUPPORTED_PROTOCOL` - v1's table has no "too big" cell - so the sender's own batch was being
    reported to its user as the *peer's* version problem. The contract's answer was "发送方…在本地按同一个数
    拦下"; the phone obeyed it and the PC shipped every such batch until round twelve put a count in
    `plan()` and in `offer()` itself. This guard is the shape-check that keeps the sentence from
    outliving its implementations again: prose says the senders stop, all three sender bodies must show it.
    """
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 5.", 1)[1].split("\n## ", 1)[0] if "## 5." in spec else ""
    # The obligation is on senders as a class ("发送方（PC 与手机）都在本地"), which is exactly what the
    # first version of this predicate let through: the old sentence 「手机的发送方在本地就按同一个数拦下」
    # also contains 发送方…本地, so only the class form - naming both ends and saying 都 - counts.
    if "## 5." not in spec or re.search(r"发送方（[^）]*）都在本地", section) is None:
        fail("§5 no longer says the senders stop an over-limit batch locally - if the sentence went away, "
             "the two bodies below should go away with it; if only the sentence did, the contract lost a rule")
    root = HERE.parent
    send = (root / "app" / "net" / "send.py").read_text(encoding="utf-8")
    if send.count("raise TooManyFilesForOffer(limit)") < 2:
        fail("app/net/send.py counts max_files_per_offer in fewer than two places - both the walk in plan() "
             "and the choke point offer() must stop, or a constructed manifest is back on the wire")
    client = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "cs-client.uts").read_text(encoding="utf-8")
    if re.search(r"opts\.paths\.length > MAX_FILES_PER_OFFER", client) is None:
        fail("cs-client.uts no longer counts max_files_per_offer locally - the phone's sender stopped obeying §5")
    for name in ("app/cli.py", "app/ui/transfer.py"):
        if not re.search(r"except TooManyFilesForOffer as \w+", (root / name).read_text(encoding="utf-8")):
            fail(f"{name} does not catch TooManyFilesForOffer - the refusal reaches the person as a raw traceback")


def check_hidden_segments() -> None:
    """§5's dot rule is per segment, and the sentence that says the *senders* obey it needs a body per segment.

    Round twenty (#186) read 「发送方…也不把点开头的文件报进清单」 against `plan()`. The PC's walk came from
    `rglob("*")` - the whole tree - while the filter read `entry.name`, the leaf. So a file under `.git`
    was offered with the dot segment still in its relpath, and the receiver, which does check every
    segment, answered the entire manifest with `400 PATH_REJECTED` and the innocent siblings never landed
    (`.probe/r20_before_probe.txt` [2]); with no base the same file went out flattened to `config`,
    the dot segment gone from the name but the bytes still on the wire ([3]/[4]). `plan()` now runs
    `_has_dot_segment` over both the relpath and the entry's position under the folder the user picked.
    The phone never had this hole and never needed the same body: it has no directory walk, and
    `pathCheck` asks the receiving end's own `pathReject` about every relpath before the offer leaves.
    """
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 5.", 1)[1].split("\n## ", 1)[0] if "## 5." in spec else ""
    flat = re.sub(r"\s+", "", section)
    for needle, why in (
        ("发送方（PC 与手机）也按段拦", "the obligation is on senders as a class, per segment - the leaf-only "
         "reading is what shipped a `.git` segment onto the wire"),
        ("只在叶子名上成立", "the measurement is written down; without it the next reader cannot tell a fixed "
         "sentence from an untested one"),
        ("_has_dot_segment", "the sentence cites the body by name, so a guard that only matches prose passes "
         "while the filter is back to one segment"),
        ("被拍平成 `config`", "the second hole - a flattened leaf name is a second path to the same bytes, and it "
         "stayed open until the relpath was judged on its own"),
        ("问的就是整条 relpath", "the phone's half is per-segment too, and it is the receiver's rejector reused, not a copy"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§5 no longer says {needle!r} - {why}")

    send = (HERE.parent / "app" / "net" / "send.py").read_text(encoding="utf-8")
    if send.count("_has_dot_segment(") < 3:
        fail("app/net/send.py calls _has_dot_segment fewer than twice in plan() - the two checks are two holes: "
             "the relpath alone leaves a folder named .私有 shipping its contents, the walked path alone leaves "
             "them shipping as a flattened leaf name")
    if 'if _has_dot_segment(rel) or _has_dot_segment(entry.relative_to(path)):' not in send:
        fail("app/net/send.py's dot filter is no longer the two-part one - §5's 按段拦 on the sender is that line")
    if 'entry.name.startswith(".")' in send:
        fail("app/net/send.py is back to filtering the leaf name only - that is the shape that put `.git` in a "
             "relpath and got a whole offer refused")

    client = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "cs-client.uts").read_text(encoding="utf-8")
    if "const why = pathReject(opts.relpaths[i])" not in client:
        fail("cs-client.uts no longer asks pathReject about each relpath before offering - the phone's sender "
             "obeying §5 per segment is that loop")

    selftest = (HERE.parent / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    for literal, why in (
        ("def phase_hidden_segments(", "§5's sender-side dot rule has no legs on the PC gate again - prose "
         "and body can drift with nothing measuring them"),
        ("base 摘掉、名字拍平成叶子名以后，那一份还是不进清单", "the flattened-name hole is the half a relpath-only "
         "filter re-opens, so its leg names it"),
        ("这一单被对面收下：一份点段都没报出去，无辜的那两份不必再为它陪葬", "the whole-offer refusal was the "
         "user-visible cost; only an end-to-end leg tells 清单没报点段 from 这一单落地了"),
    ):
        if literal not in selftest:
            fail(f"scripts/protocol_selftest.py no longer holds {literal} - {why}")


def check_manifest_fields() -> None:
    """§4's manifest block is a claim about the wire: which keys go out, and what each one is for.

    Round fourteen (#180) read the block against both senders' bodies. The block had four top keys;
    `offerJson()` in cs-protocol.uts and the dict in `send.py::offer()` had shipped six for ages
    (`compatible_versions` from §7, `from`), and six per-file fields (`type`). A reader copying the
    block would send a manifest neither end accepts, and a reader checking a real capture against the
    block would call three live keys "extra" and delete them. So the block was completed, and the three
    numbers nobody acts on got a sentence saying so. This guard pins all of that: the block's key sets
    equal both senders' key sets, the sentence about `total_size` stays, and neither receiver reads it.
    """
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    if "## 4." not in spec:
        fail("spec.md no longer has a §4 to read the manifest out of")
    section = spec.split("## 4.", 1)[1].split("\n## ", 1)[0]
    if "```json" not in section:
        fail("§4's manifest block is gone - the contract no longer says what a POST /v1/offer body holds")
    manifest = json.loads(section.split("```json", 1)[1].split("```", 1)[0])
    top = set(manifest)
    files = manifest.get("files") or [{}]
    entry = set(files[0])

    def literal_keys(text: str, anchor: str, quote: str) -> set:
        """Keys of the object literal that `anchor` opens: lines up to the closing brace on its own line,
        so a nested literal written inline (`"from": {…, …}`) does not cut the read short."""
        tail = text.split(anchor, 1)[1]
        end = re.search(r"^\s*\}", tail, re.M)
        body = tail[: end.start()] if end else tail
        return set(re.findall(fr"^\s*{quote}([a-z_][a-z0-9_]*){quote}\s*:", body, re.M))

    client = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "cs-protocol.uts").read_text(encoding="utf-8")
    phone_top = literal_keys(client.split("export function offerJson", 1)[1], "const body: UTSJSONObject = {", "")
    phone_entry = literal_keys(client.split("function manifestOf", 1)[1], "const item: UTSJSONObject = {", "")
    if phone_top != top:
        fail(f"the phone's offerJson() puts {sorted(phone_top)} on the wire while §4's block holds {sorted(top)} - "
             "a key that ships must be in the block, and a key in the block must ship")
    if phone_entry != entry:
        fail(f"the phone's manifestOf() sends {sorted(phone_entry)} per file while §4's entry holds {sorted(entry)}")
    send = (HERE.parent / "app" / "net" / "send.py").read_text(encoding="utf-8")
    pc_top = literal_keys(send, "manifest = {", '"')
    pc_entry = literal_keys(send, "def manifest(self) -> dict:\n        return {", '"')
    if pc_top != top:
        fail(f"app/net/send.py's offer() puts {sorted(pc_top)} on the wire while §4's block holds {sorted(top)}")
    if pc_entry != entry:
        fail(f"app/net/send.py's FileEntry.manifest() sends {sorted(pc_entry)} per file while §4's entry holds {sorted(entry)}")

    # The three numbers the block now admits are only a promise if the sentence about them stays put and
    # the receivers keep not consulting the total.
    if re.search(r"`total_size`[^。\n]*接收方不拿它判任何事", section) is None:
        fail("§4 no longer says the receiver judges nothing by total_size - the field is back to being "
             "undeclared authority, which is how a sender gets a whole batch refused over a number nobody should read")
    kernel = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "cs-receive.uts").read_text(encoding="utf-8")
    if "total_size" in kernel:
        fail("cs-receive.uts mentions total_size - the shared receiving kernel decides nothing from that number; "
             "§4 sizes every entry by its own `size`")
    # The PC's receiver may print it, which is what it has always done; what it may not do is act on it.
    recv = (HERE.parent / "app" / "net" / "receive.py").read_text(encoding="utf-8")
    read = [one.strip() for one in recv.splitlines() if "total_size" in one and not one.strip().startswith("log.")]
    if read:
        fail(f"app/net/receive.py uses total_size outside a log line ({read[0][:70]}) - the total is the "
             "sender's sum, and a receiver that acts on it is trusting a number it never verified")

    selftest = (HERE.parent / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    if "def phase_manifest_fields(" not in selftest or \
            re.search(r"^\s+phase_manifest_fields\(proto, workspace\)$", selftest, re.M) is None:
        fail("scripts/protocol_selftest.py has no manifest-fields phase in its run - the block's key sets are "
             "unmeasured again, and a sender can drift off §4 quietly")
    harness = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "web" / "index.uts").read_text(encoding="utf-8")
    if harness.count("'§4 total_size") < 3:
        fail("the receiving kernel has fewer than three §4 total_size legs - the phone end needs to throw a "
             "lying total at itself, not only trust the sentence")


def check_finalize_reply() -> None:
    """§4's finalize block is a claim about the wire too - and this one is load-bearing in both directions.

    Round fifteen (#181) found the paper holding `{id, ok}` while both receivers shipped four keys and the
    same section, further up, already promised `path`. Worse, the retry clause - "a sender may re-push just
    that file's problem chunks" - never said where the indexes come from, so anyone following it had to
    resend the whole batch. `missing` is that source, so the block, the two receivers' entry literals, and
    the two senders' read sites have to stay one sentence. This guard pins the shape in both directions and
    keeps the `size: 0` cell (the one clause the contract declares unfixable) measured rather than hoped.
    """
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 4.", 1)[1].split("\n## ", 1)[0]
    blocks = [one for one in re.findall(r"```json\n(.*?)```", section, re.S) if "verified" in one]
    if len(blocks) != 1:
        fail(f"§4 holds {len(blocks)} json blocks mentioning verified - one reply needs one shape, "
             "two of them are two contracts")
    block = json.loads(blocks[0])
    if set(block) != {"offer_id", "verified"}:
        fail(f"§4's finalize block is top-level {sorted(block)} - both receivers answer offer_id+verified "
             "and a third key would be a field nobody sends")
    if not isinstance(block.get("verified"), list) or len(block["verified"]) != 1:
        fail("§4's finalize block no longer shows one entry per file")
    entry = set(block["verified"][0])
    if entry != {"id", "ok", "missing", "path"}:
        fail(f"§4's finalize entry holds {sorted(entry)} - the receivers' entries and the senders' reads all "
             "name id/ok/missing/path")

    kernel = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "cs-receive.uts").read_text(encoding="utf-8")
    # Scoped to finalizeReply(): the arrivals record builds its own entries a few lines further down, and a
    # guard that reads past the function would pin one reply's keys against another object's.
    if "function finalizeReply(" not in kernel:
        fail("cs-receive.uts no longer has finalizeReply() - the reply this section describes is being built "
             "somewhere this guard cannot see")
    body = kernel.split("function finalizeReply(", 1)[1].split("\n}\n", 1)[0]
    if "const entry: UTSJSONObject = {" not in body:
        fail("cs-receive.uts's finalizeReply() no longer builds its entry where this guard reads it - go look "
             "at the new shape and point the read at it")
    phone = set(re.findall(r"\b(\w+):", body.split("const entry: UTSJSONObject = {", 1)[1].split("}\n", 1)[0]))
    if phone != entry:
        fail(f"cs-receive.uts's finalizeReply() builds {sorted(phone)} per entry while §4's block holds "
             f"{sorted(entry)}")
    if "return okWith({ offer_id: offerId, verified: verified } as UTSJSONObject)" not in kernel:
        fail("cs-receive.uts's finalize reply is no longer {offer_id, verified} - the block's top level is a "
             "second contract's shape")

    recv = (HERE.parent / "app" / "net" / "receive.py").read_text(encoding="utf-8")
    if "results.append({" not in recv:
        fail("app/net/receive.py no longer builds its finalize entries where this guard reads them - handle_finalize() "
             "changed shape, point the read at the new one")
    pc = set(re.findall(r'"(\w+)":', recv.split("results.append({", 1)[1].split("})\n", 1)[0]))
    if pc != entry:
        fail(f"app/net/receive.py's handle_finalize() appends {sorted(pc)} per entry while §4's block holds "
             f"{sorted(entry)}")
    if 'return {"offer_id": offer_id, "verified": results}' not in recv:
        fail("app/net/receive.py's finalize reply is no longer {offer_id, verified}")

    # The other half: a field nobody reads is a field free to drift.
    client = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "cs-client.uts").read_text(encoding="utf-8")
    send = (HERE.parent / "app" / "net" / "send.py").read_text(encoding="utf-8")
    if "broken[i].missing" not in client:
        fail("the phone's sender no longer reads the reply's `missing` - §4's 只补传该文件的问题分块 would be "
             "a clause with no source for the chunk indexes")
    if 'list(bad["missing"])' not in send:
        fail("app/net/send.py no longer reads the reply's `missing` - same clause, PC side")
    for needle, who in (("app/net/send.py:522-539", "the PC sender"), ("cs-client.uts:480-550", "the phone sender")):
        if needle not in section:
            fail(f"§4's retry sentence no longer names {who} by file and range - the sentence that says "
                 "where 问题分块 comes from has to say who implements it")

    # The cell the clause cannot reach: zero chunks means an empty hole list, and the resend writes nothing.
    if '"missing": [], "path": null' not in section:
        fail("§4 no longer states the ok:false reply with an empty `missing` and a null `path` - the size: 0 "
             "death is measured on three ends and belongs on the paper, not only in a probe log")
    if "不由巡检签字" not in section:
        fail("§4 no longer says the zero-byte repair would be a new three-end clause an audit round cannot "
             "sign for - that is what keeps a measurement from quietly becoming an obligation")

    selftest = (HERE.parent / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    if "def phase_finalize_reply(" not in selftest or \
            re.search(r"^\s+phase_finalize_reply\(proto, workspace\)$", selftest, re.M) is None:
        fail("scripts/protocol_selftest.py has no finalize-reply phase in its run - the reply's shape and the "
             "reply-driven resend are unmeasured again")
    harness = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "web" / "index.uts").read_text(encoding="utf-8")
    recv_legs = len(re.findall(r"check\(\s*'(§4 finalize|§4 零字节|§4 那一格)", harness))
    if recv_legs < 4:
        fail(f"the receiving kernel has {recv_legs} §4 finalize/zero-byte legs - the shared kernel needs to "
             "answer the shape itself and play out the size: 0 cell, not only trust the sentence")
    send_legs = len(re.findall(r"check\(\s*'(那块被整文件摘要推翻后|补传写的就是|它没去问 state)", harness))
    if send_legs < 3:
        fail(f"the sender self-report has {send_legs} reply-driven-resend legs - without them nothing on the "
             "phone side proves the indexes came from the finalize answer rather than a GET /state")


def check_offer_reply_shapes() -> None:
    """§4's three answers - the accepted manifest, the pending one, the abort - are claims about bytes.

    Round sixteen (#182) read the section against all four bodies that write them. The paper showed
    `200 {"accepted": true}` for a manifest somebody said yes to, while both receivers answered three
    top keys and three entry keys - and, on the phone, the sender spends that body as its chunk plan
    instead of asking `GET /state`, so a reader copying the block would have built a plan from a `files`
    array that was not there. The abort reply was not written down at all, and the half that mattered
    most was missing from the PC: 「中止并清理」 covered only an offer already being filled, so a sender
    that timed out waiting left the receiver's dialog open, where a late 接受 would register and allocate
    files for a peer that had gone. Every one of those is now on the paper and has to stay one shape here.
    """
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 4.", 1)[1].split("\n## ", 1)[0] if "## 4." in spec else ""
    flat = re.sub(r"\s+", "", section)

    def said(needle: str) -> bool:
        """§4's prose wraps mid-sentence at whatever width it was typed at, so a check that wants a whole
        clause reads the section with its line breaks folded out of the way."""
        return re.sub(r"\s+", "", needle) in flat

    blocks = [one for one in re.findall(r"```json\n(.*?)```", section, re.S) if '"accepted"' in one]
    if len(blocks) != 1:
        fail(f"§4 holds {len(blocks)} json blocks mentioning accepted - one reply needs one shape")
    reply = json.loads(blocks[0])
    top = set(reply)
    if top != {"offer_id", "accepted", "files"}:
        fail(f"§4's accepted-manifest reply is top-level {sorted(top)} - all four bodies answer "
             "offer_id/accepted/files")
    if not isinstance(reply.get("files"), list) or len(reply["files"]) != 1:
        fail("§4's accepted-manifest reply no longer shows one entry per file")
    entry = set(reply["files"][0])
    if entry != {"id", "received", "missing"}:
        fail(f"§4's reply entry holds {sorted(entry)} - both receivers build id/received/missing and the "
             "phone's statePlans() reads id/received/missing")

    # 「同一份」 is the load-bearing word: the offer answer and the state answer are produced by one
    # function per end, so pinning the two literals separately would let them drift apart on a green gate.
    if not said("和 `GET /v1/offer/{id}/state` 逐字节相同"):
        fail("§4 no longer promises the accepted reply is byte-identical to GET state - that sentence is "
             "what the phone's no-extra-round-trip depends on")
    recv = (HERE.parent / "app" / "net" / "receive.py").read_text(encoding="utf-8")
    pc_body = recv.split("def payload(self) -> dict:", 1)[1].split("        return {", 1)[1].split("\n        }\n", 1)[0]
    # One indent level in is the reply's own keys; two is one entry's. Read by depth rather than by
    # taking every key in the literal, because `{"id", "received", "missing"}` sits inside it.
    pc_top = set(re.findall(r'^            "(\w+)":', pc_body, re.M))
    pc_line = next((one for one in pc_body.splitlines() if one.startswith(" " * 16) and '{"' in one), "")
    pc_entry = set(re.findall(r'"(\w+)":', pc_line))
    if pc_top != top:
        fail(f"app/net/receive.py's OfferState.payload() answers {sorted(pc_top)} while §4's block holds {sorted(top)}")
    if pc_entry != entry:
        fail(f"app/net/receive.py's OfferState.payload() answers {sorted(pc_entry)} per entry while §4's "
             f"block holds {sorted(entry)}")
    for fn in ("def handle_offer", "def handle_state"):
        body = recv.split(fn, 1)[1].split("\n    def ", 1)[0]
        if "return state.payload()" not in body:
            fail(f"app/net/receive.py's {fn.replace('def ', '')}() no longer answers from "
                 "OfferState.payload() - the two replies are two implementations again, and §4 says one")

    utssdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    kernel = (utssdk / "cs-receive.uts").read_text(encoding="utf-8")
    if "return { offer_id: offer.offerId, accepted: true, files: list } as UTSJSONObject" not in kernel:
        fail("cs-receive.uts's payloadOf() no longer answers {offer_id, accepted, files}")
    if "{ id: file.id, received: file.chunks.size, missing: missing }" not in kernel:
        fail("cs-receive.uts's payloadOf() no longer answers id/received/missing per entry")
    # The browser's stand-in peer is the fourth body: it answers this end's own kernel's shapes, so a key
    # written wrong there teaches the sender legs to expect a reply no real peer sends.
    harness = (utssdk / "web" / "index.uts").read_text(encoding="utf-8")
    if "return { offer_id: offer.offerId, accepted: true, files: list } as UTSJSONObject" not in harness:
        fail("web/index.uts's demo peer no longer answers the same three top keys as the real receivers")

    # The pending answer: two keys, and no landing to report because nobody has chosen one yet.
    if not said('这条应答就只有这两个键，没有 `files[]`'):
        fail("§4 no longer says the pending answer carries only offer_id and accepted - a third key here "
             "would be a 落点 the receiver has not decided")
    for label, path in (("app-android/index.uts", utssdk / "app-android" / "index.uts"),
                        ("store/session.uts", HERE / "chuanshu" / "store" / "session.uts")):
        emitter = [one for one in (path.read_text(encoding="utf-8").splitlines()) if '"accepted":false' in one]
        if len(emitter) != 1:
            fail(f"{label} answers a waiting offer with {len(emitter)} lines carrying accepted:false - "
                 "the pending reply is one shape and it is this host's job to write it")
        if "files" in emitter[0]:
            fail(f"{label}'s pending reply carries a files[] before anyone has decided a landing (spec §4)")

    # Who holds the connection while the card is up is the other half of this paragraph, and the paper
    # had it wrong for one end until round twenty-one (#187): it named Android among the ends that
    # answer on the connection that asked, while that host has answered the pending shape on the spot
    # since #83 and Harmony since #59. The sentence now says what each end does, so pin it end by end.
    if not said("挂不挂这条连接是各端自己的事"):
        fail("§4's 待决应答 no longer says holding the connection is each end's own choice - that is the "
             "half a receiver implements, and one clause naming the wrong end sent a phone to park a socket")
    # The stale wording lives on in the dated note underneath, which is where a round's own finding is
    # allowed to quote it back; the claim being pinned is the paragraph the next implementor reads.
    waiting_para = next((one for one in section.split("\n\n") if "待决应答" in one), "")
    if "能挂住连接的一方（PC、Android）" in re.sub(r"\s+", "", waiting_para):
        fail("§4 names Android again as an end that answers on the connection that asked - it has not "
             "done so since #83, and the answer to that sentence is the immediate pending reply pinned above")
    gui = (HERE.parent / "app" / "ui" / "transfer.py").read_text(encoding="utf-8")
    if 'holder["event"].wait(' not in gui:
        fail("app/ui/transfer.py's _decide no longer blocks the server thread on the user's answer - the PC "
             "is the end §4 says holds the connection, and its GUI is one of the two bodies that does")
    cli = (HERE.parent / "app" / "cli.py").read_text(encoding="utf-8")
    if "socket stays open" not in cli:
        fail("app/cli.py's decide no longer says the peer's socket stays open while it prompts - the CLI is "
             "the second PC body, and blocking there is what makes its long-poll honest")
    immediate = "ids[ids.length - 1] + '\",\"accepted\":false}'"
    for label, path, emitter_name in (("app-android/index.uts", utssdk / "app-android" / "index.uts", "replyJson"),
                                      ("store/session.uts", HERE / "chuanshu" / "store" / "session.uts", "serveReply")):
        states = path.read_text(encoding="utf-8")
        if immediate not in states:
            fail(f"{label} no longer answers a waiting offer from inside the request handler - §4's phone half "
                 "is the immediate pending reply, and the sender's re-post is what carries the decision")
        decide = states.split("function receiveDecide(", 1)[1].split("\n}\n", 1)[0]
        if emitter_name + "(" in decide:
            fail(f"{label}'s receiveDecide() writes to the wire again - the user's tap cannot reach the "
                 "connection that asked, which is why this end answers pending immediately")

    # The kernel's own header teaches a new host what to do with `pending`. It used to say the host owns
    # the reply callback and that nothing differs on the wire - the same stale claim as §4's sentence,
    # written where the next phone host would read it.
    if "On the wire nothing differs" in kernel:
        fail("cs-receive.uts still tells a host that parking the callback changes nothing on the wire - "
             "for both phones it changes the first answer, which is §4's pending shape")

    # The abort reply: named on paper, sent by both receivers, read by nobody.
    if not said('`200 {"offer_id": "…", "dropped": true}`'):
        fail("§4 no longer states what DELETE /v1/offer/{id} answers - the sentence went away, but all "
             "four bodies still send those two keys")
    if recv.count('return {"offer_id": offer_id, "dropped": True}') != 2:
        fail("app/net/receive.py's handle_abort() no longer answers {offer_id, dropped} in both branches - "
             "the offer being filled and the question nobody has answered are two moments, and both are 中止")
    if "{ offer_id: offerId, dropped: true }" not in kernel:
        fail("cs-receive.uts's abortReply() no longer answers {offer_id, dropped}")
    abort = recv.split("def handle_abort", 1)[1].split("\n    def ", 1)[0]
    if "offer_id in self._asking" not in abort or '_remember(offer_id, "withdrawn")' not in abort:
        fail("app/net/receive.py's handle_abort() does not know the question still in flight - §4's 还没有人回答的"
             "那一半 is the sender's own timeout, and an id only present in _asking is that half")
    offer_fn = recv.split("def handle_offer", 1)[1].split("\n    def ", 1)[0]
    if '== "withdrawn"' not in offer_fn:
        fail("app/net/receive.py's handle_offer() answers a withdrawn offer again instead of saying "
             "OFFER_UNKNOWN - a late 接受 must not open files for a sender that already left")
    ui = (HERE.parent / "app" / "ui" / "transfer.py").read_text(encoding="utf-8")
    if "on_withdrawn=self._offer_withdrawn.emit" not in ui:
        fail("app/ui/transfer.py no longer closes the dialog when the peer withdraws - the service can stop "
             "the offer and leave the person staring at a yes/no about bytes nobody sends")
    for needle in ("已经登记在填的一单", "还没有人回答的那一问", "不登记、不开档"):
        if not said(needle):
            fail(f"§4's 中止 no longer spells out {needle} - the two moments are the clause; without one "
                 "of them a reader implements half of it, which is what this round found")

    # Who reads what: `received` and `dropped` are on the wire and judged by nobody.
    if not said('但没有任何一端拿它判事'):
        fail("§4 no longer says `received` decides nothing - a number that is parsed but never judged has "
             "to be marked as such or the next reader starts trusting it")
    send = (HERE.parent / "app" / "net" / "send.py").read_text(encoding="utf-8")
    if re.search(r'\[(?:"|\x27)(received|dropped)(?:"|\x27)\]|\.get\((?:"|\x27)(received|dropped)(?:"|\x27)', send):
        fail("app/net/send.py reads received/dropped out of a reply - the PC sender judges only `accepted`, "
             "then the missing table: those two numbers are on the wire and decided by nobody")
    client = (utssdk / "cs-client.uts").read_text(encoding="utf-8")
    if re.search(r"get(?:Boolean|Number|String)\('(received|dropped)'", client):
        fail("cs-client.uts reads received/dropped out of a reply - the phone's sender pushes from `missing` "
             "and gives up on a non-200, not on a number either end lets it decide")
    if "pushChunks(offerId, statePlans(body)" not in client:
        fail("cs-client.uts no longer feeds the accepted reply straight into statePlans() - §4's 「同一份 "
             "files[]」 is the round trip this end does not pay for, and if it goes away the sentence lies")
    protocol = (utssdk / "cs-protocol.uts").read_text(encoding="utf-8")
    if "entry.getNumber('received', 0)" not in protocol:
        fail("cs-protocol.uts no longer parses received into ChunkPlan - §4 lists it as 在场的字节 and says so")

    selftest = (HERE.parent / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    if "def phase_offer_reply(" not in selftest or \
            re.search(r"^\s+phase_offer_reply\(proto, workspace\)$", selftest, re.M) is None:
        fail("scripts/protocol_selftest.py has no offer-reply phase in its run - the three shapes and the "
             "withdrawal of a question nobody answered are unmeasured again")
    if "def phase_pending_answer(" not in selftest or \
            re.search(r"^\s+phase_pending_answer\(proto, workspace\)$", selftest, re.M) is None:
        fail("scripts/protocol_selftest.py no longer runs the sender against a receiver that answers pending "
             "on the spot - §4's 「两种写法对发送端是同一条路径」 is a claim about the sender, and the other "
             "legs all drive it against a PC-style holder")
    legs = len(re.findall(r"check\(\s*'§4 (待决|中止|接受|那句|落齐)", harness))
    if legs < 8:
        fail(f"the receiving kernel has {legs} §4 reply legs - the shared kernel needs to answer all three "
             "shapes itself, not only trust this guard")


def check_chunk_reply() -> None:
    """§4's chunk replies are the only bytes a transfer is actually made of, and until round seventeen the
    paper drew none of them.

    Round seventeen (#183) read 「分块」 against all four bodies that answer a chunk `PUT`. The section gave a
    status for a rejected chunk and nothing else: no body for the `200`, no body for the idempotent repeat,
    no detail for either `422`, and `X-File-Size` listed among the chunk headers when no end sends it and no
    end reads it. It also said 「最多 3 次」 where the PC counts three *writes* (`retries=3` around
    `range(retries)`) and the phone counts two *resends* (`CHUNK_RESEND_MAX = 2`) - the same three writes,
    spelled one number apart. Every one of those is on the paper now, so a reader copying §4 builds the body
    the receivers really answer. This guard keeps the four blocks, the sentences that carry the load, and the
    three receivers' literals from drifting back apart.
    """
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 4.", 1)[1].split("\n## ", 1)[0] if "## 4." in spec else ""
    flat = re.sub(r"\s+", "", section)

    def said(needle: str) -> bool:
        """§4's prose wraps mid-sentence, so a check that wants a whole clause folds the breaks out first."""
        return re.sub(r"\s+", "", needle) in flat

    blocks = re.findall(r"```json\n(.*?)```", section, re.S)

    stored = [json.loads(one) for one in blocks if '"stored"' in one]
    if len(stored) != 2:
        fail(f"§4 holds {len(stored)} json blocks mentioning stored - a chunk write and its repeat are two "
             "answers and both need drawing")
    fresh = [one for one in stored if set(one) == {"index", "stored"}]
    again = [one for one in stored if set(one) == {"index", "stored", "idempotent"}]
    if len(fresh) != 1 or len(again) != 1:
        fail(f"§4's chunk replies are {sorted({tuple(sorted(one)) for one in stored})} - the write answers "
             "index/stored and the byte-identical repeat adds exactly idempotent")
    if fresh[0]["stored"] is not True or again[0]["idempotent"] is not True:
        fail("§4's chunk replies no longer say stored/idempotent are true - two keys that answer nothing")
    if fresh[0]["index"] != again[0]["index"]:
        fail("§4's two chunk replies report different indexes - the repeat is the same chunk, that is the point")

    lengths = [json.loads(one) for one in blocks if '"reason"' in one]
    if len(lengths) != 1 or set(lengths[0]) != {"reason", "got", "want"}:
        fail("§4 no longer draws the length refusal as reason/got/want - all three receivers answer those "
             "three keys and a reader needs to know `want` is the manifest's own size sliced")
    if lengths and lengths[0]["reason"] != "length":
        fail("§4's detail-with-reason block is no longer the length one - `reason` has exactly one value on the wire")
    claimed = [json.loads(one) for one in blocks if '"expected"' in one]
    if len(claimed) != 1 or set(claimed[0]) != {"index", "expected"}:
        fail("§4 no longer draws the digest refusal as index/expected - and `expected` is the sender's own "
             "claim, which is the half a reader gets wrong without it written down")

    # The sentences that carry the load: who sends the header, who reads it, and what three writes means.
    for needle, why in (
        ('接收方却只在它非空时做块级校验', "a header the receivers treat as optional is not optional"),
        ('头缺失时三端都**照收、不校验**', "the accepted-but-unverified PUT is §4's sharpest edge"),
        ('没有任何一端发、也没有任何', "`X-File-Size` is back on the paper as a live header"),
        ('`expected` 里装的是**发送方自己声明的那一份**', "the receiver's own digest must not look like it went on the wire"),
        ('**一共写三次**：首发一次、重传至多两次', "「最多 3 次」 is three writes spelled two ways again - the sentence that made two ends disagree"),
        ('加进去就是一个没人读的格子', "the reason the retry count stays out of protocol.json"),
        ('detail 给 `{index, count}`', "BAD_CHUNK_INDEX's detail went back un-drawn"),
    ):
        if not said(needle):
            fail(f"§4 no longer says {needle!r} - {why}")

    recv = (HERE.parent / "app" / "net" / "receive.py").read_text(encoding="utf-8")
    chunk_body = recv.split("def handle_chunk", 1)[1].split("\n    def ", 1)[0]
    for literal, why in (
        ('return {"index": index, "stored": True}', "the accepted write"),
        ('return {"index": index, "stored": True, "idempotent": True}', "the accepted repeat"),
        ('{"index": index, "count": count}', "BAD_CHUNK_INDEX's detail"),
        ('{"reason": "length", "got": len(data), "want": want}', "the length detail"),
        ('{"index": index, "expected": claimed_digest}', "the digest detail - claimed, not computed"),
    ):
        if literal not in chunk_body:
            fail(f"app/net/receive.py's handle_chunk() no longer answers {literal} - §4 drew {why}")
    if 'if claimed_digest and claimed_digest != digest:' not in chunk_body:
        fail("app/net/receive.py no longer skips the chunk check for an absent X-Sha256 - §4's 照收、不校验 is "
             "this one condition, and the sender-side rule to always send the header is the only thing keeping it honest")

    utssdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    kernel = (utssdk / "cs-receive.uts").read_text(encoding="utf-8")
    for literal in ("return okWith({ index: index, stored: true } as UTSJSONObject)",
                    "return okWith({ index: index, stored: true, idempotent: true } as UTSJSONObject)",
                    "return failWith('BAD_CHUNK_INDEX', { index: index, count: count } as UTSJSONObject)",
                    "if (sha != '' && sha != digest)",
                    "{ reason: 'length', got: data.byteLength, want: want }",
                    "return failWith('CHUNK_DIGEST_MISMATCH', { index: index, expected: sha } as UTSJSONObject)"):
        if literal not in kernel:
            fail(f"cs-receive.uts no longer answers {literal} - the phone and the PC answer one shape, and §4 says so")

    # The browser's stand-in peer is the fourth body, and the only tier where the idempotent skip is witnessed.
    harness = (utssdk / "web" / "index.uts").read_text(encoding="utf-8")
    for literal in ("reply(200, { index: index, stored: true } as UTSJSONObject, cb)",
                    "reply(200, { index: index, stored: true, idempotent: true } as UTSJSONObject, cb)",
                    "failure('BAD_CHUNK_INDEX', { index: index, count: count } as UTSJSONObject, 400, cb)",
                    "if (sha != '' && sha != digest)",
                    "{ reason: 'length', got: data.length, want: want }",
                    "failure('CHUNK_DIGEST_MISMATCH', { index: index, expected: sha } as UTSJSONObject, 422, cb)"):
        if literal not in harness:
            fail(f"web/index.uts's routeChunk() no longer answers {literal} - the demo peer teaches the "
                 "sender legs to expect a reply no real peer sends")
    if "if (kept != null && sameBytes(kept!, data))" not in harness or "let recvWrites: number = 0" not in harness:
        fail("web/index.uts's repeat branch no longer compares bytes and counts writes - 「多带一个键」 has to "
             "come with 省掉一次重写, and the counter next to the write is the only witness of that here")

    # Neither sender may put X-File-Size back on the wire, and the retry budget stays written two ways.
    send = (HERE.parent / "app" / "net" / "send.py").read_text(encoding="utf-8")
    client = (utssdk / "cs-client.uts").read_text(encoding="utf-8")
    for label, source in (("app/net/send.py", send), ("cs-client.uts", client),
                          ("app/net/receive.py", recv), ("cs-receive.uts", kernel)):
        if "X-File-Size" in source:
            fail(f"{label} reads or writes X-File-Size again - §4 says no end sends it and no end reads it, "
                 "and the length a receiver compares is sliced from the manifest's own size")
    if "retries: int = 3" not in send or "for attempt in range(retries)" not in send:
        fail("app/net/send.py's chunk budget is no longer three writes - `range(3)` is the three §4 counts")
    if "const CHUNK_RESEND_MAX: number = 2" not in client or "attempt < CHUNK_RESEND_MAX" not in client:
        fail("cs-client.uts's chunk budget is no longer two resends after the first write - the phone writes "
             "three times too, and only the constant's name says so")

    selftest = (HERE.parent / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    if "def phase_chunk_reply(" not in selftest or \
            re.search(r"^\s+phase_chunk_reply\(proto, workspace\)$", selftest, re.M) is None:
        fail("scripts/protocol_selftest.py has no chunk-reply phase in its run - the four bodies, the "
             "headerless PUT and the three-write budget are unmeasured again")

    legs = len(re.findall(r"check\(\s*'§4 (一块写成|重复写入|那一个键换来|摘要与体不符|长度不对|序号越界|不带 X-Sha256|块级校验被跳过|这一单最后的防线)", harness))
    if legs < 9:
        fail(f"the receiving kernel has {legs} §4 chunk legs - it answers all four shapes itself, and has to prove it")
    sender_legs = len(re.findall(r"check\(\s*'(每块都被 422 拒掉|§4 那一块一共写三次|三次之间它一次 state 都没问|报出去的就是对方那一句)", harness))
    if sender_legs < 4:
        fail(f"the sending harness has {sender_legs} legs for a peer that refuses every chunk - the phone's "
             "three writes are §4's claim too, not only the PC's")


def check_finalize_replay() -> None:
    """§4's keep-alive trap has a sender half, and it lands on `finalize` - the one question a re-send
    answers differently than a first ask.

    Round eighteen (#184) read 「发送方看到连接被关要重连重发一次」 against both senders. The PC had it:
    every request goes out under `for attempt in (0, 1)`. The phone did not - `finalize` let `status == 0`
    fall into the `status != 200` branch and reported the whole order failed against a peer that had
    already verified and taken the bytes. Adding that second pass drags in an obligation the paper had
    never spelled, because a re-posted `finalize` is a *successful* question repeated: the receiver keeps
    the offer in its table after verifying (it deletes the resume ledger, not the order), so the second
    pass re-answers, and the PC announced every landed file a second time - a second row in 收到的文件 and
    a second notification for bytes that had already been reported. The phone's shared kernel had that
    gate since #35 (`hasArrival`); the PC got one keyed by destination path.

    Round nineteen (#185) asked where that gate *lives*. The record it protects is on disk (the resume
    ledger, and the PC's arrivals.json), so a gate in process memory restarts empty: stop the receiver
    mid-offer, re-adopt the same order, finish it, and the file already announced before the restart is
    announced again. The phone is restart-safe by construction - `hasArrival` reads the persisted inbox -
    so the PC's list moved into `OfferState.announced`, which rides in `.chuanshu.state.json`. This guard
    pins the three sentences, the second pass on both senders, both receivers' announce-once, and the
    fact that the PC's half of that is written down rather than remembered.
    """
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 4.", 1)[1].split("\n## ", 1)[0] if "## 4." in spec else ""
    flat = re.sub(r"\s+", "", section)

    for needle, why in (
        ('这一问可以重投', "the re-post is the whole reason the receiver needs announce-once - it went back un-said"),
        ('同一份字节只报一次「这个文件到了」', "the obligation a re-post drags along is the one thing that made the PC write two rows"),
        ('发送方看到连接被关要重连重发一次', "the sentence this round was about"),
        ('一秒后重问一次，只一次', "the phone's second pass without its bound is a retry loop"),
        ('不再复用这一条连接', "the receiver half of the trap is written as a connection rule, not a header"),
        ('活得比这一场久', "the gate is worthless if the record it guards is on disk and it is not"),
        ('先落笔再播报', "announcing before writing it down is the crash window the list exists to close"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§4 no longer says {needle!r} - {why}")

    send = (HERE.parent / "app" / "net" / "send.py").read_text(encoding="utf-8")
    if "for attempt in (0, 1):" not in send:
        fail("app/net/send.py no longer gives every request a second pass - §4's 重连重发一次 is that loop for the PC")

    client = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "cs-client.uts").read_text(encoding="utf-8")
    for literal, why in (
        ("function finalize(offerId: string, isRetry: boolean, reasked: boolean)",
         "the phone's finalize has no way to tell its first pass from its second"),
        ("if (status == 0 && codeOf(body) != 'CANCELLED' && !reasked) {",
         "an unread finalize is a question, not a verdict - and only one re-ask"),
        ("setTimeout((): void => { finalize(offerId, isRetry, true) }, 1000)",
         "the second pass itself: a re-ask one second later, on a freshly dialled connection"),
    ):
        if literal not in client:
            fail(f"cs-client.uts no longer contains {literal} - §4's 手机在路由层 says {why}")

    recv = (HERE.parent / "app" / "net" / "receive.py").read_text(encoding="utf-8")
    finalize_body = recv.split("def handle_finalize", 1)[1].split("\n    def ", 1)[0]
    persist_body = recv.split("def persist", 1)[1].split("\n    def ", 1)[0]
    load_body = recv.split("def load", 1)[1].split("\n    def ", 1)[0]
    for literal, where, name, why in (
        ('announced: list[str] = field(default_factory=list)', recv, "OfferState",
         "the list of landings already announced is no longer part of the offer's own state"),
        ('"announced": self.announced,', persist_body, "persist()",
         "the resume ledger no longer carries what this offer has announced - §4 says the gate outlives the process"),
        ('announced=[str(p) for p in body.get("announced", [])],', load_body, "load()",
         "a re-adopted offer no longer reads its announcements back, so the restart re-reports them"),
        ('fresh = [e for e in landed if str(e["path"]) not in state.announced]', finalize_body,
         "handle_finalize()", "the announcement is no longer filtered by destination - §4 says 同一份字节只报一次"),
        ('state.announced.extend(str(e["path"]) for e in fresh)', finalize_body, "handle_finalize()",
         "the announcement is no longer written down, only said"),
        ("if not finished:", finalize_body, "handle_finalize()",
         "a finished offer would persist a ledger it is about to delete - the list has nowhere to live after that"),
    ):
        if literal not in where:
            fail(f"app/net/receive.py {name} no longer contains {literal!r} - {why}")
    if "self._reported" in recv:
        fail("app/net/receive.py announces from a set kept in the service again - that set empties when the "
             "process does, and the ledger it guards does not")
    if "self.on_received(state.who, landed)" in finalize_body:
        fail("handle_finalize() announces the whole landed list again - the second pass re-announces every "
             "file this offer already reported")

    kernel = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "cs-receive.uts").read_text(encoding="utf-8")
    if "function hasArrival(inbox: Inbox, land: string): boolean {" not in kernel:
        fail("cs-receive.uts lost the arrival dedupe it has had since #35 - the phone and the PC answer one "
             "announce-once rule, and this is the phone's half")
    if "hasArrival(inbox, file.land)" not in kernel.split("function recordArrivals", 1)[1].split("\nfunction ", 1)[0]:
        fail("recordArrivals() no longer asks before writing a row - the gate has to be in the recorder, not only beside it")

    harness = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "web" / "index.uts").read_text(encoding="utf-8")
    if "muteFinalize: number = 0" not in harness or "finalizeAsks: number = 0" not in harness:
        fail("the browser's sender probe cannot inject a swallowed finalize answer any more - the phone's "
             "second pass is unwitnessed at the only tier that runs the shared client")
    recv_legs = len(re.findall(r"check\(\s*'§4 (全绿之后重投 finalize|重投那一趟不再把同一个文件报第二遍)", harness))
    if recv_legs < 2:
        fail(f"the receiving kernel has {recv_legs} re-post legs - it answers the repeat itself, and has to prove it")
    send_legs = len(re.findall(r"check\(\s*'(finalize 那一问读不到应答时这一单没被判死|它没有把已经落齐的字节重写一遍|此刻对方只被出示过一次 finalize)", harness))
    if send_legs < 3:
        fail(f"the sending harness has {send_legs} finalize legs - the re-ask has to be shown alive, cheap, and asked once")

    selftest = (HERE.parent / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    if "def phase_finalize_replay(" not in selftest or \
            re.search(r"^\s+phase_finalize_replay\(proto, workspace\)$", selftest, re.M) is None:
        fail("scripts/protocol_selftest.py has no finalize-replay phase in its run - the PC's second pass, "
             "the byte-identical re-post and the announce-once are unmeasured again")
    replay = selftest.split("def phase_finalize_replay", 1)[1].split("\ndef ", 1)[0]
    for literal, why in (
        ("restarted.adopt_interrupted_offers()",
         "there is no restart in this phase any more - §4's 活得比这一场久 is a claim about the second process"),
        ('ledger.get("announced")',
         "the phase no longer reads the announce list back out of the ledger on disk, which is the only place "
         "it can be seen surviving"),
        ('str((root / third.offer_id).resolve())',
         "the prefix the announced list is compared against went back to tempfile's short form, and the "
         "resolved landing paths never start with it"),
    ):
        if literal not in replay:
            fail(f"phase_finalize_replay() no longer contains {literal} - {why}")


def check_pair_throttle(body: dict) -> None:
    """§3's throttle is a sliding window with a per-source bucket, and both halves used to exist only in code.

    Round twenty-three (#189) read 「同一来源 5 次失败锁 60s」 - a sentence two implementations satisfy
    differently at second 59. The PC prunes then counts (``app/net/receive.py``), the shared kernel prunes
    then counts (``cs-receive.uts``), and in both the release belongs to the *oldest* of the five failures
    while a refused attempt records nothing. None of that was on paper, neither number was in
    ``protocol.json``, and the phone's copy sat in a private ``const`` the mirror check never read. So this
    guard holds four things at once: the prose says the shape, the contract owns the two numbers, every body
    reads them from there rather than typing them, and the shape has legs on both tiers.
    """
    transport = body["transport"]
    for name in ("pair_code_max_fails", "pair_code_lock_s"):
        if name not in transport:
            fail(f"protocol.json lost transport.{name} - spec §3's throttle has no home to be read from")
    fails, lock = int(transport["pair_code_max_fails"]), int(transport["pair_code_lock_s"])
    if not 3 <= fails <= 10:
        fail(f"pair_code_max_fails {fails}: few enough guesses and the code is no use, many enough and 10^6 is thin")
    if not 10 <= lock <= 600:
        fail(f"pair_code_lock_s {lock}: shorter than a person can retype a code, longer than a LAN attacker cares about")

    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 3.", 1)[1].split("\n## ", 1)[0] if "## 3." in spec else ""
    flat = re.sub(r"\s+", "", section)
    for needle, why in (
        (f"同一来源攒到 {fails} 次失败就被拒", "the count is the contract's number, spelled in the sentence that obliges it"),
        (f"{lock} 秒", "the window's length belongs on the paper too - each end typing its own is how they fork"),
        ("那五次里最早那一次", "which moment the 60 s runs from is the whole finding; without it a fixed window reads the same"),
        ("自己不往窗口里添新记录", "a refused guess must not extend the lock, and that is not something a reader can assume"),
        ("按地址分桶", "「来源」 has to be defined or the next host per-connection-ises it and the lock never fills"),
        ("哪一端都不落盘", "the list's lifetime is a promise to the person who got locked out and restarted the peer"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§3 no longer says {needle!r} - {why}")

    root = HERE.parent
    receive = (root / "app" / "net" / "receive.py").read_text(encoding="utf-8")
    if re.search(r"_CODE_(LOCK_S|MAX_FAILS)\s*=\s*\d+", receive):
        fail("app/net/receive.py types the throttle's two numbers again - they are protocol.json's, and a "
             "second copy of a promise is the fork this guard exists to catch")
    for literal in ("self.proto.pair_code_lock_s", "self.proto.pair_code_max_fails"):
        if literal not in receive:
            fail(f"app/net/receive.py no longer reads {literal} from the contract")
    handler = receive.split("def handle_pair", 1)[1].split("\n    def ", 1)[0] if "def handle_pair" in receive else ""
    if handler == "":
        fail("app/net/receive.py has no handle_pair() to inspect - the throttle's shape cannot be measured")
    if handler.find("self._prune()") < 0 or handler.find("pair_code_max_fails") < handler.find("self._prune()"):
        fail("app/net/receive.py does not prune before it counts - counting stale failures locks a peer out "
             "for longer than §3 promises, which is the fixed-window reading this round wrote down against")

    spec_py = (root / "app" / "net" / "spec.py").read_text(encoding="utf-8")
    if 'int(transport["pair_code_max_fails"])' not in spec_py or 'int(transport["pair_code_lock_s"])' not in spec_py:
        fail("app/net/spec.py loads the throttle with a fallback value or not at all - a contract copy that "
             "predates these keys must fail loudly, not pair-protect itself with different numbers")

    kernel = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "cs-receive.uts").read_text(encoding="utf-8")
    if re.search(r"const CODE_(LOCK_S|MAX_FAILS):", kernel):
        fail("cs-receive.uts keeps a private copy of the throttle's numbers again - cs-protocol.uts is the one "
             "the mirror check reads, and a const nobody compares is a number nobody verifies")
    for name in ("PAIR_CODE_MAX_FAILS", "PAIR_CODE_LOCK_S"):
        if re.search(rf"\b{name}\b", kernel) is None:
            fail(f"cs-receive.uts no longer uses {name} - the phone's §3 throttle stopped reading the contract's number")
    pair_body = kernel.split("function pairReply(", 1)[1] if "function pairReply(" in kernel else kernel
    at_prune, at_count = pair_body.find("prune(inbox, now)"), pair_body.find(">= PAIR_CODE_MAX_FAILS")
    if at_prune < 0 or at_count < 0 or at_count < at_prune:
        fail("cs-receive.uts does not prune before it counts - §3's 最早那一次 is decided by that order")

    for host, literal in (("app-android/CsServe.kt", 'sk.inetAddress?.hostAddress ?: "?"'),
                          ("app-harmony/index.uts", "c.ip == '' ? '?' : c.ip")):
        if literal not in (root / "mobile" / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / host).read_text(encoding="utf-8"):
            fail(f"{host} no longer folds an unreadable address into one '?' bucket - §3 counts failures per *source*, "
                 f"and a per-connection bucket hands a guesser a clean allowance on every retry")

    selftest = (root / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    if "def phase_pair_throttle(" not in selftest or \
            re.search(r"^\s+phase_pair_throttle\(proto, workspace\)$", selftest, re.M) is None:
        fail("scripts/protocol_selftest.py has no throttle phase in its run - the sliding window, the shared "
             "bucket and the non-persistence are unmeasured again")
    phase = selftest.split("def phase_pair_throttle", 1)[1].split("\ndef ", 1)[0]
    for literal, why in (
        ("proto.pair_code_max_fails", "the phase hardcodes its own count instead of the contract's - it would "
                                      "keep passing if the number moved"),
        ("proto.pair_code_lock_s + 1", "the release leg is one second past the window; without it the phase "
                                       "cannot tell a sliding window from a fixed one"),
        ("too many failed codes", "the refusal is identified by its reason, not by the status code PEER_BUSY "
                                  "shares with 一次只连一台"),
        ("into=again", "there is no second process in the phase any more - 不落盘 is a claim about a restart"),
    ):
        if literal not in phase:
            fail(f"phase_pair_throttle() no longer contains {literal} - {why}")

    harness = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "web" / "index.uts").read_text(encoding="utf-8")
    if "function askPairAt(" not in harness:
        fail("the H5 receiver self-check lost its clock-injecting pair helper - the kernel's `now` parameter is "
             "the only way to measure a 60-second window inside a page")
    shape_legs = len(re.findall(r"check\(\s*'§3 (攒够 5 次以后连猜对也拒|被锁住期间的尝试不往清单里添记录|门在第 61 秒开|密码猜错和配对码猜错记在同一桶里|「来源」按地址分桶)", harness))
    if shape_legs < 5:
        fail(f"the H5 receiver self-check holds {shape_legs} of the five throttle-shape legs - each one is a "
             "clause of §3's sentence, and the phone's kernel is the body they measure")


def check_random_source(body: dict) -> None:
    """§3's three secrets come out of each platform's cryptographic generator, and every end has to say which.

    Round twenty-four (#190) read 「返回随机会话 token（32 字节）」 and 「`k` 是 32 字母表 8 位」 - both of
    which said 随机 and stopped there. The PC minted all three with `secrets`; the shared phone kernel minted
    all three with `Math.random()`, on an Android host that reaches for `SecureRandom` the moment it needs a
    `peer_id`. So this guard holds four things: the paper names the source and the drop-when-indivisible rule,
    the kernel asks its host for the bytes instead of inventing them, no body can obtain an inbox without
    naming one, and each of the five hosts actually names its platform's generator.
    """
    note = body["transport"].get("note", "")
    for needle, why in (
        ("java.security.SecureRandom", "the Android half of §3's source is a fact about the contract, not a "
                                       "comment someone may delete"),
        ("cryptoFramework.createRandom", "Harmony's generator belongs on the paper the same way"),
        ("crypto.getRandomValues", "the browser harness is a fifth end, and it is the one the phone kernel's "
                                   "JS copy runs in"),
        ("never from `Math.random()`", "the whole finding: 随机 used to be readable as this"),
        ("taken modulo", "the bias §3 now forbids, so the rule and its name have to stay together"),
    ):
        if needle not in note:
            fail(f"protocol.json's transport.note no longer says {needle!r} - {why}")

    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 3.", 1)[1].split("\n## ", 1)[0] if "## 3." in spec else ""
    flat = re.sub(r"\s+", "", section)
    for needle, why in (
        ("本平台的密码学随机源", "「随机」 alone is what let three ends read three things"),
        ("不能是`Math.random()`", "the sentence has to name the thing it rules out or the next host re-does it"),
        ("要**丢掉**凑不齐的那几个字节", "rejection sampling is the second half of §3's entropy promise"),
        ("而不是直接取模", "modulo is what the phones' own id loop does, and it is not bias-free"),
        ("只是标识", "the distinction that keeps this promise off `peer_id`, offer ids and nonces"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§3 no longer says {needle!r} - {why}")

    root = HERE.parent
    sdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    kernel = (sdk / "cs-receive.uts").read_text(encoding="utf-8")
    kernel_code = "\n".join(line for line in kernel.splitlines()
                            if not line.strip().startswith(("//", "*", "/*")))
    if "Math.random" in kernel_code:
        fail("cs-receive.uts rolls its own random bytes again - §3's three secrets are the kernel's only "
             "entropy and this file is shared by four hosts that cannot agree on one generator")
    if re.search(r"^\s*randomHex,\s*$", kernel, re.M):
        fail("cs-receive.uts imports randomHex again - that function is §3's answer for *identifiers*, and "
             "leaving it in the import list is how the next credential gets minted off it")
    for literal, why in (
        ("rand: RandFn", "the Inbox no longer carries the host's source, so the kernel is back to guessing"),
        ("export function newInbox(rand: RandFn): Inbox",
         "an inbox can be made without a source again - the one shape that lets a host forget to arm itself"),
        ("const token = inbox.rand(32)",
         "the session token is not read off the host any more, and a bearer value that is guessable is a peer"),
        ("newPairCode(inbox.rand, PAIR_CODE_DIGITS)", "the pair code stopped asking the host for bytes"),
        ("newPassphrase(inbox.rand, PASSPHRASE_CHARS)", "the passphrase stopped asking the host for bytes"),
    ):
        if literal not in kernel:
            fail(f"cs-receive.uts no longer contains {literal!r} - {why}")

    proto = (sdk / "cs-protocol.uts").read_text(encoding="utf-8")
    if "export type RandFn = (byteLen: number) => string" not in proto:
        fail("cs-protocol.uts lost the RandFn type - the hosts have no name for what they hand the kernel")
    loop = proto.split("export function randomHex", 1)[1].split("\n}", 1)[0] if "export function randomHex" in proto else ""
    outside = "\n".join(line for line in proto.replace(loop, "").splitlines()
                        if not line.strip().startswith(("//", "*", "/*")))
    if "Math.random" not in loop:
        fail("randomHex no longer rolls Math.random() - fine, but then the guard's next predicate is stale")
    if "Math.random" in outside:
        fail("cs-protocol.uts sprouted a second Math.random() outside randomHex - ids may use it (§3 calls "
             "them 只是标识); nothing else may")
    for literal, why in (
        ("return pickFrom(rand, '0123456789', 250, digits)",
         "250 is 25*10: the largest multiple of ten inside a byte, and the drop step §3 just made law"),
        ("return pickFrom(rand, PASSPHRASE_ALPHABET, 256, chars)",
         "32 divides 256, so the passphrase must not discard a single byte"),
    ):
        if literal not in proto:
            fail(f"cs-protocol.uts no longer contains {literal!r} - {why}")

    ident_py = (root / "app" / "net" / "identity.py").read_text(encoding="utf-8")
    recv_py = (root / "app" / "net" / "receive.py").read_text(encoding="utf-8")
    for text, name, literal in ((ident_py, "app/net/identity.py", 'secrets.choice("0123456789")'),
                                (ident_py, "app/net/identity.py", "secrets.choice(PASSPHRASE_ALPHABET)"),
                                (recv_py, "app/net/receive.py", "secrets.token_hex(32)")):
        if literal not in text:
            fail(f"{name} no longer mints §3's secret with {literal!r} - secrets.choice is unbiased by "
                 f"construction, which is why the PC has no drop step to copy")
    if re.search(r"\brandom\.(choice|randint|getrandbits|random)\b", ident_py + recv_py):
        fail("the PC reaches for `random.` for a §3 credential - the Mersenne Twister's state is recoverable "
             "from a few outputs, and this is the sentence round twenty-four wrote against")

    hosts = (
        ("app-android/index.uts", "newInbox(recvRand)"),
        ("app-harmony/index.uts", "cryptoFramework.createRandom().generateRandomSync(n)"),
        ("app-ios/index.uts", "newInbox(recvRand)"),
        ("app-ios/CsBytes.swift", "SecRandomCopyBytes(kSecRandomDefault, count, raw)"),
        ("web/index.uts", "crypto.getRandomValues(out)"),
    )
    for host, literal in hosts:
        if literal not in (sdk / host).read_text(encoding="utf-8"):
            fail(f"{host} no longer contains {literal!r} - §3 names this end's generator, and nothing else "
                 f"in this repo proves the kernel was handed real bytes")
    # CsWire.kt's `SecureRandom().nextBytes(bytes)` appears twice in the file - newId() mints identifiers
    # with it too - so the predicate has to be about the function §3 names, not about the line.
    wire = (sdk / "app-android" / "CsWire.kt").read_text(encoding="utf-8")
    minted = wire.split("fun randomHex", 1)[1].split("\n}", 1)[0] if "fun randomHex" in wire else ""
    if "SecureRandom().nextBytes(bytes)" not in minted:
        fail("app-android/CsWire.kt's randomHex - the function the Android host hands the kernel - no longer "
             "draws from SecureRandom; newId() two lines above it may keep using one, but that is an identifier")
    page = (HERE / "chuanshu" / "store" / "session.uts").read_text(encoding="utf-8")
    if "newInbox(pageRand)" not in page:
        fail("store/session.uts arms the Harmony inbox with something other than pageRand - on that platform "
             "the *page* owns the receive inbox, so this is the only place its source can be named")

    tree = root / "mobile" / "chuanshu"
    for path in sorted(tree.glob("**/*.uts")) + sorted(tree.glob("**/*.uvue")):
        if "unpackage" in path.parts or "_archive" in path.parts:
            continue
        if re.search(r"\bnewInbox\(\s*\)", path.read_text(encoding="utf-8")):
            fail(f"{path.relative_to(root)} calls newInbox() with no source - §3's three secrets would come "
                 f"from the empty default, and an empty pair code is a code nobody can type")

    selftest = (root / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    if "def phase_random_source(" not in selftest or \
            re.search(r"^\s+phase_random_source\(proto, workspace\)$", selftest, re.M) is None:
        fail("scripts/protocol_selftest.py has no random-source phase in its run - which hand minted the "
             "three secrets is unmeasured on the tier that can actually run them")
    phase = selftest.split("def phase_random_source", 1)[1].split("\ndef ", 1)[0]
    for literal, why in (
        ("identity_mod.secrets", "the phase patches the module attribute, not the global `secrets` - patching "
                                 "the stdlib would follow the test into every other phase"),
        ("receive_mod.secrets", "the token's source lives in app/net/receive.py, a different namespace from "
                               "identity.py, and a patch on one proves nothing about the other"),
        ("identity_mod.secrets = real_secrets",
         "the patched generator is not handed back - a stub that outlives the phase makes every leg below it "
          "a measurement of the stub"),
        ("receive_mod.secrets = real_receive_secrets",
         "the token's patched generator leaks out of the phase, and the pair legs after it are no longer "
          "about the platform source"),
    ):
        if literal not in phase:
            fail(f"phase_random_source() no longer contains {literal!r} - {why}")

    harness = (sdk / "web" / "index.uts").read_text(encoding="utf-8")
    legs = len(re.findall(r"check\(\s*'§3 (码、密码、token 三样都出自宿主递进来的那一个源|一个字节除不尽 10|除得尽就一个字节也不浪费|没装源的收件箱不发证|换成真源)", harness))
    if legs < 5:
        fail(f"the H5 receiver self-check holds {legs} of the five random-source legs - each is one clause of "
             f"§3's new sentence, and the scripted source is the only way to see which hand minted a secret")


def check_pair_scope(body: dict) -> None:
    """§3 says the throttle does not filter sources by address range - and names where the LAN edge is.

    Round twenty-five (#191) read 「这份失败清单哪一端都不落盘，且只在局域网内可达时开放」. The second half
    of that sentence is a security boundary, and it was not a description of anything: no end looked at the
    range a source address falls in, because all three listeners bind every interface (PC `host=""`, Android
    `InetSocketAddress(port)`, Harmony `0.0.0.0`). The one place in this repo that ever wrote a LAN edge is
    the installer's netsh rule - `profile=any remoteip=LocalSubnet` - and a machine that answered the
    first-listen firewall prompt instead has a rule whose remote IP is *any* on the Public profile, which is
    what this machine measures today. So the paper now states that rule, forbids an address-scope test in a
    pair path, and this guard holds four things: the prose, `transport.note`, the three bind sites plus the
    installer's two flags, and the absence of any range test inside the two pair handlers.
    """
    note = body["transport"].get("note", "")
    for needle, why in (
        ("does NOT filter the source by address range", "the sentence that used to claim the opposite"),
        ("remoteip=LocalSubnet", "the paper now points at the one place a LAN edge is actually written"),
        ("a remote IP of *any* on the Public profile", "the firewall-prompt case: this is why the boundary "
                                                       "is not a property of the protocol"),
    ):
        if needle not in note:
            fail(f"protocol.json's transport.note no longer says {needle!r} - {why}")

    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 3.", 1)[1].split("\n## ", 1)[0] if "## 3." in spec else ""
    # The audit footnotes quote the sentences they delete, so the ban below reads the section without them -
    # a paragraph that starts with a round date is a record of what used to be written, not a rule.
    prose = "\n".join(p for p in section.split("\n\n") if not p.lstrip().startswith("（20"))
    flat = re.sub(r"\s+", "", section)
    if "只在局域网内可达时开放" in re.sub(r"\s+", "", prose):
        fail("§3 says the receiver is only reachable inside a LAN again - three ends bind every interface and "
             "nothing in the code keeps a public source out, so that half-sentence is a boundary nobody holds")
    for needle, why in (
        ("不按地址段筛来源", "the rule round twenty-five wrote in its place, and the one a future host may break"),
        ("都绑在本机所有接口上", "why no end *can* hold the old sentence: the bind is the wildcard on all three"),
        ("远程IP是\"任何\"", "the prompt-allowed rule is on the paper too, so nobody reads LocalSubnet as a promise"),
        ("改的是那条防火墙规则，不是这份合同", "where to tighten reachability - the alternative is a range test in §3"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§3 no longer says {needle!r} - {why}")

    root = HERE.parent
    sdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    recv_py = (root / "app" / "net" / "receive.py").read_text(encoding="utf-8")
    kernel = (sdk / "cs-receive.uts").read_text(encoding="utf-8")
    serve_kt = (sdk / "app-android" / "CsServe.kt").read_text(encoding="utf-8")
    harmony = (sdk / "app-harmony" / "index.uts").read_text(encoding="utf-8")
    for text, name, literal in (
        (recv_py, "app/net/receive.py", 'host: str = ""'),
        (serve_kt, "app-android/CsServe.kt", "srv.bind(InetSocketAddress(port.toInt()))"),
        (harmony, "app-harmony/index.uts", "port: TRANSPORT_PORT, address: '0.0.0.0'"),
    ):
        if literal not in text:
            fail(f"{name} no longer contains {literal!r} - §3 now names the wildcard bind as the reason no end "
                 f"filters by address, so a bind that moved to one interface makes that sentence false")

    scope_test = r"is_private|is_link_local|ip_address\(|subnet_of|in_network|RFC1918|192\.168\.|LocalSubnet|NetworkUtils"
    handler = recv_py.split("def handle_pair", 1)[1].split("\n    def ", 1)[0]
    handler_code = "\n".join(l for l in handler.splitlines() if not l.strip().startswith("#"))
    if re.search(scope_test, handler_code):
        fail("the PC's handle_pair tests which range its source address falls in - §3 forbids that: loopback, "
             "port-forwarded (adb forward, 10.0.2.2) and multi-homed peers all pair through this one body")
    pair_fn = kernel.split("function pairReply(", 1)[1].split("\n}", 1)[0]
    pair_code = "\n".join(l for l in pair_fn.splitlines()
                          if not l.strip().startswith(("//", "*", "/*")))
    if re.search(scope_test, pair_code):
        fail("the shared kernel's pairReply tests the source's address range - one sentence would then split "
             "the phone ends from the PC, and the emulator legs (#149/#154) dial through exactly such a test")

    iss = (root / "installer" / "setup.iss").read_text(encoding="utf-8")
    mint_rule = iss.split("function AllowInbound", 1)[1].split("\nend;", 1)[0] if "function AllowInbound" in iss else ""
    for flag, why in (("profile=any", "the installer rule is only a LAN edge because LocalSubnet bounds it - "
                                      "and profile=any is what keeps a hotspot network usable"),
                      ("remoteip=LocalSubnet", "the paper points here as the one place the boundary is written; "
                                               "if it goes, no layer of this product restricts the range")):
        if flag not in mint_rule:
            fail(f"installer/setup.iss's AllowInbound no longer writes {flag!r} - {why}")
    if iss.count("AllowInbound(ExpandConstant") < 2:
        fail("AllowInbound is not called for both exes - the CLI listens too, and a rule pinned to "
             "ChuanShu.exe only does nothing for ChuanShu-cli.exe (that pairing was measured, not guessed)")

    selftest = (root / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    if "def phase_pair_scope(" not in selftest or \
            re.search(r"^\s+phase_pair_scope\(proto, workspace\)$", selftest, re.M) is None:
        fail("scripts/protocol_selftest.py has no pair-scope phase in its run - which addresses a receiver "
             "answers is the half of §3 that only the tier that pairs can measure")
    phase = selftest.split("def phase_pair_scope", 1)[1].split("\ndef ", 1)[0]
    for literal, why in (
        ("server_address[0]", "the leg has to read back the address the socket really bound, not the string "
                              "the constructor was handed"),
        ("203.0.113", "a TEST-NET source is the only address on this machine that is certainly not a LAN peer, "
                      "and it is what would turn red if someone re-added the filter"),
        ("10.0.2.2", "the emulator's way of reaching this host - the setup §3 says must keep pairing"),
    ):
        if literal not in phase:
            fail(f"phase_pair_scope() no longer contains {literal!r} - {why}")

    harness = (sdk / "web" / "index.uts").read_text(encoding="utf-8")
    legs = len(re.findall(r"check\(\s*'§3 (来源不是一个网段判据|环回、端口转发与读不到地址)", harness))
    if legs < 2:
        fail(f"the H5 receiver self-check holds {legs} of the two pair-scope legs - the kernel takes the source "
             f"as a plain string, so these are the only legs that can feed it an address no LAN socket reports")


def check_optional_secret(body: dict) -> None:
    """§3's two optional pair keys are read off their *value*; the paper used to say "is the key there".

    Round twenty-six (#192) took 「接收方按请求体里有没有这个键决定验哪一条」 and 「`secret` 是可选字段：没有它 =
    旧构建」 as one question - what does 没有它 mean on the wire - and measured three bodies against the two
    bodies that answer them. PC read `tls_fingerprint` by value (`receive.py:554`, so absent, null and "" all
    mean "my leaf is my identity key") but read `secret` by *key presence* (`:609` before this round), while the
    shared kernel has only one reading for it (`cs-receive.uts:877`, `body.get('secret') != null`). A sender that
    serialises its optional field as JSON null - which is what a platform-side encoder does by habit - therefore
    got `403 BAD_PAIR_CODE {reason: "passphrase"}` and lost one of its source's five tries on the PC, and paired
    on the code alone on the phone. The PC was moved to the kernel's reading and the rule is now on the paper in
    both directions: null or absent is absence, and an empty string is a wrong guess - a blank passphrase box must
    never silently downgrade a pair to the 6-digit code, which is the second layer §3 names right after this.
    """
    note = body["transport"].get("note", "")
    for needle, why in (
        ("not by key presence", "the two readings are the finding; without the name on the paper the next host "
                                "picks either"),
        ("`secret` absent or JSON null", "the half that says what absence means, which is what both ends now do"),
        ("an empty string is NOT absence", "the half that keeps a blank passphrase box from downgrading to code-only"),
    ):
        if needle not in note:
            fail(f"protocol.json's transport.note no longer says {needle!r} - {why}")

    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 3.", 1)[1].split("\n## ", 1)[0] if "## 3." in spec else ""
    prose = "\n".join(p for p in section.split("\n\n") if not p.lstrip().startswith("（20"))
    flat = re.sub(r"\s+", "", prose)
    if re.sub(r"\s+", "", "请求体里有没有这个键") in flat:
        fail("§3 says the receiver decides which preimage to verify by whether the key is in the body again - "
             "no end reads it that way: both take the value, and a body whose key carries null or \"\" is \"no leaf\"")
    for needle, why in (
        ("这一格有没有值", "the sentence that replaces it, and the one the two pair bodies implement"),
        ("键不在，或者值是null", "absence has a definition now, because the two ends disagreed about it in code"),
        ("空串不是\"没有它\"", "the deliberate other half: a blank field is a wrong guess, not a legacy sender"),
        ("常量时间比较", "§3 names how the value is compared, so a `==` on a secret would not pass as 逐字相等"),
        ("直接省略这个键", "the sender-side rule that the receiving rule above is built around"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§3 no longer says {needle!r} - {why}")

    root = HERE.parent
    sdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    recv_py = (root / "app" / "net" / "receive.py").read_text(encoding="utf-8")
    send_py = (root / "app" / "net" / "send.py").read_text(encoding="utf-8")
    kernel = (sdk / "cs-receive.uts").read_text(encoding="utf-8")
    proto_uts = (sdk / "cs-protocol.uts").read_text(encoding="utf-8")

    handler = recv_py.split("def handle_pair", 1)[1].split("\n    def ", 1)[0]
    handler_code = "\n".join(l for l in handler.splitlines() if not l.strip().startswith("#"))
    if re.search(r'["\']secret["\']\s+in\s+body', handler_code):
        fail("the PC's handle_pair decides the passphrase by whether the key is in the body - that is the reading "
             "§3 retired: a sender that writes its optional field as null would spend one of five tries and get "
             "a different answer than the phone kernel gives the same bytes")
    for literal, why in (
        ('offered = body.get("secret")', "absence is read off the value, which is the kernel's one reading"),
        ("if offered is not None and not hmac.compare_digest(str(offered), self.passphrase()):",
         "the whole rule on one line: null pairs on the code alone, \"\" is a wrong guess, compared without "
         "short-circuiting"),
        ('str(body.get("tls_fingerprint") or "")', "§3 reads the leaf key the same way, and this is the line that "
                                                   "makes a body carrying null or \"\" mean \"my leaf is my key\""),
    ):
        if literal not in handler:
            fail(f"handle_pair no longer contains {literal!r} - {why}")

    pair_fn = kernel.split("function pairReply(", 1)[1].split("\n}", 1)[0]
    if "body.get('secret') != null" not in pair_fn:
        fail("the shared kernel no longer reads the passphrase with body.get('secret') != null - that is the "
             "reading §3 settled on, and the PC was moved to it, so a kernel that changes would split the ends again")
    matches = kernel.split("function secretMatches(", 1)[1].split("\n}", 1)[0] if "function secretMatches" in kernel else ""
    for literal, why in (
        ("diff = diff | (ca! ^ cb!)", "the non-short-circuit compare §3 calls 常量时间比较"),
        ("return diff == 0", "the answer comes out of the whole string, not out of the first difference"),
    ):
        if literal not in matches:
            fail(f"secretMatches no longer contains {literal!r} - {why}")
    if re.search(r"if\s*\(\s*ca\s*!=\s*cb\s*\)", matches):
        fail("secretMatches short-circuits on the first differing character - §3 promised a constant-time compare")

    pair_sender = send_py.split("def pair(", 1)[1].split("\n    def ", 1)[0] if "def pair(" in send_py else ""
    if 'if secret:\n            request["secret"] = secret' not in pair_sender:
        fail("the PC sender no longer omits an empty secret (if secret: / request[\"secret\"]) - §3 says a blank "
             "field must not go on the wire, because every receiver that keeps the passphrase concept reads it as "
             "one wrong guess")
    mint = proto_uts.split("export function pairJson(", 1)[1].split("\n}", 1)[0] if "export function pairJson" in proto_uts else ""
    if "if (secret.length > 0)" not in mint or "body['secret'] = secret" not in mint:
        fail("the shared sender no longer omits the secret key when the field is empty - the same rule as the PC's, "
             "on the half that three phone hosts compile")

    selftest = (root / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    if "def phase_optional_secret(" not in selftest or \
            re.search(r"^\s+phase_optional_secret\(proto, workspace\)$", selftest, re.M) is None:
        fail("scripts/protocol_selftest.py has no optional-secret phase in its run - what a receiver reads as "
             "absence is a fact about the pair path, and only the tier that pairs can measure it")
    phase = selftest.split("def phase_optional_secret", 1)[1].split("\ndef ", 1)[0]
    for literal, why in (
        ('if secret_slot is not _ABSENT:', "absence on these legs means the key is left off - so the null and "
                                           "blank legs really put a value on the wire, which is the whole question"),
        ('body["secret"] = secret_slot', "the slot is written verbatim: a JSON null and an empty string must reach "
                                         "the handler as those exact bytes, not be filtered on the way"),
        ("_code_failures", "the leg has to read the bucket, not just the code - burning a try is half the harm"),
    ):
        if literal not in phase:
            fail(f"phase_optional_secret() no longer contains {literal!r} - {why}")

    harness = (sdk / "web" / "index.uts").read_text(encoding="utf-8")
    legs = len(re.findall(r"check\(\s*'§3 (这一格的 null 算没有它|空串不是没有它|这一格空不空)", harness))
    if legs < 3:
        fail(f"the H5 receiver self-check holds {legs} of the three optional-key legs - the kernel is the end "
             f"whose reading the PC was moved to, and only this tier can hand it a body no sender of ours writes")


def check_session_release() -> None:
    """§3's three ways back into the one-session slot: the paper named them, PC had them, the phone had one.

    Round twenty-seven (#193) read 「三条路都会释放这个名额」 against the bodies that answer 断开 and 不再监听.
    The idle window was on all three ends (PC's ``sweep``, the kernel's ``sweep``), and 「接收服务重启」 was true
    on the PC for a reason nobody had written down - ``stop_listening`` drops the whole receiver object, token map
    included - while a phone keeps its inbox *beside* the listener, so closing the port released nothing. And
    「持有方点「断开」」 on a phone only ever gave back the half it took by dialling out (`receiveHoldSlot('')`),
    leaving the token handed to whoever dialled *in* to rot until the idle clock ran out. The kernel has
    ``releaseSession``/``releaseSessions`` now and both call sites use them; the PC's ``release()`` was moved to
    the same question - "did this peer hold the slot", which an outbound-only peer does through ``_held_by``
    alone - so the two ends answer the same way instead of answering two different questions.
    """
    note = json.loads((CONTRACT / "protocol.json").read_text(encoding="utf-8-sig"))["transport"].get("note", "")
    for needle, why in (
        ("three named events on every end", "the sentence is about every end; without it the next host "
                                            "implements whichever half its own platform happens to drop"),
        ("takes back BOTH halves", "one tap gives up the peer this end dialled and the token it handed a "
                                   "stranger that dialled in - the half the phone used to leave behind"),
        ("a phone's inbox outlives the listener", "why 不再监听 has to release by name instead of getting it "
                                                  "for free the way PC's stop_listening does"),
        ("Releasing a session is not revoking trust", "the boundary between this round and 撤销: the pin stays, "
                                                      "so the released peer returns on its signature alone"),
        ("a phone shows that button only for a peer it dialled out to", "the phone's 断开 is bound to s.connected, "
                                                                       "so the peer that only dialled in has no "
                                                                       "button on this end and the paper has to say "
                                                                       "which road it waits for instead"),
    ):
        if needle not in note:
            fail(f"protocol.json's transport.note no longer says {needle!r} - {why}")

    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 3.", 1)[1].split("\n## ", 1)[0] if "## 3." in spec else ""
    prose = "\n".join(p for p in section.split("\n\n") if not p.lstrip().startswith("（20"))
    flat = re.sub(r"\s+", "", prose)
    if re.sub(r"\s+", "", "持有方点「断开」、接收服务重启") in flat:
        fail("§3 lumps the three releases back into one comma-separated clause again - that is the wording that "
             "let three ends read one sentence as two rules: the idle window and PC's drop-the-object were real, "
             "the phone's 断开 and 不再监听 were not")
    for needle, why in (
        ("三条路都会释放这个名额", "the claim this round measured, and the reason the three are enumerated apart"),
        ("两边收回的都是", "PC and the phone give back the same thing when 断开 is pressed"),
        ("本机拨出去时登记的那一格，和对方拨进来时发给它收件箱的那枚 token",
         "the two halves named one by one, which is what releaseSession answers in one call"),
        ("二是接收服务重启，手机上就是「不再监听」", "the trigger is named per end, because only PC gets it by "
	                                              "dropping the object"),
        ("所以关端口这一趟要按名字把名额请出去", "the rule the phone had no body for until this round"),
        ("三是这台设备连续", "the third road, the one all three ends already walked"),
        ("本机没有「断开」可点，那一半只能等第二条或第三条路", "the phone's 断开 reads s.connected, which only "
                                                            "holds for a peer this end dialled - the one-way "
                                                            "inbound case has no button here, and saying so beats "
                                                            "shipping one this round"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§3 no longer says {needle!r} - {why}")
    starts, stops = flat.find("手机是传输详情"), flat.find("二是接收服务重启")
    qualified = flat.find("本机没有「断开」可点")
    if not (-1 < starts < qualified < stops):
        fail("§3's phone-button clause no longer carries its own qualification (it has to sit inside the 断开 road, "
             "between 「手机是传输详情」 and 「二是接收服务重启」) - a reader who meets the enumeration first and the "
             "exception several sentences later reads the tap as available on every peer")

    root = HERE.parent
    sdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    recv_py = (root / "app" / "net" / "receive.py").read_text(encoding="utf-8")
    ui = (root / "app" / "ui" / "transfer.py").read_text(encoding="utf-8")
    kernel = (sdk / "cs-receive.uts").read_text(encoding="utf-8")
    harness = (sdk / "web" / "index.uts").read_text(encoding="utf-8")
    android = (sdk / "app-android" / "index.uts").read_text(encoding="utf-8")
    store = (HERE / "chuanshu" / "store" / "session.uts").read_text(encoding="utf-8")

    release = recv_py.split("def release(", 1)[1].split("\n    def ", 1)[0] if "def release(" in recv_py else ""
    for literal, why in (
        ("had_token = self._tokens.pop(fingerprint, None) is not None", "the inbound half, by name"),
        ("had_slot = self._held_by == fingerprint", "the half this machine took by dialling out - the question "
                                                    "断开 asks at both doors"),
        ("if had_token or had_slot:", "one answer for either half, which is the kernel's shape the PC was "
                                      "moved to this round"),
    ):
        if literal not in release:
            fail(f"ReceiveService.release() no longer contains {literal!r} - {why}")
    if re.search(r"^\s*return had_token$", release, re.M):
        fail("PC's release() answers only whether a token was handed out - a peer this machine dialled holds the "
             "slot through _held_by and would be told it was occupying nothing")
    for caller, where in (("def _disconnect_selected", "the device card's 断开"), ("def forget", "settings' 撤销")):
        body = ui.split(caller, 1)[1].split("\n    def ", 1)[0] if caller in ui else ""
        if "self._receiver.release(" not in body:
            fail(f"{caller.replace('def ', '')} in transfer.py no longer calls the receiver's release() - "
                 f"{where} would leave the "
                 f"inbound peer sending chunks against a session the user believes is closed")
    repaint = ui.split("def _refresh_peers", 1)[1].split("\n    def ", 1)[0] if "def _refresh_peers" in ui else ""
    if "self._receiver.hold_slot_for(self._connected[0].fingerprint if len(self._connected) == 1 else \"\")" not in repaint:
        fail("the PC roster no longer repaints the receiver's outbound half of the slot - 断开 on a peer this "
             "machine dialled gives that half back from here, not from release()")

    one = kernel.split("export function releaseSession(", 1)[1].split("\n}", 1)[0] \
        if "export function releaseSession(" in kernel else ""
    for literal, why in (
        ("if (inbox.tokens[i].fingerprint == fingerprint) {", "the inbound half, taken back by name"),
        ("if (inbox.heldBy == fingerprint) {", "and the half this device took by dialling out"),
        ("return held", "the answer is \"this peer held the slot\", the same question PC's release() answers"),
    ):
        if literal not in one:
            fail(f"cs-receive.uts's releaseSession() no longer contains {literal!r} - {why}")
    if "trusted" in one:
        fail("releaseSession touches the trust store - §3 says 释放不等于撤销: the released peer must still be "
             "able to return with an empty pair code on its signature alone")
    many = kernel.split("export function releaseSessions(", 1)[1].split("\n}", 1)[0] \
        if "export function releaseSessions(" in kernel else ""
    for literal, why in (
        ("const who = activePeers(inbox)", "the same list the slot is counted from, so both halves go"),
        ("return who.length", "关端口 has to say how many it cleared, which is what the log line counts on"),
    ):
        if literal not in many:
            fail(f"cs-receive.uts's releaseSessions() no longer contains {literal!r} - {why}")

    hosts = {
        "web": (harness, "\treturn releaseSession(recvInbox, fingerprint)", "\treturn releaseSessions(recvInbox)"),
        "app-android": (android, "released = releaseSession(recvInbox, fingerprint)", "taken = releaseSessions(recvInbox)"),
    }
    for name, (text, inbound, release_all) in hosts.items():
        body = text.split("export function receiveRelease(", 1)[1].split("\n}", 1)[0] \
            if "export function receiveRelease(" in text else ""
        if inbound not in body:
            fail(f"{name}/index.uts's receiveRelease() no longer calls the kernel's releaseSession with "
                 f"{inbound!r} - a host that does not answer the slot question is the half this round added")
        all_body = text.split("export function receiveReleaseAll(", 1)[1].split("\n}", 1)[0] \
            if "export function receiveReleaseAll(" in text else ""
        if release_all not in all_body:
            fail(f"{name}/index.uts's receiveReleaseAll() no longer calls releaseSessions with {release_all!r} "
                 f"- 不再监听 on this end would close the port and leave the old peer holding the slot")

    harmony_local = store.split("function receiveRelease(fingerprint: string): boolean {", 1)[1].split("\n}", 1)[0] \
        if "function receiveRelease(fingerprint: string): boolean {" in store else ""
    if "return releaseSession(recvInbox, fingerprint)" not in harmony_local:
        fail("session.uts's Harmony-local receiveRelease() no longer wraps the kernel's releaseSession - 鸿蒙 "
             "cannot import the module entry, so this copy is the only one its 断开 has")
    if "receiveReleaseAll(): number" not in store or "return releaseSessions(recvInbox)" not in store:
        fail("session.uts has no Harmony-local receiveReleaseAll() over releaseSessions - the platform that "
             "started this round would still have a 不再监听 that releases nothing")
    disc = store.split("export function onDisconnect()", 1)[1].split("\n}", 1)[0] \
        if "export function onDisconnect()" in store else ""
    if "receiveRelease(session.peerFingerprint)" not in disc:
        fail("the phone's onDisconnect() no longer releases this peer's session - that is §3's first trigger, and "
             "before #193 the tap only ever gave back the half this end dialled")
    stopper = store.split("export function onRecvListenStop()", 1)[1].split("\n}", 1)[0] \
        if "export function onRecvListenStop()" in store else ""
    if "receiveReleaseAll()" not in stopper:
        fail("the phone's 不再监听 no longer releases the sessions beside the port it closes - a phone's inbox "
             "outlives its listener, so this is the only place that half can be given back")
    imported = store.split("import { receiveRelease, receiveReleaseAll }", 1)
    if len(imported) != 2 or "#ifdef APP-ANDROID || WEB" not in imported[0].rsplit("#endif", 1)[-1]:
        fail("the #ifdef above the phone's receiveRelease import no longer names APP-ANDROID || WEB - iOS is "
             "terminated and 鸿蒙 defines the wrappers locally, so an import list that changes would either "
             "compile nothing or break the Harmony build")

    selftest = (root / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    if "def phase_session_release(" not in selftest or \
            re.search(r"^\s+phase_session_release\(proto, workspace\)$", selftest, re.M) is None:
        fail("scripts/protocol_selftest.py has no session-release phase in its run - the slot is a fact about "
             "the pair path, and only the tier that pairs can measure it")
    phase = selftest.split("def phase_session_release", 1)[1].split("\ndef ", 1)[0]
    for literal, why in (
        ("service.hold_slot_for(fp_of(dialled))", "the outbound half has no token, so this is the only way to "
                                                  "put it on the slot and ask release() about it"),
        ("held is True and service.active_peers() == []", "the answer the PC was moved to: a peer this machine "
                                                          "dialled did hold the slot"),
        ("resumed[2] is True", "释放不等于撤销, measured as the reply's own flag rather than as a wish"),
        ("restarted._tokens == {}", "§3's 「接收服务重启」 on PC is a fresh receiver, so the old token has to "
                                    "answer nothing"),
    ):
        if literal not in phase:
            fail(f"phase_session_release() no longer contains {literal!r} - {why}")

    legs = len(re.findall(r"check\('§3 (释放自检摆好格子|一台手机的两半|本机拨出去那一半|没占着名额的那一台|"
                          r"持有方点「断开」这一趟|被请出去的那台带旧 token|释放不等于撤销|「不再监听」按名字)", harness))
    if legs < 8:
        fail(f"the H5 receiver self-check holds {legs} of the eight release legs - the kernel is the body this "
             f"round added, and this is the only tier that runs it as the three phone platforms will")


def main() -> int:
    stamp_path = CONTRACT / "SOURCE.json"
    for name in ("protocol.json", "spec.md", "SOURCE.json"):
        if not (CONTRACT / name).is_file():
            fail(f"{CONTRACT / name} is missing - re-copy it from chuanshu-pc/protocol/")

    stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
    for name, digest in stamp["files"].items():
        actual = hashlib.sha256((CONTRACT / name).read_bytes()).hexdigest()
        if actual != digest:
            fail(f"{name} does not match its stamp ({actual[:12]} != {digest[:12]}) - it was edited here, fix it upstream")

    body = json.loads((CONTRACT / "protocol.json").read_text(encoding="utf-8-sig"))
    missing = REQUIRED_KEYS - set(body)
    if missing:
        fail(f"protocol.json lacks {sorted(missing)}")
    if body["protocol_version"] != stamp["protocol_version"]:
        fail("the stamp says one protocol version, protocol.json says another")

    for code, entry in body["error_codes"].items():
        if not isinstance(entry.get("http"), int) or not 100 <= entry["http"] < 600:
            fail(f"error code {code} has no sane http status")
        if not entry.get("msgid"):
            fail(f"error code {code} has no msgid")
    for endpoint in body["endpoints"]:
        if not endpoint.get("method") or not endpoint.get("path"):
            fail(f"endpoint {endpoint} is incomplete")

    discovery = body["discovery"]
    if not {"mdns", "udp", "qr"} <= set(discovery["channels"]):
        fail(f"discovery must offer all three escape routes, found {discovery['channels']}")
    for field_list in ("mdns_txt_fields", "udp_payload_fields"):
        if "fp" not in discovery[field_list]:
            fail(f"{field_list} must advertise the fingerprint prefix")
    if not 1 <= int(discovery["announce_interval_s"]) <= 10:
        fail("announce_interval_s outside 1-10s: too slow to notice, too loud to keep")
    if not 8 <= int(discovery["fingerprint_prefix_chars"]) <= 32:
        fail("the advertised prefix must be short enough to notice a collision but not an anchor")

    chunk = body["transport"]["chunk_size"]
    if not 2**20 <= chunk <= 2**26:
        fail(f"chunk_size {chunk} is outside the 1 MiB - 64 MiB range v1 allows")

    digits = int(body["transport"]["pair_code_digits"])
    if not 4 <= digits <= 12:
        fail(f"pair_code_digits {digits}: long enough to be a one-time key, short enough to type")
    ttl = int(body["transport"]["pair_code_ttl_s"])
    if not 30 <= ttl <= 600:
        fail(f"pair_code_ttl_s {ttl}: a code that outlives the glance at the screen is no code at all")

    check_pair_throttle(body)
    check_random_source(body)
    check_pair_scope(body)
    check_optional_secret(body)
    check_uts_mirror(body)
    check_limits_in_prose(body)
    check_error_table(body)
    check_hello_features(body)
    check_endpoint_count(body)
    check_pair_code_digits(body)
    check_identity_files()
    check_peer_id_shape()
    check_spki_head()
    check_freeze_gate()
    check_sender_limit()
    check_hidden_segments()
    check_manifest_fields()
    check_finalize_reply()
    check_offer_reply_shapes()
    check_chunk_reply()
    check_finalize_replay()
    check_session_release()

    print(f"OK  protocol v{body['protocol_version']} from {stamp['source_repo']}@{stamp['source_commit'][:8]}")
    print(f"OK  {len(body['error_codes'])} error codes, {len(body['endpoints'])} endpoints, chunk {chunk // 1024} KiB")
    print(f"OK  pair code: {digits} digits, {ttl}s each"
          + (", fixed until rotated by hand" if body["transport"]["pair_code_static"] else "")
          + f", {body['transport']['passphrase_chars']}-char passphrase")
    print(f"OK  §3's throttle is one sliding window in four places: {body['transport']['pair_code_max_fails']} "
          f"failures per source, {body['transport']['pair_code_lock_s']}s each, in memory only")
    print("OK  §3's three secrets are minted by the host's generator on all five ends; the kernel asks, the "
          "hosts answer, and a byte that does not divide the alphabet is thrown away instead of bent")
    print("OK  §3 pairs whoever knocks: three ends bind the wildcard, no pair path tests the source's range, "
          "and the LAN edge is the installer's remoteip=LocalSubnet rule rather than a line of this contract")
    print("OK  §3's two optional pair keys are read off their value on both ends: null is absence and pairs on "
          "the code alone, an empty string is a wrong guess, and neither sender writes a blank secret to the wire")
    print("OK  §3's one-session slot is given back by all three roads on every end: 断开 takes both halves by "
          "name, 不再监听 clears the sessions that outlived the port, and the idle window still sweeps alone")
    print("OK  vendored copies match their stamps")
    print("OK  cs-protocol.uts mirrors the contract")
    print("OK  §5 names every limit a receiver refuses a transfer on")
    print(f"OK  cs-receive.uts and cs-protocol.uts restate all {len(body['error_codes'])} codes with the contract's numbers and words")
    print(f"OK  hello's capability list is one copy: {body['transport']['hello_features']}")
    print(f"OK  §8 counts the relay branch's endpoints the way protocol.json defines them ({len(body['endpoints'])})")
    print(f"OK  every digit count in the contract prose says {body['transport']['pair_code_digits']}")
    print("OK  §1 names only files an end actually opens")
    print("OK  peer_id is 16 random bytes of hex where all four places mint it")
    print("OK  the three ends hand-spell the same 12-byte Ed25519 SPKI header")
    print("OK  §9's gate names a script that exists, reads as runnable on both PC platforms, and has legs on both ends")
    print("OK  §5's sender-side limit has a body in every sender: PC plan()/offer(), the phone's client, both screens")
    print("OK  §5's dot rule is per segment on the senders too: PC plan() checks both paths, the phone asks pathReject")
    print("OK  §4's manifest block is the wire: both senders' keys, and no receiver acts on total_size")
    print("OK  §4's finalize reply is one shape on paper and in both receivers; `missing` is who both senders resend by")
    print("OK  §4's three offer replies are one shape on paper and in all four bodies; the abort knows the question still open")
    print("OK  §4's chunk replies are one shape on paper and in all four bodies; three writes, two names, one budget")
    print("OK  §4's re-posted finalize: a second pass on both senders, and one announcement per landing on both receivers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
