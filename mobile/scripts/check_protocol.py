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
    splice = harness.split("function pairBodySlots(", 1)[1].split("\n}", 1)[0] \
        if "function pairBodySlots(" in harness else ""
    if 'body = head + key + secretRaw + tail' not in splice:
        fail("pairBodySlots() no longer pastes the key name back before the raw slot - `mark` covers the whole "
             "`\"secret\":\"…\"` entry, so writing just `null` where it was leaves `…\"code\":\"421376\",null}` on the "
             "wire. The receiver then answers 「body is not a JSON object」 and burns no try, which is a reading of "
             "the splice rather than of §3: this is what the two null legs did for the five rounds nobody ran "
             "this tier, and a leg that can only be red has been guarding nothing the whole time")
    for literal, why in (
        ("' 送出的体 ' + nullBodyB", "the null leg prints the bytes it sent, not only the answer, so a splice that "
                                   "broke is visible in the red line itself"),
        ("' 送出的体 ' + blankBodyC", "and the blank leg the same - these two are the only legs in the file that hand "
                                   "the kernel a body our own sender could never mint"),
    ):
        if literal not in harness:
            fail(f"the optional-key legs no longer contain {literal!r} - {why}")


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
    if "const relActiveAfter = activePeers(rel).length" not in harness:
        fail("the 「不再监听」 leg reads the slot list again after the next peer has already paired, so the "
             "predicate is asking 「名额空了没有」 at the moment the slot is occupied again - that leg was red on "
             "the first run of this tier and it was red about its own order, not about releaseSessions(). Read "
             "it into a name before the next trip, as #193's leg now does")
    if "relTakenAll == 2 && activePeers(rel).length == 0" in harness:
        fail("the 「不再监听」 leg is back to counting the slot list inside the predicate - `relNext` pairs before "
             "the check() arguments are evaluated, so this can only ever be red")


def check_lost_registration() -> None:
    """§3's last clause: the peer this machine dialled is timed by its own sender, and the timeout registers as 已断开.

    Round twenty-eight (#194) found the clock running and the registration dead. Both ends keep the outbound
    half's stamp from the sender (`seenNow` / ``ReceiveService.seen``), and both sweeps do reclaim the slot -
    but the shared kernel only told the page *a name*, and the page compared it to the name ``hello`` had
    carried into the send session. Those are two different strings for exactly the peer this sentence is about:
    a device that only ever dialled out has no entry in its own inbox, so ``nameFor`` answers with the
    「对端 <fp8>…」 fallback and the `if` never fires - the card goes on promising 已连接 after the slot has
    been handed to a stranger. PC had it right for the reason the contract cannot see: ``on_lost`` carries the
    fingerprint and the name is only ever used to paint the sentence. The kernel now carries both numbers, and
    the page asks the number.
    """
    note = json.loads((CONTRACT / "protocol.json").read_text(encoding="utf-8-sig"))["transport"].get("note", "")
    for needle, why in (
        ("which also registers the loss", "the reclaim is not only a slot event: §3 says the sender also has to "
                                         "see the session go, and that half was the one missing on the phone"),
        ("by fingerprint, never by a display string", "the key of that registration - the display string is two "
                                                     "different texts depending on which side of the dial you are on"),
        ("the name hello carried", "why the sender's own word cannot be matched against the receiver's inbox"),
    ):
        if needle not in note:
            fail(f"protocol.json's transport.note no longer says {needle!r} - {why}")

    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 3.", 1)[1].split("\n## ", 1)[0] if "## 3." in spec else ""
    prose = "\n".join(p for p in section.split("\n\n") if not p.lstrip().startswith("（20"))
    flat = re.sub(r"\s+", "", prose)
    for needle, why in (
        ("本机拨出去的那台由发起方自己计时，超时同样登记为已断开", "the sentence this round measured - the clock is "
                                                              "the sender's own, and its expiry is a registration, "
                                                              "not only a release"),
        ("登记这一步认的还是那个", "the clause that says what the registration is keyed by; without it the next "
                                "implementation is free to compare display strings again"),
        ("两边从来不是同一串字", "the reason the two names cannot be the key: one came from hello, the other from "
                              "the receiver's own pin entry"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§3 no longer says {needle!r} - {why}")
    timed, keyed = flat.find("超时同样登记为已断开"), flat.find("登记这一步认的还是那个")
    if not (-1 < timed < keyed):
        fail("§3's keying clause no longer follows the sentence it qualifies - read on its own it is a promise "
             "about some other registration, and the sentence above it stays ambiguous")

    root = HERE.parent
    sdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    kernel = (sdk / "cs-receive.uts").read_text(encoding="utf-8")
    harness = (sdk / "web" / "index.uts").read_text(encoding="utf-8")
    store = (HERE / "chuanshu" / "store" / "session.uts").read_text(encoding="utf-8")
    recv_py = (root / "app" / "net" / "receive.py").read_text(encoding="utf-8")
    ui = (root / "app" / "ui" / "transfer.py").read_text(encoding="utf-8")

    if kernel.count("lostFp: string") != 2:
        fail("the kernel no longer declares lostFp in both places (the inbox and the snapshot) - a page can only "
             "register by fingerprint if the snapshot carries one")
    if kernel.count("inbox.lostFp =") != kernel.count("inbox.lostName ="):
        fail(f"lostFp is written or cleared in {kernel.count('inbox.lostFp =')} places against lostName's "
             f"{kernel.count('inbox.lostName =')} - the two are one fact about the same peer, and a stale number "
             f"next to a fresh name is how a card ends up disconnecting the wrong session")
    swept = kernel.split("export function sweep(", 1)[1].split("\n\tfor (let i = inbox.offers.length - 1", 1)[0] \
        if "export function sweep(" in kernel else ""
    for literal, why in (
        ("inbox.lostFp = entry.fingerprint", "the inbound half of the reclaim says who left, by number"),
        ("inbox.lostFp = stalled", "and the half this device took by dialling out - the one this sentence is about"),
    ):
        if literal not in swept:
            fail(f"cs-receive.uts's sweep() no longer contains {literal!r} - {why}")
    if "out.lostFp = inbox.lostFp" not in kernel:
        fail("snapshot() no longer copies the reclaimed peer's fingerprint out of the inbox - the page never sees "
             "the number, which is the state this round found the phone in")

    if re.search(r"snap\.lostName\s*==\s*s\.peerName", store):
        fail("session.uts registers the idle reclaim by comparing the kernel's display name to the send session's "
             "peerName - that is the shape #194 measured dead: the peer this phone only dialled out to has no "
             "name in the inbox, so the two strings never match and the card keeps saying 已连接")
    register = store.split("if (s.connected && snap.lostFp", 1)[1].split("\n\t}", 1)[0] \
        if "if (s.connected && snap.lostFp" in store else ""
    if "snap.lostFp == held!.peerFingerprint" not in register or "onDisconnect()" not in register:
        fail("the phone's registration no longer runs the session down by fingerprint inside the same branch "
             "that calls onDisconnect() - the reclaim would go back to being a slot event nobody reports")
    if "const held = activeSession" not in store:
        fail("the phone reads the live session out of `activeSession` before comparing it, and that line is gone - "
             "a store field copied from hello is the display-string path this round removed")

    if "on_lost=self._peer_lost.emit" not in ui:
        fail("the PC panel no longer wires the receiver's on_lost into its roster - §3's 「超时同样登记为已断开」 "
             "on this end is that one signal")
    lost_body = ui.split("def _on_peer_lost", 1)[1].split("\n    def ", 1)[0] if "def _on_peer_lost" in ui else ""
    if "peer.fingerprint == fingerprint" not in lost_body or "self.forget(fingerprint)" not in lost_body:
        fail("_on_peer_lost no longer finds the roster row by fingerprint and drops it - the name is for the "
             "status line only, which is the shape the phone was moved to this round")
    seen_py = recv_py.split("def sweep(self)", 1)[1].split("\n    def ", 1)[0] if "def sweep(self)" in recv_py else ""
    if "self.on_lost(fingerprint)" not in seen_py:
        fail("ReceiveService.sweep() no longer reports each reclaimed session to the UI - the slot goes back "
             "silently and the screen keeps promising a connection nobody is holding")

    selftest = (root / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    phase = selftest.split("def phase_session_release", 1)[1].split("\ndef ", 1)[0]
    for literal, why in (
        ("service.on_lost = lost.append", "the gate's PC leg has to watch the registration, not just the release"),
        ("swept == [fp_of(dialled)] and lost == [fp_of(dialled)]", "and it has to expect a fingerprint there, "
                                                                  "because that is all the receiver has"),
        ("service.sweep() == [] and lost == [fp_of(dialled)]", "the registration is one-shot; a second sweep may "
                                                              "not report the same peer again"),
    ):
        if literal not in phase:
            fail(f"phase_session_release() no longer contains {literal!r} - {why}")

    new_legs = len(re.findall(r"check\('§3 (只拨出去过的那台也算占着名额|发起方自己的心跳就是这一格的动静|"
                              r"沉默满窗口后收回这一格|同一趟的名字量不出这件事|下一次拨出把这一格清干净)", harness))
    if new_legs < 5:
        fail(f"the H5 receiver self-check holds {new_legs} of the five idle-registration legs - the kernel is the "
             f"only body for this clause on the phone, and this is the tier that runs the kernel")


def check_pair_shape_local() -> None:
    """§3's other half of the two secrets: a hand-typed `c`/`k` is measured for shape before it goes on the wire.

    Round twenty-nine (#195) took the sentence 「旧的当场作废」 and found all three ends doing it - so what this
    guard holds open is the clause written next to it. The receiver's only use for these two strings is equality,
    which makes a 7th digit or a lowercase letter a *wrong guess* rather than a weaker promise: it spends one of
    `pair_code_max_fails` marks booked against this source, and the person locked out is whoever pairs next. Before
    this round PC measured nothing (the fields' max length caps digits but not letters, and both entry points asked
    only "is it blank"), and the kernel's pairing-string parser asked about the code *or* the passphrase - never
    both - so every QR payload, which always carries `c`, had an unmeasured `k`.
    """
    note = json.loads((CONTRACT / "protocol.json").read_text(encoding="utf-8-sig"))["transport"].get("note", "")
    for needle, why in (
        ("Shape is asked of a value a person typed or pasted", "the clause this round added - without it the paper "
                                                             "only says what a receiver does with a wrong guess"),
        ("the kernel's pairing-string parser asks both fields rather than one of them", "the else-if that made `k` "
                                                                                        "unmeasurable on the scan path "
                                                                                        "is now part of the contract"),
        ("says why locally and sends nothing", "the promised shape of the refusal: this end speaks, the wire stays quiet"),
    ):
        if needle not in note:
            fail(f"protocol.json's transport.note no longer says {needle!r} - {why}")

    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 3.", 1)[1].split("\n## ", 1)[0] if "## 3." in spec else ""
    prose = "\n".join(p for p in section.split("\n\n") if not p.lstrip().startswith("（20"))
    flat = re.sub(r"\s+", "", prose)
    for needle, why in (
        ("人手抄进来或粘进来的`c`与`k`", "the sentence's subject is what a person typed, not what a QR carried - "
                                    "that is the path with typos on it"),
        ("一次请求都不发", "the refusal is local: a sender that could never match does not reach the peer's bucket"),
        ("`k`留空不在这一问里", "blank is the shape of「没有这个字段」, so measuring it here would turn an honest "
                          "answer into a refusal"),
        ("都不是一次更弱的承诺", "why this is a quota question and not an input-hygiene question - the reason the "
                          "contract states it rather than leaving it to taste"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§3 no longer says {needle!r} - {why}")

    root = HERE.parent
    sdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    spec_py = (root / "app" / "net" / "spec.py").read_text(encoding="utf-8")
    ident_py = (root / "app" / "net" / "identity.py").read_text(encoding="utf-8")
    ui = (root / "app" / "ui" / "transfer.py").read_text(encoding="utf-8")
    cli = (root / "app" / "cli.py").read_text(encoding="utf-8")
    kernel = (sdk / "cs-protocol.uts").read_text(encoding="utf-8")
    harness = (sdk / "web" / "index.uts").read_text(encoding="utf-8")
    store = (HERE / "chuanshu" / "store" / "session.uts").read_text(encoding="utf-8")

    for literal, why in (
        ("def code_reject(code: str, proto: Protocol) -> str:", "the code's shape question, asked of the contract's "
                                                                "own numbers"),
        ("def pass_reject(secret: str, proto: Protocol) -> str:", "and the passphrase's - blank answers it, a typed "
                                                                  "string does not"),
        ('if not secret:\n        return ""', "the blank half has to stay open: §3 reads an absent key as「没有这个字段」"),
        ("PASSPHRASE_ALPHABET = \"ABCDEFGHJKLMNPQRSTUVWXYZ23456789\"",
         "the one table both the minting side and the refusing side read"),
        ("from app.i18n import _", "the refusals are sentences a person reads, so they go through the catalogue"),
    ):
        if literal not in spec_py:
            fail(f"app/net/spec.py no longer contains {literal!r} - {why}")
    if "PASSPHRASE_ALPHABET = \"ABCDEFGHJKLMNPQRSTUVWXYZ23456789\"" in ident_py:
        fail("app/net/identity.py defines the passphrase alphabet again - two tables means the machine that mints a "
             "secret can refuse the same secret, which is the failure this clause exists to prevent; read it from "
             "app.net.spec")
    if "from app.net.spec import PASSPHRASE_ALPHABET" not in ident_py or \
            "secrets.choice(PASSPHRASE_ALPHABET)" not in ident_py:
        fail("identity.py no longer mints the passphrase from the contract's single alphabet - the minting side has "
             "to read the table the refusing side measures against")

    connect = ui.split("def _start_connect(self)", 1)[1].split("\n    def ", 1)[0] if "def _start_connect(self)" in ui else ""
    for literal, why in (
        ('protocol_spec.code_reject(code, self.proto) if code else ""', "the panel asks the code's shape, and only "
                                                                        "when there is one to ask about"),
        ("protocol_spec.pass_reject(", "and the passphrase's"),
        ("if why:\n            self.status_label.setText(why)\n            return", "the answer goes on this page, "
                                                                                     "before the thread starts"),
    ):
        if literal not in connect:
            fail(f"_start_connect() no longer contains {literal!r} - {why}")
    if "args=(peer, code, self.secret_edit.text().strip())" in connect:
        fail("the connect thread reads the passphrase field again instead of the measured `secret` - a value that "
             "went to the wire without being asked about is the state §3's new clause refuses")

    send = cli.split("def cmd_send(", 1)[1].split("\ndef ", 1)[0] if "def cmd_send(" in cli else ""
    for literal, why in (
        ('protocol_spec.code_reject(code, proto) if code else ""', "the CLI is the same sender as the panel - a "
                                                                   "typo in --code costs the peer's bucket the same way"),
        ("protocol_spec.pass_reject(secret, proto)", "and so is a typo in --secret"),
        ("return 2", "a shape refusal is an argument problem, which is the exit code this command already uses for "
                     "「没固定过这台，得用它的配对码」"),
    ):
        if literal not in send:
            fail(f"cmd_send() no longer contains {literal!r} - {why}")

    parser = kernel.split("export function parsePairUrl(", 1)[1].split("\n\treturn out\n}", 1)[0] \
        if "export function parsePairUrl(" in kernel else ""
    for literal, why in (
        ("if (out.reject.length == 0 && out.code.length > 0)", "the code is measured when present - and the guard "
                                                               "on `reject` keeps an unreadable payload's own reason "
                                                               "from being overwritten"),
        ("out.reject = codeReject(out.code)", "the code's shape question"),
        ("out.reject = passReject(out.secret)", "and the passphrase's, which used to be reachable only when `c` "
                                                "was absent - every current QR carries `c`"),
    ):
        if literal not in parser:
            fail(f"parsePairUrl() no longer contains {literal!r} - {why}")
    if re.search(r"}\s*else\s*\{\s*out\.reject\s*=\s*passReject", parser):
        fail("parsePairUrl put the two secrets back into an if/else - with `c` in the payload (which is every QR this "
             "contract prints) the passphrase then goes on the wire unmeasured")
    check_code = store.split("function checkCodeAndNetwork()", 1)[1].split("\n}", 1)[0] if "function checkCodeAndNetwork()" in store else ""
    for literal, why in (
        ("const why = codeReject(activeOptions.code)", "the hand-typed path on the phone - the one this round found "
                                                       "already whole, and it has to stay whole"),
        ("const passWhy = passReject(activeOptions.secret)", "measured on its own branch, not as the else of the code's"),
    ):
        if literal not in check_code:
            fail(f"checkCodeAndNetwork() no longer contains {literal!r} - {why}")

    head = harness.split("} from '../cs-protocol.uts'", 1)[0]
    for literal, why in (
        ("parsePairUrl,", "the browser harness calls the kernel's parser; an export used and never imported compiles "
                          "and then blanks the page"),
        ("passReject,", "same for the two shape functions"),
        ("QR_SCHEME,", "and for the scheme the legs build a payload out of"),
    ):
        if literal not in head:
            fail(f"web/index.uts no longer imports {literal!r} - {why}")
    legs = len(re.findall(r"check\('(照着屏幕抄对的码和密码不会被本地拦下|密码留空是一个答案而不是错误|"
                          r"串里没有 c 与 k 时不因缺码被拒|密码抄成小写时这一串在本地就停住|"
                          r"说的是连接密码的字母表|码多抄了一位时同样在本地停住|"
                          r"两个都抄错时先答码那一句|扫码/粘贴那一趟与手输那一格答的是同一句话)", harness))
    if legs < 8:
        fail(f"the H5 sender self-check holds {legs} of the eight shape legs - the kernel is where these functions "
             f"live for both phones, and the browser is the only tier that runs them without a device")


def check_token_repair() -> None:
    """§3's lost-token clause: the sender repairs it, and the promise is about what it asks of a person.

    Round thirty (#196) read 「token 丢了…发送方此时用已有的 key 做一次只靠签名、不靠配对码的重配对补回来」 as a
    behavioural claim and found the *middle* of it undriven by every tier: `stale token rejected by the receiver`
    measures the peer's 403, `known key re-pairs without a code` measures one explicit pair() - nothing sent a
    request, took the 403, and read the same request back afterwards. The same round found the sentence beside it
    false on all three ends: it promised 用户看不到这个过程 while the phone has written a line into 传输详情 for it
    since #67. The paper now says what the bodies protect - the repair asks nothing of the user - and says where
    the repair must make noise instead: a peer that revoked the trust as well is not a session waiting to be
    topped up. What this guard holds open is the repair's shape (an empty `code`), its sites (three on the PC, one
    in the kernel because every request goes through `authed()`), and the two tiers that now drive it.
    """
    note = json.loads((CONTRACT / "protocol.json").read_text(encoding="utf-8-sig"))["transport"].get("note", "")
    for needle, why in (
        ("A dropped token is repaired by the sender, not by a person",
         "whose job this is - left to the prose alone, the next reader finds only a 403 and a pair() somewhere"),
        ("the promise is that this asks nothing of the user",
         "the clause §3 now protects; the absolute it replaced was false on every end"),
        ("Whether a log line shows up is each end's own choice",
         "why the phone's 会话失效 line stays and the paper stopped counting silence"),
        ("a peer that revoked the trust as well refuses the empty-code pair",
         "the honest opposite half, without which 补回来 reads as always silent"),
    ):
        if needle not in note:
            fail(f"protocol.json's transport.note no longer says {needle!r} - {why}")

    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 3.", 1)[1].split("\n## ", 1)[0] if "## 3." in spec else ""
    prose = "\n".join(p for p in section.split("\n\n") if not p.lstrip().startswith("（20"))
    flat = re.sub(r"\s+", "", prose)
    for needle, why in (
        ("发送方此时用已有的key做一次**只靠签名、不靠配对码**的重配对补回来",
         "the repair itself - a signature-only pair is what makes it need no code"),
        ("它不要求用户做任何事", "the promise this round replaced the false one with"),
        ("屏幕上留不留一行字由各端自己定", "the half the absolute used to over-promise on"),
        ("报的就该是「需要配对码」", "the case that must make noise, so a reader cannot take 静默 as total"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§3 no longer says {needle!r} - {why}")
    if "用户看不到这个过程" in flat:
        fail("§3 claims the user does not see the repair again - no end ever kept that promise (the phone writes "
             "会话失效 into 传输详情, PC logs it only at _call), and a sentence nobody obeys is the kind the next "
             "round has to delete rather than measure")

    root = HERE.parent
    sdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    send_py = (root / "app" / "net" / "send.py").read_text(encoding="utf-8")
    client = (sdk / "cs-client.uts").read_text(encoding="utf-8")
    kernel = (sdk / "cs-protocol.uts").read_text(encoding="utf-8")
    harness = (sdk / "web" / "index.uts").read_text(encoding="utf-8")

    # The PC: three call sites, because a request can die at any of them, and none of them may reach for the
    # number on the screen. transfer() pairs without a code too, but as an explicit step - hence 4, not 3.
    sites = send_py.count('payload.get("code") == "NOT_PAIRED" and self.identity.is_trusted(self.fingerprint)')
    if sites != 3:
        fail(f"the PC repairs a dropped token at {sites} request sites instead of 3 (_call, the offer poll, "
             f"_put_chunk) - the sentence says 发送方 repairs its own session, and a site that forgot leaves the "
             f"person staring at a failure the peer never declared")
    if send_py.count("self.pair()") != 4:
        fail("the number of bare self.pair() calls in app/net/send.py moved off 4 - three repairs plus the "
             "explicit no-code pair in transfer(); a repair that passes a code is the mistake this clause is for")
    if 'def pair(self, code: str = ""' not in send_py:
        fail("SenderClient.pair() no longer defaults to an empty code - the repair has to be able to ask for "
             "nothing on the wire")

    for literal, why in (
        ("if (status != 403 || codeOf(resp) != 'NOT_PAIRED' || repaired)",
         "one repair per request: a peer that still says NOT_PAIRED afterwards genuinely does not know us, and "
         "looping there would ask for a code the person cannot see"),
        ("write('会话失效，用已固定的密钥重新配对')",
         "the line §3 now allows each end to write - and the M group reads it out of the log column"),
        ("pairOnce(session, '', takeSelf, signPair, call",
         "the funnel's empty code: every authed request in the shared kernel is repaired through this one call, "
         "which is why this end needs one site where the PC needs three"),
        ("write(needs != '' ? needs : '静默重新配对没成功：' + why)",
         "the出声 half on this end: a refused repair says so instead of reporting a success nobody asked for - "
         "and since #198 it says the *right* thing first, because the sentence differs by which face this was"),
    ):
        if literal not in client:
            fail(f"cs-client.uts no longer contains {literal!r} - {why}")
    if "'NOT_PAIRED'" not in kernel or "尚未与这台设备配对" not in kernel:
        fail("errorText() no longer turns NOT_PAIRED into a sentence a person reads - the revoked-trust case has "
             "to reach the user as 需要配对码, not as a silent success")

    if "must not see this" in harness:
        fail("web/index.uts still comments that spec §3 promises the user sees nothing - the contract dropped "
             "that absolute in #196, and the comment is what a reader of the harness believes next")
    stale = harness.split("function runStaleSend(", 1)[1].split("\nexport function senderSelfReport(", 1)[0] \
        if "function runStaleSend(" in harness else ""
    for literal, why in (
        ("restartLike(probe.inbox)", "the restart is what kills the token while the trust stays - without it this "
                                     "leg measures an ordinary send"),
        ("run.staleToken = session.token", "the number has to be read before the repair replaces it, or the leg "
                                            "cannot tell a new bearer from the same one"),
        ("note, noopProgress, noopFileEvent", "the writer is the log column, which is what §3 now says each end owns"),
    ):
        if literal not in stale:
            fail(f"runStaleSend() no longer contains {literal!r} - {why}")
    if "repairs == 1" not in harness:
        fail("the 「会话失效」 leg no longer counts that one line - #196 moved the paper to 「屏幕上留不留一行字由各端自己定」, "
             "and the leg written the round before still measured it the old way: it asserted the whole log column "
             "holds a single line, which is the retired absolute in another shape. The first run of this tier read "
             "six lines and went red for the column, not for the repair")
    if "stale.logLines.length == 1" in harness:
        fail("the 「会话失效」 leg is back to `stale.logLines.length == 1` - that is 「the user sees nothing」 wearing "
             "the contract's old sentence, and the browser's own log column (progress lines and all) contradicts it")
    legs = len(re.findall(r"check\('(对面重启把会话抹了，这一单仍然传成|补的那一趟 pair 带的是空码|"
                          r"补回来的是一枚新的 bearer|那一行「会话失效，用已固定的密钥重新配对」在这一单的日志里|"
                          r"那一列里没有一句在问人要配对码|补回来以后重问的那一次清单)", harness))
    if legs < 6:
        fail(f"the H5 sender self-check holds {legs} of the six repair legs - the kernel is where both phones' "
             f"sender lives, and the browser is the only tier that runs it without a device")

    gate = (root / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    if "def phase_token_repair(" not in gate:
        fail("scripts/protocol_selftest.py no longer has phase_token_repair() - the middle of §3's sentence was "
             "unmeasured by every tier until #196 wrote it")
    if "phase_token_repair(proto, workspace)" not in gate:
        fail("phase_token_repair() is defined but never called from main() - a phase nobody runs is the same as "
             "no leg at all")
    body = gate.split("def phase_token_repair(", 1)[1].split("\ndef ", 1)[0] if "def phase_token_repair(" in gate else ""
    gatelegs = len(set(re.findall(r'check\("(§3 [^"]+)"', body)))
    if gatelegs < 11:
        fail(f"phase_token_repair() carries {gatelegs} of the 11 legs this round wrote - each of the PC's three "
             f"repair sites needs its own trip, plus the revoked-trust case that must not be silent")


def check_second_layer() -> None:
    """§3's "second layer": the passphrase is a thing a *sender* puts on the wire, not a condition the line enforces.

    Round thirty-one (#197) read 「码固定之后单次锁流不够看，所以强度来自第二层：`k` 是 32 字母表 8 位」 as the
    behavioural claim it is written as - that guessing `c` is not enough - and measured one receiver with only the
    `secret` slot varying. A stranger key presenting the correct code with the key omitted, and the same key
    presenting it as JSON null, both got a token and spent none of that source's five tries; an empty string and a
    wrong value both got `BAD_PAIR_CODE {reason: "passphrase"}` and spent one (`.probe/r31_probe.txt`). That is not
    a gate - it is the compatibility concession two sentences above it, which §3 states out loud and §7 protects:
    making the field mandatory changes the semantics of an existing field, which means a `protocol_version` bump,
    which means locking out the old builds this contract promises to accept. So the paper now says who this layer
    binds, what it therefore only screens out, and what the sender side owes instead: a blank passphrase box is a
    downgrade the person can hear about, on every end, before the request goes out. The arithmetic in the same
    sentence was also a lie by one bit - 32^8 is exactly 2^40, not "more than".
    """
    note = json.loads((CONTRACT / "protocol.json").read_text(encoding="utf-8-sig"))["transport"].get("note", "")
    for needle, why in (
        ("binds a sender that sends the field, not the wire", "whose promise this is - left out, the next reader "
                                                             "finds a security sentence and assumes a receiver "
                                                             "enforces it"),
        ("omits `secret` pairs on every end and spends none of its source's five tries",
         "the measured answer, both halves: the token and the untouched bucket"),
        ("A blank passphrase box is therefore loud on the sender side instead of silent",
         "the obligation this finding leaves the senders with, which is what the bodies below implement"),
        ("the sentence that says it is `spec.pass_omitted`", "the one function every end's version of this "
                                                             "sentence comes from, so the guard can follow it"),
        ("N machines are N times the rate", "the size of the wall in front of the code space: the throttle is "
                                            "per source, so it is not a rate limit on the guessing"),
    ):
        if needle not in note:
            fail(f"protocol.json's transport.note no longer says {needle!r} - {why}")

    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 3.", 1)[1].split("\n## ", 1)[0] if "## 3." in spec else ""
    prose = "\n".join(p for p in section.split("\n\n") if not p.lstrip().startswith("（20"))
    flat = re.sub(r"\s+", "", prose)
    for needle, why in (
        ("但这一层绑的是把`k`发上线的那一方，不是这条线路", "the finding this round wrote into the contract"),
        ("把`secret`整个省略的发送方", "the case the paper used to not name at all - it is the one a blank box makes"),
        ("照样拿到token且一枚名额都不烧", "what the receiver actually answers it, measured in .probe/r31_probe.txt"),
        ("只挡\"手边有码、没有密码\"的那一种人", "what is left of this layer, said as small as it measured"),
        ("32⁸正好是2⁴⁰", "the arithmetic the sentence quotes, stated as exactly what it is"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§3 no longer says {needle!r} - {why}")
    if re.sub(r"\s+", "", "约40bit以上") in flat:
        fail("§3 calls the passphrase 约 40 bit 以上 again - 32^8 is exactly 2^40, and a security sentence that "
             "rounds itself upward is the kind a later round has to re-measure instead of trusting")
    if "下面那句「码固定之后单次锁流不够看，所以这道承诺加了第二层」" not in spec:
        fail("§3's own note about the blank passphrase box points at a sentence the contract no longer contains - "
             "this round rewrote 强度来自第二层 precisely because it claimed more than the bodies protect, and the "
             "next reader following that pointer looks for words that are gone")

    root = HERE.parent
    sdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    spec_py = (root / "app" / "net" / "spec.py").read_text(encoding="utf-8")
    cli = (root / "app" / "cli.py").read_text(encoding="utf-8")
    ui = (root / "app" / "ui" / "transfer.py").read_text(encoding="utf-8")
    kernel = (sdk / "cs-protocol.uts").read_text(encoding="utf-8")
    harness = (sdk / "web" / "index.uts").read_text(encoding="utf-8")
    store = (HERE / "chuanshu" / "store" / "session.uts").read_text(encoding="utf-8")

    for literal, why in (
        ("def pass_omitted(secret: str, proto: Protocol) -> str:",
         "the sentence this round added, and the only place the PC's downgrade is audible"),
        ('if secret:\n        return ""', "it speaks for a blank box only - a filled one has nothing to be told "
                                          "about"),
    ):
        if literal not in spec_py:
            fail(f"app/net/spec.py no longer contains {literal!r} - {why}")
    omit_fn = spec_py.split("def pass_omitted(", 1)[1].split("\ndef ", 1)[0] if "def pass_omitted(" in spec_py else ""
    if "n=proto.pair_code_digits" not in omit_fn:
        fail("pass_omitted() no longer quotes `proto.pair_code_digits` for the number in its own sentence - the "
             "point of saying the downgrade out loud is that the digit count is the contract's, and a hand-copied "
             "6 here is the first thing to drift when §3's pair code changes length")

    cmd = cli.split("def cmd_send(", 1)[1].split("\ndef ", 1)[0] if "def cmd_send(" in cli else ""
    if 'if not known and code:\n        omitted = protocol_spec.pass_omitted(secret, proto)' not in cmd:
        fail("cmd_send() no longer says the downgrade only when this end is about to spend a code on a stranger - "
             "a pinned peer never sees an empty `secret` go out, so the sentence would be a lie there")
    connect = ui.split("def _start_connect(self)", 1)[1].split("\n    def ", 1)[0] \
        if "def _start_connect(self)" in ui else ""
    if 'protocol_spec.pass_omitted(secret, self.proto) if code and not self._pin_known(peer) else ""' not in connect:
        fail("_start_connect() no longer computes the omission note from the same two conditions the CLI asks - "
             "the panel and the CLI are one sender, and a person reads whichever one they opened")
    on_connected = ui.split("def _on_connected(self", 1)[1].split("\n    def ", 1)[0] \
        if "def _on_connected(self" in ui else ""
    if "+ self._omit_note" not in on_connected:
        fail("_on_connected() no longer carries the omission note into the success line - a sentence that vanishes "
             "with the connection it warned about is the silence §3 replaced with this")
    if "self._omit_note = \"\"" not in ui:
        fail("the panel never clears the omission note - a stale 留空 sentence would then be read against the next "
             "peer, one this end may be pairing with a real passphrase")

    fn = kernel.split("export function passOmitted(", 1)[1].split("\n}", 1)[0] \
        if "export function passOmitted(" in kernel else ""
    for literal, why in (
        ("if (secret.length > 0)", "the kernel's copy of the same rule: a filled box has nothing to say"),
        ("PAIR_CODE_DIGITS.toString()", "and the number it quotes is the contract's, read the way the rest of the "
                                        "kernel reads its numbers"),
    ):
        if literal not in fn:
            fail(f"cs-protocol.uts's passOmitted() no longer contains {literal!r} - {why}")
    entry = (sdk / "app-android" / "index.uts").read_text(encoding="utf-8")
    surface = re.search(r"export \{[^}]*\} from '\.\./cs-protocol\.uts'", entry)
    if surface is None or "passOmitted" not in surface.group(0):
        fail("utssdk/app-android/index.uts no longer names passOmitted in the cs-protocol surface - a uni_modules "
             "plugin on Android keeps only the names its own entry can reach, so the kernel's export is invisible "
             "to the page and `launch app-android --compile true` fails with 找不到名称 passOmitted (that is exactly "
             "how #197's first Android run went red; the browser tier never reads this list)")
    check_code = store.split("function checkCodeAndNetwork()", 1)[1].split("\n}", 1)[0] \
        if "function checkCodeAndNetwork()" in store else ""
    for literal, why in (
        ("if (activeOptions.code != '') {", "the phone says it only on the trip that actually carries a code"),
        ("const omitted = passOmitted(activeOptions.secret)", "and with the same value the sender is about to put "
                                                             "on the wire"),
        ("log(omitted)", "into 传输详情 - the column a person reads, not a dialog this round has no business adding"),
    ):
        if literal not in check_code:
            fail(f"checkCodeAndNetwork() no longer contains {literal!r} - {why}")
    if "refuse(omitted)" in check_code:
        fail("the phone turned the omission note into a refusal - §3 reads a blank box as「没有这个字段」and pairs "
             "on the code alone, so a body that blocks it here would be stricter than the peer on the other end")

    head = harness.split("} from '../cs-protocol.uts'", 1)[0]
    if "passOmitted," not in head:
        fail("web/index.uts no longer imports 'passOmitted,' - an export used and never imported compiles and "
             "then blanks the page")
    legs = len(re.findall(r"check\('(密码留空的那一趟，线上带的是配对码|那一趟照样配上|它一枚名额都没烧|"
                          r"填了密码的那一趟，线上那个键就是这个数|码错的时候省略帮不上忙|"
                          r"而它烧掉的正是这一格来源|留空那一趟本机要有一句人话|"
                          r"填上的那个框什么都不必说)", harness))
    if legs < 8:
        fail(f"the H5 sender self-check holds {legs} of the eight second-layer legs - the kernel is what both "
             f"phones compile, and the browser is the only tier that drives a sender with a blank box against a "
             f"receiver that keeps a passphrase")

    gate = (root / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    if "def phase_second_layer(" not in gate:
        fail("scripts/protocol_selftest.py no longer has phase_second_layer() - the omitted-key answer is a fact "
             "about the pair path, and only the tier that pairs can measure it")
    if re.search(r"^\s+phase_second_layer\(proto, workspace\)$", gate, re.M) is None:
        fail("phase_second_layer() is defined but never called from main() - a phase nobody runs is the same as "
             "no leg at all")
    phase = gate.split("def phase_second_layer(", 1)[1].split("\ndef ", 1)[0] if "def phase_second_layer(" in gate else ""
    for literal, why in (
        ("len(alphabet) ** proto.passphrase_chars == 2 ** 40", "the arithmetic in the sentence, pinned to the two "
                                                               "numbers instead of to the prose"),
        ('"secret" not in omitted_body', "the sender-side half of the finding: this end decides whether the layer "
                                         "exists by whether it puts the key on the wire"),
        ("filled_body.get(\"secret\") == secret", "and the same trip with a typed value does carry it, so the "
                                                  "omission is the blank box's doing and not the sender's habit"),
        ("_code_failures", "the legs have to read the bucket, not only the code - spending a try is the other half "
                           "of what this clause costs"),
    ):
        if literal not in phase:
            fail(f"phase_second_layer() no longer contains {literal!r} - {why}")
    gatelegs = len(set(re.findall(r'check\("(§3 [^"]+)"', phase)))
    if gatelegs < 8:
        fail(f"phase_second_layer() carries {gatelegs} of the 8 legs this round wrote - the receiver's answer, the "
             f"sender's body shape, and the two sentences that have to stay audible are three different things "
             f"holding this clause up")


def check_pair_refusal() -> None:
    """§3's two faces of one `BAD_PAIR_CODE` stay apart, chosen by what this end sent rather than by the reply.

    Round thirty-two (#198) went back for 待办 44's ①那一面 - the sentence the person is left with when the
    signature-only repair cannot work - and found the wire carrying one code for two different events. The receiver
    answers a revoked trust and a mistyped code identically (`403 BAD_PAIR_CODE`, `receive.py` compares an empty
    `code` against the screen's six digits), so `.probe/r32_gate.txt` shows both faces measured through the same
    reply. Nothing but this end's own `code` separates them, and the bodies had been *ignoring* that: `pair()` turned
    every refusal into `PairNeeded`, which made the connect panel tell a person who typed a wrong code that the peer
    had stopped recognising their key, and made the send panel tell a machine's repair - for which nobody typed
    anything - to type it again. So the rule pinned here is not the wording, it is the discriminator: an empty code
    may only ask for a new code, a typed one may only ask to re-enter it, and both are one wrong guess in the peer's
    bucket, which is why §3 no longer says the repair costs nothing.
    """
    note = json.loads((CONTRACT / "protocol.json").read_text(encoding="utf-8-sig"))["transport"].get("note", "")
    for needle, why in (
        ("Both faces of that refusal answer with the same `BAD_PAIR_CODE`",
         "the fact this whole round turns on - the reply cannot tell the two events apart"),
        ("whether the `code` in that request was its own empty one",
         "the only thing that can tell them apart, and it lives on the sender"),
        ("describes a typing that never happened",
         "why the repair face may not be answered with 再输一次"),
        ("describes a revocation that never happened",
         "why the typed face may not be answered with 不再认识"),
        ("an empty code is one wrong guess, so it is booked into that source's bucket",
         "the cost §3 used to imply was zero; measured twice in the gate, once per face"),
    ):
        if needle not in note:
            fail(f"protocol.json's transport.note no longer says {needle!r} - {why}")

    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 3.", 1)[1].split("\n## ", 1)[0] if "## 3." in spec else ""
    prose = "\n".join(p for p in section.split("\n\n") if not p.lstrip().startswith("（20"))
    flat = re.sub(r"\s+", "", prose)
    for needle, why in (
        ("分开它们的只有发送端自己知道的一件事", "the finding, written as the rule it is"),
        ("空码那一面只能要一个新的配对码", "the one sentence the machine's face is allowed to say"),
        ("那一面只能请他照着屏幕重输", "and the one the typed face is allowed to say"),
        ("两面都照样在对面那一格来源的5枚里记一次", "the bucket cost of both faces, which §3's 不要求用户做任何事 did not count"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§3 no longer says {needle!r} - {why}")

    root = HERE.parent
    sdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    spec_py = (root / "app" / "net" / "spec.py").read_text(encoding="utf-8")
    send_py = (root / "app" / "net" / "send.py").read_text(encoding="utf-8")
    cli = (root / "app" / "cli.py").read_text(encoding="utf-8")
    ui = (root / "app" / "ui" / "transfer.py").read_text(encoding="utf-8")
    gate = (root / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    client = (sdk / "cs-client.uts").read_text(encoding="utf-8")
    harness = (sdk / "web" / "index.uts").read_text(encoding="utf-8")

    for literal, why in (
        ("def pair_refusal(repair: bool, proto: Protocol) -> str:",
         "the one place either PC face chooses its words"),
        ('if repair:\n        return _("对方不再认识本机的密钥。选中它，输入它屏幕上新显示的配对码再连接。")',
         "and the machine's face owns that sentence alone"),
    ):
        if literal not in spec_py:
            fail(f"app/net/spec.py no longer contains {literal!r} - {why}")
    if "对方不再认识本机的密钥" not in spec_py or "再输一次" not in spec_py:
        fail("the two sentences this round separated no longer both live in spec.py - with them split across "
             "modules the next round re-merges them, which is the exact shape #198 found")

    for literal, why in (
        ("class WrongPairCode(RuntimeError)", "the typed face needs its own name or the panel cannot pick a "
                                              "sentence for it"),
        ('raise PairNeeded() if not code else WrongPairCode(code)',
         "the discriminator itself: this end's own empty code is the only thing that may say 不再认识"),
    ):
        if literal not in send_py:
            fail(f"app/net/send.py no longer contains {literal!r} - {why}")
    if 'payload.get("code") == "BAD_PAIR_CODE":\n            raise PairNeeded()' in send_py:
        fail("send.py is back to turning every BAD_PAIR_CODE into PairNeeded - that is the conflation #198 "
             "measured: a person who typed a wrong code was told the peer had revoked their key")

    if "protocol_spec.pair_refusal(not isinstance(error, WrongPairCode), proto)" not in ui:
        fail("_connect_failed / _finished no longer read their sentence through spec.pair_refusal - two panels "
             "choosing between the same two sentences independently is how they ended up each配错了一面")
    if "except (PairNeeded, WrongPairCode)" not in ui:
        fail("the panels no longer catch both faces - a refusal that escapes as an unhandled RuntimeError reaches "
             "the person as a crash, not as a next step")
    if "except WrongPairCode:" not in cli:
        fail("app/cli.py no longer answers the typed face on its own line - a person at a terminal gets whichever "
             "sentence the GUI happened to pick, and the two are different advice")

    for literal, why in (
        ("export function repairRefused(refused: string): string",
         "the kernel's copy of the discriminator, so all three phone platforms say the same thing"),
        ("cb: (ok: boolean, message: string, refused: string) => void",
         "pairOnce has to hand the refusal back as a code, not only as a sentence, or the caller can only guess"),
        ("const needs = repairRefused(refused)", "and the repair site actually asks it"),
        ("cb(status, needs != '' ? '{\"code\":\"NOT_PAIRED\",\"detail\":{\"reason\":\"' + needs",
         "the refusal the card reads carries this end's own sentence in the detail (spec §4: a detail is a whole "
         "sentence), so the next step survives the trip to the screen"),
    ):
        if literal not in client:
            fail(f"cs-client.uts no longer contains {literal!r} - {why}")
    if "对方不再认识本机的密钥。选中它，输入它屏幕上新显示的配对码再连接。" not in client:
        fail("the kernel's machine-face sentence is no longer the PC's sentence verbatim - §3 promises one "
             "next step to a person whichever end they are standing at")

    if "except WrongPairCode:" not in gate:
        fail("phase_token_repair no longer asks which exception the typed face gets - without it the discrimination "
             "is only asserted in prose and the next refactor can re-merge the two faces silently")
    if "protocol_spec.pair_refusal(" not in gate:
        fail("scripts/protocol_selftest.py no longer reads the two sentences through spec.pair_refusal - the gate "
             "would then be checking exception names again, which is exactly the level #198 found to be too shallow: "
             "an exception cannot be wrong, only the sentence hung on it can")
    legs = len(re.findall(r"check\(\"(§3 机器自补被拒时，给人看的那句要的是屏幕上那个新码|§3 人输错码那一句说的是照着屏幕再输一次|"
                          r"§3 两面不共用一句话|§3 那一趟不肯静默的补也没有偷偷带码|§3 那一趟不肯静默的补在对面记了一次|"
                          r"§3 人输错码那一面报的是重输那一面|§3 人输错码那一趟同样在对面记了一次)", gate))
    if legs < 7:
        fail(f"the gate holds {legs} of the 7 refusal legs this round wrote - the sentences and the exception each "
             f"face gets are what §3's 「报的就该是需要配对码」 promises a person, and dropping one of them is how "
             f"the two faces quietly merge back together")
    o_legs = len(re.findall(r"check\('(对面把信任也收回时，这一单没被传成|补的那一趟仍然先按 §3 用空码试了签名|"
                            r"说的是要屏幕上那个新的配对码|那一列里也留下同一句人话|它没把人没输过的东西说成输错了|"
                            r"空码在对面就是一次错猜|人输错码那一面答的还是那句关于码的)", harness))
    if o_legs < 7:
        fail(f"the H5 sender self-check holds {o_legs} of the seven refusal legs - 待办 44's ①那一面 was the "
             f"sentence this series kept saying 「只在代码上核过、没跑」, and a leg that never runs is how it stayed owed")
    if "function runRevokedSend(" not in harness:
        fail("the browser tier lost runRevokedSend() - without a receiver that took the trust back too, the "
             "refusal face cannot be reached at all (`restartLike` deliberately keeps `trusted`, which is what "
             "makes the repair succeed)")


def check_ask_verdict() -> None:
    """§4's third shape splits in two, and the verdict follows which half it is - not which end you are on.

    Round thirty-three (#199, closing #138) read the one sentence 「只有问不到答案、或尝试次数用尽才把原来的错误
    抛出去」 as if "the question failed" were one fact. It is two: the peer answered with a refusal (it is there,
    and it says this offer is over - information the eaten reply never carried) or the peer answered nothing
    (two silences, no new fact, and the only nameable thing is the pipe that broke). Neither end had both halves:
    PC caught `ProtocolError` and `OSError` into the same `None`, so a refusal got buried under "Broken pipe";
    the kernel answered both with the question's own text, so an unanswered question reported a transport error
    as if it were a verdict (`.probe/a_133_mute.txt` is that reading on an AVD, and it now needs a re-run).
    """
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 4.", 1)[1].split("\n## ", 1)[0] if "## 4." in spec else ""
    prose = "\n".join(p for p in section.split("\n\n") if not p.lstrip().startswith("（20"))
    flat = re.sub(r"\s+", "", prose)
    for needle, why in (
        ("那一问得到了答复、答复是一个拒绝", "the first half, which the paper used to fold into one sentence"),
        ("抛出去的是**那一问的答复**", "and its verdict: what the peer just said, not what our socket did"),
        ("连那一问都没人答", "the second half"),
        ("抛出去的是**那一次写自己的错误**", "and its verdict, which is the sentence §4 always had"),
        ("分开它们的只有「那一问到没问到答复」这一件事", "the discriminator, stated as the only thing that can do it"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§4 no longer says {needle!r} - {why}")

    root = HERE.parent
    sdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    send_py = (root / "app" / "net" / "send.py").read_text(encoding="utf-8")
    client = (sdk / "cs-client.uts").read_text(encoding="utf-8")
    gate = (root / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    harness = (sdk / "web" / "index.uts").read_text(encoding="utf-8")

    held = client.split("function chunkHeld(", 1)[1].split("\n\t}", 1)[0] if "function chunkHeld(" in client else ""
    for literal, why in (
        ("if (status == 0) {", "the no-answer half has to be tested before `status != 200`, or the two merge again"),
        ("cb(false, false, fallback)", "and that half's verdict is the write's own reply text, carried in by the caller"),
    ):
        if literal not in held:
            fail(f"chunkHeld() no longer contains {literal!r} - {why}")
    if "The question died too" in held:
        fail("chunkHeld() is back to reporting the question's own failure for both halves - that is the reading "
             "#138 was opened for, and it turns a silence into a conclusion")

    landed = send_py.split("def _chunk_landed(", 1)[1].split("\n    def ", 1)[0] if "def _chunk_landed(" in send_py else ""
    if "except (http.client.HTTPException, OSError, protocol_spec.ProtocolError)" in landed:
        fail("_chunk_landed() is back to catching the peer's refusal and the dead socket into one None - the PC "
             "half of the merge #199 undid, and the reason a person could never learn 这一单已经结束了. "
             "(`_withdraw` catches all three together on purpose: a failed best-effort abort is one log line.)")
    for literal, why in (
        ("except protocol_spec.ProtocolError as exc:", "a refusal is caught apart from a silence, not merged into it"),
        ("except (http.client.HTTPException, OSError) as exc:", "and the silence keeps its own branch"),
    ):
        if literal not in landed:
            fail(f"_chunk_landed() no longer contains {literal!r} - {why}")
    if "answered, has_it, answer = self._chunk_landed(file, index)" not in send_py:
        fail("_put_chunk no longer reads the three-way answer, so the refusal branch cannot exist")

    if "那一问答的是拒绝时这一单也判死" not in gate or "报出去的是对面那句拒绝" not in gate:
        fail("the gate lost the refusal-answer legs - without them both ends can silently re-merge the two halves")
    p_legs = len(re.findall(r"check\('(那一问答的是一个拒绝时这单同样判死|它也没重写那一块|"
                            r"报出去的是对面那句拒绝，不是本机那次断管|那一问的答复里的 reason 也留得下来|"
                            r"那一问也没人答时报的是那一次写自己的错)", harness))
    if p_legs < 5:
        fail(f"the H5 sender self-check holds {p_legs} of the 5 legs that separate §4's third shape - the "
             f"browser tier is where the kernel half of this rule is executed")
    if "refuseState: number = 0" not in harness:
        fail("web/index.uts lost the refuseState injection - an answering-with-a-refusal peer cannot be built, "
             "and `muteState` alone only ever measures the silence half")


def check_channels_with_listener() -> None:
    """§2's 监听常驻 names the listener, not a screen: the two channels come up with the port (#201).

    Measured before this round: the phone's TLS listener starts by itself at `initSession`
    (`store/session.uts`'s `initReceivePanel` → `onRecvListen`) while both discovery channels sat behind
    the 找局域网设备 button. A receiving phone therefore did not announce at all until somebody opened that
    page - the peer's list simply lacked it, and no card on either end explained the difference. The
    multicast permission was never the blocker (`app-android/config.json` has had
    CHANGE_WIFI_MULTICAST_STATE since #90); the missing piece was one call.
    """
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 2.", 1)[1].split("\n## ", 1)[0] if "## 2." in spec else ""
    flat = re.sub(r"\s+", "", section)
    for needle, why in (
        ("这一条**不挂在人手里**", "the channels are not a feature switch"),
        ("接收一开，播的那两路（公告与注册）就跟着开", "and what they ride on instead: the listener"),
        ("人把通道关掉是另一个决定", "a hand that stopped them is honoured, not overruled"),
        ("屏上要说得出为什么并给出 §2.3 那条出口", "a channel that cannot start is named, per §2.3"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§2 no longer says {needle!r} - {why}")

    body = json.loads((CONTRACT / "protocol.json").read_text(encoding="utf-8-sig"))
    note = re.sub(r"\s+", " ", body["discovery"]["note"])
    for needle, why in (
        ("The channels are not a feature switch", "the machine-readable half of the same sentence"),
        ("keeps that decision for the rest of the run", "and the hand-stop is honoured, not reopened by the listener"),
    ):
        if needle not in note:
            fail(f"discovery.note no longer says {needle!r} - {why}")

    session = (HERE / "chuanshu" / "store" / "session.uts").read_text(encoding="utf-8")
    listen = session.split("export function onRecvListen()", 1)[1].split("\n}", 1)[0] if "export function onRecvListen()" in session else ""
    if "autoStartDiscovery()" not in listen:
        fail("onRecvListen no longer brings the channels up with the port - that is the whole of #201")
    auto = session.split("function autoStartDiscovery()", 1)[1].split("\n}", 1)[0] if "function autoStartDiscovery()" in session else ""
    if "discHandStopped" not in auto:
        fail("autoStartDiscovery no longer respects a hand that stopped the channels - the listener would "
             "reopen a decision the person already made")
    toggle = session.split("export function toggleDiscovery()", 1)[1].split("\n}", 1)[0] if "export function toggleDiscovery()" in session else ""
    if "discHandStopped = true" not in toggle:
        fail("toggleDiscovery stopped the channels without recording it as the person's own decision")
    if "发现通道却起不来" not in auto:
        fail("a channel that cannot start while the port is open is back to being silent - §2.3 names an "
             "escape route, it does not log one")

    root = HERE.parent
    discovery_py = (root / "app" / "net" / "discovery.py").read_text(encoding="utf-8")
    transfer_py = (root / "app" / "ui" / "transfer.py").read_text(encoding="utf-8")
    cli_py = (root / "app" / "cli.py").read_text(encoding="utf-8")
    gate = (root / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    if "self._ensure_discovery().set_port(service.port)" not in transfer_py:
        fail("the PC window no longer hands discovery the port it actually bound - the reference shape "
             "the phones are measured against (it moved from a rebuild to one call, #206)")
    if "discovery = DiscoveryService(identity, device_name(settings), service.port)" not in cli_py:
        fail("`ChuanShu-cli receive` no longer announces the port it is listening on")
    if 'self._spawn(self._announce_loop, "announce")' not in discovery_py:
        fail("the announce thread is gone, so nothing re-announces every 3 s on the end that claims to")
    if "§2 起了监听的那一端也在每 3 s 播自己" not in gate:
        fail("the gate no longer measures that a listening end has an announcement running")


def check_mdns_needs_fp() -> None:
    """§2.1's `fp` is the thing §2's prefix check has to have; three readers already refuse to guess it (#203).

    The paper used to list `fp` as one of four TXT keys and say nothing about a record that lacks it. The
    bodies were never ambiguous: PC's `_on_mdns_record` returns before `_learn`, the shared kernel's
    `parseTxt` rejects the packet, and Android below API 28 - where DNS-SD cannot carry TXT at all while
    this project's floor is 21 - reports the whole channel unavailable with that reason instead of
    offering unverifiable names. This round wrote the sentence and pinned all three readers.
    """
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 2.", 1)[1].split("\n## ", 1)[0] if "## 2." in spec else ""
    flat = re.sub(r"\s+", "", section)
    for needle, why in (
        ("TXT里的`fp`**不是可选字段**", "the key the prefix check needs is not decoration"),
        ("没有东西可钉", "why an fp-less record is not a candidate"),
        ("不拿地址或名字凑一个前缀", "and the shortcut that must never be taken"),
        ("Android9（API28）以下的系统给不出DNS-SD的TXT属性", "the environment that loses the whole channel, named"),
        ("那不是第二条说的\"多播被拦\"", "so it is not confused with §2.2's blocked multicast"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§2.1 no longer says {needle!r} - {why}")

    body = json.loads((CONTRACT / "protocol.json").read_text(encoding="utf-8-sig"))
    note = re.sub(r"\s+", " ", body["discovery"]["note"])
    if "A record without `fp` is not a candidate on any end" not in note:
        fail("discovery.note no longer states the fp rule machine-readably")

    discovery_py = (HERE.parent / "app" / "net" / "discovery.py").read_text(encoding="utf-8")
    handler = discovery_py.split("def _on_mdns_record", 1)[1].split("\n    def ", 1)[0] if "def _on_mdns_record" in discovery_py else ""
    if 'properties.get("fp", "")' not in handler or "if not prefix:" not in handler:
        fail("PC's mDNS reader no longer refuses a record with nothing to pin")
    if "self._learn(" in handler.split("if not prefix:", 1)[0]:
        fail("PC's mDNS reader learned a candidate before the fp check - the order is the whole rule")

    kernel = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "cs-discovery.uts").read_text(encoding="utf-8")
    if "广播里没有指纹前缀" not in kernel:
        fail("cs-discovery.uts no longer rejects an announcement/TXT without a prefix - the shared half of this rule")

    kotlin = (HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk" / "app-android" / "CsDiscovery.kt").read_text(encoding="utf-8")
    mdns = kotlin.split("private fun startMdns(", 1)[1].split("\n    }", 1)[0] if "private fun startMdns(" in kotlin else ""
    if "Build.VERSION.SDK_INT < 28" not in mdns:
        fail("CsDiscovery.kt no longer names the API 28 wall - below it DNS-SD has no TXT, so the channel must be reported, not guessed")
    if "带不出指纹前缀" not in mdns:
        fail("the Android mDNS channel no longer says why it is unavailable - §2 asks for a named reason, not a silent row")

    gate = (HERE.parent / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    if "§2.1 没有 fp 的 mDNS 记录进不了名单" not in gate:
        fail("the gate no longer executes PC's mDNS reader against an fp-less record")


def check_announce_port() -> None:
    """§2's announcement names a socket, so "no listener, no announcement" has to be one answer per body.

    Round thirty-four (#200) measured four bodies that kept broadcasting the contract's default port with
    nothing behind it - `ChuanShu-cli peers`, a command that never binds a listener at all, and the three
    phone hosts' `isRunning() ? port : TRANSPORT_PORT` - while their own comments claimed the packet
    carried "the port that is actually open". Whoever hears the packet dials that number, so a name nobody
    can reach is worse to a person than a name that is simply absent.
    """
    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 2.", 1)[1].split("\n## ", 1)[0] if "## 2." in spec else ""
    flat = re.sub(r"\s+", "", section)
    for needle, why in (
        ("`port` 是发出去那一刻本机**真开着**的接收端口", "the announcement is a claim about a live socket"),
        ("不发这条、也不注册 mDNS 服务", "and a machine with nothing open says nothing on either channel"),
        ("名单里出现一台拨不通的机器", "the reason: an undialable name costs a person a connect attempt"),
        ("今天没有任何一端读它", "`ts` is named as the field nobody reads, not a freshness source"),
        ("各端用自己的钟", "and the 15 s is measured on the hearer's own clock"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§2 no longer says {needle!r} - {why}")

    body = json.loads((CONTRACT / "protocol.json").read_text(encoding="utf-8-sig"))
    note = re.sub(r"\s+", " ", body["discovery"]["note"])
    for needle, why in (
        ("a machine that is not listening sends nothing and registers no mDNS service",
         "the machine-readable half of the same rule"),
        ("no end reads it", "and `ts` described as it is used: not at all"),
    ):
        if needle not in note:
            fail(f"discovery.note no longer says {needle!r} - {why}")

    root = HERE.parent
    sdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    kernel = (sdk / "cs-discovery.uts").read_text(encoding="utf-8")
    if "export function livePort(listening: boolean, port: number): number {" not in kernel:
        fail("cs-discovery.uts no longer owns the answer to `livePort` - four hosts each inventing one is "
             "exactly how #200 happened")
    if "return listening ? port : 0" not in kernel:
        fail("livePort no longer answers 0 for a machine that is not listening - the whole rule is that one value")
    report = kernel.split("export function selfReport(", 1)[1] if "export function selfReport(" in kernel else ""
    if "§2 没在监听时这一格的答案是「别说」" not in report:
        fail("the kernel self-check lost the leg that runs §2's port rule - the browser tier is where this "
             "half of discovery is actually executed")

    session = (HERE / "chuanshu" / "store" / "session.uts").read_text(encoding="utf-8")
    asked = session.split("function discServicePort()", 1)[1].split("\n}", 1)[0] if "function discServicePort()" in session else ""
    if "TRANSPORT_PORT" in asked:
        fail("discServicePort is back to handing out the contract's default port while nothing is listening, "
             "which is the lie #200 measured")
    if "livePort(serveIsRunning(), servePort())" not in asked:
        fail("session.uts's discServicePort no longer asks the kernel - the Harmony announcement is built here")

    for name in ("app-android", "app-ios"):
        host = (sdk / name / "index.uts").read_text(encoding="utf-8")
        provider = host.split("const discProvider", 1)[1].split("\n}", 1)[0] if "const discProvider" in host else ""
        if "livePort(CsServe.isRunning(), CsServe.port())" not in provider:
            fail(f"{name}/index.uts's discProvider no longer asks which port this beat may name")
        if "isRunning() ? CsServe.port() : TRANSPORT_PORT" in provider:
            fail(f"{name}/index.uts is back to the fallback that kept 43720 on the air after 停止接收")

    harmony = (sdk / "app-harmony" / "index.uts").read_text(encoding="utf-8")
    port_of = harmony.split("function discPortOf()", 1)[1].split("\n}", 1)[0] if "function discPortOf()" in harmony else ""
    if "return TRANSPORT_PORT" in port_of:
        fail("harmony's discPortOf falls back to the default port again - this file mirrors the constant, so "
             "the fallback reads like a fact and is a guess")
    publish = harmony.split("function discPublish()", 1)[1].split("\n}", 1)[0] if "function discPublish()" in harmony else ""
    if "if (want == '') {" not in publish:
        fail("discPublish no longer asks whether anything is open before registering the mDNS service "
             "(#204 moved the question into the announcement text itself)")

    kotlin = (sdk / "app-android" / "CsDiscovery.kt").read_text(encoding="utf-8")
    register = kotlin.split("private fun register(", 1)[1].split("\n    }", 1)[0] if "private fun register(" in kotlin else ""
    if 'if (text == "") {' not in register:
        fail("CsDiscovery.kt's register() has no quiet answer for a machine that is not receiving - an empty "
             "provider used to be reported as 「本机公告不是 JSON」, which blames the packet for a stopped listener")

    discovery_py = (root / "app" / "net" / "discovery.py").read_text(encoding="utf-8")
    cli_py = (root / "app" / "cli.py").read_text(encoding="utf-8")
    gate = (root / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    if "port: int | None," not in discovery_py:
        fail("DiscoveryService no longer takes 'no port', so the CLI has no way to say it is only listening")
    if "DiscoveryService(identity, device_name(settings), None)" not in cli_py:
        fail("`ChuanShu-cli peers` is back to announcing a port it never bound")
    if "if sock is None or self.port is None:" not in discovery_py:
        fail("announce() is back to sending bytes for a listener that does not exist")
    if "§2 没在监听的一端一条公告也不发" not in gate or "§2 没在监听的一端也不注册 mDNS 服务" not in gate:
        fail("the PC gate lost the legs that measure a listener-less announcement staying unsent")


def check_record_follows_beat() -> None:
    """§2.1's published record is §2.2's packet in the other channel, so it is re-asked on the same beat (#204).

    Round thirty-four wrote 「不发这条、也不注册 mDNS 服务」 and thirty-five wrote 「端口换了就播新那个」; both
    verbs share one subject, and the bodies kept two different clocks. The broadcast re-reads the port every
    3 s, while DNS-SD registration was asked once - `register()`'s only caller was `startMdns()`, `discPublish()`'s
    was `lanOpen()` - so a phone that pressed 停止接收 went silent on the air and stayed in everyone's roster
    answering a closed port, and one that restarted its listener answered the same question with two numbers.
    Harmony said so in a comment and deferred it (待办 48②); the PC never had it, because the whole
    DiscoveryService is built and torn down with the listener. iOS's `publish()` has the same shape and is left
    alone: that platform was terminated on 2026-10-24 and has no compile gate to believe.
    """
    sdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"
    kotlin = (sdk / "app-android" / "CsDiscovery.kt").read_text(encoding="utf-8")
    announce_loop = kotlin.split("}, \"chuanshu-announce\")", 1)[0] if "}, \"chuanshu-announce\")" in kotlin else ""
    if "reconcileMdns(provider)" not in announce_loop:
        fail("the Android announce beat is back to re-asking only the packet - the record then keeps a port "
             "this end closed, which is the §2.1 half of #204")

    harmony = (sdk / "app-harmony" / "index.uts").read_text(encoding="utf-8")
    beat = harmony.split("function discBeat()", 1)[1].split("\n}", 1)[0] if "function discBeat()" in harmony else ""
    if "discPublish()" not in beat:
        fail("harmony's beat no longer re-asks the record - the packet goes quiet, the name stays")
    if "discAnnounceOnce()" not in beat:
        fail("discBeat is no longer the one beat both announcements ride")

    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 2.", 1)[1].split("\n## ", 1)[0] if "## 2." in spec else ""
    flat = re.sub(r"\s+", "", section)
    for needle, why in (
        ("同一个断言的两个副本", "a record and a packet are one claim about one socket"),
        ("接收停了这条记录要**撤掉**", "so a closed listener takes it down"),
        ("端口换了要**撤了重注册**", "and a moved port re-announces it"),
        ("广播念新号、记录念旧号", "the failure this prevents: two answers from one machine"),
        ("NsdManager在同一个名字还挂着注册时不接受第二次", "the platform that forces withdraw-then-register"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§2.1 no longer says {needle!r} - {why}")

    body = json.loads((CONTRACT / "protocol.json").read_text(encoding="utf-8-sig"))
    note = re.sub(r"\s+", " ", body["discovery"]["note"])
    if "re-asked on that beat rather than once when the discovery channel opens" not in note:
        fail("discovery.note no longer states the record's lifetime machine-readably")

    kernel = (sdk / "cs-discovery.uts").read_text(encoding="utf-8")
    decide = kernel.split("export function publishAction(", 1)[1].split("\n}", 1)[0] if "export function publishAction(" in kernel else ""
    if "export function publishAction(" not in kernel:
        fail("cs-discovery.uts no longer owns the answer to `publishAction` - four hosts inventing one is how "
             "#204 happened")
    for const, why in (("PUBLISH_KEEP", "an unchanged beat leaves the record alone"),
                       ("PUBLISH_WITHDRAW", "a closed listener takes it down"),
                       ("PUBLISH_FIRST", "nothing held yet is a plain registration"),
                       ("PUBLISH_REPLACE", "a moved port is withdrawn and registered again")):
        if f"return {const}" not in decide:
            fail(f"publishAction lost its {const} answer - {why}")
    report = kernel.split("export function selfReport(", 1)[1] if "export function selfReport(" in kernel else ""
    if "§2.1 接收停了，DNS-SD 那一条要撤掉" not in report:
        fail("the kernel self-check lost the leg that runs §2.1's withdraw - the browser tier is where this "
             "rule is actually executed")

    android = kotlin.split("private fun reconcileMdns(", 1)[1].split("\n    }", 1)[0] if "private fun reconcileMdns(" in kotlin else ""
    if "unregisterService(held)" not in android:
        fail("Android's reconcile no longer takes the old record down before anything else - NsdManager "
             "refuses a second registerService while the first is held")
    if android.find("unregisterService(held)") < 0 or "register(mdnsServiceType" not in android:
        fail("Android's reconcile lost one of its two acts")
    if "pendingText != null" not in android:
        fail("Android will now stack a second unregister while the first is still awaiting its goodbye - "
             "the list blinks and the platform errors")
    goodbye = kotlin.split("override fun onServiceUnregistered", 1)[1].split("\n            }", 1)[0] if "override fun onServiceUnregistered" in kotlin else ""
    if "register(mdnsServiceType" not in goodbye:
        fail("Android's registration is never put back after the goodbye, so a port change withdraws the "
             "record and leaves this end invisible")

    root = HERE.parent
    transfer_py = (root / "app" / "ui" / "transfer.py").read_text(encoding="utf-8")
    discovery_py = (root / "app" / "net" / "discovery.py").read_text(encoding="utf-8")
    gate = (root / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    if "self._zeroconf.unregister_service(self._service_info)" not in discovery_py:
        fail("PC's DiscoveryService.stop() no longer withdraws the record it registered - the shape the "
             "phones are measured against")
    if "self._discovery.stop()" not in transfer_py:
        fail("the PC window no longer takes discovery down with the listener")
    if "§2.1 关掉发现通道时那条 DNS-SD 记录一起撤了" not in gate:
        fail("the gate lost the leg that measures PC withdrawing the record")
    if "§2.1 重开监听时注册的是这一次真绑上的端口" not in gate:
        fail("the gate lost the leg that measures PC re-registering the port it actually bound")


def check_mdns_goodbye_names_a_service() -> None:
    """§2.1's goodbye names the service, not the machine - so the remembered name→prefix is the rule (#205).

    The paper drew registration and the TXT block but never the moment a record leaves. The bodies were
    never ambiguous about it: PC fills `_mdns_names` in `_resolve` only when the answer carried an `fp` and
    pops it in `remove_service`; Android's `onServiceLost` takes `prefixesByService.remove(name)` and returns
    when nothing was remembered; Harmony reads `discNames.get(info.serviceName)` and hands `remembered ?? ''`;
    iOS is the same with `removeValue(forKey:)`. All four withdraw **that channel's presence** and leave the
    machine listed, because the broadcast may still be answering every second - and the 15 s window on the
    hearer's own clock is what actually removes a silent peer. This round wrote the sentence and pinned the
    four readers; PC's two were being executed for the first time at all.
    """
    root = HERE.parent
    sdk = HERE / "chuanshu" / "uni_modules" / "cs-transport" / "utssdk"

    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 2.", 1)[1].split("\n## ", 1)[0] if "## 2." in spec else ""
    flat = re.sub(r"\s+", "", section)
    for needle, why in (
        ('一条 goodbye 只说"这个名字走了"，它**不带 `fp`**', "the goodbye carries nothing to key the roster by"),
        ("必须自己记住上一次解析时这个名字对应哪个前缀", "so the remembered name->prefix is required, not optional"),
        ("撤掉的也只是**这一条通道的在场**，不是这台机器", "and a goodbye must not evict a still-announcing peer"),
        ("真正让一台机器离开名单的从来是**收件方自己那 15 s**", "which is why forgetting is an early act, not the rule"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§2.1 no longer says {needle!r} - {why}")

    body = json.loads((CONTRACT / "protocol.json").read_text(encoding="utf-8-sig"))
    note = re.sub(r"\s+", " ", body["discovery"]["note"])
    for needle, why in (
        ("A goodbye names the service, not the machine, and carries no `fp`", "the machine-readable half"),
        ("withdraws only that channel's presence", "and the same limit on what it may remove"),
    ):
        if needle not in note:
            fail(f"discovery.note no longer says {needle!r} - {why}")

    discovery_py = (root / "app" / "net" / "discovery.py").read_text(encoding="utf-8")
    resolve = discovery_py.split("def _resolve(self, zc, name: str)", 1)[1].split("\n    def ", 1)[0] if "def _resolve" in discovery_py else ""
    if "self.service._mdns_names[name] = prefix" not in resolve:
        fail("PC's resolver no longer remembers which prefix a service name answered under - a goodbye "
             "then has nothing to withdraw")
    if "if prefix:" not in resolve:
        fail("PC remembers a name→prefix pair for a record with nothing to pin, which is the guess §2.1 bans")
    remove_lines = discovery_py.split("def remove_service", 1)[1].splitlines() if "def remove_service" in discovery_py else []
    remove = "\n".join(remove_lines[:6])
    if 'prefix = self.service._mdns_names.pop(name, "")' not in remove:
        fail("PC's remove_service no longer takes the remembered prefix off the list")
    if "_mdns_names.pop" in discovery_py.split("def remove_service", 1)[0]:
        fail("something before remove_service pops the name map, so the goodbye itself can no longer find it")
    forget = discovery_py.split("def _forget_mdns", 1)[1].split("\n    def ", 1)[0] if "def _forget_mdns" in discovery_py else ""
    if 'peer.via.discard("mdns")' not in forget:
        fail("PC's _forget_mdns no longer removes just the mdns path")
    if "del self._peers" in forget or "_peers.pop" in forget:
        fail("PC's _forget_mdns is back to evicting the machine - a peer still announcing every 3 s would "
             "vanish from the list because one path said goodbye")

    kotlin = (sdk / "app-android" / "CsDiscovery.kt").read_text(encoding="utf-8")
    lost = kotlin.split("override fun onServiceLost", 1)[1].split("\n            }", 1)[0] if "override fun onServiceLost" in kotlin else ""
    if 'prefixesByService.remove(name)' not in lost:
        fail("Android's goodbye no longer looks the service name up in what it remembered")
    if 'if (prefix == "") {' not in lost:
        fail("Android's goodbye no longer says 'nothing remembered, nothing to withdraw' - the case the 15 s "
             "window exists for")

    harmony = (sdk / "app-harmony" / "index.uts").read_text(encoding="utf-8")
    ohos_lost = harmony.split("svc.on('serviceLost'", 1)[1].split("\n\t})", 1)[0] if "svc.on('serviceLost'" in harmony else ""
    if "discNames.get(info.serviceName)" not in ohos_lost:
        fail("Harmony's goodbye no longer resolves the name through the remembered prefix")
    if "remembered ?? ''" not in ohos_lost:
        fail("Harmony's goodbye hands out a guessed prefix instead of nothing when it never remembered one")
    ohos_find = harmony.split("resolveLocalService(discContext(), info)", 1)[1].split("\n\t\t\t}).catch", 1)[0] if "resolveLocalService(discContext(), info)" in harmony else ""
    if "discNames.set(" not in ohos_find:
        fail("Harmony no longer records name→prefix when a service resolves, so its goodbye can never match")

    kernel = (sdk / "cs-discovery.uts").read_text(encoding="utf-8")
    bye = kernel.split("export function forgetMdns(", 1)[1].split("\n}", 1)[0] if "export function forgetMdns(" in kernel else ""
    if "!= VIA_MDNS" not in bye:
        fail("the shared model's forgetMdns no longer keeps the other path alive")
    if "roster.peers =" in bye or ".splice(" in bye:
        fail("the shared model's forgetMdns is dropping the candidate, not the channel - the mistake §2.1 "
             "now names")
    report = kernel.split("export function selfReport(", 1)[1] if "export function selfReport(" in kernel else ""
    if "§2.1 一条没记住名字的 goodbye 什么都不撤" not in report:
        fail("the kernel self-check lost the leg that runs an unmatched goodbye")

    gate = (root / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    legs = len(re.findall(r'check\("§2\.1 (解析到的那一趟把 name→fp 记下来|一条 goodbye 只撤掉 mdns 那一路|'
                          r'撤完那份 name→fp 的记忆也放下|没记住那个名字的 goodbye 不炸名单)', gate))
    if legs < 4:
        fail(f"the gate runs {legs} of the 4 legs that execute PC's goodbye path - these two readers were "
             f"never executed before #205")


def check_hearing_outlives_the_port() -> None:
    """§2 splits 跟着监听 in two: 播 (the beat and the record) rides the port, 听 (browse and the listener) does not (#206).

    Measured by walking the one route a sender-only person takes - open 传书, turn 接收 off, look for a device.
    PC's window answered 「自动发现没有运行。点「手输地址…」」: the whole DiscoveryService was built with the
    port and torn down with it (`transfer.py:1484`/`1495-1497`), so finding someone cost binding a receiving
    port and a firewall rule first. `ChuanShu-cli peers` (`app/cli.py:547`) and the phones - where
    `onRecvListenStop()` closes the port and touches neither channel - had always heard without being heard.
    The paper's 「这两通道（广播与听）就跟着开」 described only the opening, and one body read it as a closing.
    """
    root = HERE.parent
    discovery_py = (root / "app" / "net" / "discovery.py").read_text(encoding="utf-8")
    transfer_py = (root / "app" / "ui" / "transfer.py").read_text(encoding="utf-8")
    cli_py = (root / "app" / "cli.py").read_text(encoding="utf-8")
    session = (HERE / "chuanshu" / "store" / "session.uts").read_text(encoding="utf-8")

    spec = (CONTRACT / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 2.", 1)[1].split("\n## ", 1)[0] if "## 2." in spec else ""
    flat = re.sub(r"\s+", "", section)
    for needle, why in (
        ("播的那两路（公告与注册）就跟着开", "which halves ride the listener"),
        ('**而"看见别人"不挂在这上面**', "and which half never did"),
        ("任何一端任何时候都可以只听不播", "hearing without being heard is a first-class mode"),
        ("命令行的 `peers` 就是这一形的标本", "the body that already proves it"),
        ("替一个只想发文件的人决定了他必须先开接收", "the cost the wrong split puts on a person"),
    ):
        if re.sub(r"\s+", "", needle) not in flat:
            fail(f"§2 no longer says {needle!r} - {why}")

    body = json.loads((CONTRACT / "protocol.json").read_text(encoding="utf-8-sig"))
    note = re.sub(r"\s+", " ", body["discovery"]["note"])
    for needle, why in (
        ("Hearing is not one of those halves", "the machine-readable split"),
        ("pay for a port they never needed", "and the reason it is a rule rather than a nicety"),
    ):
        if needle not in note:
            fail(f"discovery.note no longer says {needle!r} - {why}")

    if "def set_port(self, port: int | None) -> None:" not in discovery_py:
        fail("DiscoveryService can no longer be told that the port came or went, which is the one call that "
             "keeps 播 riding the listener without dragging 听 along")
    if "if port is None or self._service_info is not None:" not in discovery_py:
        fail("set_port registers a moved port over the record still held for the old one - §2.1's "
             "撤了再注册 (#204) applies to PC too, and the gate reads exactly that pair of calls")
    if "if self.port is not None:\n            self._spawn(self._announce_loop" in discovery_py:
        fail("the announce thread is back to being the port's servant - `announce()` already answers that "
             "question, and two copies of it drift")
    withdraw = discovery_py.split("def _withdraw_mdns", 1)[1].split("\n    def ", 1)[0] if "def _withdraw_mdns" in discovery_py else ""
    if "self._service_info = None" not in withdraw or "unregister_service" not in withdraw:
        fail("withdrawing the record no longer leaves a clean handle, so a restart would register twice or "
             "the stop would unregister it twice")
    if "browser" not in discovery_py.split("def set_port", 1)[1][:900]:
        fail("set_port no longer names the half it must not touch - the sentence a future reader needs to "
             "keep hearing alive while the port is closed")

    listen = transfer_py.split("def start_listening(self)", 1)[1].split("\n    def ", 1)[0] if "def start_listening(self)" in transfer_py else ""
    if "self._ensure_discovery().set_port(service.port)" not in listen:
        fail("the PC window no longer reports its bound port to a running discovery service")
    stop = transfer_py.split("def stop_listening(self)", 1)[1].split("\n    def ", 1)[0] if "def stop_listening(self)" in transfer_py else ""
    # The ban goes first: `stop()` in here also deletes the `set_port(None)` line, and a FAIL that only says
    # "the announcing halves were not quieted" would blame the wrong thing for the round's own regression.
    if "self._discovery.stop()" in stop:
        fail("stopping 接收 is back to tearing discovery down - that is the split #206 wrote out of the paper: "
             "a person who only wants to send loses 附近设备 with it")
    if "self._discovery.set_port(None)" not in stop:
        fail("stopping 接收 no longer quiets the announcing halves")
    if "自动发现没有运行" in transfer_py:
        fail("the screen still says 自动发现没有运行, a state the app can no longer be in outside construction")
    if 'DiscoveryService(identity, device_name(settings), None)' not in cli_py:
        fail("`ChuanShu-cli peers` is no longer the browse-only specimen §2 points at")

    halt = session.split("export function onRecvListenStop()", 1)[1].split("\n}", 1)[0] if "export function onRecvListenStop()" in session else ""
    if "lanClose" in halt or "toggleDiscovery" in halt or "discStop" in halt:
        fail("the phone now closes the hearing halves with the port too - §2 puts 听 outside that coupling")

    gate = (root / "scripts" / "protocol_selftest.py").read_text(encoding="utf-8")
    legs = len(re.findall(r'check\("§2 (没在监听的一端：浏览与收包都留着|报上端口之后公告与注册一起跟回来|'
                          r'端口换了是撤了旧的再注册新的|关掉监听只撤播的那两路|关掉窗口才是把听也关掉的唯一一刻)', gate)) + \
        len(re.findall(r'check\("§1 (改名时这台没在监听|之后再开监听，注册与公告带的是同一个新名字|'
                       r'开着监听再改名，是撤了旧的再注册新的)', gate))
    if legs < 8:
        fail(f"the gate runs {legs} of the 8 legs that measure which halves `set_port` moves - 播 riding the "
             f"port and 听 staying are two different assertions, and only the legs tell them apart")


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
    check_lost_registration()
    check_pair_shape_local()
    check_token_repair()
    check_second_layer()
    check_pair_refusal()
    check_ask_verdict()
    check_announce_port()
    check_channels_with_listener()
    check_mdns_needs_fp()
    check_record_follows_beat()
    check_mdns_goodbye_names_a_service()
    check_hearing_outlives_the_port()

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
    print("OK  §3's idle reclaim registers the loss by fingerprint on both ends: the kernel carries the number "
          "beside the caption, and the phone's card stops saying 已连接 when its own slot went quiet")
    print("OK  §3 asks a typed-in code and passphrase for their shape before they go on the wire: one alphabet on "
          "PC, both fields on the phone's scan path, and a sender that could never match says why locally")
    print("OK  §3's lost token is repaired by the sender at three PC sites and one kernel funnel: the pair carries "
          "an empty code, the log line is each end's own, and a peer that revoked the trust says so out loud")
    print("OK  §3's second layer binds the sender that writes the field: an omitted `secret` pairs and spends "
          "nothing on every end, so a blank box is said out loud before it goes on the wire")
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
    print("OK  §3's two faces of one refusal are told apart by this end's own empty code: the machine's face asks "
          "for a new code, the typed face asks to re-enter, and both still cost one record in the peer's bucket")
    print("OK  §4's third shape is two shapes: an answered refusal reports what the peer said, an unanswered "
          "question reports the write's own error, on both senders")
    print("OK  §2's announcement names the socket that is open right now: nothing is broadcast and nothing is "
          "registered while a end is not receiving, on the PC's two entry points and all three phone hosts")
    print("OK  §2's channels ride with the listener, not with a screen: they come up when the port opens, a hand "
          "that stops them is honoured for the run, and a channel that cannot start names why and offers the QR")
    print("OK  §2.1's `fp` is not optional: an mDNS record without it is no candidate on any end, and Android "
          "below API 28 reports the whole channel unavailable instead of offering names nothing can pin")
    print("OK  §2.1's record is re-asked on §2.2's beat: a closed listener takes it down, a moved port withdraws "
          "it before registering again, and the PC's build-with-the-listener shape is measured by two gate legs")
    print("OK  §2.1's goodbye names the service, not the machine: all four readers withdraw only that channel "
          "while an unmatched goodbye is left to the 15 s window - PC's two were executed for the first time")
    print("OK  §2 splits 跟着监听 in two: the beat and the record ride the port, the browse and the 43721 "
          "listener do not - the PC window reports its port instead of rebuilding discovery, and the phone's "
          "停止接收 still touches neither channel")
    return 0


if __name__ == "__main__":
    sys.exit(main())
