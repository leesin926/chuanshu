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
    for needle, who in (("app/net/send.py:522-539", "the PC sender"), ("cs-client.uts:480-539", "the phone sender")):
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
    legs = len(re.findall(r"check\(\s*'§4 (待决|中止|接受|那句|落齐)", harness))
    if legs < 8:
        fail(f"the receiving kernel has {legs} §4 reply legs - the shared kernel needs to answer all three "
             "shapes itself, not only trust this guard")


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
    check_manifest_fields()
    check_finalize_reply()
    check_offer_reply_shapes()

    print(f"OK  protocol v{body['protocol_version']} from {stamp['source_repo']}@{stamp['source_commit'][:8]}")
    print(f"OK  {len(body['error_codes'])} error codes, {len(body['endpoints'])} endpoints, chunk {chunk // 1024} KiB")
    print(f"OK  pair code: {digits} digits, {ttl}s each"
          + (", fixed until rotated by hand" if body["transport"]["pair_code_static"] else "")
          + f", {body['transport']['passphrase_chars']}-char passphrase")
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
    print("OK  §4's manifest block is the wire: both senders' keys, and no receiver acts on total_size")
    print("OK  §4's finalize reply is one shape on paper and in both receivers; `missing` is who both senders resend by")
    print("OK  §4's three offer replies are one shape on paper and in all four bodies; the abort knows the question still open")
    return 0


if __name__ == "__main__":
    sys.exit(main())
