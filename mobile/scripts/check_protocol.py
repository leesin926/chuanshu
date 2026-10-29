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
    return 0


if __name__ == "__main__":
    sys.exit(main())
