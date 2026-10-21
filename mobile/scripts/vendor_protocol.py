"""Re-copy the protocol contract from the PC side into mobile/shared/protocol and restamp it.

The contract is read-only here; editing it in the vendored copy is what the stamp exists to catch.
This is the only supported way to refresh it. stdlib only.

    python scripts/vendor_protocol.py [--source <path/to/protocol>]
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
TARGET = HERE / "shared" / "protocol"
FILES = ("protocol.json", "spec.md")


def git(*args: str) -> str:
    result = subprocess.run(("git", *args), cwd=HERE, capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=None, help="directory holding protocol.json and spec.md")
    source = parser.parse_args().source or HERE.parent / "protocol"
    for name in FILES:
        if not (source / name).is_file():
            print(f"FAIL  {source / name} not found", file=sys.stderr)
            return 1

    TARGET.mkdir(parents=True, exist_ok=True)
    digest = {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in FILES}
    for name in FILES:
        (TARGET / name).write_bytes((source / name).read_bytes())

    body = json.loads((source / "protocol.json").read_text(encoding="utf-8-sig"))
    stamp = {
        "schema": 1,
        "purpose": "本目录是从 PC 端仓库 vendored 过来的协议契约，手机端只读不改。改协议先去 PC 端改 protocol/，再运行 scripts/vendor_protocol.py 重新 vendor。",
        "source_repo": "chuanshu-pc",
        "source_commit": git("rev-parse", "HEAD"),
        "source_dirty": bool(git("status", "--porcelain", "--", ":/protocol")),
        "protocol_version": body["protocol_version"],
        "vendored_at": dt.date.today().isoformat(),
        "files": digest,
    }
    (TARGET / "SOURCE.json").write_text(json.dumps(stamp, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"OK  vendored {len(FILES)} files from {source} @ {stamp['source_commit'][:8]}"
          f"{' (working tree, uncommitted)' if stamp['source_dirty'] else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
