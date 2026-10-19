"""Runs a ReceiveService in its own process so a test can kill it and prove resume.

Prints nothing to stdout (the parent would block on the inherited pipe); everything
the harness needs goes into --port-file as JSON.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.net.identity import load_or_create  # noqa: E402
from app.net.receive import ReceiveService  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--identity", required=True, type=Path)
    ap.add_argument("--root", required=True, type=Path)
    ap.add_argument("--port-file", required=True, type=Path)
    ap.add_argument("--name", default="Receiver-Host")
    ap.add_argument("--decline", action="store_true")
    args = ap.parse_args()

    identity = load_or_create(args.identity)
    decide = (lambda manifest, who: False) if args.decline else (lambda manifest, who: True)
    service = ReceiveService(
        identity,
        args.name,
        decide,
        host="127.0.0.1",
        port=0,
        root=args.root,
    )
    adopted = service.adopt_interrupted_offers()
    port = service.start()
    args.port_file.write_text(
        json.dumps(
            {
                "port": port,
                "peer_id": identity.peer_id,
                "fingerprint": identity.fingerprint,
                "code": service.current_pair_code(),
                "adopted": adopted,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    try:
        while True:
            time.sleep(0.2)
    except KeyboardInterrupt:
        service.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
