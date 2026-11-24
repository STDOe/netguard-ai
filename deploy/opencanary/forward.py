"""Forward selected OpenCanary observations without retaining request content."""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from hashlib import sha256
from hmac import digest
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import NAMESPACE_URL, uuid5

SERVICES = {3000: "http", 3001: "http", 4000: "ssh", 2001: "ftp"}
UTC = timezone.utc  # noqa: UP017 - OpenCanary image runs Python 3.10


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def normalize(raw: dict[str, Any], fixture: bool = False) -> dict[str, Any]:
    occurred = (
        datetime.now(UTC)
        if fixture
        else datetime.strptime(raw["utc_time"], "%Y-%m-%d %H:%M:%S.%f").replace(
            tzinfo=UTC
        )
    )
    payload = {
        "sensor": raw["node_id"],
        "service": SERVICES[raw["logtype"]],
        "source_ip": str(ip_address(raw["src_host"])),
        "destination_ip": str(ip_address(raw["dst_host"])),
        "destination_port": int(raw["dst_port"]),
        "occurred_at": occurred.isoformat(),
        "demo": fixture,
    }
    identity = json.dumps([payload, raw.get("src_port", -1)], sort_keys=True)
    return {"event_id": str(uuid5(NAMESPACE_URL, identity)), **payload}


def send(url: str, secret: str, payload: dict[str, Any]) -> None:
    stamp = str(int(time.time()))
    body = json.dumps(payload, separators=(",", ":")).encode()
    signature = digest(secret.encode(), stamp.encode() + b"." + body, sha256).hex()
    request = Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-NetGuard-Timestamp": stamp,
            "X-NetGuard-Signature": f"sha256={signature}",
        },
    )
    with build_opener(ProxyHandler({}), NoRedirects()).open(request, timeout=3):
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", action="store_true")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    secret = os.environ.pop("NETGUARD_HONEYPOT_SECRET", "")
    if len(secret) < 43:
        sys.exit("Configure a separate NETGUARD_HONEYPOT_SECRET.")
    if args.fixture:
        fixture = json.loads(Path(__file__).with_name("fixture.json").read_text())
        try:
            send(
                f"http://127.0.0.1:{args.port}/api/v1/webhooks/honeypot",
                secret,
                normalize(fixture, True),
            )
        except URLError:
            sys.exit("NetGuard did not accept the fixture.")
        print("Signed offline observation accepted.")
        return

    child = subprocess.Popen(
        ["twistd", "-noy", "/opencanary/bin/opencanary.tac", "--pidfile="],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )

    def shutdown(_number: int, _frame: object) -> None:
        child.terminate()

    signal.signal(signal.SIGTERM, shutdown)
    assert child.stdout is not None
    with child.stdout as stream:
        while line := stream.readline(8193):
            if not line.endswith(b"\n"):
                while line and not line.endswith(b"\n"):
                    line = stream.readline(8193)
                continue
            try:
                payload = normalize(json.loads(line))
                send(
                    "http://netguard-app:8000/api/v1/webhooks/honeypot", secret, payload
                )
            except (ValueError, TypeError, KeyError):
                continue
            except (URLError, TimeoutError):
                print("NetGuard could not accept an observation.", flush=True)
    sys.exit(child.wait())


if __name__ == "__main__":
    main()
