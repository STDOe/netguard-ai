"""Exercise NetGuard Integration Contract v1 over HTTP."""

import argparse
import hashlib
import ipaddress
import json
import os
from time import monotonic, sleep
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import uuid4


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--disabled", action="store_true")
    parser.add_argument("--device", default="4f3884b3-28b5-5a09-8e8a-e716fa218af3")
    parser.add_argument("--destination", default="10.20.0.0/16")
    args = parser.parse_args()
    parsed = urlsplit(args.base)
    try:
        local = ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        local = parsed.hostname == "localhost"
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or not parsed.hostname
        or not (parsed.scheme == "https" or parsed.scheme == "http" and local)
    ):
        parser.error("Use an HTTPS origin or a loopback HTTP origin.")
    token = os.environ.get("NETGUARD_WORKFORCE_TOKEN")
    if not token and not args.disabled:
        parser.error("Set NETGUARD_WORKFORCE_TOKEN in the client environment.")
    opener = build_opener(ProxyHandler({}), NoRedirects())
    root = args.base.rstrip("/") + "/api/v1/integration"
    workspace = ""

    def call(path, body=None, *, scoped=False, cursor=None, method=None, expected=200):
        url = root + path
        if scoped:
            query = {"workspace_id": workspace}
            if cursor:
                query["cursor"] = cursor
            url += "?" + urlencode(query)
        headers = {"Content-Type": "application/json"} if body is not None else {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = None if body is None else json.dumps(body).encode()
        try:
            with opener.open(
                Request(url, data, headers, method=method), timeout=30
            ) as response:
                status, payload = response.status, json.load(response)
        except HTTPError as error:
            status, payload = error.code, json.load(error)
        except (URLError, TimeoutError):
            raise SystemExit(f"Unable to reach NetGuard for {path}") from None
        if status != expected:
            raise SystemExit(f"Unexpected HTTP {status} for {path}")
        return payload

    if args.disabled:
        response = call("/capabilities", expected=404)
        if response["error"]["code"] != "integration_disabled":
            raise SystemExit("Expected integration_disabled")
        print("Integration is disabled.")
        return
    capabilities = call("/capabilities")
    workspace = capabilities["workspace_id"]
    print(f"{capabilities['schema_version']} {workspace} {capabilities['mode']}")

    def submit(kind, **fields):
        body = {
            "schema_version": "1.0",
            "workspace_id": workspace,
            "task": {"kind": kind, "idempotency_key": str(uuid4()), **fields},
        }
        task = call("/tasks", body, expected=201)
        replay = call("/tasks", body, expected=201)
        if replay["task_id"] != task["task_id"]:
            raise SystemExit("Task ID changed on replay")
        return task

    design = submit(
        "greenfield",
        requirements={
            "organization": "retail",
            "sites": 2,
            "users_per_site": 12,
            "devices_per_site": 8,
            "registers_per_site": 2,
            "throughput_mbps": 100,
            "packets_per_second": 20000,
            "budget_minor": 100000,
            "currency": "USD",
            "vendors": [],
            "region": "US",
            "availability": "single",
            "security": ["segmentation", "payment_isolation"],
            "services": ["dns", "point_of_sale"],
            "address_pool": "10.4.0.0/16",
        },
    )
    path = f"/tasks/{design['task_id']}"
    deadline = monotonic() + 30
    while True:
        design = call(path, scoped=True)
        if design["status"] not in ("queued", "running"):
            break
        if monotonic() >= deadline:
            raise SystemExit("Task polling deadline exceeded")
        sleep(1)
    if design["status"] != "succeeded" or not design["artifacts"]:
        raise SystemExit("Greenfield did not produce exports")
    print(f"Greenfield task {design['task_id']}")
    cursor = None
    while page := call(path + "/events", scoped=True, cursor=cursor):
        if not page["events"]:
            break
        cursor = page["next_cursor"]
        print(f"Received {len(page['events'])} events")
    for link in design["artifacts"]:
        payload = call(f"/artifacts/{link['artifact_id']}", scoped=True)
        if hashlib.sha256(payload["content"].encode()).hexdigest() != link["sha256"]:
            raise SystemExit("Artifact content hash mismatch")
        print(f"Verified {link['name']}")

    network = capabilities["network_id"]
    goal = {
        "kind": "find_static_route",
        "device_id": args.device,
        "destination": args.destination,
    }
    preview = submit("brownfield", network_id=network, goal=goal, dry_run=True)
    if preview["status"] != "succeeded" or not preview["plan"]:
        raise SystemExit("Brownfield dry-run did not produce a plan")
    pending = submit("brownfield", network_id=network, goal=goal, dry_run=False)
    approval_path = f"/approvals/{pending['approval_id']}"
    approval = call(approval_path, scoped=True)
    refused = call(
        approval_path + "/decision",
        {"decision": "approve", "plan_hash": approval["plan_hash"]},
        scoped=True,
        expected=403,
    )
    if refused["error"]["code"] != "not_supported":
        raise SystemExit("Expected the service decision to be unsupported")
    cancelled = call(f"/tasks/{pending['task_id']}/cancel", scoped=True, method="POST")
    if cancelled["status"] != "cancelled":
        raise SystemExit("Cancellation did not complete")
    audit = submit("audit", network_id=network)
    if audit["status"] != "succeeded" or audit["audit"]["evidence_status"] != "valid":
        raise SystemExit("Audit did not produce valid evidence")
    print("Brownfield dry-run, approval denial, cancellation and audit verified.")


if __name__ == "__main__":
    main()
