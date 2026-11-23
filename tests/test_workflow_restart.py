import os
import socket
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from time import monotonic, sleep

from alembic import command
from alembic.config import Config
from httpx2 import Client, TransportError
from test_api import bearer
from test_workflows import brownfield, decision, greenfield, requirements

from app.config import Settings
from app.network.driver import PutStaticRoute
from app.network.policy import Profile


@contextmanager
def server(port: int, settings: Settings) -> Iterator[Client]:
    root = Path(__file__).resolve().parents[1] / "backend"
    environment = {
        **os.environ,
        "NETGUARD_DATABASE_PATH": str(settings.database_path),
        "NETGUARD_PROFILE_PATH": str(settings.profile_path),
        "NETGUARD_VIEWER_TOKEN": settings.viewer_token.get_secret_value(),
        "NETGUARD_ADMIN_TOKEN": settings.admin_token.get_secret_value(),
    }
    with subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:create_app",
            "--factory",
            "--port",
            str(port),
            "--no-access-log",
        ],
        cwd=root,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ) as process:
        try:
            with Client(base_url=f"http://127.0.0.1:{port}", timeout=4) as client:
                deadline = monotonic() + 15
                while monotonic() < deadline and process.poll() is None:
                    try:
                        if client.get("/api/v1/health/ready").status_code == 200:
                            break
                    except TransportError:
                        pass
                    sleep(0.05)
                else:
                    raise AssertionError("Uvicorn did not become ready")
                yield client
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def test_process_restart_preserves_input_and_approval(
    migration_config: Config,
    settings: Settings,
    network_profile: Profile,
    route_change: PutStaticRoute,
) -> None:
    command.upgrade(migration_config, "0002_network_core")
    command.upgrade(migration_config, "head")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]

    admin = bearer(settings.admin_token)
    viewer = bearer(settings.viewer_token)
    with server(port, settings) as original:
        pending = original.post(
            "/api/v1/tasks",
            headers=admin,
            json=brownfield(network_profile, route_change),
        ).json()
        incomplete = original.post(
            "/api/v1/tasks",
            headers=viewer,
            json=greenfield("restart-input", {}),
        ).json()
        assert pending["status"] == "awaiting_approval"
        assert incomplete["status"] == "awaiting_input"

    with server(port, settings) as restarted:
        path = f"/api/v1/tasks/{pending['id']}"
        restored = restarted.get(path, headers=admin).json()
        assert restored["thread_id"] == pending["thread_id"]
        assert restored["plan"] == pending["plan"]
        endpoint, body = decision(restored)
        completed = restarted.post(endpoint, headers=admin, json=body).json()
        assert completed["result"]["post_check"] == "passed"
        assert restarted.post(endpoint, headers=admin, json=body).json() == completed

        continued = restarted.post(
            f"/api/v1/tasks/{incomplete['id']}/input",
            headers=viewer,
            json=requirements(),
        ).json()
        assert continued["thread_id"] == incomplete["thread_id"]
        assert continued["status"] == "succeeded"
        topology = restarted.get(
            f"/api/v1/networks/{network_profile.network.id}/topology",
            headers=viewer,
        ).json()
        assert topology["revision"] == 2
