import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WINDOWS = sys.platform == "win32"
DOCKER_DOUBLE = """
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
state_file = Path(os.environ["INSTALLER_TEST_STATE"])
state = json.loads(state_file.read_text())
mode = state.get("mode")
with state_file.with_suffix(".calls").open("a") as trace:
    trace.write(json.dumps(args) + "\\n")

if args == ["--version"]:
    print("Docker version 29.0.0")
elif args[:2] == ["context", "inspect"]:
    print("npipe:////./pipe/docker_engine" if sys.platform == "win32"
          else "unix:///var/run/docker.sock")
elif args[0] == "info":
    if mode == "daemon":
        sys.exit(1)
    print("linux")
elif args[:2] == ["compose", "version"]:
    if mode == "compose":
        sys.exit(1)
    print("2.40.3")
elif args == ["compose", "up", "--help"]:
    print("--wait-timeout")
elif args[0] == "inspect":
    if args[2] == "{{json .Config.Labels}}":
        print(json.dumps({"org.opencontainers.image.version": "0.1.1"}))
    else:
        values = [state["container"], state["health"], state["exit_code"]]
        separator = "/" if sys.platform == "win32" else " "
        if separator == " ":
            values.append("0.1.1")
        print(separator.join(map(str, values)))
elif args[:2] == ["image", "inspect"]:
    sys.exit(0 if state.get("image") else 1)
elif args[0] == "compose":
    root, config, compose_file = (Path(args[i]) for i in (2, 4, 6))
    if root.name != "checkout with spaces":
        state_file.with_suffix(".reason").write_text("fixture-project-argument")
        sys.exit(2)
    if config != root / ".env" or compose_file != root / "docker-compose.yml":
        state_file.with_suffix(".reason").write_text("fixture-file-arguments")
        sys.exit(2)
    if any(key.startswith(("NETGUARD_", "COMPOSE_")) for key in os.environ):
        state_file.with_suffix(".reason").write_text("fixture-inherited-settings")
        sys.exit(2)
    command, *options = args[7:]
    port = 8000
    if config.exists():
        for line in config.read_text().splitlines():
            if line.startswith("NETGUARD_PORT="):
                port = int(line.partition("=")[2])
    if command == "config" and "--images" in options:
        print("checkout-with-spaces-netguard-app")
    elif command == "port":
        if state.get("container") != "running":
            sys.exit(1)
        print(f"127.0.0.1:{port}")
    elif command == "ps":
        if state.get("container"):
            print("test-container")
    elif command == "up":
        state.update(container="running", health="healthy", exit_code=0, image=True)
        if mode in ("migration", "exit"):
            code = 1 if mode == "migration" else 42
            state.update(container="exited", health="none", exit_code=code)
        if mode == "unready":
            state["health"] = "unhealthy"
        state_file.write_text(json.dumps(state))
        sys.exit(1 if mode in ("migration", "exit", "unready") else 0)
    elif command == "stop":
        state["container"] = "exited"
        state_file.write_text(json.dumps(state))
    elif command == "logs":
        for line in config.read_text().splitlines():
            if line.startswith("NETGUARD_ADMIN_TOKEN="):
                print("fixture log secret " + line.partition("=")[2], file=sys.stderr)
        print("fixture startup details")
    elif command != "config":
        sys.exit(2)
else:
    sys.exit(2)
"""


class Installer:
    def __init__(self, tmp: Path) -> None:
        self.directory = tmp / "checkout with spaces"
        self.directory.mkdir()
        name = "netguard.ps1" if WINDOWS else "netguard.sh"
        for file in (name, "docker-compose.yml", ".env.example"):
            shutil.copy(ROOT / file, self.directory)
        self.env_file = self.directory / ".env"
        self.runner = shutil.which(
            os.environ.get("INSTALLER_POWERSHELL", "pwsh") if WINDOWS else "bash"
        )
        assert self.runner
        self.bin = tmp / "bin with spaces"
        self.bin.mkdir()
        fake = self.bin / "docker_double.py"
        fake.write_text(DOCKER_DOUBLE, encoding="utf-8")
        if WINDOWS:
            (self.bin / "docker.cmd").write_text(
                f'@"{sys.executable}" "{fake}" %*\n', encoding="utf-8"
            )
            self.command = [
                self.runner,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(self.directory / name),
            ]
        else:
            launcher = self.bin / "docker"
            launcher.write_text(
                f'#!/bin/sh\nexec "{sys.executable}" "{fake}" "$@"\n', encoding="utf-8"
            )
            launcher.chmod(0o700)
            for dependency in ("uname", "dirname"):
                path = shutil.which(dependency)
                assert path
                (self.bin / dependency).symlink_to(path)
            self.command = [self.runner, str(self.directory / name)]
        self.state = tmp / "state.json"
        self.state.write_text("{}")
        self.path = str(self.bin) + os.pathsep + os.environ["PATH"]

    def set_mode(self, mode: str) -> None:
        state = json.loads(self.state.read_text())
        state["mode"] = mode
        self.state.write_text(json.dumps(state))

    def run(
        self, action: str, *, missing_docker: bool = False
    ) -> subprocess.CompletedProcess[str]:
        path = str(self.bin) if missing_docker else self.path
        if missing_docker:
            (self.bin / ("docker.cmd" if WINDOWS else "docker")).unlink()
        env = dict(os.environ, PATH=path, INSTALLER_TEST_STATE=str(self.state))
        env.pop("DOCKER_HOST", None)
        env.pop("DOCKER_CONTEXT", None)
        env["NETGUARD_DEMO_MODE"] = "false"
        env["COMPOSE_PROJECT_NAME"] = "unrelated"
        result = subprocess.run(
            [*self.command, action],
            cwd=self.directory.parent,
            env=env,
            capture_output=True,
            text=True,
            timeout=50,
        )

        if WINDOWS and os.environ.get("GITHUB_ACTIONS") == "true":
            diagnostics = []
            reason = self.state.with_suffix(".reason")
            if reason.exists():
                diagnostics.append(reason.read_text())
                reason.unlink()
            acl_error = re.search(
                r"Could not create a private \.env during ([a-z ]+) \(([A-Za-z]+)\)",
                result.stderr,
            )
            if acl_error:
                diagnostics.append(acl_error.group(0))
            if acl_error:
                stage = acl_error.group(1).replace(" ", "-")
                kind = acl_error.group(2)
                with Path(os.environ["GITHUB_OUTPUT"]).open(
                    "a", encoding="utf-8"
                ) as output:
                    output.write(f"config_stage={stage}\nconfig_error={kind}\n")
            for diagnostic in diagnostics:
                print(
                    f"\n::warning title=Windows installer diagnostic::{diagnostic}",
                    flush=True,
                )
        return result

    def calls(self) -> list[list[str]]:
        return [
            json.loads(line)
            for line in self.state.with_suffix(".calls").read_text().splitlines()
        ]


@pytest.fixture
def installer(tmp_path: Path) -> Installer:
    return Installer(tmp_path)


def expect(
    result: subprocess.CompletedProcess[str], success: bool, phrase: str
) -> None:
    assert (result.returncode == 0) is success, (result.stdout, result.stderr)
    assert phrase in result.stdout + result.stderr


def test_no_docker(installer: Installer) -> None:
    expect(installer.run("install", missing_docker=True), False, "Install Docker")
    assert not installer.env_file.exists()


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("daemon", "Docker daemon is unavailable"),
        ("compose", "Docker Compose v2"),
    ],
)
def test_docker_preflight(installer: Installer, mode: str, message: str) -> None:
    installer.set_mode(mode)
    expect(installer.run("install"), False, message)
    assert not installer.env_file.exists()


def test_occupied_port(installer: Installer) -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 8000))
        listener.listen()
        expect(installer.run("install"), False, "Port 8000 is in use")
    assert not installer.env_file.exists()


def test_install_lifecycle_and_redaction(installer: Installer) -> None:
    expect(installer.run("start"), False, "Run install first")
    expect(installer.run("install"), True, "For first sign-in")
    config = installer.env_file.read_bytes()
    values = dict(
        line.split("=", 1)
        for line in config.decode().splitlines()
        if line and not line.startswith("#")
    )
    tokens = [
        values[key]
        for key in (
            "NETGUARD_ADMIN_TOKEN",
            "NETGUARD_VIEWER_TOKEN",
            "NETGUARD_HONEYPOT_SECRET",
        )
    ]
    assert len(set(tokens)) == 3 and all(
        len(bytes.fromhex(token)) == 32 for token in tokens
    )
    assert values["NETGUARD_DEMO_MODE"] == "true"
    assert values["NETGUARD_INTEGRATION_ENABLED"] == "false"
    if not WINDOWS:
        assert installer.env_file.stat().st_mode & 0o777 == 0o600
    for action, phrase in [
        ("install", "For first sign-in"),
        ("status", "Application version: 0.1.1"),
        ("doctor", "Image: available locally"),
        ("logs", "[REDACTED]"),
        ("stop", "SQLite data was retained"),
        ("start", "API readiness: healthy"),
        ("restart", "API readiness: healthy"),
    ]:
        result = installer.run(action)
        expect(result, True, phrase)
        assert all(token not in result.stdout + result.stderr for token in tokens)
        assert installer.env_file.read_bytes() == config
    calls = installer.calls()
    ups = [call[8:] for call in calls if len(call) > 7 and call[7] == "up"]
    assert "--build" in ups[0]
    assert all(
        "--no-build" in up and up[up.index("--pull") + 1] == "never" for up in ups[1:]
    )
    assert all(
        not {"down", "--volumes", "rm", "prune"}.intersection(call) for call in calls
    )


@pytest.mark.skipif(not WINDOWS, reason="Requires Windows NTFS ACL APIs")
def test_windows_private_config_acl(installer: Installer) -> None:
    expect(installer.run("install"), True, "For first sign-in")
    before = installer.env_file.read_bytes()
    assert installer.runner
    result = subprocess.run(
        [
            installer.runner,
            "-NoProfile",
            "-Command",
            """
            $ErrorActionPreference = 'Stop'
            $file = $env:INSTALLER_TEST_ENV_FILE
            $id = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $acl = Get-Acl -LiteralPath $file
            $sid = [Security.Principal.SecurityIdentifier]
            $allow = @($acl.GetAccessRules($true, $true, $sid) |
                Where-Object { $_.AccessControlType -eq 'Allow' } |
                ForEach-Object { $_.IdentityReference.Value } |
                Sort-Object -Unique)
            if (-not $acl.AreAccessRulesProtected -or
                $acl.GetOwner($sid).Value -ne $id -or $allow.Count -ne 2 -or
                $allow -notcontains $id -or $allow -notcontains 'S-1-5-18') {
                throw 'Unexpected .env owner or ACL'
            }
            $everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $everyone, 'Read', 'Allow'
            )
            $acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $file -AclObject $acl
            """,
        ],
        env=dict(os.environ, INSTALLER_TEST_ENV_FILE=str(installer.env_file)),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    expect(installer.run("install"), False, "Restrict .env access")
    assert installer.env_file.read_bytes() == before


def test_invalid_config_preserved(installer: Installer) -> None:
    expect(installer.run("install"), True, "For first sign-in")
    original = installer.env_file.read_text()
    forged = original + "NETGUARD_ADMIN_TOKEN=$(touch should-not-exist)\n"
    installer.env_file.write_text(forged)
    expect(installer.run("install"), False, "Invalid or duplicate")
    assert installer.env_file.read_text() == forged
    assert not (installer.directory / "should-not-exist").exists()


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("migration", "exited (exit code 1)"),
        ("exit", "exited (exit code 42)"),
        ("unready", "API readiness: unhealthy"),
    ],
)
def test_failed_install(installer: Installer, mode: str, message: str) -> None:
    installer.set_mode(mode)
    result = installer.run("install")
    expect(result, False, message)
    assert "For first sign-in" not in result.stdout
    assert installer.env_file.exists()
