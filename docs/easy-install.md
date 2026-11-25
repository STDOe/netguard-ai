# Install NetGuard AI v0.1.1

NetGuard AI runs a standalone mock network on your machine. Docker builds the
application, applies SQLite migrations on startup and checks API readiness.
Install Docker separately and keep it running. The installer uses the files
beside the script, so it can run from any working directory, including when
the checkout path contains spaces.

## Windows quickstart

Use Windows 10 or 11 with Docker Desktop using the WSL 2 backend and Linux
containers. In Windows PowerShell 5.1 or PowerShell 7, open the extracted
source directory and run:

```powershell
.\netguard.ps1 install
.\netguard.ps1 status
```

If Windows blocks a downloaded script, review the source and unblock that
specific file with `Unblock-File -LiteralPath .\netguard.ps1`, subject to your
organization's execution policy. Use a local NTFS directory.

## Linux quickstart

Use Bash 4 or later, GNU core utilities, Docker Engine and Docker Compose v2
with `up --wait`. The current user needs access to the local Docker daemon.

```bash
./netguard.sh install
./netguard.sh status
```

## First sign-in and daily commands

Open the loopback Dashboard URL printed by the installer. In a local editor
open the private `.env` beside the script and copy `NETGUARD_ADMIN_TOKEN` into
the sign-in form. Use `NETGUARD_VIEWER_TOKEN` for read-only access. Keep both
tokens private.

| Command | Behavior |
| --- | --- |
| `install` | Creates private configuration if it is missing, uses the local image or builds it if missing, and waits for readiness. |
| `start` | Starts the existing configuration from the local image and waits for readiness. |
| `stop` | Stops the application container and keeps the SQLite volume. |
| `restart` | Stops and starts the application container and checks readiness. |
| `status` | Shows Docker, app state, API readiness, version from the running image label when available, and the Dashboard URL. Exits nonzero when unavailable. |
| `logs` | Shows the last 100 application log lines with configured credentials and long token-like strings masked. |
| `doctor` | Checks the platform, Docker, Compose, daemon, configuration, permissions, port, local image and readiness. Exits nonzero if a check fails. |

For example, run `./netguard.sh doctor` or `.\netguard.ps1 logs` from your
checkout. The installer manages the `netguard-app` service. The optional
OpenCanary profile can be managed separately through Docker Compose.

## Troubleshooting and data retention

- **Docker unavailable.** Install Docker and Compose v2 if missing. Start the
  daemon or Docker Desktop, verify daemon permissions, and select a local
  Linux-container context. Remote Docker contexts are outside this workflow.
- **Port occupied.** Close the listener before the initial install. For an
  existing installation, set `NETGUARD_PORT=18000` (or another available port)
  in `.env` and run `start`. Compose publishes to `127.0.0.1` only.
- **Unreadable or invalid configuration.** Correct the existing `.env` in a
  local editor. Keep one literal uppercase `NETGUARD_NAME=value` per line.
  Use standalone comment lines and plain values without interpolation, outer
  quotes or trailing spaces. The CLI uses this file in preference to inherited
  `NETGUARD_*` and `COMPOSE_*` variables. Keep `NETGUARD_DEMO_MODE=true`.
  Workforce integration starts disabled.
- **Secret file permissions.** On Linux, `chmod 600 .env` as its owner. On
  Windows, use **Properties → Security → Advanced** to set your user as owner,
  disable inheritance and grant access only to your account and SYSTEM.
  Keep `.env` in a private directory and outside version control.
- **Image missing.** Run `install` with registry access to build from the
  checkout. Subsequent starts use the local image with pulling and building
  disabled. An existing cached image is reused by `install`.
- **Build, migration, container exit or readiness failure.** A failed install
  exits nonzero. Run `doctor` and `logs`. For a build that produced no
  container, inspect Docker's build diagnostics locally before retrying.
- **Keep the installation directory and Docker context stable.** Compose
  derives the project name and volume from the checkout directory. Moving
  or renaming the checkout can select a different volume. The installer
  preserves `.env`, tokens, and the volume across repeat installs and
  stop/start. See the recovery guide before moving data.
  [Deployment security and recovery](deployment-security.md)

This installer targets the single-instance mock MVP. Real device access,
production HA and interoperability with a real Workforce OS deployment are
unverified. The Windows CI matrix exercises the PowerShell command contract against a
simulated Docker CLI. A real Docker Desktop and WSL 2 startup needs a Windows
host.
