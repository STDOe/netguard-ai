#!/usr/bin/env bash
set -euo pipefail
umask 077

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
tmp=$(mktemp -d)
project_dir="$tmp/netguard installer ${tmp##*.}"
mkdir -- "$project_dir"
cp -p -- "$root/netguard.sh" "$root/docker-compose.yml" "$root/.env.example" "$project_dir/"
mkdir -- "$project_dir/backend"
for name in Dockerfile .dockerignore pyproject.toml uv.lock alembic.ini app config migrations; do
    cp -a -- "$root/backend/$name" "$project_dir/backend/"
done

test_ca=${NETGUARD_TEST_BUILD_CA:-}
for name in ${!NETGUARD_@} ${!COMPOSE_@}; do unset "$name"; done
compose() { docker compose --project-directory "$project_dir" --env-file "$project_dir/.env" -f "$project_dir/docker-compose.yml" "$@"; }
cleanup() {
    # This randomly named project and its data belong exclusively to the smoke test.
    if [[ -f "$project_dir/.env" ]]; then compose down --volumes --rmi local >/dev/null 2>&1 || :; fi
    rm -rf -- "$tmp"
}
trap cleanup EXIT

if [[ -n $test_ca ]]; then
    # Trust the runner's CA for registry access. Production Compose is unchanged.
    export NETGUARD_TEST_BUILD_CA=$test_ca
    cat > "$project_dir/ca.yml" <<'YAML'
services:
  netguard-app:
    build:
      secrets: [netguard_ca]
secrets:
  netguard_ca:
    file: ${NETGUARD_TEST_BUILD_CA:?}
YAML
    NETGUARD_ADMIN_TOKEN=unused NETGUARD_VIEWER_TOKEN=unused docker compose \
        --project-directory "$project_dir" -f "$project_dir/docker-compose.yml" \
        -f "$project_dir/ca.yml" build netguard-app
fi

"$project_dir/netguard.sh" install
sha=$(sha256sum "$project_dir/.env")
compose exec -T netguard-app python -c '
import sqlite3
with sqlite3.connect("/var/lib/netguard/netguard.sqlite3") as connection:
    connection.execute("CREATE TABLE installer_smoke (value TEXT)")
    connection.execute("INSERT INTO installer_smoke VALUES (?)", ("retained",))
'
"$project_dir/netguard.sh" install
"$project_dir/netguard.sh" stop
"$project_dir/netguard.sh" start
"$project_dir/netguard.sh" restart
"$project_dir/netguard.sh" doctor
[[ $sha == "$(sha256sum "$project_dir/.env")" ]]
compose exec -T netguard-app python -c '
import sqlite3
with sqlite3.connect("/var/lib/netguard/netguard.sqlite3") as connection:
    assert connection.execute("SELECT value FROM installer_smoke").fetchone() == ("retained",)
'
grep -Fxq 'NETGUARD_INTEGRATION_ENABLED=false' "$project_dir/.env"
# A deliberately invalid migration revision in this disposable database must fail closed.
"$project_dir/netguard.sh" stop
compose run --rm --no-deps --pull never --entrypoint python netguard-app -c '
import sqlite3
with sqlite3.connect("/var/lib/netguard/netguard.sqlite3") as connection:
    connection.execute("UPDATE alembic_version SET version_num = ?", ("installer_invalid_revision",))
'
if "$project_dir/netguard.sh" install > "$tmp/failed-install" 2>&1; then
    printf '%s\n' 'Installer incorrectly accepted a failed migration.' >&2
    exit 1
fi
grep -Fq 'did not become ready' "$tmp/failed-install"
! grep -Fq 'For first sign-in' "$tmp/failed-install"
printf '%s\n' 'Installer smoke passed. SQLite contents and configuration persisted. Migration failure was reported.'
