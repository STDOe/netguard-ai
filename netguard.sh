#!/usr/bin/env bash
set +x
set -euo pipefail

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }

usage() {
    printf '%s\n' 'Usage: netguard.sh {install|start|stop|restart|status|logs|doctor}' \
        'Commands use the installation next to this script. Set NETGUARD_PORT in .env to change the port.'
}

case "${1:-}" in
    -h|--help|'') usage; exit 0 ;;
    install|start|stop|restart|status|logs|doctor) action=$1 ;;
    *) usage >&2; fail 'Unknown command.' ;;
esac
[[ $# == 1 ]] || fail 'This command takes no arguments.'
[[ $(uname -s) == Linux && ${BASH_VERSINFO[0]} -ge 4 ]] ||
    fail 'Use Linux with Bash 4 or newer, or netguard.ps1 on Windows.'
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
root=$(pwd -P)
env_file=$root/.env
template=$root/.env.example
[[ -f docker-compose.yml && -f $template ]] || fail 'Run the script from a complete NetGuard checkout.'

# Compose otherwise gives inherited values precedence over the installation file.
for name in ${!NETGUARD_@} ${!COMPOSE_@}; do unset "$name"; done
command -v docker >/dev/null || fail 'Install Docker Engine and Docker Compose v2, then retry.'
docker --version >/dev/null 2>&1 || fail 'Docker CLI failed. Repair the Docker installation.'
version=$(docker compose version --short 2>/dev/null) ||
    fail 'Docker Compose v2 with --wait support is required.'
[[ $version =~ ^v?2\. ]] && docker compose up --help 2>/dev/null | grep -q -- '--wait-timeout' ||
    fail 'Docker Compose v2 with --wait support is required.'
endpoint=${DOCKER_HOST:-}
if [[ -z $endpoint || -n ${DOCKER_CONTEXT:-} ]]; then
    endpoint=$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null) ||
        fail 'Select a local Docker context.'
fi
[[ $endpoint == unix://* ]] || fail 'Select a local Docker context.'
daemon=$(docker info --format '{{.OSType}}' 2>/dev/null) ||
    fail 'Docker daemon is unavailable. Start Docker and check your permissions.'
[[ $daemon == linux ]] || fail 'Docker must run Linux containers.'
if [[ $action == status || $action == doctor ]]; then
    printf '%s\n' "Platform: Linux" "Docker: available" "Compose: $version"
fi

compose() { docker compose --project-directory "$root" --env-file "$env_file" -f "$root/docker-compose.yml" "$@"; }
port=8000
declare -A config=()

read_config() {
    local permissions line key value
    [[ -f $env_file && ! -L $env_file ]] || fail '.env must be a regular file in the installation directory.'
    permissions=$(stat -c '%u:%a' -- "$env_file")
    [[ $permissions == "$(id -u):600" || $permissions == "$(id -u):400" ]] ||
        fail 'Restrict .env to its owner with chmod 600 .env and check its owner.'
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        [[ $line =~ ^[[:space:]]*($|#) ]] && continue
        [[ $line =~ ^(NETGUARD_[A-Z0-9_]+)=(.*)$ ]] ||
            fail 'Invalid .env syntax. Use one literal NETGUARD_NAME=value per line.'
        key=${BASH_REMATCH[1]} value=${BASH_REMATCH[2]}
        [[ -z ${config[$key]+set} && $value != *'$'* && $value != *'#'* &&
            $value != [[:space:]\"\']* && $value != *[[:space:]] ]] ||
            fail 'Invalid or duplicate .env setting. Use literal values without expansion or inline comments.'
        config[$key]=$value
    done < "$env_file"
    [[ ${config[NETGUARD_ADMIN_TOKEN]:-} =~ ^[A-Za-z0-9_-]{43,128}$ &&
        ${config[NETGUARD_VIEWER_TOKEN]:-} =~ ^[A-Za-z0-9_-]{43,128}$ &&
        ${config[NETGUARD_ADMIN_TOKEN]} != "${config[NETGUARD_VIEWER_TOKEN]}" ]] ||
        fail '.env requires distinct, valid Admin and Viewer tokens.'
    [[ ${config[NETGUARD_DEMO_MODE]:-true} == true ]] || fail 'NETGUARD_DEMO_MODE must be true.'
    port=${config[NETGUARD_PORT]:-8000}
    [[ $port =~ ^[1-9][0-9]{0,4}$ && $port -le 65535 ]] ||
        fail 'NETGUARD_PORT must be an integer from 1 to 65535.'
    compose config --quiet >/dev/null 2>&1 || fail 'Docker Compose rejected the configuration. Check .env and docker-compose.yml.'
}

own_port() { [[ $(compose port netguard-app 8000 2>/dev/null || :) == "127.0.0.1:$port" ]]; }

probe_port() {
    own_port && return 0
    local result=0
    timeout 2 bash -c 'exec 3<>"/dev/tcp/127.0.0.1/$1"' bash "$port" 2>/dev/null || result=$?
    [[ $result == 1 ]]
}

create_config() (
    local tmp admin viewer sensor
    umask 077
    tmp=$(mktemp "$root/.env.XXXXXXXX") || fail 'Could not create a private configuration file.'
    trap 'rm -f -- "$tmp"' EXIT
    random_token() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }
    admin=$(random_token) viewer=$(random_token) sensor=$(random_token)
    [[ $admin =~ ^[0-9a-f]{64}$ && $viewer =~ ^[0-9a-f]{64}$ && $sensor =~ ^[0-9a-f]{64}$ &&
        $admin != "$viewer" && $admin != "$sensor" && $viewer != "$sensor" ]] ||
        fail 'Could not generate independent installation tokens.'
    while IFS= read -r line || [[ -n $line ]]; do
        case ${line%$'\r'} in
            NETGUARD_ADMIN_TOKEN=) printf 'NETGUARD_ADMIN_TOKEN=%s\n' "$admin" ;;
            NETGUARD_VIEWER_TOKEN=) printf 'NETGUARD_VIEWER_TOKEN=%s\n' "$viewer" ;;
            NETGUARD_HONEYPOT_SECRET=) printf 'NETGUARD_HONEYPOT_SECRET=%s\n' "$sensor" ;;
            *) printf '%s\n' "${line%$'\r'}" ;;
        esac
    done < "$template" > "$tmp"
    ln -T -- "$tmp" "$env_file" 2>/dev/null || fail 'Could not create .env. Check write permissions or retry if another installer ran.'
)

if [[ ! -e $env_file && ! -L $env_file ]]; then
    case $action in
        install)
            probe_port || fail 'Port 8000 is in use. Stop the listener before installing.'
            create_config
            ;;
        status|doctor)
            printf '%s\n' 'Configuration: missing. Run install first.' 'Image: unknown without configuration.'
            exit 1
            ;;
        *) fail 'Configuration is missing. Run install first.' ;;
    esac
fi
read_config

container_state() {
    local id
    id=$(compose ps -a -q netguard-app 2>/dev/null) || return 1
    [[ -n $id ]] || { printf '%s' 'absent none 0 unknown'; return; }
    docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} {{.State.ExitCode}} {{index .Config.Labels "org.opencontainers.image.version"}}' "$id" 2>/dev/null
}

show_status() {
    local state health exit_code app_version
    read -r state health exit_code app_version < <(container_state) || [[ -n ${state:-} ]] ||
        fail 'Could not inspect the NetGuard container.'
    [[ $app_version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || app_version=unknown
    if [[ $state == running && $health == healthy ]] && ! own_port; then health="port mismatch"; fi
    printf '%s\n' "Container: $state (exit code $exit_code)" "API readiness: $health" \
        "Application version: $app_version" "Dashboard: http://127.0.0.1:$port/" 'Demo Mode: true'
    [[ $state == running && $health == healthy ]]
}

image_available() {
    local image
    image=$(compose config --images netguard-app 2>/dev/null) || return 1
    [[ -n $image ]] && docker image inspect "$image" >/dev/null 2>&1
}

start_service() {
    local mode=$1
    probe_port || fail "Port $port is in use. Stop the listener or change NETGUARD_PORT in .env."
    if ! compose up "${mode}" --pull never --wait --wait-timeout 60 netguard-app >/dev/null 2>&1; then
        show_status || :
        fail 'NetGuard did not become ready. Run logs to check build, migration, or startup errors.'
    fi
    show_status || fail 'NetGuard did not become ready. Run logs to check startup errors.'
}

show_logs() {
    local output line key value
    output=$(compose logs --no-color --tail 100 netguard-app 2>&1) ||
        fail 'Could not read NetGuard logs.'
    while IFS= read -r line; do
        for key in "${!config[@]}"; do
            case $key in *TOKEN*|*SECRET*|*KEY*|*PASSWORD*)
                value=${config[$key]}
                [[ -z $value ]] || line=${line//"$value"/[REDACTED]}
                ;;
            esac
        done
        while [[ $line =~ (ngw\.)?[A-Za-z0-9_-]{43,} ]]; do
            line=${line//"${BASH_REMATCH[0]}"/[REDACTED]}
        done
        printf '%s\n' "$line"
    done <<< "$output"
}

case $action in
    install)
        if image_available; then start_service --no-build; else start_service --build; fi
        printf '%s\n' 'For first sign-in, copy NETGUARD_ADMIN_TOKEN from your private .env in a local editor.'
        ;;
    start|restart)
        image_available || fail 'NetGuard image is missing locally. Run install with registry access to build it.'
        if [[ $action == restart ]]; then
            probe_port || fail "Port $port is in use. Stop the listener or change NETGUARD_PORT in .env."
            compose stop netguard-app >/dev/null 2>&1 || fail 'Could not stop NetGuard.'
        fi
        start_service --no-build
        ;;
    stop)
        compose stop netguard-app >/dev/null 2>&1 || fail 'Could not stop NetGuard.'
        printf '%s\n' 'NetGuard stopped. SQLite data was retained.'
        ;;
    status) show_status || exit 1 ;;
    logs) show_logs ;;
    doctor)
        result=0
        printf '%s\n' 'Configuration: valid' 'Secrets: owner-only permissions'
        if probe_port; then printf 'Port %s: available or in use by NetGuard\n' "$port"
        else printf 'Port %s: occupied. Stop the listener or change NETGUARD_PORT in .env.\n' "$port"; result=1
        fi
        if image_available; then printf '%s\n' 'Image: available locally'
        else printf '%s\n' 'Image: missing. Run install with registry access to build it.'; result=1
        fi
        show_status || { printf '%s\n' 'Run start if stopped, or logs if startup failed.'; result=1; }
        exit "$result"
        ;;
esac
