#!/usr/bin/env bash
#
# Interactive upgrade for HoundDog.ai Self-Hosted.

set -euo pipefail

cd "$(dirname "$0")"

color_heading=""
color_error=""
color_prompt=""
color_reset=""
if { [ -t 1 ] || [ -t 2 ]; } && [ "${TERM:-dumb}" != "dumb" ] && [ -z "${NO_COLOR:-}" ]; then
    color_heading=$'\033[1;36m'
    color_error=$'\033[0;31m'
    color_prompt=$'\033[1;35m'
    color_reset=$'\033[0m'
fi

say() { printf '%s\n' "$*"; }
heading() { printf '\n%s%s%s\n' "$color_heading" "$*" "$color_reset"; }
fail() {
    printf '%sERROR:%s %s\n' "$color_error" "$color_reset" "$*" >&2
    exit 1
}
prompt() {
    say ""
    read -r -p "${color_prompt}$1${color_reset} " REPLY
}

heading "CHECK REQUIREMENTS"
say "Checking Docker, Docker Compose, and local tools..."
command -v docker > /dev/null 2>&1 \
    || fail "Docker is required but was not found. Install it first: https://docs.docker.com/get-docker/"
docker compose version > /dev/null 2>&1 \
    || fail "Docker Compose v2 is required but was not found. Update Docker or install the compose plugin."
command -v awk > /dev/null 2>&1 \
    || fail "awk is required to upgrade HoundDog.ai."
command -v curl > /dev/null 2>&1 \
    || fail "curl is required to upgrade the HoundDog CLI."

if [ ! -e .env ] && [ ! -L .env ]; then
    fail "No installation was found. Run ./install.sh."
fi

heading "UPGRADE HOUNDDOG.AI"
say "Upgrading keeps your configuration and Docker volumes."
say "Take a database backup first. HoundDog.ai is unavailable while the database migrates."
prompt "Upgrade HoundDog.ai? [y/n, default: y]:"
case "${REPLY:-y}" in
    y | Y | yes | YES) ;;
    *)
        say "Upgrade cancelled. Nothing was changed."
        exit 0
        ;;
esac

heading "UPGRADE DOCKER COMPOSE"
say "Pulling the latest images..."
docker compose pull
api_scale="$(docker compose ps --all --format '{{.Service}}' | awk '$1 == "api" { count++ } END { print count + 0 }')"
worker_scale="$(docker compose ps --all --format '{{.Service}}' | awk '$1 == "worker" { count++ } END { print count + 0 }')"
if [ "${api_scale}" -eq 0 ]; then
    api_scale=1
fi
scale_args=(--scale "api=${api_scale}" --scale "worker=${worker_scale}")
say "Stopping the web, API, and worker containers before database migration..."
docker compose stop caddy api worker
say "Applying database migrations with the new image..."
if ! docker compose run --rm --no-deps \
    -e PGOPTIONS="-c lock_timeout=5s" \
    api python manage.py migrate --noinput; then
    fail "Database migration failed. API and worker containers remain stopped. Fix the migration forward or restore your pre-upgrade database backup before restarting the previous release."
fi
say "Updating scan rules with the new image..."
if ! docker compose run --rm --no-deps api python manage.py update_rules; then
    fail "Scan rule update failed after database migration. Containers remain stopped; rerun the upgrade after correcting the failure."
fi
say "Starting the upgraded containers while keeping Docker volumes..."
if ! docker compose up -d --wait --force-recreate --remove-orphans "${scale_args[@]}"; then
    docker compose ps || true
    fail "HoundDog.ai did not start successfully. Run 'docker compose logs' for details."
fi

heading "UPGRADE HOUNDDOG CLI"
curl -fsSL https://raw.githubusercontent.com/hounddogai/hounddog/main/install.sh | sh

export PATH="${HOME}/.hounddog/bin:${PATH}"
command -v hounddog > /dev/null 2>&1 || fail "The HoundDog CLI was upgraded but was not found in PATH."
cli_version="$(hounddog --version)" || fail "The HoundDog CLI was upgraded but could not be run."
[ -n "$cli_version" ] || fail "The HoundDog CLI did not report a version."

heading "UPGRADE COMPLETE"
say "HoundDog.ai has been upgraded."
