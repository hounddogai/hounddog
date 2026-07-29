#!/usr/bin/env bash
#
# Interactive uninstaller for HoundDog.ai Self-Hosted.

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

cli_config_env="${HOME}/.config/hounddog/.env"

heading "CHECK REQUIREMENTS"
say "Checking Docker and Docker Compose..."
command -v docker > /dev/null 2>&1 \
    || fail "Docker is required but was not found. Install it first: https://docs.docker.com/get-docker/"
docker compose version > /dev/null 2>&1 \
    || fail "Docker Compose v2 is required but was not found. Update Docker or install the compose plugin."

if [ ! -e .env ] && [ ! -L .env ]; then
    say "No installation was found. Nothing to uninstall."
    exit 0
fi

heading "UNINSTALL HOUNDDOG.AI"
say "Uninstalling will:"
say "- Stop and remove containers"
say "- Delete local Docker volumes"
say "- Delete active server and CLI configuration"
say "- Keep configuration backups, the CLI, and Docker images"
if ! grep -Eq '^COMPOSE_PROFILES=.*postgres' .env; then
    say ""
    say "External Postgres data will not be deleted."
fi
prompt "Uninstall HoundDog.ai? [y/n, default: n]:"
case "${REPLY:-n}" in
    y | Y | yes | YES) ;;
    *)
        say "Uninstall cancelled. Nothing was changed."
        exit 0
        ;;
esac

heading "REMOVE DOCKER COMPOSE"
say "Removing containers and local Docker volumes..."
docker compose down --volumes --remove-orphans

heading "DELETE CONFIGURATION"
say "Deleting $(pwd)/.env..."
rm -f .env
say "Deleting ${cli_config_env}..."
rm -f "$cli_config_env"

heading "UNINSTALL COMPLETE"
say "HoundDog.ai Self-Hosted has been uninstalled."
