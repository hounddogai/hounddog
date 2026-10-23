#!/usr/bin/env bash
#
# Interactive reset for HoundDog.ai Self-Hosted.

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
# Copies a configuration file to a timestamped backup next to it, readable only by you, then deletes the file.
back_up_and_delete() {
    local backup
    backup="$(mktemp "$1.backup.$(date +%Y%m%d-%H%M%S).XXXXXX")"
    cp "$1" "$backup"
    rm -f "$1"
    say "Backed up $1 to ${backup} and deleted it."
}

cli_config_env="${HOME}/.config/hounddog/.env"

heading "CHECK REQUIREMENTS"
say "Checking Docker and Docker Compose..."
command -v docker > /dev/null 2>&1 \
    || fail "Docker is required but was not found. Install it first: https://docs.docker.com/get-docker/"
docker compose version > /dev/null 2>&1 \
    || fail "Docker Compose v2 is required but was not found. Update Docker or install the compose plugin."

if [ ! -e .env ] && [ ! -L .env ]; then
    fail "No installation was found. Run ./install.sh."
fi

heading "RESET HOUNDDOG.AI"
say "Resetting will:"
say "- Stop and remove containers"
say "- Delete local Docker volumes"
say "- Back up and delete the server and CLI configuration"
say "- Start a fresh installation"
if ! grep -Eq '^COMPOSE_PROFILES=.*postgres' .env; then
    say ""
    say "External Postgres data will not be deleted."
    say "Use a new or empty database during installation. Reusing the current one requires HOUNDDOG_SECRET_KEY from"
    say "the configuration backup."
fi
prompt "Reset HoundDog.ai? [y/n, default: n]:"
case "${REPLY:-n}" in
    y | Y | yes | YES) ;;
    *)
        say "Reset cancelled. Nothing was changed."
        exit 0
        ;;
esac

heading "RESET DOCKER COMPOSE"
say "Stopping containers and deleting local Docker volumes..."
docker compose down --volumes --remove-orphans

heading "DELETE CONFIGURATION"
umask 077
back_up_and_delete "$(pwd)/.env"
if [ -e "$cli_config_env" ] || [ -L "$cli_config_env" ]; then
    back_up_and_delete "$cli_config_env"
fi

heading "START FRESH INSTALLATION"
exec ./install.sh
