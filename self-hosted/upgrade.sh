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

# HoundDog.ai refuses to start with a setup key without the hd_setup_ prefix, which earlier installers generated, so
# the upgrade stops here, before anything is pulled or stopped, and says how to fix it.
setup_key="$(awk -F= '$1 == "HOUNDDOG_SETUP_KEY" { sub(/^[^=]*=/, ""); value = $0 } END { print value }' .env)"
setup_key="${setup_key#[\"\']}"
setup_key="${setup_key%[\"\']}"
if [ -n "$setup_key" ] && [[ "$setup_key" != hd_setup_* ]]; then
    fail "HOUNDDOG_SETUP_KEY in .env must start with hd_setup_. If setup is complete, remove that line; otherwise, replace its value with hd_setup_ followed by a random value. Then run ./upgrade.sh again."
fi

# A pinned image version, such as one set to go back after a failed upgrade, would make this upgrade pull that version
# again, so the upgrade stops until the pin is removed. Docker Compose resolves the image as it would run it, from .env
# and the shell alike.
images="$(docker compose config --images)" || fail "Docker Compose cannot read the configuration. Check .env."
pinned_image="$(grep '^hounddogai/hounddog-self-hosted:' <<< "$images" | grep -v ':latest$' | head -n 1 || true)"
if [ -n "$pinned_image" ]; then
    fail "HOUNDDOG_IMAGE_TAG pins HoundDog.ai to ${pinned_image#*:}. Remove it from .env (and your shell) to upgrade to the latest release, then run ./upgrade.sh again."
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
# The version installed before the upgrade is what HOUNDDOG_IMAGE_TAG goes back to if it fails. A failed upgrade has
# already recreated the containers from the new image, so the version is kept in a file until an upgrade succeeds, and
# a rerun reads it from there. Only a released version can be pulled again.
previous_version_file=".upgrade-previous-version"
previous_version="$(cat "$previous_version_file" 2> /dev/null || true)"
if [ -z "$previous_version" ]; then
    api_container="$(docker compose ps --all --quiet api 2> /dev/null | head -n 1 || true)"
    if [ -n "$api_container" ]; then
        previous_version="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$api_container" \
            2> /dev/null | sed -n 's/^HOUNDDOG_VERSION=//p' | head -n 1 || true)"
    fi
fi
rollback_hint=""
if [[ "$previous_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    rollback_hint=" To go back to version ${previous_version}, stop the api, worker, and caddy containers, restore your database backup, set HOUNDDOG_IMAGE_TAG=${previous_version} in .env, and run 'docker compose up -d'."
    printf '%s\n' "$previous_version" > "$previous_version_file"
    say "Upgrading from version ${previous_version}."
fi
say "Pulling the latest images..."
docker compose pull
say "Checking database migrations before stopping containers..."
migration_status=0
docker compose run --rm --no-deps api migrate --check || migration_status=$?
if [[ "$migration_status" != 0 && "$migration_status" != 2 ]]; then
    fail "Database migration check failed. Existing containers remain running. Check database connectivity and migration status before retrying."
fi
api_scale="$(docker compose ps --all --format '{{.Service}}' | awk '$1 == "api" { count++ } END { print count + 0 }')"
worker_scale="$(docker compose ps --all --format '{{.Service}}' | awk '$1 == "worker" { count++ } END { print count + 0 }')"
# Containers removed with `docker compose down` are not listed, so start at least one of each instead of none.
if [ "${api_scale}" -eq 0 ]; then
    api_scale=1
fi
if [ "${worker_scale}" -eq 0 ]; then
    worker_scale=1
fi
scale_args=(--scale "api=${api_scale}" --scale "worker=${worker_scale}")
say "Stopping the web, API, and worker containers before database migration..."
docker compose stop --timeout 900 caddy api worker
say "Applying database migrations with the new image..."
if ! docker compose run --rm --no-deps api migrate; then
    fail "Database migration failed. API and worker containers remain stopped. Fix the migration forward and run ./upgrade.sh again.${rollback_hint}"
fi
say "Updating scan rules with the new image..."
if ! docker compose run --rm --no-deps api update-rules; then
    fail "Scan rule update failed after database migration. Containers remain stopped; rerun the upgrade after correcting the failure.${rollback_hint}"
fi
say "Starting the upgraded containers while keeping Docker volumes..."
if ! docker compose up -d --wait --force-recreate --remove-orphans "${scale_args[@]}"; then
    docker compose ps || true
    # Containers that did start would keep serving, and a restarted API would migrate again, so none keeps running.
    docker compose stop caddy api worker || true
    fail "HoundDog.ai did not start successfully, so it was stopped. Run 'docker compose logs' for details.${rollback_hint}"
fi
# The new release runs, so a later failure, such as of the CLI upgrade below, has nothing to go back to.
rm -f "$previous_version_file"

heading "UPGRADE HOUNDDOG CLI"
curl -fsSL https://raw.githubusercontent.com/hounddogai/hounddog/main/install.sh | sh

export PATH="${HOME}/.hounddog/bin:${PATH}"
command -v hounddog > /dev/null 2>&1 || fail "The HoundDog CLI was upgraded but was not found in PATH."
cli_version="$(hounddog --version)" || fail "The HoundDog CLI was upgraded but could not be run."
[ -n "$cli_version" ] || fail "The HoundDog CLI did not report a version."

heading "UPGRADE COMPLETE"
say "HoundDog.ai has been upgraded."
