#!/usr/bin/env bash
#
# Interactive installer for HoundDog.ai Self-Hosted.

set -euo pipefail

cd "$(dirname "$0")"

cli_config_temp=""
server_env_temp=""
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
    if [ "${3:-true}" = "true" ]; then
        say ""
    fi
    if [ "${2:-false}" = "true" ]; then
        read -r -s -p "${color_prompt}$1${color_reset} " REPLY
        say ""
    else
        read -r -p "${color_prompt}$1${color_reset} " REPLY
    fi
}

cleanup() {
    if [ -n "$cli_config_temp" ]; then
        rm -f "$cli_config_temp"
    fi
    if [ -n "$server_env_temp" ]; then
        rm -f "$server_env_temp"
    fi
}
trap cleanup EXIT

generate_secret() {
    # $1 = number of random bytes; prints them base64url-encoded without padding or newlines.
    if command -v openssl > /dev/null 2>&1; then
        openssl rand -base64 "$1" | tr -d '\n=' | tr '+/' '-_'
    else
        head -c "$1" /dev/urandom | base64 | tr -d '\n=' | tr '+/' '-_'
    fi
}

hash_secret() {
    if command -v openssl > /dev/null 2>&1; then
        printf '%s' "$1" | openssl dgst -sha256 -r | awk '{print $1}'
    elif command -v shasum > /dev/null 2>&1; then
        printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
    elif command -v sha256sum > /dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    else
        fail "openssl, shasum, or sha256sum is required."
    fi
}

install_cli() {
    heading "INSTALL HOUNDDOG CLI"
    curl -fsSL https://raw.githubusercontent.com/hounddogai/hounddog/main/install.sh | sh

    export PATH="${HOME}/.hounddog/bin:${PATH}"
    command -v hounddog > /dev/null 2>&1 || fail "The HoundDog CLI was installed but was not found in PATH."
    cli_version="$(hounddog --version)" || fail "The HoundDog CLI was installed but could not be run."
    [ -n "$cli_version" ] || fail "The HoundDog CLI did not report a version."
}

ensure_database() {
    if docker compose exec -T api python manage.py migrate --check > /dev/null 2>&1; then
        return
    fi

    heading "UPDATE DATABASE"
    say "Applying database migrations..."
    docker compose exec -T api python manage.py migrate --noinput
    say "Updating scan rules..."
    docker compose exec -T api python manage.py update_rules
}

cli_config_dir() {
    printf '%s/.config/hounddog\n' "$HOME"
}

heading "CHECK REQUIREMENTS"
say "Checking Docker, Docker Compose, and local tools..."
command -v docker > /dev/null 2>&1 \
    || fail "Docker is required but was not found. Install it first: https://docs.docker.com/get-docker/"
docker compose version > /dev/null 2>&1 \
    || fail "Docker Compose v2 is required but was not found. Update Docker or install the compose plugin."
command -v awk > /dev/null 2>&1 \
    || fail "awk is required to install the HoundDog CLI."
command -v curl > /dev/null 2>&1 \
    || fail "curl is required to install the HoundDog CLI."

if [ -e .env ] || [ -L .env ]; then
    heading "EXISTING INSTALLATION FOUND"
    say "Upgrading keeps your configuration and Docker volumes."
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
    if ! management_commands="$(docker compose run --rm --no-deps api python manage.py help --commands)"; then
        fail "Could not inspect the management commands in the pulled API image. The existing application is still running."
    fi
    has_ropa_preflight=false
    if grep -Fxq preflight_ropa_normalization <<< "${management_commands}"; then
        has_ropa_preflight=true
        say "Checking whether existing RoPA reports can be migrated..."
        if ! docker compose run --rm --no-deps api python manage.py preflight_ropa_normalization; then
            fail "RoPA migration preflight failed. The existing application is still running; correct the reported reports before retrying."
        fi
    else
        say "The pulled image predates the RoPA storage cutover; continuing with its normal migration path."
    fi
    say "Stopping the web and API containers before database migration..."
    docker compose stop caddy api
    if [ "${has_ropa_preflight}" = "true" ]; then
        docker compose run --rm --no-deps api python manage.py preflight_ropa_normalization \
            || fail "RoPA migration preflight changed while the API was stopping. The old worker remains available to finish a raced import. If the error names an active review, run 'docker compose start api caddy', resolve or delete that review, and retry the upgrade."
    fi
    say "Stopping worker containers before database migration..."
    docker compose stop worker
    if [ "${has_ropa_preflight}" = "true" ]; then
        docker compose run --rm --no-deps api python manage.py preflight_ropa_normalization \
            || fail "RoPA migration preflight changed while workers were stopping. Containers remain stopped; correct the reported reports before retrying."
    fi
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

    install_cli

    heading "UPGRADE COMPLETE"
    say "HoundDog.ai has been upgraded."
    exit 0
fi

heading "CHOOSE INSTALLATION"
say "1) Trial: Uses the bundled Postgres and creates a CLI API key."
say "2) Production: Uses your Postgres server."
while :; do
    prompt "Choose 1 or 2 [default: 1]:"
    install_type="${REPLY:-1}"
    case "$install_type" in
        1 | 2) break ;;
        *) say "Please enter 1 or 2." ;;
    esac
done

while :; do
    prompt "Port [default: 3300]:" false false
    hounddog_port="${REPLY:-3300}"
    case "$hounddog_port" in
        *[!0-9]* | "") say "Enter a port from 1 to 65535." ;;
        *)
            if [ "$hounddog_port" -ge 1 ] && [ "$hounddog_port" -le 65535 ]; then
                break
            fi
            say "Enter a port from 1 to 65535."
            ;;
    esac
done

hounddog_url="http://localhost:${hounddog_port}"
postgres_url=""
postgres_user="hounddog"
postgres_database="hounddog"
postgres_password="$(generate_secret 32)"
personal_api_key=""
personal_api_key_id=""
personal_api_key_hash=""
personal_api_key_prefix=""

heading "GENERATE SECRETS"
say "Generating the encryption key and one-time setup key..."
secret_key="$(generate_secret 48)"
setup_key="$(generate_secret 48)"
if [ "$install_type" = "1" ]; then
    say "Generating a Postgres password and personal CLI API key..."
    # Compose expands these placeholders when it reads the generated .env file.
    # shellcheck disable=SC2016
    postgres_url='postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}'
    personal_api_key="hd_pk_$(generate_secret 32)"
    personal_api_key_id="$(generate_secret 24)"
    personal_api_key_hash="$(hash_secret "$personal_api_key")"
    personal_api_key_prefix="${personal_api_key:0:16}"
else
    say "Production installs create their CLI API key in the web app after setup."
    say ""
    say "Enter your Postgres connection URL in this form:"
    say "postgres://USER:PASSWORD@HOST:PORT/DATABASE"
    while :; do
        prompt "Postgres URL:" true
        postgres_url="$REPLY"
        case "$postgres_url" in
            *"'"*) say "Percent-encode single quotes in the Postgres URL." ;;
            postgres://* | postgresql://*) break ;;
            *) say "Enter a URL starting with postgres:// or postgresql://." ;;
        esac
    done
fi

heading "GENERATE CONFIGURATION"
say "Creating $(pwd)/.env for Docker Compose..."
umask 077
server_env_temp="$(mktemp "$(pwd)/.env.tmp.XXXXXX")"
{
    printf '# Generated by install.sh. Keep this file private: it contains secrets.\n\n'
    printf 'HOUNDDOG_SECRET_KEY=%s\n' "$secret_key"
    printf 'HOUNDDOG_SETUP_KEY=%s\n\n' "$setup_key"
    printf 'HOUNDDOG_PORT=%s\n' "$hounddog_port"
    printf 'HOUNDDOG_URL=%s\n\n' "$hounddog_url"
    if [ "$install_type" = "1" ]; then
        printf 'COMPOSE_PROFILES=postgres\n'
        printf 'POSTGRES_USER=%s\n' "$postgres_user"
        printf 'POSTGRES_PASSWORD=%s\n' "$postgres_password"
        printf 'POSTGRES_DB=%s\n' "$postgres_database"
        printf 'HOUNDDOG_POSTGRES_URL=%s\n\n' "$postgres_url"
        printf 'HOUNDDOG_INITIAL_PERSONAL_API_KEY_ID=%s\n' "$personal_api_key_id"
        printf 'HOUNDDOG_INITIAL_PERSONAL_API_KEY_HASH=%s\n' "$personal_api_key_hash"
        printf 'HOUNDDOG_INITIAL_PERSONAL_API_KEY_PREFIX=%s\n' "$personal_api_key_prefix"
    else
        printf "HOUNDDOG_POSTGRES_URL='%s'\n" "$postgres_url"
    fi
} > "$server_env_temp"
mv "$server_env_temp" .env
server_env_temp=""

config_dir="$(cli_config_dir)"
config_env="${config_dir}/.env"
say "Creating ${config_env} for the HoundDog CLI..."
mkdir -p "$config_dir"
chmod 700 "$config_dir"
if [ -e "$config_env" ] || [ -L "$config_env" ]; then
    config_backup="$(mktemp "${config_env}.backup.$(date +%Y%m%d-%H%M%S).XXXXXX")"
    cp "$config_env" "$config_backup"
    chmod 600 "$config_backup"
    rm -f "$config_env"
    say "Backed up $config_env to $config_backup."
fi
cli_config_temp="$(mktemp "${config_dir}/.env.tmp.XXXXXX")"
{
    printf "export HOUNDDOG_ENV='self-hosted'\n"
    printf "export HOUNDDOG_URL='%s'\n" "$hounddog_url"
    printf "export HOUNDDOG_API_KEY='%s'\n" "$personal_api_key"
} > "$cli_config_temp"
chmod 600 "$cli_config_temp"
mv "$cli_config_temp" "$config_env"
cli_config_temp=""

heading "START DOCKER COMPOSE"
say "Starting Docker Compose and waiting for HoundDog.ai to become ready..."
if ! docker compose up -d --wait; then
    docker compose ps || true
    fail "HoundDog.ai did not start successfully. Run 'docker compose logs' for details."
fi

ensure_database

heading "INSTALLATION COMPLETE"
say "HoundDog.ai is running at ${hounddog_url}."
say "Server configuration: $(pwd)/.env"
say "CLI configuration: ${config_env}"

install_cli

heading "NEXT STEPS"
say "1. Open ${hounddog_url} and create your organization and owner account."
if [ -t 1 ]; then
    say "2. Use the one-time setup key ${setup_key}."
else
    say "2. Open .env and use HOUNDDOG_SETUP_KEY when prompted."
fi
if [ "$install_type" = "1" ]; then
    say "3. Open a new terminal after setup and run: hounddog scan /path/to/repository"
else
    say "3. Create a personal API key in HoundDog.ai and add it to ${config_env}."
    say "4. Open a new terminal and run: hounddog scan /path/to/repository"
fi
