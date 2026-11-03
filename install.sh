#!/bin/sh
set -e  # Exit on error
set -u  # Exit on using unset variable

echo "Installing HoundDog CLI ..."

TEMP_DIR=""
PENDING_INSTALL_PATH=""

cleanup() {
    if [ -n "$PENDING_INSTALL_PATH" ]; then
        rm -rf "$PENDING_INSTALL_PATH" > /dev/null 2>&1
    fi
    if [ -n "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR" > /dev/null 2>&1
    fi
}

abort() {
    echo "$@" 1>&2
    exit 1
}

trap cleanup 0
trap 'cleanup; exit 1' HUP INT TERM

usage() {
    cat <<EOF
Usage: sh install.sh [--version VERSION]

Options:
  -v, --version VERSION  Install a specific release version, and turn automatic
                         updates off so that it stays.
                         Allowed formats: x.y.z, x.y.z-alpha, x.y.z-beta.
                         Do not include a leading "v".
                         Defaults to "latest", which updates itself.
  -h, --help             Show this help message.

Run as root, it installs to /usr/local/bin for every user, and that copy never
updates itself: run this script again as root to upgrade it.
EOF
}

VERSION="${HOUNDDOG_VERSION:-latest}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        -v|--version)
            [ "$#" -ge 2 ] || abort "Missing value for $1."
            VERSION="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            abort "Unknown option: $1. Use --help to see supported options."
            ;;
    esac
done

[ -n "$VERSION" ] || abort "Version cannot be empty."

# Check operating system.
OS=$(uname -s)
case "$OS" in
    Linux*) OS="linux" ;;
    Darwin*) OS="macos" ;;
    *) abort "This HoundDog CLI installation script only supports Linux and macOS." ;;
esac

# Check CPU architecture.
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) abort "Unsupported CPU architecture. HoundDog CLI requires a AMD64 or ARM64 processor." ;;
esac
if [ "$OS" = "macos" ] && [ "$ARCH" = "amd64" ]; then
    # A shell running under Rosetta reports x86_64 on Apple silicon, which runs the ARM64 build natively.
    [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = "1" ] ||
        abort "HoundDog CLI does not support Intel Macs. Use the Docker image hounddogai/hounddog instead."
    ARCH="arm64"
fi

# Check other prerequisites.
command -v curl >/dev/null 2>&1 || abort "Command 'curl' is required to install HoundDog CLI."
command -v tar >/dev/null 2>&1 || abort "Command 'tar' is required to install HoundDog CLI."
command -v awk >/dev/null 2>&1 || abort "Command 'awk' is required to install HoundDog CLI."
if [ "$OS" = "macos" ]; then
    command -v shasum >/dev/null 2>&1 || abort "Command 'shasum' is required to install HoundDog CLI."
else
    command -v sha256sum >/dev/null 2>&1 || abort "Command 'sha256sum' is required to install HoundDog CLI."
fi

if [ "$VERSION" != "latest" ]; then
    printf '%s\n' "$VERSION" | awk 'BEGIN { ok = 0 } /^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta))?$/ { ok = 1 } END { exit(ok ? 0 : 1) }' \
        || abort "Invalid version '${VERSION}'. Use x.y.z, x.y.z-alpha, or x.y.z-beta (without a leading 'v')."
fi

# Download the tarball and checksum files to a private temporary directory.
TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/hounddog.XXXXXX") || abort "Failed to create a temporary directory."
TARBALL_PATH="${TEMP_DIR}/hounddog.tar.gz"
CHECKSUM_PATH="${TEMP_DIR}/hounddog.sha256"
EXTRACT_DIR="${TEMP_DIR}/extract"

download_release_assets() {
    RELEASES_URL="https://github.com/hounddogai/hounddog/releases"
    ARTIFACT="hounddog-${OS}-${ARCH}.tar.gz"
    TAGS_TO_TRY=""

    if [ "$VERSION" = "latest" ]; then
        TAGS_TO_TRY="latest"
    else
        TAGS_TO_TRY="${VERSION} v${VERSION}"
    fi

    for TAG in $TAGS_TO_TRY; do
        if [ "$TAG" = "latest" ]; then
            DL_URL="${RELEASES_URL}/latest/download"
        else
            DL_URL="${RELEASES_URL}/download/${TAG}"
        fi

        if curl -fsSL "${DL_URL}/${ARTIFACT}" -o "$TARBALL_PATH" \
            && curl -fsSL "${DL_URL}/${ARTIFACT}.sha256" -o "$CHECKSUM_PATH"; then
            return
        fi
    done

    abort "Failed to download HoundDog CLI version '${VERSION}'. Ensure the release exists and uses x.y.z, x.y.z-alpha, or x.y.z-beta."
}

download_release_assets

# Verify checksum.
EXPECTED_CHECKSUM=$(awk '{print $1}' "$CHECKSUM_PATH")
if [ "$OS" = "macos" ]; then
    ACTUAL_CHECKSUM=$(shasum -a 256 "$TARBALL_PATH" | awk '{print $1}')
else
    ACTUAL_CHECKSUM=$(sha256sum "$TARBALL_PATH" | awk '{print $1}')
fi
[ "$EXPECTED_CHECKSUM" = "$ACTUAL_CHECKSUM" ] || abort "Checksum mismatch. Aborting installation."

mkdir "$EXTRACT_DIR"
tar -x -f "$TARBALL_PATH" -C "$EXTRACT_DIR" hounddog
STAGED_BINARY="${EXTRACT_DIR}/hounddog"
[ -f "$STAGED_BINARY" ] || abort "The release archive does not contain the HoundDog CLI executable."
chmod 755 "$STAGED_BINARY"
STAGED_VERSION=$("$STAGED_BINARY" --version) || abort "The downloaded HoundDog CLI executable could not be run."
[ -n "$STAGED_VERSION" ] || abort "The downloaded HoundDog CLI executable did not report a version."
case "$STAGED_VERSION" in
    *[!0-9A-Za-z.-]*) abort "The downloaded HoundDog CLI executable reported an invalid version: ${STAGED_VERSION}" ;;
esac

install_binary() {
    INSTALL_DIR="$1"
    INSTALL_PATH="${INSTALL_DIR}/hounddog"
    PENDING_INSTALL_PATH=$(mktemp "${INSTALL_DIR}/.hounddog.XXXXXX") \
        || abort "Failed to create a temporary installation file in ${INSTALL_DIR}."
    cp "$STAGED_BINARY" "$PENDING_INSTALL_PATH"
    chmod 755 "$PENDING_INSTALL_PATH"
    mv -f "$PENDING_INSTALL_PATH" "$INSTALL_PATH"
    PENDING_INSTALL_PATH=""

    INSTALLED_VERSION=$("$INSTALL_PATH" --version) || abort "The installed HoundDog CLI executable could not be run."
    [ "$INSTALLED_VERSION" = "$STAGED_VERSION" ] || abort "The installed HoundDog CLI executable failed verification."
}

# Installs the staged binary into the managed layout in $1, which `hounddog update` keeps current:
# versions/<version>/hounddog, and bin/hounddog, a link to the current version that an update replaces in one rename.
# A plain bin/hounddog that an earlier installer put there becomes the link, so the PATH stays as it was.
install_managed() {
    HOME_DIR="$1"
    mkdir -p "${HOME_DIR}/versions" "${HOME_DIR}/bin"
    PENDING_INSTALL_PATH=$(mktemp -d "${HOME_DIR}/versions/.hounddog.XXXXXX") \
        || abort "Failed to create a temporary installation folder in ${HOME_DIR}/versions."
    chmod 755 "$PENDING_INSTALL_PATH"
    cp "$STAGED_BINARY" "${PENDING_INSTALL_PATH}/hounddog"
    chmod 755 "${PENDING_INSTALL_PATH}/hounddog"
    rm -rf "${HOME_DIR}/versions/${STAGED_VERSION}"
    mv "$PENDING_INSTALL_PATH" "${HOME_DIR}/versions/${STAGED_VERSION}"
    PENDING_INSTALL_PATH="${HOME_DIR}/bin/.hounddog.link.$$"
    ln -s "../versions/${STAGED_VERSION}/hounddog" "$PENDING_INSTALL_PATH"
    mv -f "$PENDING_INSTALL_PATH" "${HOME_DIR}/bin/hounddog"
    PENDING_INSTALL_PATH=""

    INSTALLED_VERSION=$("${HOME_DIR}/bin/hounddog" --version) \
        || abort "The installed HoundDog CLI executable could not be run."
    [ "$INSTALLED_VERSION" = "$STAGED_VERSION" ] || abort "The installed HoundDog CLI executable failed verification."
}

# If the script is not running as root, install to ~/.hounddog, with the CLI at ~/.hounddog/bin/hounddog.
if [ "$(id -u)" -ne 0 ]; then
    # Detect shell configuration file.
    SHELL_NAME=$(basename "${SHELL:-}")
    case "$SHELL_NAME" in
        bash)
            SHELL_RC="$HOME/.bashrc"
            PATH_LINE="export PATH=\"\$HOME/.hounddog/bin:\$PATH\""
            ;;
        zsh)
            SHELL_RC="$HOME/.zshrc"
            PATH_LINE="export PATH=\"\$HOME/.hounddog/bin:\$PATH\""
            ;;
        fish)
            SHELL_RC="$HOME/.config/fish/config.fish"
            PATH_LINE="set -gx PATH \"\$HOME/.hounddog/bin\" \$PATH"
            ;;
        # Other shells, or none, as in many CI containers: install, and leave PATH to the user.
        *) SHELL_RC="" ;;
    esac

    INSTALL_DIR="${HOME}/.hounddog/bin"
    install_managed "${HOME}/.hounddog"

    # A given version stays until the user asks for another, so it turns automatic updates off, and installing the
    # latest version turns them on again. A version too old to have automatic updates refuses the command.
    UPDATES_NOTE=""
    if [ "$VERSION" != "latest" ]; then
        if "${INSTALL_DIR}/hounddog" update --auto off > /dev/null 2>&1; then
            UPDATES_NOTE="Automatic updates are off, so ${INSTALLED_VERSION} stays. Run 'hounddog update --auto on' to turn them on."
        fi
    elif [ -f "${HOME}/.hounddog/update.json" ] && grep -q '"automatic": false' "${HOME}/.hounddog/update.json"; then
        if "${INSTALL_DIR}/hounddog" update --auto on > /dev/null 2>&1; then
            UPDATES_NOTE="Automatic updates are on again."
        fi
    fi

    if [ -z "$SHELL_RC" ]; then
        NEXT_STEP="Add ${INSTALL_DIR} to the front of your PATH, then run 'hounddog --help' to get started."
    else
        # Prepend ~/.hounddog/bin so another hounddog executable cannot shadow the installed version.
        if ! { [ -f "$SHELL_RC" ] && grep -Fqx "$PATH_LINE" "$SHELL_RC"; }; then
            echo "Adding ${HOME}/.hounddog/bin to PATH in ${SHELL_RC}..."
            mkdir -p "$(dirname "$SHELL_RC")"
            printf "\n%s\n" "$PATH_LINE" >> "$SHELL_RC"
        fi
        NEXT_STEP="Open a new shell and run 'hounddog --help' to get started."
    fi

# If the script is running as root, install to /usr/local/bin/hounddog, which only root may change, so the CLI there
# does not update itself: run this script again to upgrade it.
else
    # Check prerequisites.
    [ -d "/usr/local/bin" ] || abort "Directory '/usr/local/bin' does not exist. Aborting installation."
    [ -w "/usr/local/bin" ] || abort "No write permission to '/usr/local/bin'. Aborting installation."
    case ":$PATH:" in
        *:/usr/local/bin:*) ;;
        *) abort "Directory '/usr/local/bin' is not in PATH. Aborting installation." ;;
    esac

    install_binary "/usr/local/bin"
    UPDATES_NOTE="Installed for every user, so it does not update itself: run this script again as root to upgrade it."
    NEXT_STEP="Run 'hounddog --help' to get started."
fi

echo ""
echo "HoundDog CLI installed successfully."
echo "Installed version: ${INSTALLED_VERSION}"
[ -z "$UPDATES_NOTE" ] || echo "$UPDATES_NOTE"
echo "$NEXT_STEP"
