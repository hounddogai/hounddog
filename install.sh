#!/bin/sh
set -e  # Exit on error
set -u  # Exit on using unset variable

echo "Installing HoundDog CLI ..."

TEMP_DIR=""
PENDING_INSTALL_PATH=""

cleanup() {
    if [ -n "$PENDING_INSTALL_PATH" ]; then
        rm -f "$PENDING_INSTALL_PATH" > /dev/null 2>&1
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
  -v, --version VERSION  Install a specific release version.
                         Allowed formats: x.y.z, x.y.z-alpha, x.y.z-beta.
                         Do not include a leading "v".
                         Defaults to "latest".
  -h, --help             Show this help message.
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

# If the script is not running as root, install to ~/.hounddog/bin/hounddog.
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
        *) abort "HoundDog CLI only supports Bash, Zsh, and Fish shells." ;;
    esac

    INSTALL_DIR="${HOME}/.hounddog/bin"
    mkdir -p "$INSTALL_DIR"
    install_binary "$INSTALL_DIR"

    # Prepend ~/.hounddog/bin so another hounddog executable cannot shadow the installed version.
    if ! { [ -f "$SHELL_RC" ] && grep -Fqx "$PATH_LINE" "$SHELL_RC"; }; then
        echo "Adding ${HOME}/.hounddog/bin to PATH in ${SHELL_RC}..."
        mkdir -p "$(dirname "$SHELL_RC")"
        printf "\n%s\n" "$PATH_LINE" >> "$SHELL_RC"
    fi
    NEXT_STEP="Open a new shell and run 'hounddog --help' to get started."

# If the script is running as root, install to /usr/local/bin/hounddog.
else
    # Check prerequisites.
    [ -d "/usr/local/bin" ] || abort "Directory '/usr/local/bin' does not exist. Aborting installation."
    [ -w "/usr/local/bin" ] || abort "No write permission to '/usr/local/bin'. Aborting installation."
    case ":$PATH:" in
        *:/usr/local/bin:*) ;;
        *) abort "Directory '/usr/local/bin' is not in PATH. Aborting installation." ;;
    esac

    install_binary "/usr/local/bin"
    NEXT_STEP="Run 'hounddog --help' to get started."
fi

echo ""
echo "HoundDog CLI installed successfully."
echo "Installed version: ${INSTALLED_VERSION}"
echo "$NEXT_STEP"
