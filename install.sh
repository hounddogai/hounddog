#!/bin/sh
set -e  # Exit on error
set -u  # Exit on using unset variable

echo "Installing HoundDog CLI ..."

cleanup() {
    rm -rf /tmp/hounddog.tar.gz /tmp/hounddog.sha256 > /dev/null 2>&1
}

abort() {
  cleanup
  echo "$@" 1>&2
  exit 1
}

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

# Download the binary zip and checksum files to a temporary directory.
DL_URL="https://github.com/hounddogai/hounddog/releases/latest/download"
curl -fsSL ${DL_URL}/hounddog-${OS}-${ARCH}.tar.gz -o /tmp/hounddog.tar.gz
curl -fsSL ${DL_URL}/hounddog-${OS}-${ARCH}.tar.gz.sha256 -o /tmp/hounddog.sha256

# Verify checksum.
EXPECTED_CHECKSUM=$(awk '{print $1}' /tmp/hounddog.sha256)
if [ "$OS" = "macos" ]; then
    ACTUAL_CHECKSUM=$(shasum -a 256 /tmp/hounddog.tar.gz | awk '{print $1}')
else
    ACTUAL_CHECKSUM=$(sha256sum /tmp/hounddog.tar.gz | awk '{print $1}')
fi
[ "$EXPECTED_CHECKSUM" = "$ACTUAL_CHECKSUM" ] || abort "Checksum mismatch. Aborting installation."

# If the script is not running as root, install to ~/.hounddog/bin/hounddog.
if [ "$(id -u)" -ne 0 ]; then
    # Detect shell configuration file.
    SHELL_NAME=$(basename "${SHELL:-}")
    case "$SHELL_NAME" in
        bash) SHELL_RC="$HOME/.bashrc" ;;
        zsh) SHELL_RC="$HOME/.zshrc" ;;
        fish) SHELL_RC="$HOME/.config/fish/config.fish" ;;
        *) abort "HoundDog CLI only supports Bash, Zsh, and Fish shells." ;;
    esac

    # Extract binary to ~/.hounddog/bin/hounddog
    mkdir -p "${HOME}/.hounddog/bin"
    tar -x -f /tmp/hounddog.tar.gz -C "${HOME}/.hounddog/bin" hounddog
    chmod 755 "${HOME}/.hounddog/bin/hounddog"

    # Add ~/.hounddog/bin to user's PATH in shell rc file.
    if ! grep -q "export PATH=\$PATH:\$HOME/.hounddog/bin" "${SHELL_RC}"; then
        echo "Adding ${HOME}/.hounddog/bin to PATH in ${SHELL_RC}..."
        printf "\nexport PATH=\$PATH:\$HOME/.hounddog/bin\n" >> "${SHELL_RC}"
        export PATH="${HOME}/.hounddog/bin:${PATH}"
    fi

    # Add ~/.hounddog/bin to PATH in current shell.
    export PATH="${PATH}:${HOME}/.hounddog/bin"

    cleanup
    echo ""
    echo "HoundDog CLI installed successfully."
    echo "Please restart your shell and run 'hounddog --help' to get started."

# If the script is running as root, install to /usr/local/bin/hounddog.
else
    # Check prerequisites.
    [ -d "/usr/local/bin" ] || abort "Directory '/usr/local/bin' does not exist. Aborting installation."
    [ -w "/usr/local/bin" ] || abort "No write permission to '/usr/local/bin'. Aborting installation."
    case ":$PATH:" in
        *:/usr/local/bin:*) ;;
        *) abort "Directory '/usr/local/bin' is not in PATH. Aborting installation." ;;
    esac

    # Extract tarball to /usr/local/bin/hounddog
    tar -x -f /tmp/hounddog.tar.gz -C /usr/local/bin hounddog
    chmod 755 /usr/local/bin/hounddog

    cleanup
    echo ""
    echo "HoundDog CLI has been installed successfully."
    echo "Run 'hounddog --help' to get started."
fi
