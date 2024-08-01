#!/bin/bash
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
OS=${OSTYPE}
if [[ ${OS} == "linux-gnu"* ]]; then
    OS="linux"
elif [[ ${OS} == "darwin"* ]]; then
    OS="macos"
else
  abort "HoundDog CLI only supports Linux and macOS."
fi

# Check CPU architecture.
ARCH=$(uname -m)
if [[ ${ARCH} == "x86_64" ]]; then
    ARCH="amd64"
elif [[ ${ARCH} == "aarch64" || ${ARCH} == "arm64" ]]; then
    ARCH="arm64"
else
    abort "HoundDog CLI only supports Intel 64 and ARM 64 processors."
fi

# Check other prerequisites.
if [[ ! -x "$(command -v curl)" ]]; then
    abort "Command 'curl' is required to download HoundDog CLI. Please install it and try again."
fi
if [[ ! -x "$(command -v tar)" ]]; then
    abort "Command 'tar' is required to unzip HoundDog CLI. Please install it and try again."
fi
if [[ ! -x "$(command -v awk)" ]]; then
    abort "Command 'awk' is required to verify checksums. Please install it and try again."
fi
if [[ ${OS} == "macos" && ! -x "$(command -v shasum)" ]]; then
    abort "Command 'shasum' is required to verify checksums. Please install it and try again."
fi
if [[ ${OS} == "linux" && ! -x "$(command -v sha256sum)" ]]; then
    abort "Command 'sha256sum' is required to verify checksums. Please install it and try again."
fi

# Download binary and checksum.
DL_URL="https://github.com/hounddogai/hounddog/releases/latest/download"
curl -fsSL ${DL_URL}/hounddog-${OS}-${ARCH}.tar.gz -o /tmp/hounddog.tar.gz
curl -fsSL ${DL_URL}/hounddog-${OS}-${ARCH}.tar.gz.sha256 -o /tmp/hounddog.sha256

# Verify checksum.
EXPECTED_CHECKSUM=$(awk '{print $1}' /tmp/hounddog.sha256)
if [[ ${OS} == "macos" ]] ; then
    ACTUAL_CHECKSUM=$(shasum -a 256 /tmp/hounddog.tar.gz | awk '{print $1}')
else
    ACTUAL_CHECKSUM=$(sha256sum /tmp/hounddog.tar.gz | awk '{print $1}')
fi
if [[ ${EXPECTED_CHECKSUM} != "${ACTUAL_CHECKSUM}" ]]; then
    abort "Checksum mismatch. Aborting installation."
fi

# If the script is not running as root, install to ~/.hounddog/bin/hounddog.
if [[ $(id -u) -ne 0 ]]; then
    # Check the user's shell.
    SHELL_NAME=$(basename "${SHELL}")
    if [[ ${SHELL_NAME} == "bash" ]]; then
        SHELL_RC="${HOME}/.bashrc"
    elif [[ ${SHELL_NAME} == "zsh" ]]; then
        SHELL_RC="${HOME}/.zshrc"
    elif [[ ${SHELL_NAME} == "fish" ]]; then
        SHELL_RC="${HOME}/.config/fish/config.fish"
    else
        abort "HoundDog CLI only supports Bash, Zsh, and Fish shells."
    fi

    # Extract binary to ~/.hounddog/bin/hounddog
    mkdir -p "${HOME}/.hounddog/bin"
    tar -x -f /tmp/hounddog.tar.gz -C "${HOME}/.hounddog/bin" hounddog
    chmod 755 "${HOME}/.hounddog/bin/hounddog"

    # Add ~/.hounddog/bin to user's PATH in shell rc file.
    if ! grep -q "export PATH=\$PATH:\$HOME/.hounddog/bin" "${SHELL_RC}"; then
        echo "Adding ${HOME}/.hounddog/bin to PATH in ${SHELL_RC}..."
        echo "export PATH=\$PATH:\$HOME/.hounddog/bin" >> "${SHELL_RC}"
        export PATH="${HOME}/.hounddog/bin:${PATH}"
    fi

    # Add ~/.hounddog/bin to PATH in current shell.
    export PATH="${PATH}:${HOME}/.hounddog/bin"

    cleanup
    echo ""
    echo "HoundDog CLI has been installed successfully."
    echo "Please restart your shell and run 'hounddog --help' to get started."

# If the script is running as root, install to /usr/local/bin/hounddog.
else
    # Check prerequisites.
    if [[ ! -d "/usr/local/bin" ]]; then
        abort "Directory '/usr/local/bin' does not exist. Aborting installation."
    fi
    if [[ ! -w "/usr/local/bin" ]]; then
        abort "No write permission to '/usr/local/bin'. Aborting installation."
    fi
    if [[ ! ":${PATH}:" == *":/usr/local/bin:"* ]]; then
        abort "Directory '/usr/local/bin' is not in PATH. Aborting installation."
    fi

    # Extract tarball to /usr/local/bin/hounddog
    tar -x -f /tmp/hounddog.tar.gz -C /usr/local/bin hounddog
    chmod 755 /usr/local/bin/hounddog

    cleanup
    echo ""
    echo "HoundDog CLI has been installed successfully."
    echo "Run 'hounddog --help' to get started."
fi
