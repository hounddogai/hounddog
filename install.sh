#!/bin/sh
#
# Installs the HoundDog.ai CLI from its GitHub releases. The latest release:
#
#   curl -fsSL https://raw.githubusercontent.com/hounddogai/hounddog/main/install.sh | sh
#
# Or a version, which then stays: it turns the CLI's automatic updates off, and installing the latest release turns
# them on again:
#
#   curl -fsSL https://raw.githubusercontent.com/hounddogai/hounddog/main/install.sh | sh -s -- --version 4.0.0
#
# The CLI installs to ~/.local/bin, or to HOUNDDOG_INSTALL_DIR, which goes on the PATH in the profile of the user's
# shell, zsh, bash, or fish, unless it is already there. The command there is a link into ~/.hounddog, where each
# version keeps a folder, versions/<version>, and bin/hounddog names the current one, which `hounddog update` repoints
# to update the CLI in place. A plain binary that an earlier installer put there becomes the link. Run as root, the
# script installs the CLI for every user, as a plain binary in /usr/local/bin or HOUNDDOG_INSTALL_DIR, which never
# updates itself: running the script again as root upgrades it. Releases have builds for Linux on amd64 and arm64
# and for macOS on arm64, named hounddog-<os>-<arch>, and a SHA256SUMS file that each download must match before it
# replaces the installed CLI. Windows installs with install.ps1 instead.
#
# HOUNDDOG_RELEASES_URL replaces https://github.com/hounddogai/hounddog/releases, such as with a mirror or a test's
# server, which serves the same paths: <url>/latest/download/<file> and <url>/download/<version>/<file>.

set -eu

# Prints each argument as a line of an error, and stops.
fail() {
    printf 'Error: %s\n' "$1" >&2
    shift
    [ "$#" -eq 0 ] || printf '%s\n' "$@" >&2
    exit 1
}

say() {
    printf '%s\n' "$@"
}

# $1 with the home folder written as ~, which reads shorter.
# The ~ is printed as is, for the reader.
# shellcheck disable=SC2088
shorten() {
    case "$1" in
        "${HOME:-}"/*) printf '~/%s' "${1#"${HOME}/"}" ;;
        *) printf '%s' "$1" ;;
    esac
}

# Whether $1 is a version, which is a release's tag, such as 1.2.3 or 1.2.3-beta.1. The character check also refuses
# line breaks, which grep would read as separate lines.
is_version() {
    case "$1" in
        *[!0-9A-Za-z.-]*) return 1 ;;
    esac
    printf '%s\n' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
}

# Bold marks the title and the commands to copy, in a terminal that shows it.
bold='' reset=''
if [ -t 1 ] && [ "${TERM:-dumb}" != dumb ] && [ -z "${NO_COLOR:-}" ]; then
    bold="$(printf '\033[1m')" reset="$(printf '\033[0m')"
fi
scripts='https://raw.githubusercontent.com/hounddogai/hounddog/main'
usage() {
    printf '%s\n' "Usage: curl -fsSL ${scripts}/install.sh | sh -s -- [--version <version>]" '' \
        '  -v, --version <version>  Install this version, such as 1.2.3 or 1.2.3-beta.1, which then stays:' \
        '                           it turns automatic updates off. Without it, the latest release installs.' \
        '  -h, --help               Show this help.'
}
version='' is_version_given=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        -v | --version)
            [ "$#" -ge 2 ] || fail "$1 needs a version, such as $1 1.2.3."
            version="$2" is_version_given=1
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) fail "Unknown option: $1" 'Run with --help to see the options.' ;;
    esac
done
[ -z "${is_version_given}" ] || is_version "${version}" ||
    fail "${version} is not a version of HoundDog.ai CLI." 'A version looks like 1.2.3 or 1.2.3-beta.1.'

case "$(uname -s)" in
    Linux) os=linux os_name=Linux ;;
    Darwin) os=macos os_name=macOS ;;
    # Git Bash, MSYS2, and Cygwin on Windows.
    MINGW* | MSYS* | CYGWIN*)
        if [ -n "${version}" ]; then
            fail 'On Windows, install HoundDog.ai CLI in PowerShell:' \
                "  & ([scriptblock]::Create((irm ${scripts}/install.ps1))) -Version ${version}"
        fi
        fail 'On Windows, install HoundDog.ai CLI in PowerShell:' "  irm ${scripts}/install.ps1 | iex"
        ;;
    *) fail 'HoundDog.ai CLI runs on Linux, macOS, and Windows.' "This computer runs $(uname -s)." ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) fail 'HoundDog.ai CLI runs on amd64 and arm64.' "This computer is $(uname -m)." ;;
esac
# A shell that runs under Rosetta on Apple silicon reports x86_64, and the arm64 build runs natively there.
if [ "${os}" = macos ] && [ "${arch}" = amd64 ] && [ "$(sysctl -n hw.optional.arm64 2> /dev/null)" = 1 ]; then
    arch=arm64
fi
command -v curl > /dev/null 2>&1 || fail 'Install curl, then run this again.'
# Both print the checksum of standard input first: sha256sum on Linux, and shasum on macOS.
if command -v sha256sum > /dev/null 2>&1; then
    hash_file() { sha256sum < "$1"; }
elif command -v shasum > /dev/null 2>&1; then
    hash_file() { shasum -a 256 < "$1"; }
else
    fail 'Install sha256sum or shasum to verify downloads,' 'then run this again.'
fi

releases="${HOUNDDOG_RELEASES_URL:-https://github.com/hounddogai/hounddog/releases}"
releases="${releases%/}"
if [ -n "${version}" ]; then
    files="${releases}/download/${version}"
    release="HoundDog.ai CLI ${version}"
else
    files="${releases}/latest/download"
    release='the latest HoundDog.ai CLI release'
fi
asset="hounddog-${os}-${arch}"

# Downloads the release's file named $1 to $2, or fails with the lines after them when the release does not have it.
download_file() {
    url="${files}/$1"
    status="$(curl -sSL -o "$2" -w '%{http_code}' "${url}")" ||
        fail 'Cannot download:' "  ${url}" 'Check your connection, then run this again.'
    case "${status}" in
        2??) ;;
        404)
            shift 2
            fail "$@"
            ;;
        *) fail 'Cannot download:' "  ${url}" "Server answered HTTP ${status}." ;;
    esac
}

say "${bold}Installing HoundDog.ai CLI...${reset}" ''
is_root=''
[ "$(id -u)" != 0 ] || is_root=1
if [ -n "${is_root}" ]; then
    directory="${HOUNDDOG_INSTALL_DIR:-/usr/local/bin}"
else
    directory="${HOUNDDOG_INSTALL_DIR:-${HOME}/.local/bin}"
fi
mkdir -p "${directory}"
# Download beside the destination and rename, so a failed download never replaces a working CLI.
download="$(mktemp "${directory}/.hounddog.XXXXXX")"
sums="$(mktemp "${directory}/.hounddog.XXXXXX")"
trap 'rm -f "${download}" "${sums}"' EXIT
download_file SHA256SUMS "${sums}" "Cannot find ${release}, or its SHA256SUMS." 'See releases at:' "  ${releases}"
download_file "${asset}" "${download}" "There is no build for ${os_name} on ${arch} in ${release}." \
    'See releases at:' "  ${releases}"

# SHA256SUMS lists each file as <checksum>  <name>, or <checksum> *<name> in binary mode.
expected="$(awk -v name="${asset}" '$2 == name || $2 == "*" name { print tolower($1); exit }' "${sums}")"
case "${expected}" in
    '' | *[!0-9a-f]*) fail "SHA256SUMS of ${release} has no checksum for ${asset}." ;;
esac
actual="$(hash_file "${download}" | awk '{ print tolower($1) }')"
[ "${actual}" = "${expected}" ] ||
    fail "Download of ${asset} does not match SHA256SUMS." \
        'Installed CLI is unchanged.' \
        'Run this again. A repeated failure means downloads get damaged in transit.'
chmod 755 "${download}"
# The release the download is, as the CLI tells it, such as `4.0.0`, which names its folder.
reported="$("${download}" --version 2> /dev/null | awk 'NR == 1 { print $NF }')" || reported=''
case "${reported}" in
    '' | *[!0-9A-Za-z.-]*) fail "The downloaded HoundDog.ai CLI does not run here, or reports no version." ;;
esac
cli="HoundDog.ai CLI ${reported}"
# The note on automatic updates for the summary.
updates=''
if [ -n "${is_root}" ]; then
    # For every user, a plain binary that only root changes, which never updates itself. It replaces what is there,
    # such as a link into root's own ~/.hounddog that an earlier installer made, which other users could not run.
    mv -f "${download}" "${directory}/hounddog"
    updates='It is installed for every user, so it does not update itself: run this script again as root to upgrade it.'
else
    home="${HOME}/.hounddog"
    mkdir -p "${home}/versions" "${home}/bin"
    staged="$(mktemp -d "${home}/versions/.hounddog.XXXXXX")"
    trap 'rm -f "${download}" "${sums}"; rm -rf "${staged}"' EXIT
    chmod 755 "${staged}"
    mv -f "${download}" "${staged}/hounddog"
    rm -rf "${home}/versions/${reported}"
    mv "${staged}" "${home}/versions/${reported}"
    # Each link is made beside its place and renamed over it, so a command never finds the CLI missing.
    link="${home}/bin/.hounddog.link.$$"
    ln -s "../versions/${reported}/hounddog" "${link}"
    mv -f "${link}" "${home}/bin/hounddog"
    if [ "$(cd "${directory}" && pwd -P)" != "$(cd "${home}/bin" && pwd -P)" ]; then
        link="${directory}/.hounddog.link.$$"
        ln -s "${home}/bin/hounddog" "${link}"
        mv -f "${link}" "${directory}/hounddog"
    fi
    # A given version stays until the user asks for another, so it turns automatic updates off, and installing the
    # latest release turns them on again. A release too old to have automatic updates refuses the command.
    if [ -n "${version}" ]; then
        if "${home}/bin/hounddog" update --auto off > /dev/null 2>&1; then
            updates="Automatic updates are off, so it stays at ${reported}."
            updates="${updates} Run hounddog update --auto on to turn them on."
        fi
    elif [ -f "${home}/settings.json" ] && grep -q '"automatic": false' "${home}/settings.json" &&
        "${home}/bin/hounddog" update --auto on > /dev/null 2>&1; then
        updates='Automatic updates are on again.'
    fi
fi
rm -f "${sums}"
trap - EXIT
shown="$(shorten "${directory}")"
binary="$(shorten "${directory}/hounddog")"
say "Downloaded and verified ${cli} for ${os_name} (${arch})." "Installed binary at ${binary}."
[ -z "${updates}" ] || printf '%s\n' "${updates}"

# Puts the folder on the PATH in the profile of the user's shell, and says how: zsh and fish do not read ~/.profile, and
# bash reads ~/.bashrc in Linux terminals, which start shells that are not login shells, and ~/.bash_profile in macOS's,
# which start them. Another shell's user adds the folder by hand.
case ":${PATH}:" in
    *":${directory}:"*) next='HoundDog.ai CLI is installed. Next:' ;;
    *)
        # The folder as the profile names it, under $HOME when it is there, so the line reads the same for every user.
        case "${directory}" in
            "${HOME:-}"/*) entry="\$HOME/${directory#"${HOME}/"}" ;;
            *) entry="${directory}" ;;
        esac
        profile=''
        # A folder whose name the profile's quotes cannot hold goes on the PATH by hand.
        case "${directory}" in
            *[\"\`\\$]*) ;;
            *)
                case "${SHELL:-}" in
                    */zsh) profile="${ZDOTDIR:-${HOME}}/.zshrc" line="export PATH=\"${entry}:\$PATH\"" ;;
                    */bash)
                        profile="${HOME}/.bashrc"
                        [ "${os}" != macos ] || profile="${HOME}/.bash_profile"
                        line="export PATH=\"${entry}:\$PATH\""
                        ;;
                    */fish)
                        profile="${XDG_CONFIG_HOME:-${HOME}/.config}/fish/config.fish"
                        line="fish_add_path \"${entry}\""
                        ;;
                esac
                ;;
        esac
        if [ -n "${profile}" ] && [ -f "${profile}" ] && grep -Fqx "${line}" "${profile}"; then
            next='HoundDog.ai CLI is installed. Open a new terminal, then:'
        elif [ -n "${profile}" ] && mkdir -p "$(dirname "${profile}")" 2> /dev/null &&
            printf '\n# HoundDog.ai CLI\n%s\n' "${line}" >> "${profile}" 2> /dev/null; then
            printf '%s\n' "Added ${shown} to your PATH in $(shorten "${profile}")."
            next='HoundDog.ai CLI is installed. Open a new terminal, then:'
        else
            printf '%s\n' "Add ${shown} to your PATH, such as in your shell's profile:" \
                "  export PATH=\"${entry}:\$PATH\""
            next='HoundDog.ai CLI is installed. Once it is on your PATH:'
        fi
        ;;
esac

say '' "${next}" '' \
    '  Scan a repository, from its root folder:' '' \
    "     ${bold}hounddog scan${reset}" '' \
    '  To upload the results, set HOUNDDOG_API_KEY to a HoundDog.ai API key.'
