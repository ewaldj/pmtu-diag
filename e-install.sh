#!/usr/bin/env bash

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# e-install.sh by ewald@jeitler.cc 2026 https://www.jeitler.guru
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

readonly VERSION="1.0"
readonly SCRIPT_NAME="$(basename "$0")"

set -euo pipefail

readonly CUSTOM_GITHUB_TOOLS=(
    "pmut-diag.py|https://raw.githubusercontent.com/ewaldj/pmtu-diag/main/pmtu-diag.py"
)

readonly DEFAULT_BINDIR="/usr/local/bin"

print_line() {
    printf '%s\n' "------------------------------------------------------------"
}

print_title() {
    echo
    print_line
    printf '%s\n' "$1"
    print_line
}

get_existing_parent() {
    local path="$1"
    while [ ! -e "$path" ]; do
        path="$(dirname "$path")"
    done
    printf '%s\n' "$path"
}

get_default_status() {
    local target_file="$1"
    local target_link="$2"
    local file_exists=0
    local link_exists=0

    if [ -e "$target_file" ] || [ -L "$target_file" ]; then
        file_exists=1
    fi

    if [ -n "$target_link" ]; then
        if [ -e "$target_link" ] || [ -L "$target_link" ]; then
            link_exists=1
        fi
    fi

    if [ "$file_exists" -eq 1 ] && [ "$link_exists" -eq 1 ]; then
        printf '%s\n' "file and link exist, will be overwritten"
    elif [ "$file_exists" -eq 1 ] && [ "$link_exists" -eq 0 ] && [ -n "$target_link" ]; then
        printf '%s\n' "file exists, will be overwritten; new link will be created"
    elif [ "$file_exists" -eq 0 ] && [ "$link_exists" -eq 1 ]; then
        printf '%s\n' "link exists, will be overwritten; new file will be installed"
    elif [ "$file_exists" -eq 1 ]; then
        printf '%s\n' "file exists, will be overwritten"
    elif [ "$link_exists" -eq 1 ]; then
        printf '%s\n' "link exists, will be overwritten"
    elif [ -n "$target_link" ]; then
        printf '%s\n' "new file, new link"
    else
        printf '%s\n' "new file"
    fi
}

print_default_plan_list() {
    local entry file_name link_name target_file target_link status

    for entry in "${CUSTOM_GITHUB_TOOLS[@]}"; do
        file_name="${entry%%|*}"
        link_name="${file_name%.*}"
        target_file="${DEFAULT_BINDIR}/${file_name}"
        target_link=""

        if [ "$link_name" != "$file_name" ]; then
            target_link="${DEFAULT_BINDIR}/${link_name}"
        fi

        status="$(get_default_status "$target_file" "$target_link")"

        if [ -n "$target_link" ]; then
            printf ' - %-12s -> %-10s [%s]\n' "$file_name" "$link_name" "$status"
        else
            printf ' - %-12s            [%s]\n' "$file_name" "$status"
        fi
    done
}

TMPDIR_INSTALL="$(mktemp -d)"
cleanup() {
    rm -rf "$TMPDIR_INSTALL"
}
trap cleanup EXIT

print_title "Tool Installer by Ewald Jeitler"
echo "Downloads configured tools from GitHub, installs them into"
echo "the target directory, and creates extensionless command links"
echo "when applicable."

print_title "Tools to be installed"
echo "Planned installation status: ${DEFAULT_BINDIR}"
print_default_plan_list

print_title "Connectivity check"
if ! curl -fsSLI https://raw.githubusercontent.com/ >/dev/null; then
    echo "Error: unable to reach raw.githubusercontent.com"
    exit 1
fi
echo "GitHub connectivity OK."

print_title "Install directory | no further prompts"
echo "Default directory: ${DEFAULT_BINDIR}"
read -r -p "Install directory [${DEFAULT_BINDIR}]: " BINDIR
BINDIR="${BINDIR:-$DEFAULT_BINDIR}"

case "$BINDIR" in
    ~)
        BINDIR="$HOME"
        ;;
    ~/*)
        BINDIR="$HOME/${BINDIR#~/}"
        ;;
    /*)
        ;;
    *)
        BINDIR="$(pwd)/$BINDIR"
        ;;
esac

echo "Target directory: $BINDIR"


EXISTING_PARENT="$(get_existing_parent "$BINDIR")"
USE_SUDO=0

if [ -e "$BINDIR" ]; then
    if [ ! -w "$BINDIR" ]; then
        USE_SUDO=1
    fi
else
    if [ ! -w "$EXISTING_PARENT" ]; then
        USE_SUDO=1
    fi
fi

echo "Target directory: $BINDIR"

if [ "$USE_SUDO" -eq 1 ]; then
    print_title "Sudo authentication required - enter password"
    sudo -v
fi

print_title "Installation"
if [ "$USE_SUDO" -eq 1 ]; then
    sudo mkdir -p "$BINDIR"
else
    mkdir -p "$BINDIR"
fi

for entry in "${CUSTOM_GITHUB_TOOLS[@]}"; do
    file_name="${entry%%|*}"
    file_url="${entry#*|}"
    link_name="${file_name%.*}"
    tmp_file="${TMPDIR_INSTALL}/${file_name}"

    printf 'Installing:   %s\n' "$file_name"
    curl -fsSL "$file_url" -o "$tmp_file"

    if [ "$USE_SUDO" -eq 1 ]; then
        sudo install -m 0755 "$tmp_file" "$BINDIR/$file_name"
        if [ "$link_name" != "$file_name" ]; then
            sudo ln -sfn "$file_name" "$BINDIR/$link_name"
        fi
    else
        install -m 0755 "$tmp_file" "$BINDIR/$file_name"
        if [ "$link_name" != "$file_name" ]; then
            ln -sfn "$file_name" "$BINDIR/$link_name"
        fi
    fi

    printf 'Installed:   %s\n' "$BINDIR/$file_name"
    if [ "$link_name" != "$file_name" ]; then
        printf 'Linked as:   %s\n' "$BINDIR/$link_name"
    fi
    echo
done

print_title "Done"
echo "All tools were installed successfully."
echo "Have a zero‑downtime day!"

case ":$PATH:" in
    *":$BINDIR:"*)
        echo "The install directory is already in PATH."
        echo "You can run the tools directly by link name."
        ;;
    *)
        echo "The install directory is not in PATH."
        echo "Add this line to your shell profile:"
        echo "export PATH=\"$BINDIR:\$PATH\""
        ;;

esac
