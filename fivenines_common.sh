#!/bin/sh
# Fivenines Agent - Shared Shell Functions
# This file is the source of truth for functions shared across install scripts.
# It is inlined into each script at build time by ci/build-scripts.sh.
# Do NOT distribute this file separately - install scripts must be self-contained.

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_success() {
    printf '%b\n' "${GREEN}[+]${NC} $1"
}

print_warning() {
    printf '%b\n' "${YELLOW}[!]${NC} $1"
}

print_error() {
    printf '%b\n' "${RED}[-]${NC} $1"
}

exit_with_error() {
    print_error "$1"
    echo ""
    echo "For assistance, contact: sebastien@fivenines.io"
    exit 1
}

download_file() {
    url="$1"
    output="$2"

    if command -v wget > /dev/null 2>&1; then
        wget -q -T 10 "$url" -O "$output"
    elif command -v curl > /dev/null 2>&1; then
        curl -sL --connect-timeout 10 "$url" -o "$output"
    else
        return 1
    fi
}

download_with_fallback() {
    filename="$1"
    output="$2"
    r2_url="${R2_BASE_URL}/${filename}"
    github_url="$3"

    print_warning "Downloading ${filename}..."

    # Try R2 first (IPv6 compatible)
    if download_file "$r2_url" "$output" 2>/dev/null; then
        print_success "Downloaded from releases.fivenines.io"
        return 0
    fi

    # Fallback to GitHub
    print_warning "R2 mirror unavailable, trying GitHub..."
    if download_file "$github_url" "$output" 2>/dev/null; then
        print_success "Downloaded from GitHub"
        return 0
    fi

    return 1
}

detect_libc() {
    # Check ldd first - if it explicitly reports glibc or musl, trust that
    LDD_OUTPUT=$(ldd --version 2>&1 || true)
    if printf '%s' "$LDD_OUTPUT" | grep -qi glibc; then
        echo "glibc"
    elif printf '%s' "$LDD_OUTPUT" | grep -qi musl; then
        echo "musl"
    elif [ -f "/lib/ld-musl-x86_64.so.1" ] || [ -f "/lib/ld-musl-aarch64.so.1" ]; then
        echo "musl"
    else
        echo "glibc"
    fi
}

detect_system() {
    # Check if this is UNRAID
    if [ -f "/etc/unraid-version" ] || [ -d "/boot/config" ]; then
        echo "unraid"
        return
    fi

    # Check if OpenRC is available (Alpine Linux)
    if command -v rc-service >/dev/null 2>&1 && [ -d "/etc/init.d" ]; then
        echo "openrc"
        return
    fi

    # Check if systemd is available
    if command -v systemctl >/dev/null 2>&1 && [ -d "/etc/systemd/system" ]; then
        echo "systemd"
        return
    fi

    # Fallback - check for other init systems
    if [ -f "/sbin/init" ]; then
        init_system=$(readlink -f /sbin/init)
        case "$init_system" in
            *systemd*)
                echo "systemd"
                ;;
            *)
                echo "other"
                ;;
        esac
    else
        echo "unknown"
    fi
}
