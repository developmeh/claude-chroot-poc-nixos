#!/usr/bin/env bash
set -euo pipefail

CHROOT_DIR="/srv/claude-chroot"
CHROOT_USER="claude"
CHROOT_UID=1000

# Find required commands (NixOS puts them in /nix/store)
CHROOT_BIN=$(command -v chroot || echo "/run/current-system/sw/bin/chroot")
UNSHARE_BIN=$(command -v unshare || echo "/run/current-system/sw/bin/unshare")
MOUNT_BIN=$(command -v mount || echo "/run/current-system/sw/bin/mount")
UMOUNT_BIN=$(command -v umount || echo "/run/current-system/sw/bin/umount")
NFT_BIN=$(command -v nft || echo "/run/current-system/sw/bin/nft")
BASH_BIN=$(command -v bash || echo "/run/current-system/sw/bin/bash")

# Verify chroot exists
if [[ ! -x "$CHROOT_BIN" ]]; then
    echo "ERROR: chroot not found. On NixOS, run:"
    echo "  nix-shell -p coreutils util-linux"
    exit 1
fi

# Anthropic official CIDR ranges (stable)
ANTHROPIC_IPV4="160.79.104.0/23"
ANTHROPIC_IPV6="2607:6bc0::/48"
ANTHROPIC_OUTBOUND="160.79.104.0/21"

# Load IPs from sync file if it exists, otherwise resolve at runtime
IP_FILE="$CHROOT_DIR/allowed-ips.conf"
if [[ -f "$IP_FILE" ]]; then
    echo "Loading IPs from $IP_FILE"
    # Parse the file: extract IPs from lines like "domain=ip1,ip2,ip3"
    ALLOWED_IPS=$(grep -v '^#' "$IP_FILE" | grep '=' | cut -d= -f2 | tr ',' '\n' | grep -E '^[0-9]+\.[0-9]+' | sort -u | tr '\n' ' ')
else
    echo "No IP file found, resolving at runtime..."
    echo "Run 'sudo sh scripts/claude-chroot-sync-ips.sh' to create a vetted IP list"
    # Resolve essential domains
    ALLOWED_IPS=$(dig +short \
        api.anthropic.com \
        console.anthropic.com \
        auth.anthropic.com \
        claude.ai \
        statsig.anthropic.com \
        cache.nixos.org \
        A 2>/dev/null | grep -E '^[0-9]+\.' | sort -u | tr '\n' ' ' || echo "")
fi

print_usage() {
    echo "Usage: $0 [options] [workspace_path]"
    echo ""
    echo "Options:"
    echo "  --no-network    Disable all network access"
    echo "  --full-network  Allow unrestricted network (unsafe)"
    echo "  --help          Show this help"
    echo ""
    echo "Example:"
    echo "  $0 /home/user/myproject"
    echo ""
    echo "To exit the chroot: type 'exit' or press Ctrl+D"
}

NETWORK_MODE="restricted"
WORKSPACE=""
UNSHARE_NET=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --no-network)
            NETWORK_MODE="none"
            shift
            ;;
        --full-network)
            NETWORK_MODE="full"
            shift
            ;;
        --help)
            print_usage
            exit 0
            ;;
        *)
            WORKSPACE="$1"
            shift
            ;;
    esac
done

# Verify chroot exists
if [[ ! -d "$CHROOT_DIR" ]]; then
    echo "ERROR: Chroot not found at $CHROOT_DIR"
    echo "Run claude-chroot-setup.sh first"
    exit 1
fi

# Sync claude config from host user
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")
if [[ -d "$REAL_HOME/.claude" ]]; then
    echo "=== Syncing Claude config from $REAL_HOME/.claude ==="
    mkdir -p "$CHROOT_DIR/home/$CHROOT_USER/.claude"
    cp -r "$REAL_HOME/.claude/"* "$CHROOT_DIR/home/$CHROOT_USER/.claude/" 2>/dev/null || true
    chown -R "$CHROOT_UID:$CHROOT_UID" "$CHROOT_DIR/home/$CHROOT_USER/.claude"
fi

# Install managed settings (denies network tools)
MANAGED_SETTINGS="$REAL_HOME/.config/claude-chroot/managed-settings.json"
SCRIPT_DIR="$(dirname "$0")"
FALLBACK_SETTINGS="$SCRIPT_DIR/claude-chroot-managed-settings.json"

echo "=== Installing managed settings (network tools denied) ==="
mkdir -p "$CHROOT_DIR/etc/claude-code"

# Remove immutable flag if file exists (so we can update it)
chattr -i "$CHROOT_DIR/etc/claude-code/managed-settings.json" 2>/dev/null || true

if [[ -f "$MANAGED_SETTINGS" ]]; then
    echo "Using custom settings from $MANAGED_SETTINGS"
    cp "$MANAGED_SETTINGS" "$CHROOT_DIR/etc/claude-code/managed-settings.json"
elif [[ -f "$FALLBACK_SETTINGS" ]]; then
    echo "Using default settings from $FALLBACK_SETTINGS"
    cp "$FALLBACK_SETTINGS" "$CHROOT_DIR/etc/claude-code/managed-settings.json"
else
    echo "WARNING: No managed-settings.json found, network tools not restricted at config level"
fi

# Make it read-only and immutable (cannot be modified even by root inside chroot)
if [[ -f "$CHROOT_DIR/etc/claude-code/managed-settings.json" ]]; then
    chmod 444 "$CHROOT_DIR/etc/claude-code/managed-settings.json"
    chattr +i "$CHROOT_DIR/etc/claude-code/managed-settings.json" 2>/dev/null || true
fi

# Pass through API key if set
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"

echo "=== Mounting filesystems ==="

# Mount essential filesystems
mount_if_needed() {
    local src="$1"
    local dst="$2"
    local type="${3:-bind}"

    if ! mountpoint -q "$dst" 2>/dev/null; then
        if [[ "$type" == "bind" ]]; then
            $MOUNT_BIN --bind "$src" "$dst"
        else
            $MOUNT_BIN -t "$type" "$src" "$dst"
        fi
    fi
}

# Core mounts
mount_if_needed /dev "$CHROOT_DIR/dev" bind
mount_if_needed /proc "$CHROOT_DIR/proc" bind
mount_if_needed /sys "$CHROOT_DIR/sys" bind
mount_if_needed tmpfs "$CHROOT_DIR/tmp" tmpfs

# Mount Nix store (read-write so nix develop can work)
if [[ -d /nix ]]; then
    mount_if_needed /nix "$CHROOT_DIR/nix" bind
fi

# Mount /run AFTER creating subdirs, then mount sw inside
mkdir -p "$CHROOT_DIR/run/current-system/sw"
mount_if_needed /run/current-system/sw "$CHROOT_DIR/run/current-system/sw" bind

# Create symlinks for standard paths (point to the bind-mounted sw)
mkdir -p "$CHROOT_DIR/bin" "$CHROOT_DIR/usr/bin"
ln -sf /run/current-system/sw/bin/bash "$CHROOT_DIR/bin/sh" 2>/dev/null || true
ln -sf /run/current-system/sw/bin/bash "$CHROOT_DIR/bin/bash" 2>/dev/null || true
ln -sf /run/current-system/sw/bin/env "$CHROOT_DIR/usr/bin/env" 2>/dev/null || true

# Mount workspace if provided
if [[ -n "$WORKSPACE" && -d "$WORKSPACE" ]]; then
    mkdir -p "$CHROOT_DIR/workspace"
    mount_if_needed "$WORKSPACE" "$CHROOT_DIR/workspace" bind
    echo "Workspace mounted at /workspace"
fi

echo "=== Setting up network restrictions ==="

setup_nftables() {
    # Create nftables rules for the chroot user
    $NFT_BIN -f - << EOF
table inet claude_filter {
    chain output {
        type filter hook output priority 0; policy accept;

        # Allow loopback
        oif "lo" accept

        # Match only traffic from claude user (UID $CHROOT_UID)
        meta skuid != $CHROOT_UID accept

        # Allow DNS (needed for API hostname resolution)
        udp dport 53 accept
        tcp dport 53 accept

        # Allow Anthropic API
        ip daddr $ANTHROPIC_IPV4 tcp dport {80, 443} accept
        ip daddr $ANTHROPIC_OUTBOUND tcp dport {80, 443} accept
        ip6 daddr $ANTHROPIC_IPV6 tcp dport {80, 443} accept

        # Allow IPs from vetted list (auth, telemetry, nix cache)
        $(for ip in $ALLOWED_IPS; do
            echo "        ip daddr $ip tcp dport {80, 443} accept"
        done)

        # Allow established connections
        ct state established,related accept

        # Log and drop everything else from claude user
        log prefix "claude-blocked: " drop
    }
}
EOF
    echo "nftables rules installed"
}

cleanup_nftables() {
    $NFT_BIN delete table inet claude_filter 2>/dev/null || true
}

case "$NETWORK_MODE" in
    restricted)
        cleanup_nftables
        setup_nftables
        echo "Network restricted to Anthropic API + Nix cache"
        ;;
    none)
        # Use unshare to create isolated network namespace
        echo "Network completely disabled"
        UNSHARE_NET="$UNSHARE_BIN --net"
        ;;
    full)
        cleanup_nftables
        echo "WARNING: Full network access enabled"
        ;;
esac

echo "=== Entering chroot ==="
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  You are now in the Claude chroot environment            ║"
echo "║  To EXIT: type 'exit' or press Ctrl+D                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Enter chroot as claude user (symlinks point to /run/current-system/sw/bin)
# CLAUDE_OAUTH_BIND_ADDRESS forces OAuth callback to localhost (fixes chroot network detection)
$UNSHARE_NET $CHROOT_BIN --userspec=$CHROOT_USER:$CHROOT_USER "$CHROOT_DIR" \
    /usr/bin/env \
    HOME="/home/$CHROOT_USER" \
    USER="$CHROOT_USER" \
    PATH="/run/current-system/sw/bin:/bin:/usr/bin" \
    CLAUDE_OAUTH_BIND_ADDRESS="127.0.0.1" \
    ${ANTHROPIC_API_KEY:+ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY"} \
    /bin/bash -l || true

# Cleanup on exit
echo ""
echo "=== Cleaning up ==="

if [[ "$NETWORK_MODE" == "restricted" ]]; then
    cleanup_nftables
    echo "Removed nftables rules"
fi

# Unmount filesystems (run/current-system/sw first, then run)
$UMOUNT_BIN "$CHROOT_DIR/run/current-system/sw" 2>/dev/null || true
for mount_point in workspace tmp run sys proc dev nix; do
    $UMOUNT_BIN "$CHROOT_DIR/$mount_point" 2>/dev/null || true
done
echo "Unmounted filesystems"

echo "Chroot session ended"
