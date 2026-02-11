#!/usr/bin/env bash
set -euo pipefail

CHROOT_DIR="/srv/claude-chroot"
CLAUDE_USER="claude"
CLAUDE_UID=1000

echo "=== Creating Claude Chroot Environment (Nix-based) ==="

# Create directory structure
mkdir -p "$CHROOT_DIR"/{etc,tmp,home/$CLAUDE_USER,dev,proc,sys,run,nix,var/{tmp,cache}}
mkdir -p "$CHROOT_DIR/home/$CLAUDE_USER/.claude"
mkdir -p "$CHROOT_DIR/home/$CLAUDE_USER/.config/nix"
chmod 1777 "$CHROOT_DIR/tmp" "$CHROOT_DIR/var/tmp"

# Create minimal /etc files
cat > "$CHROOT_DIR/etc/passwd" << EOF
root:x:0:0:root:/root:/bin/bash
$CLAUDE_USER:x:$CLAUDE_UID:$CLAUDE_UID:Claude User:/home/$CLAUDE_USER:/bin/bash
nobody:x:65534:65534:Nobody:/:/bin/false
EOF

cat > "$CHROOT_DIR/etc/group" << EOF
root:x:0:
$CLAUDE_USER:x:$CLAUDE_UID:
nogroup:x:65534:
nixbld:x:30000:
EOF

cat > "$CHROOT_DIR/etc/nsswitch.conf" << EOF
passwd:     files
group:      files
shadow:     files
hosts:      files dns
networks:   files
protocols:  files
services:   files
EOF

# Copy host DNS config
cp /etc/resolv.conf "$CHROOT_DIR/etc/"

# Create /etc/hosts for localhost resolution
cat > "$CHROOT_DIR/etc/hosts" << EOF
127.0.0.1   localhost
::1         localhost ip6-localhost ip6-loopback
EOF

# Copy SSL certs for HTTPS
mkdir -p "$CHROOT_DIR/etc/ssl/certs"
if [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
    cp /etc/ssl/certs/ca-certificates.crt "$CHROOT_DIR/etc/ssl/certs/"
elif [[ -f /etc/ssl/certs/ca-bundle.crt ]]; then
    cp /etc/ssl/certs/ca-bundle.crt "$CHROOT_DIR/etc/ssl/certs/"
fi

# Nix config for flakes
mkdir -p "$CHROOT_DIR/etc/nix"
cat > "$CHROOT_DIR/etc/nix/nix.conf" << EOF
build-users-group =
sandbox = false
experimental-features = nix-command flakes
EOF

# User nix config
cat > "$CHROOT_DIR/home/$CLAUDE_USER/.config/nix/nix.conf" << EOF
experimental-features = nix-command flakes
EOF

echo "=== Finding nixpkgs path ==="

# Find the actual nixpkgs path (works on NixOS with flakes)
NIXPKGS_PATH=$(nix eval --raw nixpkgs#path 2>/dev/null || nix-instantiate --eval -E '<nixpkgs>' 2>/dev/null | tr -d '"' || echo "")

if [[ -z "$NIXPKGS_PATH" || ! -d "$NIXPKGS_PATH" ]]; then
    echo "ERROR: Could not find nixpkgs. Make sure nix is working."
    exit 1
fi

echo "Using nixpkgs at: $NIXPKGS_PATH"

echo "=== Creating shell.nix for Claude environment ==="

# Create a shell.nix with hardcoded nixpkgs path (no network needed for resolution)
cat > "$CHROOT_DIR/home/$CLAUDE_USER/shell.nix" << NIXEOF
{ pkgs ? import $NIXPKGS_PATH { config = { allowUnfree = true; }; } }:

pkgs.mkShell {
  packages = with pkgs; [
    # Claude Code
    claude-code

    # Essential tools
    bash
    coreutils
    gnugrep
    gnused
    gawk
    findutils
    git
    curl
    jq
    ripgrep
    fd
    tree

    # For builds
    nodejs
    python3
  ];

  shellHook = ''
    export HOME=/home/claude
    export PS1="[claude-chroot] \\w \\\$ "
    echo "Claude environment ready. Run 'claude' to start."
  '';
}
NIXEOF

# Create bashrc that enters nix-shell with correct NIX_PATH
cat > "$CHROOT_DIR/home/$CLAUDE_USER/.bashrc" << EOF
# Claude chroot bashrc
export PATH="/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:\$PATH"
export NIX_PATH="nixpkgs=$NIXPKGS_PATH"
export NIXPKGS_ALLOW_UNFREE=1

# Auto-enter nix-shell if available (guard against loop)
if [[ -z "\$IN_NIX_SHELL" && -f ~/shell.nix ]] && command -v nix-shell &>/dev/null; then
    echo "Entering Claude nix-shell environment..."
    exec nix-shell ~/shell.nix
fi
EOF

cat > "$CHROOT_DIR/home/$CLAUDE_USER/.profile" << 'EOF'
# Source bashrc
if [[ -f ~/.bashrc ]]; then
    source ~/.bashrc
fi
EOF

echo "=== Setting permissions ==="
chown -R "$CLAUDE_UID:$CLAUDE_UID" "$CHROOT_DIR/home/$CLAUDE_USER"

echo "=== Setup complete ==="
echo ""
echo "The chroot uses a Nix flake to provide Claude and tools."
echo "On first entry, it will download/build claude-code from nixpkgs."
echo ""
echo "Run: sudo sh scripts/claude-chroot-enter.sh [workspace]"
echo "Exit: type 'exit' or press Ctrl+D"
