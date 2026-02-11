#!/usr/bin/env bash
set -euo pipefail

CHROOT_DIR="/srv/claude-chroot"

echo "=== Cleaning up Claude chroot ==="

# Remove immutable flag from managed settings so purge can delete it
chattr -i "$CHROOT_DIR/etc/claude-code/managed-settings.json" 2>/dev/null || true

# Remove nftables rules
if nft list table inet claude_filter &>/dev/null; then
    nft delete table inet claude_filter && echo "Removed nftables rules" || echo "WARN: Failed to remove nftables rules"
else
    echo "No nftables rules to remove"
fi

# Kill any processes still running in chroot
if [[ -d "$CHROOT_DIR/proc" ]] && mountpoint -q "$CHROOT_DIR/proc" 2>/dev/null; then
    echo "Checking for processes in chroot..."
    # Find and kill processes with root in chroot
    for pid in $(find /proc -maxdepth 2 -name root -type l 2>/dev/null | xargs -I{} readlink {} 2>/dev/null | grep "^$CHROOT_DIR" | cut -d/ -f3); do
        if [[ -n "$pid" ]] && [[ "$pid" =~ ^[0-9]+$ ]]; then
            echo "Killing process $pid"
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
fi

# Lazy unmount all mounts (works even if busy)
echo "Unmounting filesystems..."
for mount_point in workspace tmp run sys proc dev nix; do
    target="$CHROOT_DIR/$mount_point"
    if mountpoint -q "$target" 2>/dev/null; then
        if umount "$target" 2>/dev/null; then
            echo "  Unmounted $mount_point"
        elif umount -l "$target" 2>/dev/null; then
            echo "  Lazy unmounted $mount_point (was busy)"
        else
            echo "  WARN: Failed to unmount $mount_point"
        fi
    fi
done

# Double-check for any remaining mounts
remaining=$(grep "$CHROOT_DIR" /proc/mounts 2>/dev/null | awk '{print $2}' || true)
if [[ -n "$remaining" ]]; then
    echo "Forcing unmount of remaining mounts..."
    echo "$remaining" | sort -r | while read -r mnt; do
        umount -l "$mnt" 2>/dev/null && echo "  Force unmounted $mnt" || true
    done
fi

# Optionally remove the chroot entirely
if [[ "${1:-}" == "--purge" ]]; then
    echo "Removing chroot directory..."
    rm -rf "$CHROOT_DIR"
    echo "Chroot removed"
else
    echo ""
    echo "Cleanup complete. Use --purge to remove chroot entirely:"
    echo "  sh $0 --purge"
fi
