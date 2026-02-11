# Claude Code Chroot POC

A proof-of-concept for running Claude Code in an isolated chroot environment with restricted network access.

> **Note:** This POC is specifically designed for **NixOS**. It relies on NixOS-specific paths like `/run/current-system/sw/bin/` and the Nix package manager. Adapting to other distributions requires significant modification.

## Overview

This POC creates a sandboxed environment where Claude Code can:
- Access only the Anthropic API (and required auth/telemetry endpoints)
- Read/write only a specific workspace directory
- Use Nix to install dependencies (from cache only)
- NOT make arbitrary network calls
- NOT access your home directory or system files

## Quick Start

```bash
# 1. Setup the chroot (one time)
sudo sh scripts/claude-chroot-setup.sh

# 2. Sync allowed IPs (run periodically to update)
sudo sh scripts/claude-chroot-sync-ips.sh

# 3. Enter the chroot with your project
sudo sh scripts/claude-chroot-enter.sh /path/to/your/project

# 4. Inside chroot, your project is at /workspace
cd /workspace
claude

# 5. Exit with 'exit' or Ctrl+D

# Cleanup (if needed)
sudo sh scripts/claude-chroot-cleanup.sh         # unmount only
sudo sh scripts/claude-chroot-cleanup.sh --purge # delete everything
```

## Scripts

### `claude-chroot-setup.sh`

Creates the chroot environment at `/srv/claude-chroot/`.

**What it does:**
- Creates directory structure (`/etc`, `/home/claude`, `/nix`, etc.)
- Creates minimal `/etc/passwd`, `/etc/group`, `/etc/hosts`
- Copies SSL certificates for HTTPS
- Finds the host's nixpkgs path and creates a `shell.nix` for Claude
- Sets up Nix configuration for flakes and unfree packages
- Creates `.bashrc` that auto-enters the nix-shell environment

**Files created in chroot:**
```
/srv/claude-chroot/
├── etc/
│   ├── passwd, group, hosts, resolv.conf
│   ├── nix/nix.conf
│   └── ssl/certs/
├── home/claude/
│   ├── .claude/          # Claude config (synced on enter)
│   ├── .bashrc           # Auto-enters nix-shell
│   └── shell.nix         # Nix environment with claude-code
├── nix/                  # Bind-mounted from host
├── workspace/            # Bind-mounted project directory
└── ...
```

### `claude-chroot-enter.sh`

Enters the chroot with network restrictions and mounts.

**Usage:**
```bash
sudo sh scripts/claude-chroot-enter.sh [options] [workspace_path]

Options:
  --no-network    Completely disable network (even API)
  --full-network  Allow unrestricted network (unsafe, for debugging)
  --help          Show help
```

**What it does:**
1. Syncs `~/.claude/` config from host to chroot
2. Installs managed-settings.json (denies network tools)
3. Mounts filesystems:
   - `/dev`, `/proc`, `/sys` (system)
   - `/nix` (package store)
   - `/run/current-system/sw` (NixOS binaries)
   - `/tmp`, `/run` (tmpfs)
   - Workspace directory at `/workspace`
4. Loads allowed IPs from `/srv/claude-chroot/allowed-ips.conf`
5. Sets up nftables firewall rules:
   - Allows: Anthropic API, auth endpoints, telemetry, Nix cache
   - Blocks: Everything else (logged as `claude-blocked:`)
6. Enters chroot as unprivileged `claude` user (UID 1000)
7. On exit: removes firewall rules, unmounts filesystems

### `claude-chroot-sync-ips.sh`

Resolves and saves allowed IPs for the firewall.

**Usage:**
```bash
sudo sh scripts/claude-chroot-sync-ips.sh
```

**What it does:**
1. Resolves IPs for required domains:
   - `api.anthropic.com` - API
   - `console.anthropic.com`, `platform.claude.com`, `claude.ai` - Auth/OAuth
   - `statsig.anthropic.com`, `statsig.com` - Telemetry
   - `o1137031.ingest.sentry.io` - Error reporting
   - `cache.nixos.org` - Nix packages
2. Filters out bogus/reserved IPs (TEST-NET, private ranges, etc.)
3. Shows diff if file exists, prompts for confirmation
4. Saves to `/srv/claude-chroot/allowed-ips.conf`

**Run this periodically** to catch IP changes. Review the diff before applying.

### `claude-chroot-cleanup.sh`

Cleans up mounts and optionally removes the chroot.

**Usage:**
```bash
sudo sh scripts/claude-chroot-cleanup.sh          # unmount only
sudo sh scripts/claude-chroot-cleanup.sh --purge  # delete chroot
```

**What it does:**
1. Removes immutable flag from managed-settings.json
2. Removes nftables firewall rules
3. Kills any processes still running in chroot
4. Unmounts all bind mounts (lazy unmount if busy)
5. Optionally deletes `/srv/claude-chroot/` entirely

### `claude-chroot-managed-settings.json`

Claude Code managed settings that deny network-related tools.

**Location priority:**
1. `~/.config/claude-chroot/managed-settings.json` (custom)
2. `scripts/claude-chroot-managed-settings.json` (default)

**What it denies:**
- `WebSearch`, `WebFetch` (Claude's web tools)
- `curl`, `wget`, `nc`, `telnet`, `ssh`, `scp`, etc.
- `git clone/fetch/pull/push` (network git operations)
- Package managers (`npm install`, `pip install`, `cargo install`, etc.)
- Container commands (`docker pull`, `podman pull`)

The file is installed as **immutable** (`chattr +i`) inside the chroot, so Claude cannot modify or delete it.

## Customization

### Custom managed settings

```bash
mkdir -p ~/.config/claude-chroot
cp scripts/claude-chroot-managed-settings.json ~/.config/claude-chroot/managed-settings.json
# Edit to add/remove denied tools
```

### API key authentication

If OAuth doesn't work in chroot, use an API key:

```bash
sudo ANTHROPIC_API_KEY="sk-ant-..." sh scripts/claude-chroot-enter.sh .
```

### Adding allowed domains

Edit `scripts/claude-chroot-sync-ips.sh` and add domains to the `DOMAINS` array, then re-run the sync.

## Requirements

### Operating System

- **NixOS** (tested on NixOS 25.11)
- Other distros may work with modifications but are not supported

### Dependencies

The scripts require the following tools. On NixOS, most are available via `/run/current-system/sw/bin/` or can be added temporarily with `nix-shell`.

| Tool | Package | Used By | Purpose |
|------|---------|---------|---------|
| `bash` | coreutils | All scripts | Shell interpreter |
| `chroot` | coreutils | enter.sh | Enter the chroot environment |
| `mount`/`umount` | util-linux | enter.sh, cleanup.sh | Bind mount filesystems |
| `nft` | nftables | enter.sh, cleanup.sh | Firewall rules |
| `dig` | dnsutils/bind | sync-ips.sh | DNS resolution |
| `chattr` | e2fsprogs | enter.sh, cleanup.sh | Set immutable flag |
| `nix` | nix | setup.sh, inside chroot | Package management |
| `getent` | glibc | sync-ips.sh (fallback) | DNS resolution fallback |
| `host` | bind | sync-ips.sh (fallback) | DNS resolution fallback |

### Installing Dependencies

```bash
# Temporarily for current session
nix-shell -p dig nftables e2fsprogs

# Or add to configuration.nix
environment.systemPackages = with pkgs; [
  dnsutils    # provides dig
  nftables
  e2fsprogs   # provides chattr
];
```

### Permissions

- **Root access required** for:
  - Creating/entering chroot
  - Mounting filesystems
  - Setting up nftables rules
  - Setting immutable file flags

## File Locations

| File | Purpose |
|------|---------|
| `/srv/claude-chroot/` | Chroot root directory |
| `/srv/claude-chroot/allowed-ips.conf` | Vetted IP allowlist |
| `/srv/claude-chroot/etc/claude-code/managed-settings.json` | Immutable settings |
| `~/.config/claude-chroot/managed-settings.json` | Custom settings (optional) |
