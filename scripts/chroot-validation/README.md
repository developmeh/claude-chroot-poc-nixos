# Claude Chroot Security Validation Scripts

These scripts validate the security findings documented in `docs/claude-chroot-security-audit.md`.

## Quick Start

```bash
# Run all tests from inside chroot:
sudo sh scripts/claude-chroot-enter.sh /path/to/this/repo
bash /workspace/scripts/chroot-validation/10-full-validation-suite.sh

# Or run individual tests:
bash /workspace/scripts/chroot-validation/01-proc-escape-check.sh
```

## Scripts

| Script | Finding | Severity |
|--------|---------|----------|
| 01-proc-escape-check.sh | /proc filesystem escape vector | CRITICAL |
| 02-dev-escape-check.sh | /dev device node access | CRITICAL |
| 03-dns-exfil-check.sh | DNS exfiltration channel | HIGH |
| 04-uid-bypass-check.sh | UID-based filter bypass | CRITICAL |
| 05-managed-settings-bypass.sh | Tool restriction bypass | HIGH |
| 06-nix-store-write-check.sh | Nix store write access | HIGH |
| 07-sys-escape-check.sh | /sys information disclosure | MEDIUM |
| 08-credential-exposure-check.sh | Credential exposure | MEDIUM |
| 09-no-resource-limits-check.sh | Resource limits missing | LOW |
| 10-full-validation-suite.sh | Run all tests | - |

## Safety

All scripts are **read-only** tests. They:
- Do NOT modify files
- Do NOT execute exploits
- Do NOT exfiltrate data
- Do NOT perform DoS attacks

They only check what's *possible*, not execute attacks.

## Validation Checklist

Run inside the chroot and verify each finding:

- [ ] `/proc/1/root` points to real root filesystem
- [ ] Block devices visible in `/dev`
- [ ] Can resolve arbitrary DNS domains
- [ ] Setuid binaries exist in accessible paths
- [ ] Network tools available despite managed settings
- [ ] `/nix/store` is writable
- [ ] Hardware info exposed via `/sys`
- [ ] API keys visible in environment
- [ ] No ulimit restrictions

## Expected Results

If the chroot is configured as documented, all tests should show **VULNERABLE** (except possibly resource limits if run with ulimits).

A properly secured environment would use:
- Linux namespaces (user, mount, network, PID)
- Seccomp-bpf syscall filtering
- Cgroups resource limits
- Read-only root with tmpfs overlay
