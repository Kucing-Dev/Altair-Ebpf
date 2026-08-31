
<p align="center">
  <img src="https://github.com/user-attachments/assets/998c35d1-5ea0-4087-9cf0-50388b8851e4" width="400" alt="Altair-Ebpf Logo">
</p>


# Altair eBPF

Runtime process execution monitor built with **Rust + eBPF (Aya)**, focused on **Docker/container runtime visibility** and simple behavioral alerting.

> Status: **Learning / Prototype**  
> Not a production EDR/CDR or vulnerability scanner.

---

## Overview

Altair attaches to the Linux kernel tracepoint `sys_enter_execve` and monitors process executions in real time.

Pipeline:

1. **Fase 1 – Basic monitoring**  
   Capture PID/UID/comm/filename in eBPF and stream events to userspace via RingBuf
2. **Fase 2 – Container awareness**  
   Classify `HOST` vs `CONTAINER`, support `--container-only`
3. **Fase 3 – Threat rules**  
   Severity scoring (`INFO` / `LOW` / `MEDIUM` / `HIGH`) for suspicious container behavior

All earlier stages are still active and required by later stages.

---

## What this is (and is not)

### This project is
- a runtime **behavioral** detector
- focused on process execution inside Linux/Docker
- useful for learning eBPF + container security concepts

### This project is not
- a CVE/vulnerability scanner
- a replacement for Trivy/Grype/Snyk
- a full SOC detection platform

Severity levels are based on **behavioral rules**, not CVSS scores.

---

## Features

### Implemented

**Fase 1 – Basic process monitoring**
- eBPF attach on `sys_enter_execve`
- Collect PID/TGID, UID, `comm`, filename
- Kernel → userspace event streaming via RingBuf
- Terminal output

**Fase 2 – Container awareness**
- Detect container context using:
  - Docker PID namespace correlation
  - cgroup inode correlation
  - `/proc/<pid>/cgroup` fallback
- `--container-only` mode
- Internal noise filtering

**Fase 3 – Threat rules**
- Severity model: `INFO` / `LOW` / `MEDIUM` / `HIGH`
- `--min-severity` filter
- Benign binary whitelist
- Rules for:
  - root shell in container
  - network tools (`curl`, `wget`, `nc`, ...)
  - package managers (`apk`, `apt`, ...)
  - mount/umount in container
  - namespace/chroot-related tools (`nsenter`, `unshare`, ...)

### Not implemented yet (Fase 4+)
- True file-open monitoring (`security_file_open`)
- Network connect monitoring (`tcp_connect`)
- Docker name/image metadata enrichment
- JSON logging / Prometheus export
- Auto-response actions

---

## Architecture

```text
Linux Kernel
  └─ tracepoint: sys_enter_execve
        └─ eBPF program (Aya)
              └─ RingBuf
                    └─ Rust userspace
                          ├─ parse ExecEvent
                          ├─ detect HOST vs CONTAINER
                          ├─ apply filters
                          ├─ evaluate severity rules
                          └─ print logs / alerts
```

---

## Project structure

```text
altair-ebpf/
├── altair-ebpf/            # userspace application
├── altair-ebpf-ebpf/       # eBPF program
├── altair-ebpf-common/     # shared event struct
├── Cargo.toml
└── README.md
```

---

## Requirements

- Linux with eBPF support
- Rust toolchain (nightly may be required for eBPF build)
- `bpf-linker`
- Root privileges to load eBPF programs
- Docker (recommended)

---

## Build

```bash
cargo build
```

Release:

```bash
cargo build --release
```

---

## Usage

### All events

```bash
sudo ./target/debug/altair-ebpf
```

### Container only

```bash
sudo ./target/debug/altair-ebpf --container-only
```

### Recommended demo mode

```bash
sudo ./target/debug/altair-ebpf --container-only --min-severity medium
```

### Help

```bash
./target/debug/altair-ebpf --help
```



## CLI options

| Option | Description |
|------|-------------|
| `--container-only` | Show only container events |
| `--all` | Show host + container events |
| `--min-severity <level>` | `info` \| `low` \| `medium` \| `high` |
| `-h`, `--help` | Show help |

Default min severity: `info`

---

## Severity model

| Level | Meaning | Examples |
|------|---------|----------|
| `INFO` | Normal execution | `ls`, `whoami` |
| `LOW` | Mild interest | non-root shell in container |
| `MEDIUM` | Notable risk behavior | `apk` / `apt` / toolchain as root in container |
| `HIGH` | Strong suspicious behavior | root shell, `wget`/`curl`/`nc`, `mount` in container |

Whitelisted binaries are forced to `INFO` (for example: `ls`, `whoami`, `cat`, `grep`, `ps`, `sleep`, ...).

---

## Example output

```text
┌─ ALERT [CONTAINER/HIGH] ──────────────────────────
│  PID         : 3755
│  UID         : 0
│  COMM        : sh
│  BINARY      : /usr/bin/wget
│  CONTAINER   : 8576485edfec
│  SEVERITY    : HIGH
│  REASON      : root network tool inside container
└────────────────────────────────────────────────

┌─ ALERT [CONTAINER/MEDIUM] ──────────────────────────
│  BINARY      : /sbin/apk
│  SEVERITY    : MEDIUM
│  REASON      : package manager executed as root in container
└────────────────────────────────────────────────

┌─ ALERT [CONTAINER/HIGH] ──────────────────────────
│  BINARY      : /bin/mount
│  SEVERITY    : HIGH
│  REASON      : mount/umount executed as root inside container
└────────────────────────────────────────────────
```

---

## Quick test

Terminal 1:

```bash
sudo ./target/debug/altair-ebpf --container-only --min-severity medium
```

Terminal 2:

```bash
docker run --rm -it --privileged alpine sh
whoami
wget example.com
apk update
mount
```

Expected:
- benign commands stay quiet at `medium+`
- network/package/mount activity raises alerts

---

## Roadmap

- [x] Fase 1: basic execve monitoring
- [x] Fase 2: container awareness + `--container-only`
- [x] Fase 3: threat rules + severity + whitelist
- [ ] Fase 4: file/network hooks, metadata enrichment, JSON logs

---

## Disclaimer

This project is for **education and research**.  
Detection logic is intentionally simple and may produce false positives or false negatives.

It does **not** classify CVEs and should not be treated as a complete runtime security product.

---
<!-- License -->

With the exception of eBPF code, altair-ebpf is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
