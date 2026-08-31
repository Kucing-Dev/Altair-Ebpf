
<p align="center">
  <img src="https://github.com/user-attachments/assets/998c35d1-5ea0-4087-9cf0-50388b8851e4" width="400" alt="Altair-Ebpf Logo">
</p>


# Altair eBPF

Runtime process execution monitor built with **Rust + eBPF (Aya)**, focused on **Docker/container runtime visibility** and simple threat-oriented alerting.

> Status: **Learning / Prototype**  
> Not a production EDR/CDR product.

---

## Overview

Altair attaches to the Linux kernel tracepoint `sys_enter_execve` and monitors process executions in real time.

Events flow from kernel space to userspace through a **RingBuf**, then are enriched with container context and evaluated by severity rules.

It can:
- classify events as `HOST` or `CONTAINER`
- filter to container-only mode
- apply severity-based alerting (`INFO` / `LOW` / `MEDIUM` / `HIGH`)
- reduce noise with binary whitelist and self-process filtering

---

## Features

### Implemented

- eBPF process execution monitoring (`sys_enter_execve`)
- Kernel → userspace streaming via RingBuf
- Docker/container awareness
  - PID namespace correlation
  - cgroup inode correlation
  - `/proc` cgroup fallback
- `--container-only` mode
- Severity rules for suspicious activity
- `--min-severity` filter
- Whitelist for common benign binaries
- Internal noise filtering (self process / tracking CLI)

### Not implemented yet

- Container name/image enrichment via Docker API object model
- JSON/file logging or SIEM export
- Network/file integrity detectors
- Auto-response / process kill
- Production hardening and packaging

---

## Architecture

```
Linux Kernel
  └─ tracepoint: sys_enter_execve
        └─ eBPF program (Aya)
              └─ RingBuf events
                    └─ Rust userspace
                          ├─ parse ExecEvent
                          ├─ detect HOST vs CONTAINER
                          ├─ apply filters (--container-only, --min-severity)
                          ├─ evaluate severity rules
                          └─ print logs / alerts
```

---

## Project structure

```text
altair-ebpf/
├── altair-ebpf/            # userspace application
├── altair-ebpf-ebpf/       # eBPF kernel program
├── altair-ebpf-common/     # shared event definitions
├── Cargo.toml
└── README.md
```

---

## Requirements

- Linux with eBPF support
- Rust toolchain (nightly may be required for eBPF builds)
- `bpf-linker`
- Root privileges to load eBPF programs
- Docker (recommended for container detection features)

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

### Container events only

```bash
sudo ./target/debug/altair-ebpf --container-only
```

### Container alerts only (recommended demo mode)

```bash
sudo ./target/debug/altair-ebpf --container-only --min-severity medium
```

### Help

```bash
./target/debug/altair-ebpf --help
```

---

## CLI options

| Option | Description |
|------|-------------|
| `--container-only` | Show only container events |
| `--all` | Show host + container events (default behavior) |
| `--min-severity <level>` | `info` \| `low` \| `medium` \| `high` |
| `-h`, `--help` | Show help |

Default min severity: `info`

---

## Severity model

| Severity | Meaning | Example |
|------|---------|---------|
| `INFO` | Normal execution | `ls`, `whoami` |
| `LOW` | Mild interest | non-root shell in container |
| `MEDIUM` | Notable risk behavior | `apk`, `apt`, `python` as root in container |
| `HIGH` | Strong suspicious behavior | root shell / `curl` / `wget` / `nc` in container |

Whitelisted binaries (always treated as `INFO`) include common utilities such as:

`ls`, `whoami`, `id`, `pwd`, `cat`, `echo`, `grep`, `sed`, `awk`, `head`, `tail`, `uname`, `ps`, `sleep`, and similar.

---

## Example output

### Normal container event

```text
• [CONTAINER] pid=1889 uid=0 comm=sh cid=48b28ea5957d → /usr/bin/whoami
```

### High severity alert

```text
┌─ ALERT [CONTAINER/HIGH] ──────────────────────────
│  PID         : 15558
│  UID         : 0
│  COMM        : sh
│  BINARY      : /usr/bin/wget
│  CONTAINER   : bcb2a9f6fe50
│  CGROUP_ID   : 3565
│  SEVERITY    : HIGH
│  REASON      : root network tool inside container
└────────────────────────────────────────────────
```

### Medium severity alert

```text
┌─ ALERT [CONTAINER/MEDIUM] ──────────────────────────
│  BINARY      : /sbin/apk
│  SEVERITY    : MEDIUM
│  REASON      : package manager executed as root in container
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
docker run --rm -it alpine sh
whoami          # usually hidden at medium+
wget example.com
apk update
```

Expected:
- host noise is hidden
- benign commands are quiet at `medium+`
- network tools / package managers raise alerts

---

## Notes on host noise

If you run without `--container-only`, you will see many host processes such as:

- shell initialization (`bash`, `lesspipe`, `dircolors`, ...)
- Docker runtime components on host (`containerd`, `runc`, ...)

This is expected in `ALL EVENTS` mode.

For practical monitoring demos, prefer:

```bash
sudo ./target/debug/altair-ebpf --container-only --min-severity medium
```

---

## Roadmap

- [x] eBPF execve monitoring with Aya
- [x] Container awareness
- [x] `--container-only`
- [x] Severity rules
- [x] Whitelist + `--min-severity`
- [ ] Container name/image enrichment
- [ ] JSON logging
- [ ] Optional network/file detectors

---

## Disclaimer

This repository is for **education and research**.  
Detection logic is intentionally simple and may produce false positives or false negatives.

Do not use it as a complete runtime security solution.

---

## License

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
