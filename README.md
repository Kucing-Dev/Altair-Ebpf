
<p align="center">
  <img src="https://github.com/user-attachments/assets/9cc35bf5-4845-44fc-996f-a43f6317c9e3" alt="my logo" style="width: 50%;">
</p>



<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white">
  <img src="https://img.shields.io/badge/eBPF-FF5722?style=for-the-badge&logo=linux&logoColor=white">
  <img src="https://img.shields.io/badge/Aya-0A66C2?style=for-the-badge&logo=rust&logoColor=white">
  <img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white">
  <img src="https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black">
  <img src="https://img.shields.io/badge/CLI-333333?style=for-the-badge&logo=gnubash&logoColor=white">
  <img src="https://img.shields.io/badge/Runtime%20Security-B71C1C?style=for-the-badge">
  <img src="https://img.shields.io/badge/MIT-00C853?style=for-the-badge">
</p>

# Altair eBPF

Runtime process execution monitor built with **Rust + eBPF (Aya)**, focused on **Docker/container runtime visibility**, behavioral alerting, and simple JSON logging.

> Status: **Learning / Prototype**  
> Not a production EDR/CDR or vulnerability scanner.

---

## Overview

Altair attaches to the Linux kernel tracepoint `sys_enter_execve` and monitors process executions in real time.

Pipeline:

1. **Phase 1 – Basic monitoring**  
   Capture PID/UID/comm/filename in eBPF and stream events via RingBuf
2. **Phase 2 – Container awareness**  
   Classify `HOST` vs `CONTAINER`, support `--container-only`
3. **Phase 3 – Threat rules**  
   Severity scoring (`INFO` / `LOW` / `MEDIUM` / `HIGH`)
4. **Phase 4 (partial) – Export**  
   JSONL logging for alerts/events

Earlier phases remain active and are required by later phases.

---

## What this is (and is not)

### This project is
- a runtime **behavioral** detector
- focused on process execution in Linux/Docker
- useful for learning eBPF + container security concepts

### This project is not
- a CVE/vulnerability scanner
- a replacement for Trivy/Grype/Snyk
- a full SOC platform

Severity is based on **behavioral rules**, not CVSS.

---

## Features

### Implemented

**Phase 1 – Basic process monitoring**
- eBPF on `sys_enter_execve`
- Collect PID/TGID, UID, `comm`, filename
- RingBuf kernel → userspace streaming
- Terminal output

**Phase 2 – Container awareness**
- Detect container context via:
  - Docker PID namespace correlation
  - cgroup inode correlation
  - `/proc/<pid>/cgroup` fallback
- `--container-only` mode
- Internal noise filtering

**Phase 3 – Threat rules**
- Severity model: `INFO` / `LOW` / `MEDIUM` / `HIGH`
- `--min-severity` filter
- Benign binary whitelist
- Rules for:
  - root shell in container
  - network tools (`curl`, `wget`, `nc`, ...)
  - package managers (`apk`, `apt`, ...)
  - mount/umount in container
  - namespace/chroot-related tools (`nsenter`, `unshare`, ...)

**Phase 4 (partial) – JSON export**
- `--json-log <path>` write JSONL
- `--json-all` optionally log all printed events
- default JSON mode logs alerts only

### Not implemented yet
- Network connect monitoring (`tcp_connect`)
- File-open monitoring (`security_file_open`)
- Docker name/image metadata enrichment
- Prometheus metrics
- Auto-response / process kill

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
                          ├─ print logs / alerts
                          └─ optional JSONL export
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

### With JSON logging

```bash
sudo ./target/debug/altair-ebpf \
  --container-only \
  --min-severity medium \
  --json-log /tmp/altair.jsonl
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
| `--min-severity <level>` | `info` \| `low` \| `medium` \| `high` |
| `--json-log <path>` | Append JSONL records to file |
| `--json-all` | With `--json-log`, write all printed events (not only alerts) |
| `-h`, `--help` | Show help |

Default min severity: `info`

---

## Severity model

| Level | Meaning | Examples |
|------|---------|----------|
| `INFO` | Normal execution | `ls`, `whoami` |
| `LOW` | Mild interest | non-root shell in container |
| `MEDIUM` | Notable risk behavior | `apk` / `apt` as root in container |
| `HIGH` | Strong suspicious behavior | root shell, `wget`/`curl`/`nc`, `mount` in container |

---

## Example terminal alert

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
```

## Example JSONL

```json
{"ts":1788181756604,"type":"alert","scope":"CONTAINER","severity":"HIGH","pid":3048,"uid":0,"comm":"sh","binary":"/usr/bin/wget","container":"8430102cfd11","cgroup_id":2712,"reason":"root network tool inside container"}
```

---

## Quick test

Terminal 1:

```bash
sudo ./target/debug/altair-ebpf \
  --container-only \
  --min-severity medium \
  --json-log /tmp/altair.jsonl
```

Terminal 2:

```bash
docker run --rm -it --privileged alpine sh
whoami
wget example.com
apk update
mount
```

Then:

```bash
cat /tmp/altair.jsonl
```

---

## Roadmap

- [x] Phase 1: basic execve monitoring
- [x] Phase 2: container awareness + `--container-only`
- [x] Phase 3: threat rules + severity + whitelist
- [x] Phase 4a: JSONL export
<!-- [x] Phase 4b: network/file hooks, metadata, Prometheus -->

---

## Disclaimer

This project is for **education and research**.  
Detection logic is intentionally simple and may produce false positives or false negatives.

It does **not** classify CVEs and should not be treated as a complete runtime security product.


---
<!-- License -->

<!-- With the exception of eBPF code, altair-ebpf is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.-->

<!-- Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.-->

<!-- ### eBPF -->

<!-- All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.-->

<!-- Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.-->

<!-- [Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2 -->
