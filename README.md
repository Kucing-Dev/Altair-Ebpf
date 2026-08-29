
<p align="center">
  <img src="https://github.com/user-attachments/assets/998c35d1-5ea0-4087-9cf0-50388b8851e4" width="400" alt="Altair-Ebpf Logo">
</p>



# Altair eBPF

Runtime process execution monitor built with **Rust + eBPF (Aya)**, focused on early **Docker/container awareness**.

> Status: **Learning / Prototype**  
> Not production-ready.

---

## Overview

Altair attaches to the Linux kernel tracepoint `sys_enter_execve` and monitors process executions in real time.

Events are streamed from kernel space to userspace through a **RingBuf**, then enriched with container context using:

- Docker PID / namespace tracking
- cgroup inode correlation
- `/proc` fallback inspection

The tool can classify events as `HOST` or `CONTAINER`, and raise a simple alert when a root shell/tool runs inside a container.

---

## Features

### Working

- eBPF-based process execution monitoring (`sys_enter_execve`)
- Kernel → userspace event streaming via RingBuf
- Container awareness for Docker workloads
- `--container-only` mode (hide host events)
- Simple terminal UI with colored logs
- Alert on suspicious root activity inside containers
  - examples: `/bin/sh`, `/bin/bash`, `/bin/busybox`, `curl`, `wget`, `python`, `nc`
- Internal noise filtering (self process / Docker CLI used for tracking)

### Not yet

- Advanced severity model (`INFO` / `LOW` / `MEDIUM` / `HIGH`)
- Docker metadata enrichment (container name, image)
- JSON / file logging
- Network or filesystem detectors
- Production packaging and hardening

---

## Architecture

```text
Linux Kernel
  └─ tracepoint: sys_enter_execve
        └─ eBPF program (Aya)
              └─ RingBuf event stream
                    └─ Rust userspace
                          ├─ parse ExecEvent
                          ├─ detect HOST vs CONTAINER
                          ├─ apply --container-only filter
                          └─ print logs / alerts
```

Container detection strategy:

1. Match event `cgroup_id` with active Docker container cgroup inodes
2. Match process PID namespace with running container namespaces
3. Fallback to `/proc/<pid>/cgroup` text inspection

---

## Project structure

```text
altair-ebpf/
├── altair-ebpf/           # userspace application
├── altair-ebpf-ebpf/      # eBPF program
├── altair-ebpf-common/    # shared event struct
├── Cargo.toml
└── README.md
```

---

## Requirements

- Linux environment with eBPF support
- Rust toolchain (nightly may be required for eBPF build)
- `bpf-linker`
- Root privileges to load eBPF programs
- Docker (for container detection features)

---

## Build

```bash
cargo build
```

Release build:

```bash
cargo build --release
```

---

## Usage

### Show all events (host + container)

```bash
sudo ./target/debug/altair-ebpf
```

### Show container events only

```bash
sudo ./target/debug/altair-ebpf --container-only
```

### Help

```bash
./target/debug/altair-ebpf --help
```

---

## Example output

### Container event

```text
• [CONTAINER] pid=15483 uid=0 comm=sh cid=07a246c48261 → /usr/bin/whoami
• [CONTAINER] pid=15607 uid=0 comm=sh cid=07a246c48261 → /bin/ls
```

### Alert

```text
┌─ ALERT [CONTAINER] ─────────────────────────────
│  PID         : 16633
│  UID         : 0
│  COMM        : sh
│  BINARY      : /bin/sh
│  CONTAINER   : 07a246c48261
│  CGROUP_ID   : 4965
│  REASON      : root shell/tool inside container
└────────────────────────────────────────────────
```

---

## Quick test

Terminal 1:

```bash
cd /path/to/altair-ebpf
sudo ./target/debug/altair-ebpf --container-only
```

Terminal 2:

```bash
# should stay quiet in container-only mode
whoami
ls

# should produce CONTAINER events / alerts
docker run --rm -it alpine sh
whoami
ls
```

Expected:

- host commands are hidden in `--container-only`
- container commands appear as `[CONTAINER]`
- container root shell may trigger `ALERT [CONTAINER]`

---

## Current detection logic

Very simple prototype rules:

- Classify process as container using Docker/namespace/cgroup correlation
- Alert if all are true:
  - event is inside a container
  - UID is `0`
  - binary looks like a shell or common probing tool

This can still produce false positives/negatives and is intended for learning.

---

## Roadmap

- [x] Runtime execve monitoring with eBPF + Aya
- [x] Container awareness
- [x] `--container-only` mode
- [ ] Better alert rules and severity levels
- [ ] Enrich events with container name/image
- [ ] JSON logging
- [ ] Optional network/file-related detectors

---

## Disclaimer

This project is for **education and research**.  
It is not a complete runtime security product and should not be treated as production EDR/CDR.

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
