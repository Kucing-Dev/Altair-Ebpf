
<p align="center">
  <img src="https://github.com/user-attachments/assets/998c35d1-5ea0-4087-9cf0-50388b8851e4" width="400" alt="Altair-Ebpf Logo">
</p>



# Altair eBPF

Runtime process execution monitor built with **Rust + eBPF (Aya)**, with early **container awareness** for Docker/Linux environments.

> Status: **Learning / Prototype**  
> Not production-ready.

---

## What it does

Altair attaches to the kernel tracepoint `sys_enter_execve` and monitors process executions in real time.

For each event, it collects:
- PID / TGID
- UID
- Process name (`comm`)
- Binary path
- cgroup id (for container awareness)

It then classifies events as:
- `HOST`
- `CONTAINER`

and raises a simple alert when a **root shell/tool** is executed inside a container.

---
```
## Features

### Working
- eBPF-based process execution monitoring
- Kernel → userspace event streaming via RingBuf
- Basic terminal UI
- Container awareness using cgroup id + `/proc` enrichment
- Simple alert rule for suspicious root activity in containers

### Not yet
- `--container-only` filter mode
- Docker metadata enrichment (container name/image)
- Advanced detection rules / severity levels
- Persistent logging / SIEM export
- Production hardening

---

## Architecture


Linux Kernel
  └─ tracepoint: sys_enter_execve
        └─ eBPF program (Aya)
              └─ RingBuf events
                    └─ Rust userspace
                          ├─ parse event
                          ├─ detect host vs container
                          └─ print logs / alerts
```

---

## Requirements

- Linux (tested on Parrot/WSL2-like environments)
- Rust toolchain (nightly recommended for eBPF build)
- `bpf-linker`
- Root privileges to load eBPF programs
- Docker (optional, for container testing)

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

## Run

```bash
sudo ./target/debug/altair-ebpf
```

or:

```bash
sudo ./target/release/altair-ebpf
```

---

## Example output

```text
[✓] eBPF program loaded
[✓] Attached to sys_enter_execve
[✓] Container awareness enabled (cgroup_id)
[*] Listening... (Ctrl+C to stop)

• [HOST] pid=2032 uid=0 comm=bash → /usr/bin/ls

• [CONTAINER] pid=16422 uid=0 comm=sh cid=cg:22 → /bin/ls

┌─ ALERT [CONTAINER] ─────────────────────────────
│  PID         : 16418
│  UID         : 0
│  COMM        : bash
│  BINARY      : /bin/bash
│  CONTAINER   : cg:22
│  CGROUP_ID   : 22
│  REASON      : root shell/tool inside container
└────────────────────────────────────────────────
```

---

## Test with Docker

Terminal 1:

```bash
sudo ./target/debug/altair-ebpf
```

Terminal 2:

```bash
docker run --rm -it alpine sh
whoami
ls
```

Expected:
- host commands appear as `[HOST]`
- container commands appear as `[CONTAINER]`
- root shell inside container may trigger `ALERT [CONTAINER]`

---

## Project structure

```text
altair-ebpf/
├── altair-ebpf/              # userspace application
├── altair-ebpf-ebpf/         # eBPF program
├── altair-ebpf-common/       # shared event struct
├── Cargo.toml
└── README.md
```

---

## Current detection logic

Very simple prototype rules:

- Classify by cgroup information
- Alert if:
  - event is inside container
  - UID is 0
  - binary looks like shell/tool (`sh`, `bash`, `curl`, `wget`, `python`, `nc`, etc.)

This will produce false positives and is intended for learning.

---

## Roadmap

- [ ] `--container-only` mode
- [ ] Reduce false positives with better rules
- [ ] Enrich events with Docker container name/image
- [ ] JSON logging
- [ ] Severity levels (`INFO`, `LOW`, `MEDIUM`, `HIGH`)
- [ ] Optional network/file-related detectors

---

## Disclaimer

This project is for **education and research**.
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
