use aya::{include_bytes_aligned, maps::RingBuf, programs::TracePoint, Ebpf};
use aya_log::EbpfLogger;
use altair_ebpf_common::ExecEvent;
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::signal;

fn print_banner(container_only: bool) {
    println!(
        r#"
╔══════════════════════════════════════════════════════╗
║              ALTAIR eBPF Runtime Detector            ║
║     Process + Container Awareness • Rust + Aya       ║
╚══════════════════════════════════════════════════════╝
"#
    );

    if container_only {
        println!("\x1b[1;35m[*]\x1b[0m Mode: \x1b[1;35mCONTAINER-ONLY\x1b[0m (host events hidden)");
    } else {
        println!("\x1b[1;36m[*]\x1b[0m Mode: \x1b[1;36mALL EVENTS\x1b[0m (host + container)");
    }
}

fn read_text(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn read_link(path: &str) -> Option<PathBuf> {
    fs::read_link(path).ok()
}

fn cgroup_inode_from_pid(pid: u32) -> Option<u64> {
    let text = read_text(&format!("/proc/{}/cgroup", pid))?;
    let rel = text
        .lines()
        .rev()
        .find_map(|l| l.split("::").nth(1))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())?;

    let path = if rel.starts_with('/') {
        format!("/sys/fs/cgroup{rel}")
    } else {
        format!("/sys/fs/cgroup/{rel}")
    };

    let meta = fs::metadata(path).ok()?;
    Some(meta.ino())
}

#[derive(Clone, Debug)]
struct ContainerInfo {
    id: String,
    _pid: u32,
}

#[derive(Default, Clone)]
struct DockerIndex {
    by_ns: HashMap<PathBuf, ContainerInfo>,
    by_cgroup: HashMap<u64, String>,
}

fn refresh_docker_index() -> DockerIndex {
    let mut index = DockerIndex::default();

    let output = match Command::new("docker").args(["ps", "-q"]).output() {
        Ok(o) if o.status.success() => o,
        _ => return index,
    };

    let ids = String::from_utf8_lossy(&output.stdout);
    for id in ids.split_whitespace() {
        let inspect = match Command::new("docker")
            .args(["inspect", "-f", "{{.State.Pid}} {{.Id}}", id])
            .output()
        {
            Ok(o) if o.status.success() => o,
            _ => continue,
        };

        let text = String::from_utf8_lossy(&inspect.stdout);
        let mut parts = text.split_whitespace();
        let Some(pid_str) = parts.next() else { continue };
        let Some(full_id) = parts.next() else { continue };
        let Ok(pid) = pid_str.parse::<u32>() else { continue };
        if pid == 0 {
            continue;
        }

        let short_id: String = full_id.chars().take(12).collect();
        let info = ContainerInfo {
            id: short_id.clone(),
            _pid: pid,
        };

        if let Some(ns) = read_link(&format!("/proc/{}/ns/pid", pid)) {
            index.by_ns.insert(ns, info);
        }

        if let Some(ino) = cgroup_inode_from_pid(pid) {
            index.by_cgroup.insert(ino, short_id);
        }
    }

    index
}

fn detect_container(event: &ExecEvent, docker: &Mutex<DockerIndex>) -> (bool, String) {
    let docker = docker.lock().unwrap();

    // 1) cocokkan cgroup_id dari eBPF
    if event.cgroup_id != 0 {
        if let Some(cid) = docker.by_cgroup.get(&event.cgroup_id) {
            return (true, cid.clone());
        }
    }

    // 2) cocokkan pid namespace
    for id in [event.tgid, event.pid] {
        if let Some(ns) = read_link(&format!("/proc/{}/ns/pid", id)) {
            if let Some(info) = docker.by_ns.get(&ns) {
                return (true, info.id.clone());
            }
        }
    }

    // 3) fallback teks cgroup (hanya pola docker/container runtime)
    for id in [event.tgid, event.pid] {
        if let Some(text) = read_text(&format!("/proc/{}/cgroup", id)) {
            let lower = text.to_lowercase();
            if lower.contains("docker")
                || lower.contains("containerd")
                || lower.contains("podman")
                || lower.contains("libpod")
            {
                let cid = text
                    .split(|c| c == '/' || c == '-' || c == '.' || c == ':')
                    .find(|t| {
                        t.len() >= 12
                            && t.len() <= 64
                            && t.chars().all(|ch| ch.is_ascii_hexdigit())
                    })
                    .map(|t| t.chars().take(12).collect())
                    .unwrap_or_else(|| format!("cg:{}", event.cgroup_id));
                return (true, cid);
            }
        }
    }

    (false, "n/a".to_string())
}

fn is_self_noise(comm: &str, filename: &str, event: &ExecEvent) -> bool {
    // event dari binary Altair sendiri
    if comm == "altair-ebpf" {
        return true;
    }

    // pemanggilan docker CLI oleh process Altair (tracking internal)
    if event.tgid == std::process::id() && filename.ends_with("/docker") {
        return true;
    }

    // path docker CLI yang sering muncul dari refresh internal
    if filename.ends_with("/docker")
        && (filename.contains("/usr/bin/docker")
            || filename.contains("/usr/local/bin/docker")
            || filename.contains("/usr/sbin/docker")
            || filename.contains("/usr/local/sbin/docker"))
        && comm == "altair-ebpf"
    {
        return true;
    }

    false
}

fn print_event(event: &ExecEvent, docker: &Mutex<DockerIndex>, container_only: bool) {
    let comm = String::from_utf8_lossy(&event.comm)
        .trim_end_matches('\0')
        .to_string();

    let filename = String::from_utf8_lossy(
        &event.filename[..event.filename.iter().position(|&c| c == 0).unwrap_or(256)],
    )
    .to_string();

    // filter noise internal
    if is_self_noise(&comm, &filename, event) {
        return;
    }

    let (is_container, container_id) = detect_container(event, docker);

    // fitur 2: hanya tampilkan container
    if container_only && !is_container {
        return;
    }

    let scope = if is_container { "CONTAINER" } else { "HOST" };
    let is_root = event.uid == 0;

    let suspicious = filename.ends_with("/bash")
        || filename.ends_with("/sh")
        || filename.ends_with("/ash")
        || filename.ends_with("/busybox")
        || filename.contains("/curl")
        || filename.contains("/wget")
        || filename.contains("/python")
        || filename.contains("/nc");

    if is_container && is_root && suspicious {
        println!("\x1b[1;31m┌─ ALERT [CONTAINER] ─────────────────────────────\x1b[0m");
        println!("\x1b[1;31m│\x1b[0m  PID         : {}", event.tgid);
        println!("\x1b[1;31m│\x1b[0m  UID         : {}", event.uid);
        println!("\x1b[1;31m│\x1b[0m  COMM        : {}", comm);
        println!("\x1b[1;31m│\x1b[0m  BINARY      : {}", filename);
        println!("\x1b[1;31m│\x1b[0m  CONTAINER   : {}", container_id);
        println!("\x1b[1;31m│\x1b[0m  CGROUP_ID   : {}", event.cgroup_id);
        println!("\x1b[1;31m│\x1b[0m  REASON      : root shell/tool inside container");
        println!("\x1b[1;31m└────────────────────────────────────────────────\x1b[0m\n");
        return;
    }

    if is_container {
        println!(
            "\x1b[1;35m•\x1b[0m [\x1b[1;35m{}\x1b[0m] pid={:<6} uid={:<5} comm={:<12} cid={:<14} \x1b[32m→\x1b[0m {}",
            scope, event.tgid, event.uid, comm, container_id, filename
        );
    } else {
        println!(
            "\x1b[1;36m•\x1b[0m [\x1b[90m{}\x1b[0m] pid={:<6} uid={:<5} comm={:<12} \x1b[32m→\x1b[0m {}",
            scope, event.tgid, event.uid, comm, filename
        );
    }
}

fn print_help() {
    println!(
        r#"
Altair eBPF - Runtime Detector

USAGE:
  sudo ./target/debug/altair-ebpf [OPTIONS]

OPTIONS:
  --container-only   Show only container events (hide host)
  --all              Show host + container events (default)
  -h, --help         Show this help
"#
    );
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return Ok(());
    }

    let container_only = args.iter().any(|a| a == "--container-only");
    print_banner(container_only);

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/altair-ebpf"
    )))?;
    let _ = EbpfLogger::init(&mut bpf);

    let program: &mut TracePoint = bpf
        .program_mut("altair_ebpf")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    let docker_index = Arc::new(Mutex::new(refresh_docker_index()));

    {
        let docker_index = Arc::clone(&docker_index);
        thread::spawn(move || loop {
            let fresh = refresh_docker_index();
            if let Ok(mut guard) = docker_index.lock() {
                *guard = fresh;
            }
            thread::sleep(Duration::from_secs(1));
        });
    }

    println!("\x1b[1;32m[✓]\x1b[0m eBPF program loaded");
    println!("\x1b[1;32m[✓]\x1b[0m Attached to sys_enter_execve");
    println!("\x1b[1;32m[✓]\x1b[0m Docker tracking via PID ns + cgroup inode");
    println!("\x1b[1;33m[*]\x1b[0m Listening... (Ctrl+C to stop)\n");

    let mut ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("\n\x1b[1;33m[*]\x1b[0m Shutting down Altair...");
                break;
            }
            _ = async {
                if let Some(item) = ring_buf.next() {
                    let event: ExecEvent = *bytemuck::from_bytes(&item);
                    print_event(&event, &docker_index, container_only);
                }
            } => {}
        }
    }

    Ok(())
}