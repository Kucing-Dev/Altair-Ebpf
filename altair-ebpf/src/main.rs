use aya::{include_bytes_aligned, maps::RingBuf, programs::TracePoint, Ebpf};
use aya_log::EbpfLogger;
use altair_ebpf_common::ExecEvent;
use std::collections::HashSet;
use std::convert::TryInto;
use std::fs;
use std::sync::Mutex;
use tokio::signal;

fn print_banner() {
    println!(
        r#"
╔══════════════════════════════════════════════════════╗
║              ALTAIR eBPF Runtime Detector            ║
║     Process + Container Awareness • Rust + Aya       ║
╚══════════════════════════════════════════════════════╝
"#
    );
}

fn read_cgroup_text(id: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/cgroup", id)).ok()
}

fn parse_container_id(cgroup_text: &str) -> String {
    for token in cgroup_text.split(|c| c == '/' || c == '-' || c == '.' || c == ':') {
        let t = token.trim();
        if t.len() >= 12 && t.len() <= 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
            return t.chars().take(12).collect();
        }
    }
    "n/a".to_string()
}

fn is_container_cgroup_text(cgroup_text: &str) -> bool {
    let lower = cgroup_text.to_lowercase();
    lower.contains("docker")
        || lower.contains("containerd")
        || lower.contains("podman")
        || lower.contains("libpod")
        || lower.contains("cri-containerd")
        || lower.contains("kubepods")
        || lower.contains("lxc")
        || lower.contains(".scope")
}

fn detect_container(
    event: &ExecEvent,
    host_cgroup_id: u64,
    known_container_cgroups: &Mutex<HashSet<u64>>,
) -> (bool, String) {
    // 1) Coba baca /proc dulu (paling akurat kalau process masih hidup)
    if let Some(text) = read_cgroup_text(event.tgid).or_else(|| read_cgroup_text(event.pid)) {
        if is_container_cgroup_text(&text) {
            let mut set = known_container_cgroups.lock().unwrap();
            set.insert(event.cgroup_id);
            return (true, parse_container_id(&text));
        }
    }

    // 2) Fallback: bedakan lewat cgroup_id dari kernel
    //    Kalau cgroup_id berbeda dari proses host Altair, kemungkinan besar container/runtime lain.
    if event.cgroup_id != 0 && event.cgroup_id != host_cgroup_id {
        let mut set = known_container_cgroups.lock().unwrap();
        set.insert(event.cgroup_id);
        return (true, format!("cg:{}", event.cgroup_id));
    }

    // 3) Kalau cgroup_id ini pernah terdeteksi sebagai container sebelumnya
    {
        let set = known_container_cgroups.lock().unwrap();
        if set.contains(&event.cgroup_id) {
            return (true, format!("cg:{}", event.cgroup_id));
        }
    }

    (false, "n/a".to_string())
}

fn print_event(
    event: &ExecEvent,
    host_cgroup_id: u64,
    known_container_cgroups: &Mutex<HashSet<u64>>,
) {
    let comm = String::from_utf8_lossy(&event.comm)
        .trim_end_matches('\0')
        .to_string();

    let filename = String::from_utf8_lossy(
        &event.filename[..event.filename.iter().position(|&c| c == 0).unwrap_or(256)],
    )
    .to_string();

    let (is_container, container_id) =
        detect_container(event, host_cgroup_id, known_container_cgroups);
    let scope = if is_container { "CONTAINER" } else { "HOST" };

    let is_root = event.uid == 0;
    let suspicious = filename.contains("bash")
        || filename.contains("/sh")
        || filename.contains("nc")
        || filename.contains("curl")
        || filename.contains("wget")
        || filename.contains("python");

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

fn host_cgroup_id() -> u64 {
    // Ambil cgroup_id process Altair sendiri lewat /proc/self
    // Fallback 0 kalau gagal
    // Catatan: ini approximate; pembeda utama tetap event.cgroup_id dari kernel.
    let text = fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    // tidak selalu bisa map text -> id, jadi kembalikan 0 dan andalkan perbandingan dinamis
    let _ = text;
    0
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    print_banner();

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

    let host_cg = host_cgroup_id();
    let known_container_cgroups = Mutex::new(HashSet::<u64>::new());

    println!("\x1b[1;32m[✓]\x1b[0m eBPF program loaded");
    println!("\x1b[1;32m[✓]\x1b[0m Attached to sys_enter_execve");
    println!("\x1b[1;32m[✓]\x1b[0m Container awareness enabled (cgroup_id)");
    println!("\x1b[1;33m[*]\x1b[0m Listening... (Ctrl+C to stop)\n");

    let mut ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;

    // Bootstrap: catat cgroup_id host dari beberapa event awal yang jelas host-like
    // (dilakukan dinamis di detect_container)

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("\n\x1b[1;33m[*]\x1b[0m Shutting down Altair...");
                break;
            }
            _ = async {
                if let Some(item) = ring_buf.next() {
                    let event: ExecEvent = *bytemuck::from_bytes(&item);
                    print_event(&event, host_cg, &known_container_cgroups);
                }
            } => {}
        }
    }

    Ok(())
}