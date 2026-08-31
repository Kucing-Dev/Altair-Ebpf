use aya::{include_bytes_aligned, maps::RingBuf, programs::TracePoint, Ebpf};
use aya_log::EbpfLogger;
use altair_ebpf_common::ExecEvent;
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::signal;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
        }
    }

    fn color(self) -> &'static str {
        match self {
            Severity::Info => "\x1b[1;36m",
            Severity::Low => "\x1b[1;33m",
            Severity::Medium => "\x1b[1;35m",
            Severity::High => "\x1b[1;31m",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "med" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            _ => None,
        }
    }
}

struct Findings {
    severity: Severity,
    reason: &'static str,
}

struct Config {
    container_only: bool,
    min_severity: Severity,
    json_log: Option<PathBuf>,
    json_all: bool, // true = log semua event lolos filter; false = hanya alert
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn print_banner(cfg: &Config) {
    println!(
        r#"
╔══════════════════════════════════════════════════════╗
║              ALTAIR eBPF Runtime Detector            ║
║         Phases 1-3 + JSON Logging • Rust/Aya         ║
╚══════════════════════════════════════════════════════╝
"#
    );

    if cfg.container_only {
        println!("\x1b[1;35m[*]\x1b[0m Mode: \x1b[1;35mCONTAINER-ONLY\x1b[0m");
    } else {
        println!("\x1b[1;36m[*]\x1b[0m Mode: \x1b[1;36mALL EVENTS\x1b[0m");
    }
    println!(
        "\x1b[1;36m[*]\x1b[0m Min severity: \x1b[1;36m{}\x1b[0m",
        cfg.min_severity.as_str()
    );
    match &cfg.json_log {
        Some(p) => println!(
            "\x1b[1;36m[*]\x1b[0m JSON log: \x1b[1;36m{}\x1b[0m ({})",
            p.display(),
            if cfg.json_all { "all events" } else { "alerts only" }
        ),
        None => println!("\x1b[1;36m[*]\x1b[0m JSON log: disabled"),
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

    if event.cgroup_id != 0 {
        if let Some(cid) = docker.by_cgroup.get(&event.cgroup_id) {
            return (true, cid.clone());
        }
    }

    for id in [event.tgid, event.pid] {
        if let Some(ns) = read_link(&format!("/proc/{}/ns/pid", id)) {
            if let Some(info) = docker.by_ns.get(&ns) {
                return (true, info.id.clone());
            }
        }
    }

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
    if comm == "altair-ebpf" {
        return true;
    }
    if event.tgid == std::process::id() && filename.ends_with("/docker") {
        return true;
    }
    false
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn is_whitelisted(filename: &str) -> bool {
    matches!(
        basename(filename),
        "ls" | "whoami" | "id" | "pwd" | "cat" | "echo"
            | "true" | "false" | "basename" | "dirname"
            | "head" | "tail" | "tr" | "grep" | "sed"
            | "awk" | "sort" | "find" | "uname" | "date"
            | "which" | "tput" | "dircolors" | "lesspipe"
            | "env" | "printenv" | "ps" | "sleep"
    )
}

fn evaluate_rules(is_container: bool, uid: u32, filename: &str) -> Findings {
    if is_whitelisted(filename) {
        return Findings {
            severity: Severity::Info,
            reason: if is_container {
                "container process execution (whitelisted)"
            } else {
                "host process execution (whitelisted)"
            },
        };
    }

    let bin = basename(filename);
    let is_root = uid == 0;
    let lower_path = filename.to_ascii_lowercase();

    let is_shell = matches!(bin, "sh" | "bash" | "ash" | "zsh" | "dash" | "busybox");
    let is_net_tool = matches!(
        bin,
        "curl" | "wget" | "nc" | "ncat" | "netcat" | "nmap" | "dig" | "socat"
    );
    let is_pkg_mgr = matches!(
        bin,
        "apk" | "apt" | "apt-get" | "dpkg" | "yum" | "dnf" | "microdnf" | "pip" | "pip3"
    );
    let is_compiler = matches!(bin, "gcc" | "g++" | "make" | "cc" | "python" | "python3" | "perl");
    let is_privesc_tool = matches!(bin, "sudo" | "su" | "chmod" | "chown" | "setcap" | "capsh");
    let is_mount_tool = matches!(
        bin,
        "mount" | "umount" | "mount.nfs" | "mount.cifs" | "fusermount" | "fusermount3"
    );
    let is_escape_tool = matches!(
        bin,
        "nsenter" | "unshare" | "chroot" | "pivot_root" | "setns"
    );
    let sensitive_path_exec = lower_path.contains("/proc/1/")
        || lower_path.contains("/proc/self/root")
        || lower_path.contains("docker.sock")
        || lower_path.contains("/var/run/docker.sock");

    if is_container {
        if is_root && is_mount_tool {
            return Findings {
                severity: Severity::High,
                reason: "mount/umount executed as root inside container",
            };
        }
        if is_root && is_escape_tool {
            return Findings {
                severity: Severity::High,
                reason: "namespace/chroot tool executed as root inside container",
            };
        }
        if sensitive_path_exec {
            return Findings {
                severity: Severity::High,
                reason: "execution related to sensitive host/container path",
            };
        }
        if is_root && is_shell {
            return Findings {
                severity: Severity::High,
                reason: "root interactive shell inside container",
            };
        }
        if is_root && is_net_tool {
            return Findings {
                severity: Severity::High,
                reason: "root network tool inside container",
            };
        }
        if is_root && is_pkg_mgr {
            return Findings {
                severity: Severity::Medium,
                reason: "package manager executed as root in container",
            };
        }
        if is_root && is_compiler {
            return Findings {
                severity: Severity::Medium,
                reason: "compiler/runtime toolchain used as root in container",
            };
        }
        if is_root && is_privesc_tool {
            return Findings {
                severity: Severity::Medium,
                reason: "privilege-related binary in container",
            };
        }
        if is_shell {
            return Findings {
                severity: Severity::Low,
                reason: "shell executed inside container",
            };
        }
        return Findings {
            severity: Severity::Info,
            reason: "container process execution",
        };
    }

    if is_root && is_escape_tool {
        return Findings {
            severity: Severity::Low,
            reason: "namespace/chroot tool on host",
        };
    }
    if is_root && is_net_tool {
        return Findings {
            severity: Severity::Low,
            reason: "root network tool on host",
        };
    }

    Findings {
        severity: Severity::Info,
        reason: "host process execution",
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn write_json_line(
    path: &PathBuf,
    event: &ExecEvent,
    comm: &str,
    filename: &str,
    is_container: bool,
    container_id: &str,
    findings: &Findings,
    is_alert: bool,
) {
    let scope = if is_container { "CONTAINER" } else { "HOST" };
    let line = format!(
        "{{\"ts\":{},\"type\":\"{}\",\"scope\":\"{}\",\"severity\":\"{}\",\"pid\":{},\"uid\":{},\"comm\":\"{}\",\"binary\":\"{}\",\"container\":\"{}\",\"cgroup_id\":{},\"reason\":\"{}\"}}\n",
        now_unix_ms(),
        if is_alert { "alert" } else { "event" },
        scope,
        findings.severity.as_str(),
        event.tgid,
        event.uid,
        json_escape(comm),
        json_escape(filename),
        json_escape(container_id),
        event.cgroup_id,
        json_escape(findings.reason),
    );

    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(line.as_bytes());
    }
}

fn print_alert(
    severity: Severity,
    event: &ExecEvent,
    comm: &str,
    filename: &str,
    container_id: &str,
    is_container: bool,
    reason: &str,
) {
    let c = severity.color();
    let scope = if is_container { "CONTAINER" } else { "HOST" };

    println!(
        "{c}┌─ ALERT [{scope}/{sev}] ──────────────────────────\x1b[0m",
        scope = scope,
        sev = severity.as_str()
    );
    println!("{c}│\x1b[0m  PID         : {}", event.tgid);
    println!("{c}│\x1b[0m  UID         : {}", event.uid);
    println!("{c}│\x1b[0m  COMM        : {}", comm);
    println!("{c}│\x1b[0m  BINARY      : {}", filename);
    if is_container {
        println!("{c}│\x1b[0m  CONTAINER   : {}", container_id);
        println!("{c}│\x1b[0m  CGROUP_ID   : {}", event.cgroup_id);
    }
    println!("{c}│\x1b[0m  SEVERITY    : {}", severity.as_str());
    println!("{c}│\x1b[0m  REASON      : {}", reason);
    println!("{c}└────────────────────────────────────────────────\x1b[0m\n");
}

fn print_event(event: &ExecEvent, docker: &Mutex<DockerIndex>, cfg: &Config) {
    let comm = String::from_utf8_lossy(&event.comm)
        .trim_end_matches('\0')
        .to_string();

    let filename = String::from_utf8_lossy(
        &event.filename[..event.filename.iter().position(|&c| c == 0).unwrap_or(256)],
    )
    .to_string();

    if is_self_noise(&comm, &filename, event) {
        return;
    }

    let (is_container, container_id) = detect_container(event, docker);
    if cfg.container_only && !is_container {
        return;
    }

    let findings = evaluate_rules(is_container, event.uid, &filename);
    if findings.severity < cfg.min_severity {
        return;
    }

    let is_alert = findings.severity != Severity::Info;

    if let Some(path) = &cfg.json_log {
        if is_alert || cfg.json_all {
            write_json_line(
                path,
                event,
                &comm,
                &filename,
                is_container,
                &container_id,
                &findings,
                is_alert,
            );
        }
    }

    if is_alert {
        print_alert(
            findings.severity,
            event,
            &comm,
            &filename,
            &container_id,
            is_container,
            findings.reason,
        );
        return;
    }

    if is_container {
        println!(
            "\x1b[1;35m•\x1b[0m [\x1b[1;35mCONTAINER\x1b[0m] pid={:<6} uid={:<5} comm={:<12} cid={:<14} \x1b[32m→\x1b[0m {}",
            event.tgid, event.uid, comm, container_id, filename
        );
    } else {
        println!(
            "\x1b[1;36m•\x1b[0m [\x1b[90mHOST\x1b[0m] pid={:<6} uid={:<5} comm={:<12} \x1b[32m→\x1b[0m {}",
            event.tgid, event.uid, comm, filename
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
  --container-only              Show only container events
  --min-severity <level>        info | low | medium | high (default: info)
  --json-log <path>             Append JSONL events/alerts to file
  --json-all                    With --json-log, write all printed events (not only alerts)
  -h, --help                    Show this help

EXAMPLES:
  sudo ./target/debug/altair-ebpf --container-only --min-severity medium
  sudo ./target/debug/altair-ebpf --container-only --min-severity medium --json-log /tmp/altair.jsonl
"#
    );
}

fn parse_args() -> Config {
    let args: Vec<String> = env::args().collect();
    let container_only = args.iter().any(|a| a == "--container-only");
    let json_all = args.iter().any(|a| a == "--json-all");

    let mut min_severity = Severity::Info;
    if let Some(i) = args.iter().position(|a| a == "--min-severity") {
        if let Some(v) = args.get(i + 1) {
            if let Some(sev) = Severity::parse(v) {
                min_severity = sev;
            } else {
                eprintln!("Invalid --min-severity value: {v}");
                std::process::exit(1);
            }
        } else {
            eprintln!("Missing value for --min-severity");
            std::process::exit(1);
        }
    }

    let mut json_log = None;
    if let Some(i) = args.iter().position(|a| a == "--json-log") {
        if let Some(v) = args.get(i + 1) {
            json_log = Some(PathBuf::from(v));
        } else {
            eprintln!("Missing value for --json-log");
            std::process::exit(1);
        }
    }

    Config {
        container_only,
        min_severity,
        json_log,
        json_all,
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return Ok(());
    }

    let cfg = parse_args();
    print_banner(&cfg);

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
    println!("\x1b[1;32m[✓]\x1b[0m Docker tracking enabled");
    println!("\x1b[1;32m[✓]\x1b[0m Threat rules enabled");
    println!("\x1b[1;32m[✓]\x1b[0m JSON logging ready");
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
                    print_event(&event, &docker_index, &cfg);
                }
            } => {}
        }
    }

    Ok(())
}