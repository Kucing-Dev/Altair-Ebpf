use aya::{include_bytes_aligned, maps::RingBuf, programs::TracePoint, Ebpf};
use aya_log::EbpfLogger;
use altair_ebpf_common::ExecEvent;
use std::convert::TryInto;
use tokio::signal;

fn print_banner() {
    println!(
        r#"
╔══════════════════════════════════════════════════════╗
║              ALTAIR eBPF Runtime Detector            ║
║         Process Execution Monitor • Rust + Aya       ║
╚══════════════════════════════════════════════════════╝
"#
    );
}

fn print_event(event: &ExecEvent) {
    let comm = String::from_utf8_lossy(&event.comm)
        .trim_end_matches('\0')
        .to_string();

    let filename = String::from_utf8_lossy(
        &event.filename[..event.filename.iter().position(|&c| c == 0).unwrap_or(256)],
    )
    .to_string();

    let is_root = event.uid == 0;
    let suspicious = filename.contains("bash")
        || filename.contains("/sh")
        || filename.contains("nc")
        || filename.contains("curl")
        || filename.contains("wget")
        || filename.contains("python");

    if is_root && suspicious {
        // ALERT - merah
        println!(
            "\x1b[1;31m┌─ ALERT ─────────────────────────────────────────\x1b[0m"
        );
        println!("\x1b[1;31m│\x1b[0m  PID      : {}", event.pid);
        println!("\x1b[1;31m│\x1b[0m  UID      : {}", event.uid);
        println!("\x1b[1;31m│\x1b[0m  COMM     : {}", comm);
        println!("\x1b[1;31m│\x1b[0m  BINARY   : {}", filename);
        println!("\x1b[1;31m│\x1b[0m  REASON   : root + suspicious binary");
        println!(
            "\x1b[1;31m└────────────────────────────────────────────────\x1b[0m\n"
        );
    } else {
        // INFO - hijau/cyan
        println!(
            "\x1b[1;36m•\x1b[0m \x1b[90mpid=\x1b[0m{:<6} \x1b[90muid=\x1b[0m{:<5} \x1b[90mcomm=\x1b[0m{:<12} \x1b[32m→\x1b[0m {}",
            event.pid, event.uid, comm, filename
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    print_banner();

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/altair-ebpf"
    )))?;

    // logger eBPF opsional, boleh diabaikan kalau gagal
    let _ = EbpfLogger::init(&mut bpf);

    let program: &mut TracePoint = bpf
        .program_mut("altair_ebpf")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    println!("\x1b[1;32m[✓]\x1b[0m eBPF program loaded");
    println!("\x1b[1;32m[✓]\x1b[0m Attached to sys_enter_execve");
    println!("\x1b[1;33m[*]\x1b[0m Listening for process executions... (Ctrl+C to stop)\n");

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
                    print_event(&event);
                }
            } => {}
        }
    }

    Ok(())
}
