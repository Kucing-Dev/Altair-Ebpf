use aya::{include_bytes_aligned, maps::RingBuf, programs::TracePoint, Ebpf};
use aya_log::EbpfLogger;
use log::{info, warn};
use altair_ebpf_common::ExecEvent;
use std::convert::TryInto;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/altair-ebpf"
    )))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Gagal init eBPF logger: {}", e);
    }

    let program: &mut TracePoint = bpf
        .program_mut("altair_ebpf")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    info!("Altair eBPF loaded. Menunggu execve... (Ctrl+C untuk keluar)");

    let mut ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Keluar...");
                break;
            }
            _ = async {
                if let Some(item) = ring_buf.next() {
                    let event: ExecEvent = *bytemuck::from_bytes(&item);

                    let comm = String::from_utf8_lossy(&event.comm);
                    let filename = String::from_utf8_lossy(
                        &event.filename[..event.filename.iter().position(|&c| c == 0).unwrap_or(256)]
                    );

                    let is_root = event.uid == 0;
                    let suspicious = filename.contains("bash")
                        || filename.contains("/sh")
                        || filename.contains("nc")
                        || filename.contains("curl")
                        || filename.contains("wget")
                        || filename.contains("python");

                    if is_root && suspicious {
                        warn!(
                            "⚠️  ALERT [ROOT + SUSPICIOUS] pid={} uid={} comm={} → {}",
                            event.pid, event.uid, comm.trim_end_matches('\0'), filename
                        );
                    } else {
                        info!(
                            "Exec: pid={} uid={} comm={} → {}",
                            event.pid, event.uid, comm.trim_end_matches('\0'), filename
                        );
                    }
                }
            } => {}
        }
    }

    Ok(())
}
