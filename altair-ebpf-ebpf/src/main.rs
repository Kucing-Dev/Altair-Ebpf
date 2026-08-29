#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use altair_ebpf_common::ExecEvent;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4096 * 64, 0);

#[tracepoint]
pub fn altair_ebpf(ctx: TracePointContext) -> u32 {
    match try_altair_ebpf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_altair_ebpf(ctx: TracePointContext) -> Result<u32, u32> {
    let filename_ptr: *const u8 = unsafe { ctx.read_at(16).map_err(|_| 1u32)? };

    let mut event = ExecEvent {
        pid: 0,
        tgid: 0,
        uid: 0,
        cgroup_id: 0,
        comm: [0u8; 16],
        filename: [0u8; 256],
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid & 0xFFFFFFFF) as u32;
    event.tgid = (pid_tgid >> 32) as u32;
    event.uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm = comm;
    }

    let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename) };

    if let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}