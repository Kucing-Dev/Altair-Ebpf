#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}

#[cfg(feature = "user")]
unsafe impl bytemuck::Zeroable for ExecEvent {}

#[cfg(feature = "user")]
unsafe impl bytemuck::Pod for ExecEvent {}
