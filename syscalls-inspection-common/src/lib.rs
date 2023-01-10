#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SysCallLog {
    pub ts: u64,
    pub syscall: u64,
    pub pid: u64,
    pub pname_bytes: [u8; 16], // &str with Static lifetime
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SysCallLog {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ExecveArgs {
    pub exec: [u8; 16],
    pub exec_comm: [u8; 32],
    pub arg_buf: [[u8; 16]; 7],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecveArgs {}