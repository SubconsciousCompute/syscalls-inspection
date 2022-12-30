#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SysCallLog {
    pub ts      : u64,
    pub syscall : u64,
    pub pid     : u64,
    pub pname_bytes   : [u8; 16], // &str with Static lifetime
}

// #[cfg(feature = "user")]
// unsafe impl aya::Pod for SysCallLog {}
// #[repr(C)]
// #[derive(Copy, Clone)]
// pub struct Filename {
//     pub filename: [u8; 127],
//     pub filename_len: u8,
// }

// #[cfg(feature = "user")]
// unsafe impl aya::Pod for Filename {}
