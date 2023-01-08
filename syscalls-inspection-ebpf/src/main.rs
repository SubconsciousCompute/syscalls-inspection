#![no_std]
#![no_main]

use core::slice;

use aya_bpf::{
    helpers::*,
    macros::{map, raw_tracepoint},
    maps::{PerfEventArray},
    programs::{RawTracePointContext},
    BpfContext, 
};
use aya_log_ebpf::info;

use syscalls_inspection_common::SysCallLog;

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<SysCallLog> = PerfEventArray::<SysCallLog>::with_max_entries(1024, 0);

// #[map(name = "PIDS")]
// static mut PIDS: HashMap<u32, Filename> = HashMap::with_max_entries(10240000, 0);

#[raw_tracepoint(name="syscalls_inspection")]
pub fn syscalls_inspection(ctx: RawTracePointContext) -> u32 {
    match unsafe { try_syscalls_inspection(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_syscalls_inspection(ctx: RawTracePointContext) -> Result<u32, u32> {
    let args = unsafe { slice::from_raw_parts(ctx.as_ptr() as *const usize, 6) };
    // info!(&ctx, "arg0: {}", args[1]);
    let ts          = bpf_ktime_get_ns();
    let syscall     = args[1] as u64;
    let pid         = ctx.pid() as u64;
    let pname_bytes   = ctx.command().map_err(|e| e as u32)?;
    let pname      = core::str::from_utf8_unchecked(&pname_bytes[..]);
    // convert args[0] to PtRegs
    // let regs = PtRegs::new((args[0] as *mut pt_regs).arg(0).unwrap());

    let logs = SysCallLog {
        ts,
        syscall,
        pid,
        pname_bytes,
    };
    info!(&ctx, "ts: {}ns | id: {} | pid: {} | pname: {}", ts,syscall,pid,pname);
    EVENTS.output(&ctx, &logs, 0);
    Ok(0)
}

/// log_pid is attached to the execve function in the kernel
/// it logs the pid and filename to the PIDS map

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
h
