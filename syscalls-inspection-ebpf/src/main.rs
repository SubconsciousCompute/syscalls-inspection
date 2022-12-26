#![no_std]
#![no_main]

use aya_bpf::{
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[tracepoint(name="syscalls_inspection")]
pub fn syscalls_inspection(ctx: TracePointContext) -> u32 {
    match try_syscalls_inspection(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_syscalls_inspection(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint sys_enter called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
