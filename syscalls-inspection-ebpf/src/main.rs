#![no_std]
#![no_main]

use core::slice;

use aya_bpf::{
    helpers::*,
    macros::{map, raw_tracepoint, tracepoint},
    maps::{PerfEventArray},
    programs::{RawTracePointContext, TracePointContext},
    BpfContext, 
};
use aya_log_ebpf::info;

use syscalls_inspection_common::{SysCallLog, ExecveArgs};

#[map(name = "SYSCALL_EVENTS")]
static mut SYSCALL_EVENTS: PerfEventArray<SysCallLog> = PerfEventArray::<SysCallLog>::with_max_entries(1024, 0);

#[map(name = "EXECVE_EVENTS")]
static mut EXECVE_EVENTS: PerfEventArray<ExecveArgs> = PerfEventArray::<ExecveArgs>::with_max_entries(1024, 0);

// #[map(name = "PIDS")]
// static mut PIDS: HashMap<u32, Filename> = HashMap::with_max_entries(10240000, 0);

#[raw_tracepoint(name="syscalls_inspection")]
pub fn syscalls_inspection(ctx: RawTracePointContext) -> u32 {
    match unsafe { try_syscalls_inspection(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint(name = "execve_args")]
pub fn execve_args(ctx: TracePointContext) -> u32 {
    match unsafe { try_execve_args(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
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
    SYSCALL_EVENTS.output(&ctx, &logs, 0);
    Ok(0)
}

unsafe fn try_execve_args(ctx: &TracePointContext) -> Result<u32, i64> {
    // info!(ctx, "hello");
    let exec = bpf_get_current_comm()?;
    let exec_comm = ctx.read_at::<*const u8>(16)?;
    let argv = ctx.read_at::<*const *const u8>(24)?;
    // calculate the length of argv
    let mut argv_len = 0;
    for i in 0..10 {
        let arg_ptr = bpf_probe_read_user(argv.offset(i))?;
        if arg_ptr.is_null() {
            break;
        }
        argv_len += 1;
    }

    // create an array of array of 10 32b
    let mut arg_buf = [[0u8; 26]; 8];
    for i in 0..argv_len {
        let arg_ptr = bpf_probe_read_user(argv.offset(i))?;
        if arg_ptr.is_null() {
            return Ok(0);
        }
        bpf_probe_read_user_str_bytes(arg_ptr, &mut arg_buf[i as usize]).unwrap_or_default();
        // bpf_probe_read_user_str(arg_ptr, &mut arg_buf[i])?;
        // bpf_printk!(b"hahahaha: %s", arg_ptr);
    }


    bpf_printk!(b"argv_len: %d", argv_len);
    bpf_printk!(b"exec: %s, exec_comm: %s arg1: %s, arg2: %s, arg3: %s, arg4: %s, arg5: %s, arg6: %s", exec.as_ptr(), exec_comm, arg_buf[1].as_ptr(), arg_buf[2].as_ptr(), arg_buf[3].as_ptr(), arg_buf[4].as_ptr(), arg_buf[5].as_ptr(), arg_buf[6].as_ptr() );
    
    let entry: ExecveArgs = ExecveArgs { exec, arg_buf: arg_buf };
    EXECVE_EVENTS.output(ctx, &entry, 0);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}