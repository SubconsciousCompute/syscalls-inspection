use aya::programs::{RawTracePoint, TracePoint};
use aya::{include_bytes_aligned, maps::perf::AsyncPerfEventArray, util::online_cpus, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::{signal, sync::mpsc, task};

use std::{collections::HashMap, process::Command};

use bytes::BytesMut;
use regex::Regex;
use syscalls_inspection_common::SysCallLog;

#[derive(Debug, Parser)]
struct Opt {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/syscalls-inspection"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/syscalls-inspection"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Creates a handler for the loads the program for tracing raw syscalls
    let program: &mut RawTracePoint = bpf.program_mut("syscalls_inspection").unwrap().try_into()?;
    program.load()?;
    program.attach("sys_enter")?;
    
    // Creates a handler for the loads the program for tracing execve args
    let execve_args: &mut TracePoint = bpf.program_mut("execve_args").unwrap().try_into()?;
    execve_args.load()?;
    execve_args.attach("syscalls", "sys_enter_execve")?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("SYSCALL_EVENTS")?)?;
    let mut execve_array = AsyncPerfEventArray::try_from(bpf.map_mut("EXECVE_EVENTS")?)?;

    // the following section creates a map of available syscalls based on their IDs.
    let mut syscalls: HashMap<u64, String> = HashMap::new();
    let output = Command::new("ausyscall").arg("--dump").output()?;
    let pattern = Regex::new(r"([0-9]+)\t(.*)")?;
    String::from_utf8(output.stdout)?
        .lines()
        .filter_map(|line| pattern.captures(line))
        .map(|cap| (cap[1].parse::<u64>().unwrap(), cap[2].trim().to_string()))
        .for_each(|(k, v)| {
            syscalls.insert(k, v);
        });

    info!("Spawning Event Processing Thread");
    // let (tx, mut rx) = crossbeam_channel::bounded(100);
    let (tx, mut rx) = mpsc::channel(100);
    task::spawn(async move {
        while let Some((ts, syscall, pid, pname)) = rx.recv().await {

            // The following section converts the timestamp from the kernel to a timestamp
            let nsec = std::time::Duration::from(
                nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).unwrap(),
            )
            .as_nanos() as u64;
            let epoch_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time went backwards")
                .as_nanos() as u64;
            let syscall_timestamp = epoch_time - nsec + ts;


            println!(
                "timestamp: {} syscall: {} pid: {} process: {}",
                syscall_timestamp / 1_000_000,
                syscalls.get(&syscall).unwrap_or(&syscall.to_string()),
                pid,
                pname,
            );

            // send the data to a socket
        }
    });

    info!("Spawning eBPF Event Listener");
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        // let mut arg_buf = execve_array.open(cpu_id, None)?;
        let tx = tx.clone();

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            
            // let mut execve_buffers = (1..10)
            //     .map(|_| BytesMut::with_capacity(1024))
            //     .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                // let execve_events = arg_buf.read_events(&mut execve_buffers).await.unwrap();

                let mut results = vec![];
                // create an optional results vector that can store two differen types of data

                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const SysCallLog;
                    let data = unsafe { ptr.read_unaligned() };
                    let pname =
                    unsafe { String::from_utf8_unchecked(data.pname_bytes[..].to_vec()) };
                    results.push((data.ts, data.syscall, data.pid, pname));
                    
                // for arg in execve_buffers.iter_mut().take(execve_events.read) {
                //     let ptr = arg.as_ptr() as *const ExecveArgs;
                //     let data = unsafe { ptr.read_unaligned() };
                //     let exec = unsafe { String::from_utf8_unchecked(data.exec[..].to_vec()) };
                //     // results.push()
                // }
                
                }
                for res in results {
                    // println!("sending data");
                    tx.send(res).await.unwrap();
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
