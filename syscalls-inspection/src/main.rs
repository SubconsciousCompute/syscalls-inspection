use aya::{include_bytes_aligned,
    maps::{perf::AsyncPerfEventArray},
    util::online_cpus, Bpf};
use aya::programs::RawTracePoint;
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::{signal, task, sync::mpsc};

use std::{
    process::Command,
    collections::HashMap,
};

use regex::Regex;
use bytes::BytesMut;
use syscalls_inspection_common::SysCallLog;

#[derive(Debug, Parser)]
struct Opt {
    
}

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
    let program: &mut RawTracePoint = bpf.program_mut("syscalls_inspection").unwrap().try_into()?;
    program.load()?;
    program.attach("sys_enter")?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    // let mut pid_map: BpfHashMap<MapRefMut, u32, Filename> =
    //     BpfHashMap::try_from(bpf.map_mut("PIDS").unwrap()).unwrap();

    let mut syscalls: HashMap<u64, String> = HashMap::new();
    let output = Command::new("ausyscall").arg("--dump").output()?;
    // println!("status: {}", output.status);
    // io::stdout().write_all(&output.stdout).unwrap();
    // io::stderr().write_all(&output.stderr).unwrap();
    let pattern = Regex::new(r"([0-9]+)\t(.*)")?;
    String::from_utf8(output.stdout)?
        .lines()
        .filter_map(|line| pattern.captures(line))
        .map(|cap| (cap[1].parse::<u64>().unwrap(), cap[2].trim().to_string()))
        .for_each(|(k, v)| {
            syscalls.insert(k, v);
    });
    
    info!("Spawning Event Processing Thread");
    let (tx, mut rx) = mpsc::channel(100);
    task::spawn(async move {
        while let Some((ts, syscall, pid)) = rx.recv().await {
            let nsec = std::time::Duration::from(nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).unwrap()).as_nanos() as u64;
            // let boot_time: Duration = std::time::Duration::from_nanos(nsec);
            // println!("nsec: {}, boot_time: {}", nsec, boot_time.as_nanos() as u64);
            // let timestamp = nsec - ts;
            // get unix timestamp
            let epoch_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("time went backwards").as_nanos() as u64;
            let syscall_timestamp = epoch_time - nsec + ts;
            println!(
                "timestamp: {} syscall: {} pid: {}",
                syscall_timestamp / 1_000_000,
                syscalls.get(&syscall).unwrap_or(&syscall.to_string()),
                pid,
            );
        }
    });

    info!("Spawning eBPF Event Listener");
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let tx = tx.clone();
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                let mut results = vec![];
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const SysCallLog;
                    let data = unsafe { ptr.read_unaligned() };
                    results.push((data.ts, data.syscall, data.pid));
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
