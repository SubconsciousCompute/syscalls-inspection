use aya::programs::{RawTracePoint, TracePoint};
use aya::{include_bytes_aligned, maps::perf::AsyncPerfEventArray, util::online_cpus, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::{signal, sync::mpsc, task};

use std::vec;
use std::net::UdpSocket;
use std::{collections::HashMap, process::Command};

use regex::Regex;
use bytes::BytesMut;
// use serde::Serialize;
use syscalls_inspection_common::{SysCallLog, ExecveArgs};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(long, default_value = "both")]
    pub mode: String,

    // Run with socket
    #[clap(long, default_value = "both")]
    pub features: String,
}

#[derive(Debug, serde::Serialize)]
struct AllSysCalls{
    timestamp: u64,
    syscall: String,
    pid: u64,
    pname: String,
}

// derive debug and serizalize for the struct
#[derive(Debug, serde::Serialize)]
struct ExecveStrings {
    exec: String,
    exec_comm: String,
    arg0: String,
    arg1: String,
    arg2: String,
    arg3: String,
    arg4: String,
    arg5: String,
    arg6: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    println!("{:?}", opt);

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
    let (tx_execve, mut rx_execve) = mpsc::channel(100);

    let execve_mode = opt.mode.clone();
    let execve_features = opt.features.clone();
    task::spawn(async move {
        while let Some((exec, exec_comm, arg0, arg1, arg2, arg3, arg4, arg5, arg6)) = rx_execve.recv().await {
            let execve: ExecveStrings = ExecveStrings {
                    exec: exec,
                    exec_comm: exec_comm,
                    arg0: arg0,
                    arg1: arg1,
                    arg2: arg2,
                    arg3: arg3,
                    arg4: arg4,
                    arg5: arg5,
                    arg6: arg6,
                };

            if &execve_mode.clone() == &"execve".to_string() || &execve_mode.clone() == &"both".to_string() {  
                if &execve_features.clone() == &"all".to_string() || &execve_features == &"socket".to_string(){
                    let socket = UdpSocket::bind("127.0.0.1:32524");
                    let socket = match socket {
                        Ok(s) => s,
                        Err(e) => {
                            println!("couldn't bind to address: {}", e);
                            return;
                        }
                    };
                    let execve_json = serde_json::to_string(&execve).unwrap();
                    let execve_json = execve_json.as_bytes();
                    _ = socket.send_to(execve_json, "127.0.0.1:32525");
                } else {

                    // println!(
                    //     "execve: {} exec_comm: {} arg0: {} arg1: {} arg2: {} arg3: {} arg4: {} arg5: {} arg6: {} ",
                    //     exec, exec_comm, arg0, arg1, arg2, arg3, arg4, arg5, arg6
                    // );
                    println!("{:?}", execve);
                }
            }
        }
    
    });

    let syscalls_mode = opt.mode.clone();
    let syscalls_features = opt.features.clone();
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

            let all_syscalls: AllSysCalls = AllSysCalls{
                timestamp: syscall_timestamp / 1_000_000,
                syscall: syscalls.get(&syscall).unwrap_or(&syscall.to_string()).clone(),
                pid: pid,
                pname: pname,
            };

            if &syscalls_mode.clone() == &"syscalls".to_string() || &syscalls_mode.clone() == &"both".to_string() {     
                if &syscalls_features.clone() == &"all".to_string() || &syscalls_features == &"socket".to_string(){
                    let socket = UdpSocket::bind("127.0.0.1:32526");
                    let socket = match socket {
                        Ok(s) => s,
                        Err(e) => {
                            println!("couldn't bind to address: {}", e);
                            return;
                        }
                    };
                    let all_syscalls_json = serde_json::to_string(&all_syscalls).unwrap();
                    let all_syscalls_json = all_syscalls_json.as_bytes();
                    _ = socket.send_to(all_syscalls_json, "127.0.0.1:32525")
                } else {
                    // println!(
                    //     "timestamp: {} syscall: {} pid: {} process: {}",
                    //     syscall_timestamp / 1_000_000,
                    //     syscalls.get(&syscall).unwrap_or(&syscall.to_string()),
                    //     pid,
                    //     pname,
                    // );
                    println!("{:?}", all_syscalls);
                }        
            }


        }
    });


    info!("Spawning eBPF Event Listener");
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let mut arg_buf = execve_array.open(cpu_id, None)?;
        let tx = tx.clone();
        let tx_execve = tx_execve.clone();

        task::spawn(async move {

            let mut execve_buffers = (1..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

                loop {
                    // let events = buf.read_events(&mut buffers).await.unwrap();
                    let execve_events = arg_buf.read_events(&mut execve_buffers).await.unwrap();
    
                    let mut results: Vec<(String, String, String, String, String, String, String, String, String)> = vec![];

                            
                    for arg in execve_buffers.iter_mut().take(execve_events.read) {
                        let ptr = arg.as_ptr() as *const ExecveArgs;
                        let data = unsafe { ptr.read_unaligned() };
                        let exec: String= unsafe { String::from_utf8_unchecked(data.exec[..].to_vec()).replace("\0", "") };
                        let exec_comm = unsafe { String::from_utf8_unchecked(data.exec_comm[..].to_vec()).replace("\0", "")};
                        let arg0 = unsafe { String::from_utf8_unchecked(data.arg_buf[0].to_vec()).replace("\0", "")};
                        let arg1 = unsafe { String::from_utf8_unchecked(data.arg_buf[1].to_vec()).replace("\0", "")};
                        let arg2 = unsafe { String::from_utf8_unchecked(data.arg_buf[2].to_vec()).replace("\0", "")};
                        let arg3 = unsafe { String::from_utf8_unchecked(data.arg_buf[3].to_vec()).replace("\0", "")};
                        let arg4 = unsafe { String::from_utf8_unchecked(data.arg_buf[4].to_vec()).replace("\0", "")};
                        let arg5 = unsafe { String::from_utf8_unchecked(data.arg_buf[5].to_vec()).replace("\0", "")};
                        let arg6 = unsafe { String::from_utf8_unchecked(data.arg_buf[6].to_vec()).replace("\0", "")};
                        // let arg7 = unsafe { String::from_utf8_unchecked(data.arg_buf[7].to_vec())};
                        // results.push()
                        // results.push((exec, arg0, )
                        results.push((exec, exec_comm, arg0, arg1, arg2, arg3, arg4, arg5, arg6));
                    }
                    
                    for res in results {
                        // println!("sending data");
                        tx_execve.send(res).await.unwrap();
                    }
                }
        });


        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                // let execve_events = arg_buf.read_events(&mut execve_buffers).await.unwrap();

                let mut results = vec![];
                // create an enum of different vector types

                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const SysCallLog;
                    let data = unsafe { ptr.read_unaligned() };
                    let pname =
                    unsafe { String::from_utf8_unchecked(data.pname_bytes[..].to_vec()) };
                    // remove unicode null characters from pname
                    let pname = pname.replace("\0", "");
                    results.push((data.ts, data.syscall, data.pid, pname));
                    // results.push(Result_Type::SysCallLog(vec![(data.ts, data.syscall, data.pid, pname)]));
                    
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
