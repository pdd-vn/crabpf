use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::{MapData, Queue},
    programs::{Xdp, XdpFlags},
    Bpf,
};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use std::{thread, time};
#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlp0s20f3")]
    iface: String,
}

fn read_bpf_queue(q: &mut Queue<&mut MapData, u32>) {
    info!("Start reading from bpf queue...");
    loop {
        let res = q.pop(0);
        match res {
            Ok(v) => {
                let bytes = v.to_be_bytes();
                info!(
                    "Got SRC IP from bpf program {}.{}.{}.{}",
                    bytes[0], bytes[1], bytes[2], bytes[3]
                );
            }
            Err(e) => {
                info!("Error: {:?}", e);
            }
        }
        thread::sleep(time::Duration::from_secs(1));
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/crabpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/crabpf"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("crabpf").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // Shared queue
    let mut bpf_queue: Queue<_, u32> = Queue::try_from(bpf.map_mut("BPF_QUEUE").unwrap())?;

    thread::scope(|s| {
        s.spawn(move || read_bpf_queue(&mut bpf_queue));
        info!("Running...");
    });

    Ok(())
}
