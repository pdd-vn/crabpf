#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::Queue,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static BPF_QUEUE: Queue<u32> = Queue::<u32>::with_max_entries(1024, 0);

#[xdp]
pub fn crabpf(ctx: XdpContext) -> u32 {
    match process_ctx(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)] //
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn process_ctx(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

            let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
            let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

            // let source_port = match unsafe { (*ipv4hdr).proto } {
            //     IpProto::Tcp => {
            //         let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            //         u16::from_be(unsafe { (*tcphdr).source })
            //     }
            //     IpProto::Udp => {
            //         let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            //         u16::from_be(unsafe { (*udphdr).source })
            //     }
            //     _ => return Err(()),
            // };

            info!(&ctx, "SRC IP: {:i}, DST IP: {:i}", source_addr, dst_addr);
            let _ = BPF_QUEUE.push(&source_addr, 0);
        }
        EtherType::Ipv6 => {}
        _ => {}
    }

    Ok(xdp_action::XDP_PASS)
}
