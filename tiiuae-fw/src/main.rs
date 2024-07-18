/*
    Copyright 2022-2024 TII (SSRC) and the contributors
    SPDX-License-Identifier: Apache-2.0
*/
/*

KNOWN LIMITATIONS:
- whitelisting/blacklisting for output
- blacklisting for input dev cases
- if there is no destination_ip input from user, obtain it from interface for input
- if there is no source_ip input from user, obtain it from for output
- unicast/broadcast ip handling?
- plugged network interfaces(ex. usb-to-ethernet converter) must be handled through user space
*/

#![allow(unused)]
mod cli;
use aya::maps::HashMap as AyaHashMap;
use aya::maps::{Array, HashMap};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Pod;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use cli::cli_impl;
use log::{debug, info, warn};
use std::collections::HashMap as StdHashMap;
use tiiuae_fw::*;
use tiiuae_fw_common::*;
use tokio::signal;

fn static_filtering_init(bpf: &mut Bpf, file_path: &str) -> Result<(), anyhow::Error> {
    info!("Static filtering init");

    let mut static_tcpv4: AyaHashMap<_, Ipv4FlowKey, Tcpv4FlowVal> =
        AyaHashMap::try_from(bpf.map_mut("STATIC_TCPV4").unwrap())?;

    Ok(())
}

fn static_range_filtering_init(bpf: &mut Bpf, file_path: &str) -> Result<(), anyhow::Error> {
    info!("Static port range filtering init");
    let _tcpv4_dest_port_arr = Tcpv4DestPortRangeFlowArrVal::default();

    let _static_port_tcpv4_val: Array<_, Tcpv4DestPortRangeFlowArrVal> =
        Array::try_from(bpf.map_mut("STATIC_PORT_RANGE_ARR_TCPV4").unwrap())?;

    let _static_port_tcpv4_key: Array<_, Ipv4DestPortRangeFlowKey> =
        Array::try_from(bpf.map_mut("STATIC_PORT_RANGE_TCPV4").unwrap())?;

    //Vec([u16;2], Tcpv4DestPortRangeFlowArrVal)
    let mut dest_port_map: StdHashMap<[u16; 2], Tcpv4DestPortRangeFlowVal> = StdHashMap::new();
    // Insert entries into the HashMap
    dest_port_map.insert([80, 90], Tcpv4DestPortRangeFlowVal::default());
    dest_port_map.insert([1024, 65535], Tcpv4DestPortRangeFlowVal::default());

    //static_port_tcpv4_key.set(80, 0, 0);

    // Access and print values from the HashMap
    for (key, value) in &dest_port_map {
        println!("Key: {:?}, Value: {:?}", key, value);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli_args = &cli_impl::CLI_ARGS;
    if cli_args.log {
        std::env::set_var("RUST_LOG", "info");
        env_logger::init();
    }
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tiiuae-fw"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tiiuae-fw"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let x = Config::from_string("").unwrap();
    let _: StdHashMap<String, StdHashMap<Ipv4FlowKey, Tcpv4FlowVal>> = x.extract_single_ipv4_flow();
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    // let _ = tc::qdisc_add_clsact(&opt.iface);
    // let program: &mut SchedClassifier = bpf.program_mut("tiiuae_fw").unwrap().try_into()?;
    // program.load()?;
    // program.attach(&opt.iface, TcAttachType::Ingress)?;
    let _ = static_range_filtering_init(&mut bpf, "");
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
