/*
    Copyright 2022-2024 TII (SSRC) and the contributors
    SPDX-License-Identifier: Apache-2.0
*/
#![no_std]
#![no_main]

use aya_ebpf::maps::Array;
use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map, tracepoint},
    programs::TcContext,
};
use aya_log_ebpf::info;
use core::mem;
use tiiuae_fw_common::{Ipv4DestPortRangeFlowKey, Tcpv4DestPortRangeFlowArrVal, TOT_RANGE_RULES};

#[map]
pub static STATIC_PORT_RANGE_TCPV4: Array<Ipv4DestPortRangeFlowKey> =
    Array::with_max_entries(u16::MAX as u32, 0);

#[map]
pub static STATIC_PORT_RANGE_ARR_TCPV4: Array<Tcpv4DestPortRangeFlowArrVal> =
    Array::with_max_entries(TOT_RANGE_RULES as u32, 0);

#[classifier]
pub fn tiiuae_fw(ctx: TcContext) -> i32 {
    match try_tiiuae_fw(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tiiuae_fw(ctx: TcContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");
    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
