/*
    Copyright 2022-2024 TII (SSRC) and the contributors
    SPDX-License-Identifier: Apache-2.0
*/
#![no_std]
#![allow(unused)]

use core::default::Default;
use core::net::IpAddr;
use core::net::Ipv4Addr;
pub const TOT_RANGE_RULES: usize = 10;
pub const NUM_RANGE_FOR_EACH_RULE: usize = 10;

pub type ProtoType = u16;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[repr(C)]
pub enum Policy {
    Whitelist,
    Blacklist,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[repr(C)]
pub struct CommonStaticSettings {
    pub ipv4_enabled: bool,
    pub ipv6_enabled: bool,
    pub input_policy: Policy,
    pub output_policy: Policy,
}

impl Default for Ipv4FlowKey {
    fn default() -> Self {
        Self {
            src_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(0, 0, 0, 0),
            src_port: 0,
            dest_port: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[repr(C)]
pub struct Ipv4FlowKey {
    pub src_ip: Ipv4Addr,
    pub dest_ip: Ipv4Addr,
    pub src_port: u16,
    pub dest_port: u16,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Default)]
#[repr(C)]
pub struct Ipv4PortRangeFlowKey {
    pub prefix: u32,
    pub port: u32,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[repr(C)]
pub struct Ipv4DestPortRangeFlowKey {
    range_index_map: [u16; NUM_RANGE_FOR_EACH_RULE],
    len: u8,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Default)]
#[repr(C)]
pub struct Tcpv4DestPortRangeFlowVal {
    pub action: u8,
    pub src_ip_range: [u32; 2],
    pub dest_ip_range: [u32; 2],
    pub new_dest_ip: u32,
    pub new_src_port: u16,
    pub new_dest_port: u16,
    pub src_port_range: [u16; 2],
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Default)]
#[repr(C)]
pub struct Tcpv4DestPortRangeFlowArrVal {
    pub len: u8,
    pub ipv4_flow_key: [Tcpv4DestPortRangeFlowVal; TOT_RANGE_RULES],
}
impl Default for Ipv4FlowVal {
    fn default() -> Self {
        Self {
            action: 0,
            new_dest_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            new_src_port: 0,
            new_dest_port: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[repr(C)]
pub struct Ipv4FlowVal {
    pub action: u8,
    pub new_dest_ip: IpAddr,
    pub new_src_port: u16,
    pub new_dest_port: u16,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Default)]
#[repr(C)]
pub struct Tcpv4FlowVal {
    pub val: Ipv4FlowVal,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Default)]
#[repr(C)]
pub struct Udpv4FlowVal {
    pub val: Ipv4FlowVal,
}
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Default)]
#[repr(C)]
pub struct OtherProtov4Key {
    pub ipv4_flow_key: Ipv4FlowKey,
    pub proto: ProtoType,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Default)]
#[repr(C)]
pub struct OtherProtov4Val {
    pub ipv4_flow_key: Ipv4FlowVal,
    pub packet_count: u64,
    pub byte_count: u64,
    pub last_seen: u64,
}
#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for Ipv4FlowKey {}
    unsafe impl aya::Pod for Ipv4FlowVal {}
    unsafe impl aya::Pod for Tcpv4FlowVal {}
    unsafe impl aya::Pod for Udpv4FlowVal {}
    unsafe impl aya::Pod for OtherProtov4Key {}
    unsafe impl aya::Pod for OtherProtov4Val {}
    unsafe impl aya::Pod for Tcpv4DestPortRangeFlowVal {}
    unsafe impl aya::Pod for Tcpv4DestPortRangeFlowArrVal {}
    unsafe impl aya::Pod for Ipv4DestPortRangeFlowKey {}
}
