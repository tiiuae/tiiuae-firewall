/*
    Copyright 2022-2024 TII (SSRC) and the contributors
    SPDX-License-Identifier: Apache-2.0
*/
//! # Helper functions for config module
#![allow(unused)]
use crate::config::rule::Port;
use core::net::*;
use ipnetwork::IpNetwork;
use log::{debug, info, warn};
use pnet::datalink;
use std::collections::HashMap as StdHashMap;
use std::str::FromStr;

/// Checks if a given string consists of only numeric characters.
///
/// # Arguments
///
/// * `s` - A string slice that is checked for numeric characters.
///
/// # Returns
///
/// * `true` if all characters in the string are ASCII digits, `false` otherwise.
///
/// # Examples
///
/// ```
/// use tiiuae_fw::config::utils::is_numeric;
/// let result = is_numeric("12345");
/// assert_eq!(result, true);
///
/// let result = is_numeric("123a5");
/// assert_eq!(result, false);
/// ```
pub fn is_numeric(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_digit())
}
/// Retrieves all IP addresses for each network interface on the system.
///
/// # Returns
///
/// A `HashMap` where each key is the name of a network interface and the corresponding value is a vector of `IpAddr`
/// associated with that interface.
///
/// # Examples
///
/// ```
/// use tiiuae_fw::config::utils::*;
/// let ip_map = get_all_ip_and_ifaces();
/// for (iface_name, ips) in ip_map {
///     println!("Interface: {}", iface_name);
///     for ip in ips {
///         println!("IP Address: {}", ip);
///     }
/// }
/// ```
pub fn get_all_ip_and_ifaces() -> StdHashMap<String, Vec<IpAddr>> {
    let mut ip_map = StdHashMap::new();

    // Get network interfaces
    let interfaces = datalink::interfaces();

    for interface in interfaces {
        // Collect IP addresses for each interface
        let ip_addresses: Vec<IpAddr> = interface
            .ips
            .iter()
            .map(|ip_network| ip_network.ip())
            .collect();

        // Insert into the HashMap
        ip_map.insert(interface.name.clone(), ip_addresses);
    }

    ip_map
}
/// Searches for a specific IP address in the provided IP map.
///
/// # Arguments
///
/// * `ip_map` - A reference to a `HashMap` where each key is a network interface name and each value is a vector of `IpAddr`.
/// * `ip` - The `IpAddr` to search for.
///
/// # Returns
///
/// An `Option` containing a tuple with the interface name and the IP address if found, otherwise `None`.
///
/// # Examples
///
/// ```
/// use tiiuae_fw::config::utils::*;
/// let ip_map = get_all_ip_and_ifaces();
/// if let Some((iface_name, ip)) = search_ip(&ip_map, "192.168.1.1".parse().unwrap()) {
///     println!("Found IP {} on interface {}", ip, iface_name);
/// } else {
///     println!("IP not found");
/// }
/// ```
pub fn search_ip(ip_map: &StdHashMap<String, Vec<IpAddr>>, ip: IpAddr) -> Option<(String, IpAddr)> {
    for (iface_name, ips) in ip_map {
        for ip_found in ips {
            if *ip_found == ip {
                info!("[iface:{}]IP Address is found: {}", iface_name, ip_found);
                return Some((iface_name.to_string(), *ip_found));
            }
        }
    }

    None
}
/// Checks if a network interface name exists in the IP map.
///
/// # Arguments
///
/// * `ip_map` - A reference to a `HashMap` where each key is a network interface name and each value is a vector of `IpAddr`.
/// * `iface_name` - The name of the network interface to search for.
///
/// # Returns
///
/// `true` if the interface name is found in the IP map, `false` otherwise.
///
/// # Examples
///
/// ```
/// use tiiuae_fw::config::utils::*;
/// let ip_map = get_all_ip_and_ifaces();
/// if search_iface(&ip_map, "eth0") {
///     println!("Interface found");
/// } else {
///     println!("Interface not found");
/// }
/// ```
pub fn search_iface(ip_map: &StdHashMap<String, Vec<IpAddr>>, iface_name: &str) -> bool {
    for iface_found in ip_map.keys() {
        if *iface_found == iface_name {
            info!("[iface is found: {}", iface_name);
            return true;
        }
    }
    false
}
/// Checks if a given string represents a network range (CIDR notation).
///
/// # Arguments
///
/// * `input` - A string slice that is checked for CIDR notation.
///
/// # Returns
///
/// `true` if the input is a valid network range, `false` otherwise.
///
/// # Examples
///
/// ```
/// use tiiuae_fw::config::rule::Port;
/// use tiiuae_fw::config::utils::is_network_range;
/// let result = is_network_range("192.168.1.0/24");
/// assert_eq!(result, true);
///
/// let result = is_network_range("192.168.1.256/24");
/// assert_eq!(result, false);
/// ```
pub fn is_network_range(input: &str) -> bool {
    // Try to parse the input as a network range (CIDR notation)
    match IpNetwork::from_str(input) {
        Ok(IpNetwork::V4(_)) | Ok(IpNetwork::V6(_)) => true,
        Err(_) => false,
    }
}

/// Extracts the IPv4 address from an `Option<IpAddr>`.
///
/// # Arguments
///
/// * `ip` - An optional `IpAddr` that may contain an IPv4 address.
///
/// # Returns
///
/// The `Ipv4Addr` if the input is an `IpAddr::V4`, otherwise a default `Ipv4Addr` of `0.0.0.0`.
///
/// # Examples
///
/// ```
/// use std::net::IpAddr;
/// use std::net::Ipv4Addr;
/// use tiiuae_fw::config::utils::*;
/// let ip = Some(IpAddr::V4("192.168.1.1".parse::<Ipv4Addr>().unwrap()));
/// let ipv4 = extract_ipv4(ip.as_ref());
/// assert_eq!(ipv4, "192.168.1.1".parse::<Ipv4Addr>().unwrap());
///
/// ```
pub fn extract_ipv4(ip: Option<&IpAddr>) -> Ipv4Addr {
    match ip {
        Some(IpAddr::V4(ipv4)) => *ipv4,
        Some(IpAddr::V6(_)) => unimplemented!(), // Handle case where T is Ipv4Addr and `ip` is Ipv6Addr
        None => Ipv4Addr::new(0, 0, 0, 0),
    }
}
/// Extracts the IPv6 address from an `Option<IpAddr>`.
///
/// # Arguments
///
/// * `ip` - An optional `IpAddr` that may contain an IPv6 address.
///
/// # Returns
///
/// The `Ipv6Addr` if the input is an `IpAddr::V6`, otherwise a default `Ipv6Addr` of `::` (all zeros).
///
/// # Examples
///
/// ```
/// use std::net::IpAddr;
/// use std::net::Ipv6Addr;
/// use tiiuae_fw::config::utils::*;
/// let ip = Some(IpAddr::V6("::1".parse::<Ipv6Addr>().unwrap()));
/// let ipv6 = extract_ipv6(ip.as_ref());
/// assert_eq!(ipv6, "::1".parse::<Ipv6Addr>().unwrap());
///
/// ```
pub fn extract_ipv6(ip: Option<&IpAddr>) -> Ipv6Addr {
    match ip {
        Some(IpAddr::V4(_)) => unimplemented!(),
        Some(IpAddr::V6(ipv6)) => *ipv6, // Handle case where T is Ipv4Addr and `ip` is Ipv6Addr
        None => Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
    }
}

/// Extracts the port number from an `Option<Port>`. Only single ports are currently supported.
///
/// # Arguments
///
/// * `port` - An optional `Port` that may contain a single port value or a range of ports.
///
/// # Returns
///
/// The port number if the `Port` is `Port::Single`, otherwise `0` if `Port` is `Port::Range` or `None`.
///
/// # Examples
///
/// ```
/// use tiiuae_fw::config::utils::*;
/// use tiiuae_fw::config::rule::Port;
/// let port = Port::Single(8080);
/// let extracted_port = extract_port_single(Some(&port));
/// assert_eq!(extracted_port, 8080);
///
/// //let port = Port::Range(vec![8080, 8081]);
/// //let extracted_port = extract_port_single(Some(&port));
/// //assert_eq!(extracted_port, 0); // Currently unimplemented
///
/// let extracted_port = extract_port_single(None);
/// assert_eq!(extracted_port, 0);
/// ```
pub fn extract_port_single(port: Option<&Port>) -> u16 {
    match port {
        Some(Port::Single(port)) => *port,
        Some(Port::Range(port_vec)) => {
            unimplemented!()
        }
        None => 0, // Default value if source_port is None
    }
}
