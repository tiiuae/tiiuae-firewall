/*
    Copyright 2022-2024 TII (SSRC) and the contributors
    SPDX-License-Identifier: Apache-2.0
*/
//! # Rule section parser and validator
use super::{field_maps::Action, utils};
use crate::config::field_maps::*;
use core::net::IpAddr;
use serde::de::{self, Unexpected};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap as StdHashMap;
use std::str::FromStr;
use tiiuae_fw_common::Policy;
/// Represents a network rule with various fields for configuration.
///
/// The `Rule` struct is used to deserialize and validate network rules from input data.
/// Each field corresponds to a specific aspect of the rule, such as action, interface, protocol, and IP addresses.
///
#[derive(Debug, Deserialize)]
pub struct Rule {
    #[serde(deserialize_with = "deserialize_action")]
    pub action: Option<Action>,
    #[serde(default)]
    #[serde(rename = "if_input")]
    pub if_input: Option<Vec<String>>,
    #[serde(default)]
    #[serde(rename = "if_output")]
    pub if_output: Option<Vec<String>>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_protocol")]
    pub protocol: Option<String>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_ip")]
    pub source_ip: Option<IpAddr>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_ip")]
    pub destination_ip: Option<IpAddr>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_port")]
    pub source_port: Option<Port>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_port")]
    pub destination_port: Option<Port>,
    pub description: Option<String>,
    #[serde(rename = "reject-type")]
    pub reject_type: Option<String>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_ip")]
    pub new_dest_ip: Option<IpAddr>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_port")]
    pub new_source_port: Option<Port>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_port")]
    pub new_destination_port: Option<Port>,
}

#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct IfaceGroup {
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    pub interface_grp: StdHashMap<String, Vec<String>>,
    #[serde(skip)]
    pub interface_group_1: Vec<String>,
    #[serde(skip)]
    pub interface_group_2: Vec<String>,
    #[serde(skip)]
    pub interface_not_grouped: Vec<String>,
}
impl IfaceGroup {
    // Define an associated constant for the maximum number of groups
    pub const MAX_GROUP: usize = 2;
    pub const NOT_GROUPED_IFACES_STR: &str = "&NOT_GROUPED_IFACES";
    pub const CONFIG_REFERENCE_PREFIX_STR: &str = "&";
}
#[derive(Debug, Deserialize, Default)]
pub struct IpOpts {
    /// Indicates if IPv4 rules are enabled.
    pub ipv4_enabled: bool,
    /// Indicates if IPv6 rules are enabled.
    pub ipv6_enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct DefaultPolicy {
    #[serde(deserialize_with = "deserialize_default_policy")]
    pub input: Policy,
    #[serde(deserialize_with = "deserialize_default_policy")]
    pub output: Policy,
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        Self {
            input: Policy::Whitelist,
            output: Policy::Blacklist,
        }
    }
}

impl DefaultPolicy {
    // Define an associated constant for the maximum number of groups
    pub const WHITE_LIST: &str = "whitelist";
    pub const BLACK_LIST: &str = "blacklist";
}

fn deserialize_default_policy<'de, D>(deserializer: D) -> Result<Policy, D::Error>
where
    D: Deserializer<'de>,
{
    // Deserialize the input as a string
    let s: String = String::deserialize(deserializer)?;

    // Map the string to the corresponding Policy variant
    match s.as_str() {
        DefaultPolicy::WHITE_LIST => Ok(Policy::Whitelist),
        DefaultPolicy::BLACK_LIST => Ok(Policy::Blacklist),
        _ => Err(de::Error::custom(format!(
            "Default policy must be '{}' or '{}'",
            DefaultPolicy::WHITE_LIST,
            DefaultPolicy::BLACK_LIST
        ))),
    }
}
/// Represents a port or range of ports.
///
/// The `Port` enum is used to capture either a single port number or a range of ports for network rules.
///
/// # Variants
///
/// - `Single(u16)` - Represents a single port number.
/// - `Range(Vec<u16>)` - Represents a range of port numbers as a vector of `u16` values.
#[derive(Debug, PartialEq, Eq)]

pub enum Port {
    Single(u16),
    Range(Vec<u16>),
}
/// Deserializes a protocol field from a string.
///
/// Handles the special case where "any" or an empty string is considered as `None`. Checks if the protocol is supported.
///
/// # Arguments
///
/// * `deserializer` - The deserializer instance.
///
/// # Returns
///
/// A `Result` containing `Option<String>` where `None` indicates "any" or an empty string, and `Some` contains a valid protocol string.
///
/// # Errors
///
/// Returns an error if the protocol is not supported.
fn deserialize_protocol<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    // Deserialize the input as an Option<String>
    let s: Option<String> = Option::deserialize(deserializer)?;

    // Match on the deserialized string
    match s {
        Some(proto_str) if proto_str.trim() == "any" || proto_str.trim() == "" => Ok(None), // Handle "any" as None
        Some(proto_str) => {
            if !ALLOW_PROTOCOLS.contains_key(&proto_str) {
                return Err(de::Error::custom(format!(
                    "protocol is not supported :{}",
                    proto_str
                )));
            }
            Ok(Some(proto_str))
        }
        None => Ok(None), // Handle None as None
    }
}
/// Deserializes an interface field from a string.
///
/// Validates the interface against known interfaces and returns an error if it is not found.
///
/// # Arguments
///
/// * `deserializer` - The deserializer instance.
///
/// # Returns
///
/// A `Result` containing `Option<String>` where `None` indicates the absence of an interface and `Some` contains a valid interface string.
///
/// # Errors
///
/// Returns an error if the interface is not found.
// fn deserialize_iface<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
// where
//     D: Deserializer<'de>,
// {
//     // Deserialize the input as an Option<String>
//     let s: Option<Vec<String>> = Option::deserialize(deserializer)?;
//     // Define static array of action strings
//     let all_ip_ifaces: StdHashMap<String, Vec<IpAddr>> = get_all_ip_and_ifaces();

//     // Match on the deserialized string
//     match s {
//         Some(iface_vec) => {
//             for iface_str in &iface_vec {
//                 if !search_iface(&all_ip_ifaces, iface_str) {
//                     return Err(de::Error::custom(format!(
//                         "interface is not found :{}",
//                         iface_str
//                     )));
//                 }
//             }

//             Ok(Some(iface_vec))
//         }
//         None => Ok(None), // Handle None case
//     }
// }
/// Deserializes an action field from a string.
///
/// Converts the string to an `Action` enum variant and returns an error if the action is invalid.
///
/// # Arguments
///
/// * `deserializer` - The deserializer instance.
///
/// # Returns
///
/// A `Result` containing `Option<Action>` where `Some` contains a valid `Action` variant and `None` is not valid for this field.
///
/// # Errors
///
/// Returns an error if the action is invalid or missing.
fn deserialize_action<'de, D>(deserializer: D) -> Result<Option<Action>, D::Error>
where
    D: Deserializer<'de>,
{
    // Deserialize the input as an Option<String>
    let s: Option<String> = Option::deserialize(deserializer)?;
    // Define static array of action strings

    // Match on the deserialized string
    match s {
        Some(action_str) => match Action::from_string(&action_str) {
            Some(action) => Ok(Some(action)),
            None =>  Err(de::Error::custom(format!(
                "Invalid action '{}'. Valid actions are: 'allow-input', 'reject-input', 'drop-output', 'forward', 'masquerade'",
                action_str
            ))),
        },
        None => Err(de::Error::missing_field("action field is missing")), // Handle None case
    }
}
/// Deserializes an IP address field from a string.
///
/// This function is used to convert a string representation of an IP address into an `Option<IpAddr>`.
/// Special cases are handled where the input string may be "any" or empty, which are considered as `None`.
/// Valid IP addresses are parsed and returned as `Some(IpAddr)`. If the string is not a valid IP address,
/// an error is returned.
///
/// # Arguments
///
/// * `deserializer` - The deserializer instance which provides the string input.
///
/// # Returns
///
/// A `Result` containing `Option<IpAddr>`. The result is:
/// - `Ok(None)` if the input is "any" or an empty string, indicating no IP address.
/// - `Ok(Some(IpAddr))` if the input is a valid IP address, parsed into an `IpAddr` instance.
/// - `Err` if the input is an invalid IP address format.
///
/// # Errors
///
/// Returns an error if the provided string cannot be parsed as a valid IP address. The error message will
/// indicate the expected format of the IP address.
fn deserialize_ip<'de, D>(deserializer: D) -> Result<Option<IpAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;

    match s {
        Some(ip_str) if ip_str.trim() == "any" || ip_str.trim() == "" => Ok(None), // Handle "any" as None
        Some(ip_str) => match IpAddr::from_str(&ip_str) {
            Ok(ip) => Ok(Some(ip)),
            Err(_) => Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Str(&ip_str),
                &"a valid IP address",
            )),
        },
        None => Ok(None), // Handle None as None
    }
}
/// Deserializes a port field from a string.
///
/// Handles special cases for "any" and empty strings. Parses ports as single values or ranges.
///
/// # Arguments
///
/// * `deserializer` - The deserializer instance.
///
/// # Returns
///
/// A `Result` containing `Option<Port>` where `None` indicates "any" or an invalid format, and `Some` contains a valid port or range.
///
/// # Errors
///
/// Returns an error if the port format is invalid.
fn deserialize_port<'de, D>(deserializer: D) -> Result<Option<Port>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = match String::deserialize(deserializer) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };

    match s.trim() {
        "any" | "" => Ok(None),
        s if s.starts_with('[') && s.ends_with(']') => {
            // Parse as a list of ports
            let s = &s[1..s.len() - 1]; // Strip brackets
            let ports: Result<Vec<u16>, _> = s
                .split(',')
                .map(str::trim)
                .filter(|port_str| utils::is_numeric(port_str)) // Filter out non-numeric
                .map(|port_str| port_str.parse::<u16>())
                .collect();

            match ports {
                Ok(ports) => Ok(Some(Port::Range(ports))),
                Err(_) => Ok(None),
            }
        }
        s if utils::is_numeric(s) => {
            // Try parsing as a single port number
            match u16::from_str(s) {
                Ok(port) => Ok(Some(Port::Single(port))),
                Err(_) => Ok(None),
            }
        }
        _ => Err(de::Error::invalid_value(
            Unexpected::Str(&s),
            &"a valid port format",
        )), // Return None for invalid formats
    }
}
