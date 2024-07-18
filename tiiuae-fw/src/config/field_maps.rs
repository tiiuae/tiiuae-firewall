/*
    Copyright 2022-2024 TII (SSRC) and the contributors
    SPDX-License-Identifier: Apache-2.0
*/
//! # Configuration field mapping
use lazy_static::lazy_static;
use phf::phf_map;
use std::collections::HashMap as StdHashMap;
/// Represents various network actions that can be applied.
///
/// The `Action` enum defines different types of actions that can be used in a firewall or network configuration.
///
/// # Variants
///
/// - `AllowInput` - Allows incoming network traffic.
/// - `RejectInput` - Rejects incoming network traffic.
/// - `DropOutput` - Drops outgoing network traffic.
/// - `Forward` - Forwards network traffic to another destination.
/// - `Masquerade` - Modifies the source address of outgoing network traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    AllowInput,
    RejectInput,
    DropOutput,
    Forward,
    Masquerade,
}

impl Action {
    /// Converts a string representation of an action to an `Action` enum variant.
    ///
    /// # Arguments
    ///
    /// * `s` - A string slice representing the action.
    ///
    /// # Returns
    ///
    /// An `Option` containing the `Action` enum variant if the string matches, otherwise `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// use tiiuae_fw::config::field_maps::Action;
    /// let action = Action::from_string("allow-input");
    /// assert_eq!(action, Some(Action::AllowInput));
    ///
    /// let action = Action::from_string("unknown-action");
    /// assert_eq!(action, None);
    /// ```
    pub fn from_string(s: &str) -> Option<Self> {
        match s {
            "allow-input" => Some(Self::AllowInput),
            "reject-input" => Some(Self::RejectInput),
            "drop-output" => Some(Self::DropOutput),
            "forward" => Some(Self::Forward),
            "masquerade" => Some(Self::Masquerade),
            _ => None,
        }
    }

    /// Returns the string representation of an `Action` enum variant.
    ///
    /// # Returns
    ///
    /// A string slice corresponding to the `Action` variant.
    ///
    /// # Examples
    ///
    /// ```
    /// use tiiuae_fw::config::field_maps::Action;
    /// let action = Action::AllowInput;
    /// assert_eq!(action.as_str(), "allow-input");
    /// ```
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AllowInput => "allow-input",
            Self::RejectInput => "reject-input",
            Self::DropOutput => "drop-output",
            Self::Forward => "forward",
            Self::Masquerade => "masquerade",
        }
    }
}
/// Represents the category of fields in a network rule.
///
/// The `FieldCategory` enum classifies fields in network rules into different categories.
///
/// # Variants
///
/// - `Mandatory(u8)` - A mandatory field with an associated index value.
/// - `Optional` - An optional field that is not required.
/// - `Restricted` - A restricted field that has specific constraints.
#[derive(Debug, PartialEq, Eq)]
pub enum FieldCategory {
    Mandatory(u8),
    Optional,
    Restricted,
}
/// Represents various network protocols identified by their numeric codes.
///
/// The `Protocol` enum defines several common network protocols with their respective codes.
///
#[derive(Debug)]
pub enum Protocol {
    HopOpt = 0,
    Tcp = 6,
    Udp = 17,
    Icmp = 1,
    Igmp = 2,
    Ipv4 = 4,
    Ipv6 = 41,
    Ipv6Frag = 44,
    Ipv6Route = 43,
    Icmpv6 = 58,
    Sctp = 132,
    Reserved = 255,
}
/// A static map of allowed protocols and their corresponding numeric codes.
///
/// This map allows quick lookups of protocol codes based on protocol names.
///
/// # Example
///
/// ```
/// use tiiuae_fw::config::field_maps::ALLOW_PROTOCOLS;
/// let protocol_code = ALLOW_PROTOCOLS.get("tcp");
/// assert_eq!(protocol_code, Some(&6));
/// ```
pub static ALLOW_PROTOCOLS: phf::Map<&'static str, u16> = phf_map! {
    "tcp" => Protocol::Tcp as u16,
    "udp" => Protocol::Udp as u16,
    "icmp" => Protocol::Icmp as u16,
    "igmp" => Protocol::Igmp as u16,
    "ipv4" => Protocol::Ipv4 as u16,
    "ipv6" =>Protocol::Ipv6 as u16,
    "ipv6-route" => Protocol::Ipv6Route as u16,
    "ipv6-frag" => Protocol::Ipv6Frag as u16,
    "icmpv6" => Protocol::Icmpv6 as u16,
     "sctp" => Protocol::Sctp as u16,
     "hopopt" => Protocol::HopOpt as u16,
     "" => Protocol::Reserved as u16
};
/// A static map of field categories for the `allow-input` action.
///
/// This map defines which fields are mandatory, optional, or restricted for the `allow-input` action.
///
/// # Example
///
/// ```
/// use tiiuae_fw::config::field_maps::*;
/// let field_category = ALLOW_INPUT_FIELDS.get("action");
/// assert_eq!(field_category, Some(&FieldCategory::Mandatory(0)));
/// ```
pub static ALLOW_INPUT_FIELDS: phf::Map<&'static str, FieldCategory> = phf_map! {
    "action" => FieldCategory::Mandatory(0),
    "if_input" => FieldCategory::Mandatory(1),
    "if_output" => FieldCategory::Restricted,
    "protocol" => FieldCategory::Optional,
    "source_ip"=> FieldCategory::Optional,
    "destination_ip"=>FieldCategory::Optional,
    "source_port"=> FieldCategory::Optional,
    "destination_port"=> FieldCategory::Optional,
    "description"=> FieldCategory::Optional,
    "reject_type" => FieldCategory::Restricted,
    "new_dest_ip"=> FieldCategory::Restricted,
    "new_source_port"=> FieldCategory::Restricted,
    "new_destination_port"=> FieldCategory::Restricted,
};
/// A static map of field categories for the `reject-input` action.
///
/// This map defines which fields are mandatory, optional, or restricted for the `reject-input` action.
///
/// # Example
///
/// ```
/// use tiiuae_fw::config::field_maps::*;
/// let field_category = REJECT_INPUT_FIELDS.get("reject_type");
/// assert_eq!(field_category, Some(&FieldCategory::Mandatory(2)));
/// ```
pub static REJECT_INPUT_FIELDS: phf::Map<&'static str, FieldCategory> = phf_map! {
    "action" => FieldCategory::Mandatory(0),
    "if_input" => FieldCategory::Mandatory(1),
    "if_output" => FieldCategory::Restricted,
    "protocol" => FieldCategory::Optional,
    "source_ip"=> FieldCategory::Optional,
    "destination_ip"=> FieldCategory::Optional,
    "source_port"=> FieldCategory::Optional,
    "destination_port"=> FieldCategory::Optional,
    "description"=> FieldCategory::Optional,
    "reject_type" => FieldCategory::Mandatory(2),
    "new_dest_ip"=> FieldCategory::Restricted,
    "new_source_port"=> FieldCategory::Restricted,
    "new_destination_port"=> FieldCategory::Restricted,
};
/// A static map of field categories for the `drop-output` action.
///
/// This map defines which fields are mandatory, optional, or restricted for the `drop-output` action.
///
/// # Example
///
/// ```
/// use tiiuae_fw::config::field_maps::*;
/// let field_category = DROP_OUTPUT_FIELDS.get("source_ip");
/// assert_eq!(field_category, Some(&FieldCategory::Mandatory(1)));
/// ```
pub static DROP_OUTPUT_FIELDS: phf::Map<&'static str, FieldCategory> = phf_map! {
    "action" => FieldCategory::Mandatory(0),
    "if_input" => FieldCategory::Restricted,
    "if_output" => FieldCategory::Mandatory(1),
    "protocol" => FieldCategory::Optional,
    "source_ip"=> FieldCategory::Mandatory(1),
    "destination_ip"=> FieldCategory::Optional,
    "source_port"=> FieldCategory::Optional,
    "destination_port"=> FieldCategory::Optional,
    "description"=> FieldCategory::Optional,
    "reject_type" => FieldCategory::Restricted,
    "new_dest_ip"=> FieldCategory::Restricted,
    "new_source_port"=> FieldCategory::Restricted,
    "new_destination_port"=> FieldCategory::Restricted,

};
/// A static map of field categories for the `forward` action.
///
/// This map defines which fields are mandatory, optional, or restricted for the `forward` action.
///
/// # Example
///
/// ```
/// use tiiuae_fw::config::field_maps::*;
/// let field_category = FORWARD_FIELDS.get("new_dest_ip");
/// assert_eq!(field_category, Some(&FieldCategory::Mandatory(3)));
/// ```
pub static FORWARD_FIELDS: phf::Map<&'static str, FieldCategory> = phf_map! {
    "action" => FieldCategory::Mandatory(0),
    "if_input" => FieldCategory::Mandatory(1),
    "if_output" => FieldCategory::Mandatory(2),
    "protocol" => FieldCategory::Optional,
    "source_ip"=> FieldCategory::Optional,
    "destination_ip"=> FieldCategory::Optional,
    "source_port"=> FieldCategory::Optional,
    "destination_port"=> FieldCategory::Optional,
    "description"=> FieldCategory::Optional,
    "reject_type" => FieldCategory::Restricted,
    "new_dest_ip"=> FieldCategory::Mandatory(3),
    "new_source_port"=> FieldCategory::Mandatory(4),
    "new_destination_port"=> FieldCategory::Restricted,

};
/// A static map of field categories for the `masquerade` action.
///
/// This map defines which fields are mandatory, optional, or restricted for the `masquerade` action.
///
/// # Example
///
/// ```
///  use tiiuae_fw::config::field_maps::*;
/// let field_category = MASQUERADE_FIELDS.get("new_source_port");
/// assert_eq!(field_category, Some(&FieldCategory::Mandatory(4)));
/// ```
pub static MASQUERADE_FIELDS: phf::Map<&'static str, FieldCategory> = phf_map! {
    "action" => FieldCategory::Mandatory(0),
    "if_input" => FieldCategory::Mandatory(1),
    "if_output" => FieldCategory::Mandatory(2),
    "protocol" => FieldCategory::Optional,
    "source_ip"=> FieldCategory::Optional,
    "destination_ip"=> FieldCategory::Optional,
    "source_port"=> FieldCategory::Optional,
    "destination_port"=> FieldCategory::Optional,
    "description"=> FieldCategory::Optional,
    "reject_type" => FieldCategory::Restricted,
    "new_dest_ip"=> FieldCategory::Mandatory(3),
    "new_source_port"=> FieldCategory::Mandatory(4),
    "new_destination_port"=> FieldCategory::Restricted,

};

// A static map that combines field categories for all actions.
//
// This map allows quick access to the field categories for a specific action by its name.
//
// # Example
//
// ```
// let field_map = FIELD_MAPS.get("allow-input");
// assert!(field_map.is_some());
// let field_category = field_map.unwrap().get("source_ip");
// assert_eq!(field_category, Some(&FieldCategory::Optional));
// ```
lazy_static! {
    pub static ref FIELD_MAPS: StdHashMap<&'static str, &'static phf::Map<&'static str, FieldCategory>> = {
        let mut m = StdHashMap::new();
        m.insert(Action::AllowInput.as_str(), &ALLOW_INPUT_FIELDS);
        m.insert(Action::RejectInput.as_str(), &REJECT_INPUT_FIELDS);
        m.insert(Action::DropOutput.as_str(), &DROP_OUTPUT_FIELDS);
        m.insert(Action::Forward.as_str(), &FORWARD_FIELDS);
        m.insert(Action::Masquerade.as_str(), &MASQUERADE_FIELDS);
        m
    };
}
