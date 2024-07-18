/*
    Copyright 2022-2024 TII (SSRC) and the contributors
    SPDX-License-Identifier: Apache-2.0
*/
//! # Configuration Management and Flow Extraction
//!
//! This module handles configuration management and flow extraction from configuration rules for both IPv4 and IPv6.
//! It includes functionalities for reading configurations from files, validating rules, and extracting flow information for different protocols.
use crate::config::field_maps::*;
use crate::config::rule::*;
use crate::config::utils::*;
use core::net::{IpAddr, Ipv4Addr};
use core::panic;
use serde::Deserialize;
use std::any::*;
use std::collections::HashMap as StdHashMap;
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::Path;
use tiiuae_fw_common::*;

/// Represents the configuration settings for the system.
#[derive(Deserialize)]
pub struct Config {
    #[serde(rename = "default_policy")]
    default_policy: DefaultPolicy,
    #[serde(rename = "ip_options")]
    ip_options: IpOpts,
    /// A list of rules to be applied.
    rules: Vec<Rule>,
    /// interface groups
    interface_groups: Option<IfaceGroup>,
    #[serde(skip)]
    system_iface_ips: StdHashMap<String, Vec<IpAddr>>,
}

#[derive(Debug, Deserialize)]
pub struct DefaultPolicies {
    #[serde(rename = "input_default_policy")]
    pub input_default_policy: String,
    #[serde(rename = "output_default_policy")]
    pub output_default_policy: String,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "IPv4 Enabled: {}", self.ip_options.ipv4_enabled)?;
        writeln!(f, "IPv6 Enabled: {}", self.ip_options.ipv6_enabled)?;
        writeln!(f, "interface groups: {:?}", self.interface_groups)?;
        writeln!(f, "Default Policy: {:?}", self.default_policy)?;

        writeln!(f, "Rules:")?;
        for (i, rule) in self.rules.iter().enumerate() {
            writeln!(f, "Rule {}: {:?}", i + 1, rule)?;
        }

        Ok(())
    }
}

/// Trait for extracting flow information from configuration.
///
pub trait Extractor<K: fmt::Debug + aya::Pod, V: fmt::Debug + aya::Pod> {
    /// Extracts a single IPv4 flow from the configuration.
    ///
    /// # Returns
    /// - `StdHashMap<String, StdHashMap<K, V>>`: A map where the keys are network interface
    ///    names with 'egress/ingress'postfix and the values are maps of flow keys to flow values.
    ///    Example: "eth0-ingress", "eth1-egress"
    fn extract_single_ipv4_flow(&self) -> StdHashMap<String, StdHashMap<K, V>>;
}
impl Extractor<Ipv4FlowKey, Tcpv4FlowVal> for Config {
    fn extract_single_ipv4_flow(
        &self,
    ) -> StdHashMap<String, StdHashMap<Ipv4FlowKey, Tcpv4FlowVal>> {
        let mut outer_map = StdHashMap::new();

        let ip_flow = self.get_single_ipv4_flow::<Tcpv4FlowVal>();
        for (iface, inner_map) in ip_flow {
            let map = outer_map.entry(iface).or_insert_with(StdHashMap::new);
            for (key, value) in inner_map {
                map.insert(key.0, Tcpv4FlowVal { val: value });
            }
        }
        outer_map
    }
}

impl Extractor<Ipv4FlowKey, Udpv4FlowVal> for Config {
    fn extract_single_ipv4_flow(
        &self,
    ) -> StdHashMap<String, StdHashMap<Ipv4FlowKey, Udpv4FlowVal>> {
        let mut outer_map = StdHashMap::new();

        let ip_flow = self.get_single_ipv4_flow::<Udpv4FlowVal>();
        for (iface, inner_map) in ip_flow {
            let map = outer_map.entry(iface).or_insert_with(StdHashMap::new);
            for (key, value) in inner_map {
                map.insert(key.0, Udpv4FlowVal { val: value });
            }
        }
        outer_map
    }
}

impl Extractor<OtherProtov4Key, OtherProtov4Val> for Config {
    fn extract_single_ipv4_flow(
        &self,
    ) -> StdHashMap<String, StdHashMap<OtherProtov4Key, OtherProtov4Val>> {
        let mut outer_map = StdHashMap::new();
        let ip_flow = self.get_single_ipv4_flow::<OtherProtov4Val>();
        for (iface, inner_map) in ip_flow {
            let map = outer_map.entry(iface).or_insert_with(StdHashMap::new);
            for (key, value) in inner_map {
                let other_proto_key = OtherProtov4Key {
                    ipv4_flow_key: key.0,
                    proto: key.1,
                };
                let other_proto_val = OtherProtov4Val {
                    ipv4_flow_key: value,
                    packet_count: 0,
                    byte_count: 0,
                    last_seen: 0,
                };
                map.insert(other_proto_key, other_proto_val);
            }
        }
        outer_map
    }
}
impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    /// Creates a new instance of `Config` with default values.
    ///
    /// This constructor initializes a `Config` object with the following default settings:
    ///
    /// - `ip_options`: `IpOpts::default()` — Initializes IPv4 and IPv6 support as disabled by default.
    /// - `rules`: `Vec::new()` — The rules vector is initialized as an empty vector.
    /// - `interface_groups`: `None` — No interface groups are set by default.
    /// - `default_policy`: `DefaultPolicy::default()` — Uses default policies for input and output actions.
    /// - `system_iface_ips`: Result from `get_all_ip_and_ifaces()` — Retrieves all system interface IPs.
    ///
    /// # Returns
    ///
    /// Returns a new `Config` instance with the default values set.
    ///
    /// # Examples
    ///
    /// ```
    /// use tiiuae_fw::Config;
    /// use tiiuae_fw::config::rule::DefaultPolicy;
    /// // Create a new `Config` instance with default values
    /// let config = Config::new();
    ///
    /// println!("Config created with default values: {:?}", config);
    /// ```
    ///
    /// # Note
    ///
    /// The `system_iface_ips` field is populated using the `get_all_ip_and_ifaces` function, which retrieves
    /// the current IP addresses assigned to system interfaces. This field is used internally to help with
    /// validating and assigning interface groups.
    pub fn new() -> Self {
        Self {
            ip_options: IpOpts::default(),
            rules: Vec::new(), // Initialize with an empty vector
            interface_groups: None,
            default_policy: DefaultPolicy::default(),
            system_iface_ips: get_all_ip_and_ifaces(),
        }
    }
    /// Parses a TOML configuration string into a `Config` object.
    ///
    /// # Arguments
    ///
    /// * `toml_str` - A string slice that holds the TOML configuration.
    ///
    /// # Returns
    ///
    /// * `Ok(Config)` if the TOML string is valid and successfully parsed.
    /// * `Err` if parsing fails, containing a description of the error.
    ///
    /// # Examples
    ///
    /// ```
    /// use tiiuae_fw::Config;
    ///
    /// let toml_str = r#"
    ///     [default_policy]
    ///     input = "whitelist"
    ///     output = "blacklist"
    ///     [ip_options]
    ///     ipv4_enabled = true
    ///     ipv6_enabled = true
    ///     [[rules]]
    ///     action = "allow-input"
    ///     if_input = ["lo"]
    ///     protocol = "tcp"
    ///     source_ip = "any"
    ///     destination_ip = "192.168.1.10"
    ///     source_port = "any"
    ///     destination_port = "[22, 1024]"
    ///     description = "Allow SSH traffic from any source to 192.168.1.10"
    /// "#;
    ///
    /// let config = Config::from_string(toml_str).expect("Failed to parse configuration");
    /// println!("{:?}", config);
    /// ```
    /// # Note
    ///
    /// Ensure that the TOML string contains all the required fields for the `Config` object, including
    /// sections for `rules`, `ip_options`, and `default_policy`. Missing or incorrect fields may cause parsing
    /// errors.
    pub fn from_string(toml_str: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml_str)
    }
    /// Reads and validates a TOML configuration from a file and parses it into a `Config` object.
    ///
    /// # Arguments
    ///
    /// * `path` - A string slice that holds the path to the TOML configuration file.
    ///
    /// # Returns
    ///
    /// * `Ok(Config)` if the file is read and parsed successfully.
    /// * `Err` if reading the file or parsing fails, containing a description of the error.
    ///
    /// # Examples
    ///
    /// ```
    /// use tiiuae_fw::Config;
    ///
    /// let config = Config::from_file("src/tests/config_all_valid.toml").expect("Failed to read configuration from file");
    /// println!("{:?}", config);
    /// ```
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let mut config = Config::from_string(&content)?;
        config.validate_and_assign();

        Ok(config)
    }

    pub fn ip_port_range_handling(&self) {
        //trie will be used for both of them
        todo!("ip port range assignment handling functionality")
    }

    /// Validates the configuration to ensure all required fields are present and correctly formatted.
    ///
    /// This method performs validation checks on the configuration, including ensuring that all required fields
    /// are properly set and correctly formatted. It will panic if any validation checks fail, so it's important
    /// to ensure that the configuration is constructed correctly before calling this method.
    ///
    /// # Panics
    ///
    /// This method will panic if:
    /// - Required fields are missing or incorrectly formatted.
    /// - Validation checks for `interface_groups` or `rules` fail.
    ///
    /// # Note
    ///
    /// Ensure that the configuration is properly initialized and populated with valid data before calling this method.
    /// This will help avoid panics due to validation errors.
    fn validate_and_assign(&mut self) {
        self.validate_and_assign_interface_groups();
        self.validate_rules();
    }

    fn validate_rules(&self) {
        for rule in &self.rules {
            let field_map = FIELD_MAPS
                .get(rule.action.as_ref().unwrap().as_str())
                .unwrap_or_else(|| panic!("Unknown action: {}", rule.action.unwrap().as_str()));

            let mut mandatory_fields_by_id: StdHashMap<u8, HashSet<&str>> = StdHashMap::new();

            // Collect mandatory fields by their ID
            for (field, category) in field_map.entries() {
                match category {
                    FieldCategory::Mandatory(id) => {
                        let entry = mandatory_fields_by_id.entry(*id).or_default();
                        entry.insert(*field);
                    }
                    FieldCategory::Restricted => {
                        if self.get_field_value(rule, field).is_some() {
                            panic!(
                                "Field '{}' is restricted for action '{}'",
                                field,
                                rule.action.unwrap().as_str()
                            );
                        }
                    }
                    _ => {}
                }
            }

            // Check if at least one mandatory field for each ID is present
            for (id, fields) in &mandatory_fields_by_id {
                let mut found = false;
                for field in fields {
                    if self.get_field_value(rule, field).is_some() {
                        found = true;

                        //TODO: select/process one of them
                        break;
                    }
                }
                if !found {
                    panic!(
                        "Missing mandatory field group (id: {}) for action '{}',Fields: {:?}",
                        id,
                        rule.action.unwrap().as_str(),
                        fields
                    );
                }
            }
        }
    }

    fn validate_and_assign_interface_groups(&mut self) {
        if let Some(group) = self.interface_groups.as_mut() {
            let len = group.interface_grp.keys().len();
            let mut keys: Vec<String> = group.interface_grp.keys().cloned().collect();

            let mut seen = HashSet::new(); // To keep track of seen values
            for vec in group.interface_grp.values() {
                for val in vec {
                    if !seen.insert(val) {
                        // If insert returns false, it means `val` was already in the set
                        panic!("Duplicate value found in interface groups");
                    }
                }
            }
            if len > IfaceGroup::MAX_GROUP {
                panic!(
                    "Number of interface groups could be {} maximum, currently {}",
                    IfaceGroup::MAX_GROUP,
                    len
                );
            }

            // Assign groups based on available keys
            match len {
                1 => {
                    if let Some(group_val) = group.interface_grp.get(&keys[0]) {
                        group.interface_group_1 = group_val.clone();
                    }
                }
                2 => {
                    if let Some(group1) = group.interface_grp.get(&keys[0]) {
                        group.interface_group_1 = group1.clone();
                    }
                    if let Some(group2) = group.interface_grp.get(&keys[1]) {
                        group.interface_group_2 = group2.clone();
                    }
                }
                _ => {} // No action needed for 0 groups
            }
            Self::validate_and_assign_non_grouped_interfaces(&self.system_iface_ips, group);
            // add "&" prefix for reference search in interface_groups
            keys.iter_mut().for_each(|key| {
                *key = format!("&{}", key);
            });

            for rule in &mut self.rules {
                Self::update_interface_group_field(
                    &mut rule.if_input,
                    &keys,
                    &group.interface_group_1,
                    &group.interface_group_2,
                    &group.interface_not_grouped,
                );
                Self::update_interface_group_field(
                    &mut rule.if_output,
                    &keys,
                    &group.interface_group_1,
                    &group.interface_group_2,
                    &group.interface_not_grouped,
                );
            }
        }
    }

    fn validate_and_assign_non_grouped_interfaces(
        system_iface_ips: &StdHashMap<String, Vec<IpAddr>>,
        group: &mut IfaceGroup,
    ) {
        // Iterate over each system interface
        for iface_name in system_iface_ips.keys() {
            // Check if the system interface is in interface_group section
            if !group.interface_group_1.contains(iface_name)
                && !group.interface_group_2.contains(iface_name)
            {
                println!(
                    "Interface '{}' not found in interface_group section",
                    iface_name
                );
                group.interface_not_grouped.push(iface_name.clone()); // Collect the interface name to be removed
            }
        }
    }

    fn update_interface_group_field(
        field: &mut Option<Vec<String>>,
        keys: &[String],
        group1: &[String],
        group2: &[String],
        not_grouped: &[String],
    ) {
        if let Some(vec) = field.as_mut() {
            if vec.len() == 1 {
                match vec.first() {
                    //keyler karşılaştırılmalı.group1[0] value tutuyor
                    Some(v) if v == &keys[0] => {
                        vec.clear();
                        vec.extend(group1.iter().cloned());
                    }
                    Some(v) if !group2.is_empty() && v == &keys[1] => {
                        vec.clear();
                        vec.extend(group2.iter().cloned());
                    }
                    Some(v)
                        if !not_grouped.is_empty() && v == IfaceGroup::NOT_GROUPED_IFACES_STR =>
                    {
                        vec.clear();
                        vec.extend(not_grouped.iter().cloned());
                    }
                    _ => {} // Handle cases where the value does not match expected groups
                }
            } else {
                panic!("interface group size cannot be greater than 1");
            }
        }
    }
    fn get_field_value(&self, rule: &Rule, field: &str) -> Option<String> {
        match field {
            "action" => rule.action.as_ref().map(|action| format!("{:?}", action)),
            "if_input" => rule.if_input.as_ref().map(|input| input.join(", ")),
            "if_output" => rule.if_output.as_ref().map(|output| output.join(", ")),
            "protocol" => rule.protocol.clone(),
            "source_ip" => rule.source_ip.as_ref().map(|ip| format!("{:?}", ip)),
            "destination_ip" => rule.destination_ip.as_ref().map(|ip| format!("{:?}", ip)),
            "source_port" => rule.source_port.as_ref().map(|p| format!("{:?}", p)),
            "destination_port" => rule.destination_port.as_ref().map(|p| format!("{:?}", p)),
            "description" => rule.description.clone(),
            "reject_type" => rule.reject_type.clone(),
            "new_dest_ip" => rule.new_dest_ip.as_ref().map(|ip| format!("{:?}", ip)),
            "new_source_port" => rule.new_source_port.as_ref().map(|p| format!("{:?}", p)),
            _ => None,
        }
    }

    fn is_valid_protocol<T: 'static>(&self, protocol: &str) -> bool {
        match TypeId::of::<T>() {
            id if id == TypeId::of::<Tcpv4FlowVal>() => protocol == "tcp",
            id if id == TypeId::of::<Udpv4FlowVal>() => protocol == "udp",
            id if id == TypeId::of::<OtherProtov4Val>() => protocol != "udp" && protocol != "tcp",
            _ => false,
        }
    }
    /// Extracts and returns a `HashMap` of IPv4 flow rules based on the given flow type.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type representing the flow value (e.g., `Tcpv4FlowVal`).
    ///
    /// # Returns
    ///
    /// * A `HashMap` where the keys are strings representing flow categories and the values
    ///   are `HashMap`s of flow rules.
    ///
    fn get_single_ipv4_flow<T: 'static>(
        &self,
    ) -> StdHashMap<String, StdHashMap<(Ipv4FlowKey, ProtoType), Ipv4FlowVal>> {
        let mut outer_map = StdHashMap::new();

        if !self.ip_options.ipv4_enabled {
            return outer_map;
        }

        for rule in &self.rules {
            if rule.destination_ip.is_some() && !rule.destination_ip.unwrap().is_ipv4() {
                continue;
            }
            if rule.source_ip.is_some() && !rule.source_ip.unwrap().is_ipv4() {
                continue;
            }
            if !self.is_valid_protocol::<T>(rule.protocol.as_ref().unwrap()) {
                continue;
            }

            let flow_key = Ipv4FlowKey {
                src_ip: extract_ipv4(rule.source_ip.as_ref()),
                src_port: extract_port_single(rule.source_port.as_ref()),
                dest_ip: extract_ipv4(rule.destination_ip.as_ref()),
                dest_port: extract_port_single(rule.destination_port.as_ref()),
            };

            let flow_val = Ipv4FlowVal {
                action: rule.action.unwrap() as u8,
                new_dest_ip: rule
                    .new_dest_ip
                    .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                new_dest_port: extract_port_single(rule.new_source_port.as_ref()),
                new_src_port: extract_port_single(rule.new_destination_port.as_ref()),
            };

            if let Some(ref inputs) = rule.if_input {
                for input in inputs {
                    let entry = outer_map
                        .entry(input.to_owned() + "-ingress")
                        .or_insert_with(StdHashMap::new);
                    if entry
                        .insert(
                            (
                                flow_key,
                                *ALLOW_PROTOCOLS
                                    .get(rule.protocol.as_ref().unwrap_or(&"".to_string()))
                                    .unwrap(),
                            ),
                            flow_val,
                        )
                        .is_some()
                    {
                        panic!("flow key already inserted: {:?}", flow_key);
                    }
                }
            }

            if let Some(ref outputs) = rule.if_output {
                for output in outputs {
                    let entry = outer_map
                        .entry(output.to_owned() + "-egress")
                        .or_insert_with(StdHashMap::new);
                    if entry
                        .insert(
                            (
                                flow_key,
                                *ALLOW_PROTOCOLS
                                    .get(rule.protocol.as_ref().unwrap_or(&"".to_string()))
                                    .unwrap(),
                            ),
                            flow_val,
                        )
                        .is_some()
                    {
                        panic!("flow key already inserted: {:?}", flow_key);
                    }
                }
            }
        }
        outer_map
        // Specific logic for OtherProtoKey
    }
    /// Retrieves common configuration settings from the `Config` instance.
    ///
    /// This method extracts the following settings from the `Config` object and returns them in a `CommonStaticSettings` struct:
    ///
    /// - `input_policy` - The policy applied to input traffic, as specified in the `default_policy` field.
    /// - `output_policy` - The policy applied to output traffic, as specified in the `default_policy` field.
    /// - `ipv4_enabled` - A boolean indicating whether IPv4 support is enabled, as specified in the `ip_options` field.
    /// - `ipv6_enabled` - A boolean indicating whether IPv6 support is enabled, as specified in the `ip_options` field.
    ///
    /// # Returns
    ///
    /// Returns a `CommonStaticSettings` struct containing the common configuration settings.
    ///
    /// # Examples
    ///
    /// ```
    /// use tiiuae_fw_common::CommonStaticSettings;
    /// use tiiuae_fw::Config;
    ///
    /// // Create or load a Config instance
    /// let config = Config::new(); // Replace with actual configuration loading as needed
    ///
    /// // Retrieve common settings
    /// let common_settings = config.get_common_settings();
    ///
    /// // Use the common settings
    /// println!("Input Policy: {:?}", common_settings.input_policy);
    /// println!("Output Policy: {:?}", common_settings.output_policy);
    /// println!("IPv4 Enabled: {}", common_settings.ipv4_enabled);
    /// println!("IPv6 Enabled: {}", common_settings.ipv6_enabled);
    /// ```
    ///
    /// # Panics
    ///
    /// This function will not panic if the `Config` instance is valid. However, ensure that the `Config` is correctly
    /// initialized to avoid unexpected behavior.
    pub fn get_common_settings(&self) -> CommonStaticSettings {
        CommonStaticSettings {
            input_policy: self.default_policy.input,
            output_policy: self.default_policy.output,
            ipv4_enabled: self.ip_options.ipv4_enabled,
            ipv6_enabled: self.ip_options.ipv6_enabled,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::catch_unwind;

    #[test]
    fn test_validate_and_assign_config() {
        let toml_str = r#"
            [ip_options]
            ipv4_enabled = true
            ipv6_enabled = true
            [default_policy]
            input = "whitelist"
            output = "blacklist"
            
            [[rules]]
            action = "allow-input"
            if_input = ["lo"]
            protocol = "tcp"
            source_ip = "any"
            destination_ip = "192.168.1.10"
            source_port = "any"
            destination_port = "[22, 1024]"
            description = "Allow SSH traffic from any source to 192.168.1.10"
            "#;

        let mut config = Config::from_string(toml_str).unwrap();
        println!("config:{:?}", config);
        config.validate_and_assign();
    }

    #[test]
    fn test_validate_and_assign_config_with_empty_action() {
        let toml_str = r#"
            [ip_options]
            ipv4_enabled = true
            ipv6_enabled = true
            [default_policy]
            input = "whitelist"
            output = "blacklist"
            [[rules]]
            action = ""
            if_input = ["lo"]
            protocol = "tcp"
            source_ip = "any"
            destination_ip = "192.168.1.10"
            source_port = "any"
            destination_port = "[22, 1024]"
            description = "Allow SSH traffic from any source to 192.168.1.10"
            "#;

        // Use catch_unwind to test for panic
        let config = std::panic::catch_unwind(|| {
            Config::from_string(toml_str).unwrap(); // This should panic
        });
        assert!(config.is_err());
    }

    #[test]
    fn test_read_from_file() {
        let config = Config::from_file("src/tests/config_all_valid.toml").unwrap();
        println!("{:?}", config);
    }

    // Helper function to create a valid TOML configuration string
    fn valid_toml_config() -> &'static str {
        r#"
            [ip_options]
            ipv4_enabled = true
            ipv6_enabled = true
            [default_policy]
            input = "whitelist"
            output = "blacklist"
            [[rules]]
            action = "allow-input"
            if_input = ["lo"]
            protocol = "tcp"
            source_ip = "any"
            destination_ip = "192.168.1.10"
            source_port = "any"
            destination_port = "[22, 1024]"
            description = "Allow SSH traffic from any source to 192.168.1.10"
            "#
    }

    // Helper function to create an invalid TOML configuration string
    fn invalid_toml_config() -> &'static str {
        r#"
            [ip_options]
            ipv4_enabled = true
            ipv6_enabled = true
            [default_policy]
            input = "whitelist"
            output = "blacklist"
            [[rules]]
            action = "allow-input"
            if_input = ["lo"]
            protocol = "tcp"
            source_ip = "any"
            destination_ip = "192.168.1.10"
            source_port = "any"
            destination_port = "invalid_port"
            description = "Allow SSH traffic from any source to 192.168.1.10"
            "#
    }

    // Test parsing a valid configuration string
    #[test]
    fn test_parse_valid_config() {
        let toml_str = valid_toml_config();
        let config = Config::from_string(toml_str);
        assert!(config.is_ok());
        let config = config.unwrap();
        assert!(config.ip_options.ipv4_enabled);
        assert!(config.ip_options.ipv6_enabled);
        assert_eq!(config.rules.len(), 1);
    }

    // Test parsing an invalid configuration string
    #[test]
    fn test_parse_invalid_config() {
        let toml_str = invalid_toml_config();
        let config = Config::from_string(toml_str);
        assert!(config.is_err());
    }

    // Test validating a configuration with valid rules
    #[test]
    fn test_validate_and_assign_valid_config() {
        let toml_str = valid_toml_config();
        let mut config = Config::from_string(toml_str).unwrap();
        config.validate_and_assign(); // Should not panic
    }

    // Test validating a configuration with invalid rules
    #[test]
    fn test_validate_and_assign_invalid_config() {
        let toml_str = r#"
            [ip_options]
            ipv4_enabled = true
            ipv6_enabled = true
            [default_policy]
            input = "whitelist"
            output = "blacklist"
            [[rules]]
            action = "allow-input"
            if_input = ["lo"]
            protocol = "tcp"
            source_ip = "any"
            destination_ip = "192.168.1.10"
            source_port = "any"
            destination_port = "[22, 1024]"
            description = "Allow SSH traffic from any source to 192.168.1.10"
            "#;

        let mut config = Config::from_string(toml_str).unwrap();

        // Use `catch_unwind` to catch panics during validation
        config.validate_and_assign();
    }

    // Test for missing mandatory fields in validation
    #[test]
    fn test_validate_and_assign_missing_mandatory_field() {
        let toml_str = r#"
            [ip_options]
            ipv4_enabled = true
            ipv6_enabled = true
            [default_policy]
            input = "whitelist"
            output = "blacklist"
            [[rules]]
            action = "allow-input"
            if_input = ["lo"]
            protocol = "tcp"
            source_ip = "any"
            destination_ip = "192.168.1.10"
            source_port = "any"
            destination_port = "[22, 1024]"
            "#;

        let mut config = Config::from_string(toml_str).unwrap();

        // Use `catch_unwind` to test for panic
        config.validate_and_assign();
    }

    // Test edge case for empty configuration
    #[test]
    fn test_empty_config() {
        let toml_str = r#"
            [ip_options]
            ipv4_enabled = false
            ipv6_enabled = false
            [default_policy]
            input = "whitelist"
            output = "blacklist"
            "#;
        // Use catch_unwind to test for panic
        let config = std::panic::catch_unwind(|| {
            Config::from_string(toml_str).unwrap(); // This should panic
        });
        assert!(config.is_err());
    }

    // Test configuration with only IPv4 rules
    #[test]
    fn test_ipv4_only_config() {
        let toml_str = r#"
            [ip_options]
            ipv4_enabled = true
            ipv6_enabled = false
            [default_policy]
            input = "whitelist"
            output = "blacklist"
            [[rules]]
            action = "allow-input"
            if_input = ["lo"]
            protocol = "tcp"
            source_ip = "any"
            destination_ip = "192.168.1.10"
            source_port = "any"
            destination_port = "[22, 1024]"
            description = "Allow SSH traffic from any source to 192.168.1.10"
            "#;

        let config = Config::from_string(toml_str).unwrap();
        assert!(config.ip_options.ipv4_enabled);
        assert!(!config.ip_options.ipv6_enabled);
        assert_eq!(config.rules.len(), 1);
    }

    // Test configuration with only IPv6 rules
    #[test]
    fn test_ipv6_only_config() {
        let toml_str = r#"
            [ip_options]
            ipv4_enabled = false
            ipv6_enabled = true
            [default_policy]
            input = "whitelist"
            output = "blacklist"
            [[rules]]
            action = "allow-input"
            if_input = ["lo"]
            protocol = "tcp"
            source_ip = "any"
            destination_ip = "2001:db8::1"
            source_port = "any"
            destination_port = "[22, 1024]"
            description = "Allow SSH traffic from any source to 2001:db8::1"
            "#;

        let config = Config::from_string(toml_str).unwrap();
        assert!(!config.ip_options.ipv4_enabled);
        assert!(config.ip_options.ipv6_enabled);
        assert_eq!(config.rules.len(), 1);
    }

    // Test configuration with mixed IP rules and incorrect types
    #[test]
    fn test_mixed_ip_rules_with_errors() {
        let toml_str = r#"
            [ip_options]
            ipv4_enabled = true
            ipv6_enabled = true
            [[rules]]
            action = "allow-input"
            if_input = "lo"
            protocol = "tcp"
            source_ip = "any"
            destination_ip = "invalid_ip"
            source_port = "any"
            destination_port = "[22, 1024]"
            description = "Allow SSH traffic with invalid IP"
            "#;

        let config = Config::from_string(toml_str);
        assert!(config.is_err());
    }

    // Test configuration with various actions
    #[test]
    fn test_config_with_various_actions() {
        let toml_str = r#"
            [ip_options]
            ipv4_enabled = true
            ipv6_enabled = true
            [default_policy]
            input = "whitelist"
            output = "blacklist"
            [[rules]]
            action = "allow-input"
            if_input = ["lo"]
            protocol = "tcp"
            source_ip = "any"
            destination_ip = "192.168.1.10"
            source_port = "any"
            destination_port = "[22, 1024]"
            description = "Allow SSH traffic from any source to 192.168.1.10"
            
            [[rules]]
            action = "reject-input"
            if_input = ["lo"]
            protocol = "udp"
            source_ip = "192.168.1.10"
            destination_ip = "192.168.1.20"
            source_port = "1024"
            destination_port = "2048"
            reject-type = "icmp-unreachable"
            description = "Deny UDP traffic between specified IPs"
            "#;

        let config = Config::from_string(toml_str).unwrap();
        assert_eq!(config.rules.len(), 2);
    }

    // Test handling of edge case for rule attributes
    #[test]
    fn test_rule_edge_cases() {
        let toml_str = r#"
            [ip_options]
            ipv4_enabled = true
            ipv6_enabled = true
            [default_policy]
            input = "whitelist"
            output = "blacklist"
            [[rules]]
            action = "allow-input"
            if_input = ["lo"]
            protocol = ""
            source_ip = "any"
            destination_ip = "192.168.1.10"
            source_port = ""
            destination_port = "[22, 1024]"
            description = "Allow traffic with empty fields"
            "#;

        let mut config = Config::from_string(toml_str).unwrap();
        assert_eq!(config.rules.len(), 1);
        // validate_and_assign that the empty fields do not cause issues in processing
        config.validate_and_assign(); // Should not panic
    }

    #[test]
    fn test_get_single_flow_empty_config() {
        let config = Config {
            ip_options: IpOpts {
                ipv4_enabled: true,
                ipv6_enabled: false,
            },
            interface_groups: None,
            rules: Vec::new(),
            default_policy: DefaultPolicy::default(),
            system_iface_ips: get_all_ip_and_ifaces(),
        };

        let result = config.get_single_ipv4_flow::<Tcpv4FlowVal>();

        assert!(result.is_empty());
    }

    #[test]
    fn test_get_single_flow_with_rules() {
        let config = Config {
            ip_options: IpOpts {
                ipv4_enabled: true,
                ipv6_enabled: false,
            },
            interface_groups: None,
            default_policy: DefaultPolicy::default(),
            system_iface_ips: get_all_ip_and_ifaces(),

            rules: vec![Rule {
                action: Some(Action::AllowInput),
                protocol: Some("tcp".into()),
                source_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                destination_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
                source_port: Some(Port::Single(80)),
                destination_port: Some(Port::Single(443)),
                if_input: Some(vec!["eth0".into()]),
                if_output: None,
                new_dest_ip: None,
                new_source_port: None,
                new_destination_port: None,
                description: None,
                reject_type: None,
            }],
        };

        let result = config.get_single_ipv4_flow::<Tcpv4FlowVal>();

        let expected_key = Ipv4FlowKey {
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            src_port: 80,
            dest_ip: Ipv4Addr::new(192, 168, 1, 10),
            dest_port: 443,
        };

        let expected_val = Ipv4FlowVal {
            action: Action::AllowInput as u8,
            new_dest_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            new_dest_port: 0,
            new_src_port: 0,
        };

        let mut expected_map = StdHashMap::new();
        expected_map.insert(
            (expected_key, *ALLOW_PROTOCOLS.get("tcp").unwrap()),
            expected_val,
        );

        let mut result_map = StdHashMap::new();
        result_map.insert("eth0-ingress".into(), expected_map);

        assert_eq!(result, result_map);
    }

    #[test]
    fn test_get_single_flow_with_multiple_rules() {
        let config = Config {
            system_iface_ips: get_all_ip_and_ifaces(),

            ip_options: IpOpts {
                ipv4_enabled: true,
                ipv6_enabled: false,
            },
            interface_groups: None,
            default_policy: DefaultPolicy::default(),

            rules: vec![
                Rule {
                    action: Some(Action::AllowInput),
                    protocol: Some("tcp".into()),
                    source_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    destination_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
                    source_port: Some(Port::Single(80)),
                    destination_port: Some(Port::Single(443)),
                    if_input: Some(vec!["eth0".into()]),
                    if_output: None,
                    new_dest_ip: None,
                    new_source_port: None,
                    new_destination_port: None,
                    description: None,
                    reject_type: None,
                },
                Rule {
                    action: Some(Action::DropOutput),
                    protocol: Some("tcp".into()),
                    source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                    destination_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                    source_port: Some(Port::Single(53)),
                    destination_port: Some(Port::Single(53)),
                    if_input: None,
                    if_output: Some(vec!["eth1".into()]),
                    new_dest_ip: None,
                    new_source_port: None,
                    new_destination_port: None,
                    description: None,
                    reject_type: None,
                },
            ],
        };

        let result = config.get_single_ipv4_flow::<Tcpv4FlowVal>();

        let mut expected_map = StdHashMap::new();

        let key1 = Ipv4FlowKey {
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            src_port: 80,
            dest_ip: Ipv4Addr::new(192, 168, 1, 10),
            dest_port: 443,
        };
        let val1 = Ipv4FlowVal {
            action: Action::AllowInput as u8,
            new_dest_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            new_dest_port: 0,
            new_src_port: 0,
        };
        let mut ingress_map = StdHashMap::new();
        ingress_map.insert((key1, *ALLOW_PROTOCOLS.get("tcp").unwrap()), val1);
        expected_map.insert("eth0-ingress".into(), ingress_map);

        let key2 = Ipv4FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 53,
            dest_ip: Ipv4Addr::new(10, 0, 0, 2),
            dest_port: 53,
        };
        let val2 = Ipv4FlowVal {
            action: Action::DropOutput as u8,
            new_dest_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            new_dest_port: 0,
            new_src_port: 0,
        };
        let mut egress_map = StdHashMap::new();
        egress_map.insert((key2, *ALLOW_PROTOCOLS.get("tcp").unwrap()), val2);
        expected_map.insert("eth1-egress".into(), egress_map);

        assert_eq!(result, expected_map);
    }

    #[test]
    fn test_get_single_flow_with_multiple_rules_ignore_diff_type() {
        let config = Config {
            system_iface_ips: get_all_ip_and_ifaces(),

            ip_options: IpOpts {
                ipv4_enabled: true,
                ipv6_enabled: false,
            },
            interface_groups: None,
            default_policy: DefaultPolicy::default(),

            rules: vec![
                Rule {
                    action: Some(Action::AllowInput),
                    protocol: Some("udp".into()),
                    source_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    destination_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
                    source_port: Some(Port::Single(80)),
                    destination_port: Some(Port::Single(443)),
                    if_input: Some(vec!["eth0".into()]),
                    if_output: None,
                    new_dest_ip: None,
                    new_source_port: None,
                    new_destination_port: None,
                    description: None,
                    reject_type: None,
                },
                Rule {
                    action: Some(Action::DropOutput),
                    protocol: Some("tcp".into()),
                    source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                    destination_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                    source_port: Some(Port::Single(53)),
                    destination_port: Some(Port::Single(53)),
                    if_input: None,
                    if_output: Some(vec!["eth1".into()]),
                    new_dest_ip: None,
                    new_source_port: None,
                    new_destination_port: None,
                    description: None,
                    reject_type: None,
                },
            ],
        };
        //first rule should be ignored because it is udp
        let result = config.get_single_ipv4_flow::<Tcpv4FlowVal>();
        let mut expected_map = StdHashMap::new();

        let key2 = Ipv4FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 53,
            dest_ip: Ipv4Addr::new(10, 0, 0, 2),
            dest_port: 53,
        };
        let val2 = Ipv4FlowVal {
            action: Action::DropOutput as u8,
            new_dest_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            new_dest_port: 0,
            new_src_port: 0,
        };
        let mut egress_map = StdHashMap::new();
        egress_map.insert((key2, *ALLOW_PROTOCOLS.get("tcp").unwrap()), val2);
        expected_map.insert("eth1-egress".into(), egress_map);

        assert_eq!(result, expected_map);
    }
    // Sample configurations and flow values
    fn sample_config() -> Config {
        Config {
            system_iface_ips: get_all_ip_and_ifaces(),

            ip_options: IpOpts {
                ipv4_enabled: true,
                ipv6_enabled: false,
            },
            interface_groups: Some(IfaceGroup::default()),
            default_policy: DefaultPolicy::default(),

            rules: vec![
                // TCP Rule
                Rule {
                    action: Some(Action::AllowInput),
                    protocol: Some("tcp".into()),
                    source_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    destination_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
                    source_port: Some(Port::Single(80)),
                    destination_port: Some(Port::Single(443)),
                    if_input: Some(vec!["eth0".into()]),
                    if_output: None,
                    new_dest_ip: None,
                    new_source_port: None,
                    new_destination_port: None,
                    description: None,
                    reject_type: None,
                },
                // UDP Rule
                Rule {
                    action: Some(Action::AllowInput),
                    protocol: Some("udp".into()),
                    source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                    destination_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                    source_port: Some(Port::Single(1234)),
                    destination_port: Some(Port::Single(5678)),
                    if_input: Some(vec!["eth1".into()]),
                    if_output: None,
                    new_dest_ip: None,
                    new_source_port: None,
                    new_destination_port: None,
                    description: None,
                    reject_type: None,
                },
                // ICMP Rule
                Rule {
                    action: Some(Action::DropOutput),
                    protocol: Some("icmp".into()),
                    source_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))),
                    destination_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2))),
                    source_port: None,
                    destination_port: None,
                    if_input: None,
                    if_output: Some(vec!["eth2".into()]),
                    new_dest_ip: None,
                    new_source_port: None,
                    new_destination_port: None,
                    description: None,
                    reject_type: None,
                },
            ],
        }
    }

    #[test]
    fn test_tcp_flow_extraction() {
        let config = sample_config();
        let result: StdHashMap<String, StdHashMap<Ipv4FlowKey, Tcpv4FlowVal>> =
            config.extract_single_ipv4_flow();

        let mut inner_map = StdHashMap::new();
        inner_map.insert(
            Ipv4FlowKey {
                src_ip: Ipv4Addr::new(192, 168, 1, 1),
                src_port: 80,
                dest_ip: Ipv4Addr::new(192, 168, 1, 10),
                dest_port: 443,
            },
            Tcpv4FlowVal {
                val: Ipv4FlowVal {
                    action: Action::AllowInput as u8,
                    new_dest_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    new_src_port: 0,
                    new_dest_port: 0,
                },
            },
        );

        let mut expected = StdHashMap::new();
        expected.insert("eth0-ingress".into(), inner_map);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_udp_flow_extraction() {
        let config = sample_config();
        let result: StdHashMap<String, StdHashMap<Ipv4FlowKey, Udpv4FlowVal>> =
            config.extract_single_ipv4_flow();

        let mut inner_map = StdHashMap::new();

        inner_map.insert(
            Ipv4FlowKey {
                src_ip: Ipv4Addr::new(10, 0, 0, 1),
                src_port: 1234,
                dest_ip: Ipv4Addr::new(10, 0, 0, 2),
                dest_port: 5678,
            },
            Udpv4FlowVal {
                val: Ipv4FlowVal {
                    action: Action::AllowInput as u8,
                    new_dest_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    new_src_port: 0,
                    new_dest_port: 0,
                },
            },
        );

        let mut expected = StdHashMap::new();
        expected.insert("eth1-ingress".into(), inner_map);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_other_proto_flow_extraction() {
        let config = sample_config();
        let result: StdHashMap<String, StdHashMap<OtherProtov4Key, OtherProtov4Val>> =
            config.extract_single_ipv4_flow();

        let mut inner_map = StdHashMap::new();

        inner_map.insert(
            OtherProtov4Key {
                ipv4_flow_key: Ipv4FlowKey {
                    src_ip: Ipv4Addr::new(192, 168, 0, 1),
                    src_port: 0,
                    dest_ip: Ipv4Addr::new(192, 168, 0, 2),
                    dest_port: 0,
                },
                proto: Protocol::Icmp as u16,
            },
            OtherProtov4Val {
                ipv4_flow_key: Ipv4FlowVal {
                    action: Action::DropOutput as u8,
                    new_dest_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    new_src_port: 0,
                    new_dest_port: 0,
                },
                packet_count: 0,
                byte_count: 0,
                last_seen: 0,
            },
        );

        let mut expected = StdHashMap::new();
        expected.insert("eth2-egress".into(), inner_map);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_interface_groups_parsing() {
        // Define a TOML string representing the configuration.
        let toml_data = r#"
        [ip_options]
        ipv4_enabled = true
        ipv6_enabled = true
        [default_policy]
        input = "whitelist"
        output = "blacklist"
        [[interface_groups]]
        interface_group_1 = ["eth0", "eth1"]
        interface_group_2 = ["lo", "wlp0s3"]

        [[rules]]
        action = "allow-input"
        if_input = ["lo"]
        protocol = "tcp"
        source_ip = "any"
        destination_ip = "192.168.1.10"
        source_port = "any"
        destination_port = "[22, 1024]"
        description = "Allow SSH traffic from any source to 192.168.1.10"

        [[rules]]
        action = "allow-input"
        protocol = "icmp"
        if_input = ["lo"]
        source_ip = "any"
        destination_ip = "any"
        source_port = "any"
        destination_port = "any"
        description = "Allow all icmp packets"
        "#;

        // Deserialize the TOML string into a `Config` instance.
        let mut config = Config::from_string(toml_data).expect("Failed to deserialize TOML");
        config.validate_and_assign();
        if let Some(groups) = &config.interface_groups {
            assert!(
                (groups.interface_group_1.clone() == vec!["eth0".to_string(), "eth1".to_string()]
                    && groups.interface_group_2.clone()
                        == vec!["lo".to_string(), "wlp0s3".to_string()])
                    || (groups.interface_group_1 == vec!["lo".to_string(), "wlp0s3".to_string()]
                        && groups.interface_group_2
                            == vec!["eth0".to_string(), "eth1".to_string()])
            );
        }
        // Check if the deserialized `interface_groups` matches the expected value.
    }
    #[test]
    fn test_iface_group_parsing_with_dynamic_keys() {
        // Define a TOML string with dynamic group names.
        let toml_data = r#"
        [ip_options]
        ipv4_enabled = true
        ipv6_enabled = true
        [default_policy]
        input = "whitelist"
        output = "blacklist"
        [[interface_groups]]
        my_group_1 = ["eth0", "eth5"]

        [[rules]]
        action = "allow-input"
        if_input = ["lo"]
        protocol = "tcp"
        source_ip = "any"
        destination_ip = "192.168.1.10"
        source_port = "any"
        destination_port = "[22, 1024]"
        description = "Allow SSH traffic from any source to 192.168.1.10"

        [[rules]]
        action = "allow-input"
        protocol = "icmp"
        if_input = ["lo"]
        source_ip = "any"
        destination_ip = "any"
        source_port = "any"
        destination_port = "any"
        description = "Allow all icmp packets"
        "#;

        // Deserialize the TOML string into a `Config` instance.
        let mut config = Config::from_string(toml_data).expect("Failed to deserialize TOML");
        config.validate_and_assign();
        if let Some(groups) = &config.interface_groups {
            // assert_eq!(
            //     groups.interface_group_1,
            //     vec!["eth0".to_string(), "eth5".to_string()]
            // );
            // assert!(groups.interface_group_2.is_empty());
        }
    }

    #[test]
    #[should_panic]
    fn test_iface_group_parsing_with_more_than_max_group_limit() {
        // Define a TOML string with dynamic group names.
        let toml_data = r#"
        [ip_options]
        ipv4_enabled = true
        ipv6_enabled = true
        [default_policy]
        input = "whitelist"
        output = "blacklist"
        [[interface_groups]]
        my_group_1 = ["eth0", "eth5"]
        my_group_2 = ["eth1", "eth4"]
        my_group_3 = ["eth2", "eth3"]

        [[rules]]
        action = "allow-input"
        if_input = ["lo"]
        protocol = "tcp"
        source_ip = "any"
        destination_ip = "192.168.1.10"
        source_port = "any"
        destination_port = "[22, 1024]"
        description = "Allow SSH traffic from any source to 192.168.1.10"

        [[rules]]
        action = "allow-input"
        protocol = "icmp"
        if_input = ["lo"]
        source_ip = "any"
        destination_ip = "any"
        source_port = "any"
        destination_port = "any"
        description = "Allow all icmp packets"
        "#;

        // Deserialize the TOML string into a `Config` instance.
        let mut config = Config::from_string(toml_data).unwrap();
        config.validate_and_assign();
    }

    #[test]
    fn test_iface_group_parsing_with_same_group_name() {
        // Define a TOML string with dynamic group names.
        let toml_data = r#"
        [ip_options]
        ipv4_enabled = true
        ipv6_enabled = true
        [default_policy]
        input = "whitelist"
        output = "blacklist"
        [interface_groups]
        my_group_1 = ["eth0", "eth5"]
        my_group_1 = ["eth1", "eth4"]
      

        [[rules]]
        action = "allow-input"
        if_input = ["lo"]
        protocol = "tcp"
        source_ip = "any"
        destination_ip = "192.168.1.10"
        source_port = "any"
        destination_port = "[22, 1024]"
        description = "Allow SSH traffic from any source to 192.168.1.10"

        [[rules]]
        action = "allow-input"
        protocol = "icmp"
        if_input = ["lo"]
        source_ip = "any"
        destination_ip = "any"
        source_port = "any"
        destination_port = "any"
        description = "Allow all icmp packets"
        "#;

        // Deserialize the TOML string into a `Config` instance.
        let config = catch_unwind(|| Config::from_string(toml_data).expect("error"));

        // Ensure that it panics
        assert!(config.is_err(), "Expected panic but did not occur.");
    }

    #[test]
    fn test_iface_group_parsing_no_interfaces() {
        // Define a TOML string with dynamic group names.
        let toml_data = r#"
        [ip_options]
        ipv4_enabled = true
        ipv6_enabled = true
        [default_policy]
        input = "whitelist"
        output = "blacklist"
        [[rules]]
        action = "allow-input"
        if_input = ["lo"]
        protocol = "tcp"
        source_ip = "any"
        destination_ip = "192.168.1.10"
        source_port = "any"
        destination_port = "[22, 1024]"
        description = "Allow SSH traffic from any source to 192.168.1.10"

        [[rules]]
        action = "allow-input"
        protocol = "icmp"
        if_input = ["lo"]
        source_ip = "any"
        destination_ip = "any"
        source_port = "any"
        destination_port = "any"
        description = "Allow all icmp packets"
        "#;

        // Deserialize the TOML string into a `Config` instance.
        let mut config = Config::from_string(toml_data).expect("error");
        config.validate_and_assign();
        assert_eq!(config.interface_groups, None);
        // Ensure that it panics
    }

    #[test]
    #[should_panic]
    fn test_iface_group_parsing_same_item_in_different_groups() {
        // Define a TOML string with dynamic group names.
        let toml_data = r#"
        [ip_options]
        ipv4_enabled = true
        ipv6_enabled = true
        [default_policy]
        input = "whitelist"
        output = "blacklist"
        [[interface_groups]]
        my_group_1 = ["eth0", "eth5"]
        my_group_2 = ["eth1", "eth0"]
        [[rules]]
        action = "allow-input"
        if_input = ["lo"]
        protocol = "tcp"
        source_ip = "any"
        destination_ip = "192.168.1.10"
        source_port = "any"
        destination_port = "[22, 1024]"
        description = "Allow SSH traffic from any source to 192.168.1.10"

        [[rules]]
        action = "allow-input"
        protocol = "icmp"
        if_input = ["lo"]
        source_ip = "any"
        destination_ip = "any"
        source_port = "any"
        destination_port = "any"
        description = "Allow all icmp packets"
        "#;

        // Deserialize the TOML string into a `Config` instance.
        let mut config = Config::from_string(toml_data).unwrap();
        config.validate_and_assign();
    }

    #[test]
    fn test_iface_group_parsing_interface_bulk_assignment() {
        // Define a TOML string with dynamic group names.
        let toml_data = r#"
        [ip_options]
        ipv4_enabled = true
        ipv6_enabled = true
        [default_policy]
        input = "whitelist"
        output = "blacklist"
        [[interface_groups]]
        my_group_1 = ["eth0", "eth5"]
        my_group_2 = ["eth1", "eth2"]
        [[rules]]
        action = "allow-input"
        if_input = ["&my_group_1"]
        protocol = "tcp"
        source_ip = "any"
        destination_ip = "192.168.1.10"
        source_port = "any"
        destination_port = "[22, 1024]"
        description = "Allow SSH traffic from any source to 192.168.1.10"

        [[rules]]
        action = "allow-input"
        protocol = "icmp"
        if_input = ["lo"]
        source_ip = "any"
        destination_ip = "any"
        source_port = "any"
        destination_port = "any"
        description = "Allow all icmp packets"
        "#;

        // Deserialize the TOML string into a `Config` instance.
        let mut config = Config::from_string(toml_data).unwrap();
        config.validate_and_assign_interface_groups();
        if let Some(groups) = &config.interface_groups {
            assert!(
                (groups.interface_group_1.clone() == vec!["eth0".to_string(), "eth5".to_string()]
                    && groups.interface_group_2.clone()
                        == vec!["eth1".to_string(), "eth2".to_string()])
                    || (groups.interface_group_1 == vec!["eth1".to_string(), "eth2".to_string()]
                        && groups.interface_group_2
                            == vec!["eth0".to_string(), "eth5".to_string()])
            );
        }

        for rule in &config.rules {
            if let Some(ref input) = rule.if_input {
                if input.len() > 1 {
                    if config.interface_groups.as_ref().unwrap().interface_group_1
                        == vec!["eth0", "eth5"]
                    {
                        assert_eq!(
                            config.interface_groups.as_ref().unwrap().interface_group_1,
                            *input
                        );
                    } else {
                        assert_eq!(
                            config.interface_groups.as_ref().unwrap().interface_group_2,
                            *input
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_iface_group_non_grouped_interfaces() {
        // TOML configuration string
        let toml_str = r#"
            [ip_options]
            ipv4_enabled = true
            ipv6_enabled = true

            [default_policy]
            input = "whitelist"
            output = "blacklist"

            [[interface_groups]]
            interface_group_1 = ["eth0", "eth1"]

            [[rules]]
            if_input = ["&interface_group_1"]  # Use actual interfaces, not groups
            action = "allow-input"
            protocol = "tcp"
            source_ip = "any"
            source_port = "any"
            destination_port = "30"
            description = "interface group example"

            [[rules]]
            if_output = ["eth2"]  # Non-grouped interface
            action = "drop-output"
            protocol = "icmp"
            source_ip = "any"
            source_port = "any"
            destination_port = "50"
            description = "interface group example"

            [[rules]]
            action = "allow-input"
            if_input = ["&NOT_GROUPED_IFACES"]
            protocol = "tcp"
            source_ip = "any"
            destination_ip = "192.168.1.10"
            source_port = "any"
            destination_port = "[22, 1024]"
            description = "Allow SSH traffic from any source to 192.168.1.10"
        "#;

        // Parse the configuration
        let mut config = Config::from_string(toml_str).expect("Failed to parse configuration");

        //To Mock system interface IPs, we need to replace real ones with mocks
        config.system_iface_ips = StdHashMap::from([
            ("eth0".to_string(), vec!["192.168.1.1".parse().unwrap()]),
            ("eth1".to_string(), vec!["192.168.1.2".parse().unwrap()]),
            ("lo".to_string(), vec!["127.0.0.1".parse().unwrap()]),
            ("wlp0s3".to_string(), vec!["192.168.0.1".parse().unwrap()]),
            ("eth2".to_string(), vec!["192.168.2.1".parse().unwrap()]), // Non-grouped
        ]);

        // Call validate_and_assign to process the configuration
        config.validate_and_assign(); // Should not panic

        // Validate that interface groups and non-grouped interfaces are assigned correctly
        let iface_group: &mut IfaceGroup = config.interface_groups.as_mut().unwrap();
        iface_group.interface_not_grouped.sort();
        let mut expected_vec: Vec<String> =
            vec!["lo".to_string(), "wlp0s3".to_string(), "eth2".to_string()];
        expected_vec.sort();
        assert_eq!(iface_group.interface_not_grouped, expected_vec);

        for rule in config.rules {

            //  if rule.
        }
    }

    #[test]
    fn test_iface_extraction() {
        println!("interfaces and ips:{:?}", get_all_ip_and_ifaces());
    }
}
