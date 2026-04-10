// Copyright 2021 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;

use crate::{KrunvmConfig, VmConfig, APP_NAME};

/// Linux capabilities that can be dropped inside the guest VM.
/// Names follow the kernel convention (lowercase, no "cap_" prefix stored).
const VALID_CAPABILITIES: &[&str] = &[
    "audit_control",
    "audit_read",
    "audit_write",
    "block_suspend",
    "bpf",
    "checkpoint_restore",
    "chown",
    "dac_override",
    "dac_read_search",
    "fowner",
    "fsetid",
    "ipc_lock",
    "ipc_owner",
    "kill",
    "lease",
    "linux_immutable",
    "mac_admin",
    "mac_override",
    "mknod",
    "net_admin",
    "net_bind_service",
    "net_broadcast",
    "net_raw",
    "perfmon",
    "setfcap",
    "setgid",
    "setpcap",
    "setuid",
    "sys_admin",
    "sys_boot",
    "sys_chroot",
    "sys_module",
    "sys_nice",
    "sys_pacct",
    "sys_ptrace",
    "sys_rawio",
    "sys_resource",
    "sys_time",
    "sys_tty_config",
    "syslog",
    "wake_alarm",
];

/// Normalize and validate a capability name.
/// Accepts "CAP_NET_RAW", "cap_net_raw", or "net_raw" — returns "net_raw".
pub fn validate_capability(name: &str) -> Result<String, String> {
    let normalized = name.to_lowercase();
    let stripped = normalized.strip_prefix("cap_").unwrap_or(&normalized);
    if VALID_CAPABILITIES.contains(&stripped) {
        Ok(stripped.to_string())
    } else {
        Err(format!(
            "Unknown capability '{}'. Valid capabilities: {}",
            name,
            VALID_CAPABILITIES
                .iter()
                .map(|c| format!("cap_{}", c))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

/// Escape a string for safe interpolation into a POSIX shell script.
/// Wraps in single quotes; embedded single quotes become '\\'' (end quote,
/// escaped literal quote, restart quote).
pub fn shell_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Parse a MAC address string "xx:xx:xx:xx:xx:xx" into 6 bytes.
pub fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!(
            "Invalid MAC address '{}': expected 6 colon-separated hex pairs",
            s
        ));
    }
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err(format!(
                "Invalid MAC address '{}': '{}' must be exactly two hex digits",
                s, part
            ));
        }
        bytes[i] = u8::from_str_radix(part, 16).map_err(|_| {
            format!(
                "Invalid MAC address '{}': '{}' is not a valid hex byte",
                s, part
            )
        })?;
    }
    Ok(bytes)
}

/// Generate a random locally-administered unicast MAC address.
///
/// When --net is specified without --mac, a random MAC is generated.
/// This matches krunvm's UX pattern of sensible defaults (like auto-naming
/// VMs and defaulting CPUs/RAM/DNS). krunkit requires an explicit MAC,
/// but krunvm targets a higher-level audience where "just works" matters
/// more than explicit control. Users who need deterministic MACs (e.g.,
/// static DHCP leases in gvproxy) can still pass --mac explicitly.
pub fn generate_mac() -> String {
    let mut bytes = [0u8; 6];
    let mut f = File::open("/dev/urandom").expect("Failed to open /dev/urandom");
    f.read_exact(&mut bytes)
        .expect("Failed to read from /dev/urandom");
    // Set locally-administered bit (bit 1) and clear multicast bit (bit 0)
    bytes[0] = (bytes[0] | 0x02) & 0xfe;
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

pub enum BuildahCommand {
    From,
    Inspect,
    Mount,
    Unmount,
    Remove,
}

#[cfg(target_os = "linux")]
pub fn get_buildah_args(_cfg: &KrunvmConfig, cmd: BuildahCommand) -> Vec<String> {
    match cmd {
        BuildahCommand::From => vec!["from".to_string()],
        BuildahCommand::Inspect => vec!["inspect".to_string()],
        BuildahCommand::Mount => vec!["mount".to_string()],
        BuildahCommand::Unmount => vec!["umount".to_string()],
        BuildahCommand::Remove => vec!["rm".to_string()],
    }
}

#[cfg(target_os = "macos")]
pub fn get_buildah_args(cfg: &KrunvmConfig, cmd: BuildahCommand) -> Vec<String> {
    let mut hbpath = std::env::current_exe().unwrap();
    hbpath.pop();
    hbpath.pop();
    let hbpath = hbpath.as_path().display();
    let policy_json = format!("{}/etc/containers/policy.json", hbpath);
    let registries_json = format!("{}/etc/containers/registries.conf", hbpath);
    let storage_root = format!("{}/root", cfg.storage_volume);
    let storage_runroot = format!("{}/runroot", cfg.storage_volume);

    let mut args = vec![
        "--root".to_string(),
        storage_root,
        "--runroot".to_string(),
        storage_runroot,
    ];

    match cmd {
        BuildahCommand::From => {
            args.push("--signature-policy".to_string());
            args.push(policy_json);
            args.push("--registries-conf".to_string());
            args.push(registries_json);

            args.push("from".to_string());
            args.push("--os".to_string());
            args.push("linux".to_string());
        }
        BuildahCommand::Inspect => {
            args.push("inspect".to_string());
        }
        BuildahCommand::Mount => {
            args.push("mount".to_string());
        }
        BuildahCommand::Unmount => {
            args.push("umount".to_string());
        }
        BuildahCommand::Remove => {
            args.push("rm".to_string());
        }
    }
    args
}

#[derive(Debug, Clone)]
pub struct PortPair {
    pub host_port: String,
    pub guest_port: String,
}

pub fn port_pairs_to_hash_map(
    port_pairs: impl IntoIterator<Item = PortPair>,
) -> HashMap<String, String> {
    port_pairs
        .into_iter()
        .map(|pair: PortPair| (pair.host_port, pair.guest_port))
        .collect()
}

impl FromStr for PortPair {
    type Err = &'static str;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let vtuple: Vec<&str> = input.split(':').collect();
        if vtuple.len() != 2 {
            return Err("Too many ':' separators");
        }
        let host_port: u16 = match vtuple[0].parse() {
            Ok(p) => p,
            Err(_) => {
                return Err("Invalid host port");
            }
        };
        let guest_port: u16 = match vtuple[1].parse() {
            Ok(p) => p,
            Err(_) => {
                return Err("Invalid guest port");
            }
        };
        Ok(PortPair {
            host_port: host_port.to_string(),
            guest_port: guest_port.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PathPair {
    pub host_path: String,
    pub guest_path: String,
}

pub fn path_pairs_to_hash_map(
    volume_pairs: impl IntoIterator<Item = PathPair>,
) -> HashMap<String, String> {
    volume_pairs
        .into_iter()
        .map(|pair: PathPair| (pair.host_path, pair.guest_path))
        .collect()
}

impl FromStr for PathPair {
    type Err = &'static str;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let vtuple: Vec<&str> = input.split(':').collect();
        if vtuple.len() != 2 {
            return Err("Too many ':' separators");
        }

        let host_path = Path::new(vtuple[0]);
        if !host_path.is_absolute() {
            return Err("Invalid volume, host_path is not an absolute path");
        }
        if !host_path.exists() {
            return Err("Invalid volume, host_path does not exists");
        }
        let guest_path = Path::new(vtuple[1]);
        if !guest_path.is_absolute() {
            return Err("Invalid volume, guest_path is not an absolute path");
        }
        if guest_path.components().count() != 2 {
            return Err(
                "Invalid volume, only single direct root children are supported as guest_path",
            );
        }
        Ok(Self {
            host_path: vtuple[0].to_string(),
            guest_path: vtuple[1].to_string(),
        })
    }
}

#[cfg(target_os = "macos")]
fn fix_root_mode(rootfs: &str) {
    let mut args = vec!["-w", "user.containers.override_stat", "0:0:0555"];
    args.push(rootfs);

    let output = match Command::new("xattr")
        .args(&args)
        .stderr(std::process::Stdio::inherit())
        .output()
    {
        Ok(output) => output,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                println!("{} requires xattr to manage the OCI images, and it wasn't found on this system.", APP_NAME);
            } else {
                println!("Error executing xattr: {}", err);
            }
            std::process::exit(-1);
        }
    };

    let exit_code = output.status.code().unwrap_or(-1);
    if exit_code != 0 {
        println!("xattr returned an error: {}", exit_code);
        std::process::exit(-1);
    }
}

#[allow(unused_variables)]
pub fn mount_container(cfg: &KrunvmConfig, vmcfg: &VmConfig) -> Result<String, std::io::Error> {
    let mut args = get_buildah_args(cfg, BuildahCommand::Mount);
    args.push(vmcfg.container.clone());

    let output = match Command::new("buildah")
        .args(&args)
        .stderr(std::process::Stdio::inherit())
        .output()
    {
        Ok(output) => output,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                println!("{} requires buildah to manage the OCI images, and it wasn't found on this system.", APP_NAME);
            } else {
                println!("Error executing buildah: {}", err);
            }
            std::process::exit(-1);
        }
    };

    let exit_code = output.status.code().unwrap_or(-1);
    if exit_code != 0 {
        println!(
            "buildah returned an error: {}",
            std::str::from_utf8(&output.stdout).unwrap()
        );
        std::process::exit(-1);
    }

    let rootfs = std::str::from_utf8(&output.stdout).unwrap().trim();

    #[cfg(target_os = "macos")]
    fix_root_mode(rootfs);

    Ok(rootfs.to_string())
}

#[allow(unused_variables)]
pub fn umount_container(cfg: &KrunvmConfig, vmcfg: &VmConfig) -> Result<(), std::io::Error> {
    let mut args = get_buildah_args(cfg, BuildahCommand::Unmount);
    args.push(vmcfg.container.clone());

    let output = match Command::new("buildah")
        .args(&args)
        .stderr(std::process::Stdio::inherit())
        .output()
    {
        Ok(output) => output,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                println!("{} requires buildah to manage the OCI images, and it wasn't found on this system.", APP_NAME);
            } else {
                println!("Error executing buildah: {}", err);
            }
            std::process::exit(-1);
        }
    };

    let exit_code = output.status.code().unwrap_or(-1);
    if exit_code != 0 {
        println!(
            "buildah returned an error: {}",
            std::str::from_utf8(&output.stdout).unwrap()
        );
        std::process::exit(-1);
    }

    Ok(())
}

#[allow(unused_variables)]
pub fn remove_container(cfg: &KrunvmConfig, vmcfg: &VmConfig) -> Result<(), std::io::Error> {
    let mut args = get_buildah_args(cfg, BuildahCommand::Remove);
    args.push(vmcfg.container.clone());

    let output = match Command::new("buildah")
        .args(&args)
        .stderr(std::process::Stdio::inherit())
        .output()
    {
        Ok(output) => output,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                println!("{} requires buildah to manage the OCI images, and it wasn't found on this system.", APP_NAME);
            } else {
                println!("Error executing buildah: {}", err);
            }
            std::process::exit(-1);
        }
    };

    let exit_code = output.status.code().unwrap_or(-1);
    if exit_code != 0 {
        println!(
            "buildah returned an error: {}",
            std::str::from_utf8(&output.stdout).unwrap()
        );
        std::process::exit(-1);
    }

    Ok(())
}

// === Balloon utilities ===

/// Validate balloon target against memory size.
/// Returns Ok(balloon_mb) or Err with a human-readable message.
pub fn validate_balloon(balloon_mb: u32, mem_mb: u32) -> Result<u32, String> {
    if balloon_mb >= mem_mb {
        return Err(format!(
            "--balloon ({} MiB) must be less than --mem ({} MiB)",
            balloon_mb, mem_mb
        ));
    }
    if balloon_mb < 32 {
        return Err(format!(
            "--balloon ({} MiB) must be at least 32 MiB (boot may fail below this)",
            balloon_mb
        ));
    }
    Ok(balloon_mb)
}

/// Calculate the balloon initial target in 4KB pages.
/// The balloon inflates (mem - balloon) MiB worth of pages so the VM
/// starts with only `balloon_mb` resident.
pub fn balloon_pages(mem_mb: u32, balloon_mb: u32) -> u32 {
    (mem_mb - balloon_mb) * 256
}

/// Derive the default control socket path for a VM.
pub fn control_socket_path(vm_name: &str) -> String {
    format!("/tmp/krunvm-{}.sock", vm_name)
}

/// Format a balloon_set JSON command.
pub fn balloon_set_cmd(target_mib: u32) -> String {
    format!("{{\"cmd\":\"balloon_set\",\"target_mib\":{}}}", target_mib)
}

/// Format a balloon_stats JSON command.
pub fn balloon_stats_cmd() -> String {
    "{\"cmd\":\"balloon_stats\"}".to_string()
}

/// Parse a balloon_stats JSON response into (actual, target, free) in MiB.
/// Returns Err with the error string if the response indicates failure.
pub fn parse_balloon_stats(response: &str) -> Result<(u64, u64, u64), String> {
    let val: serde_json::Value =
        serde_json::from_str(response).map_err(|e| format!("Failed to parse response: {}", e))?;
    if val.get("ok") != Some(&serde_json::Value::Bool(true)) {
        let err = val["error"].as_str().unwrap_or("unknown error");
        return Err(err.to_string());
    }
    let actual = val["actual_mib"].as_u64().unwrap_or(0);
    let target = val["target_mib"].as_u64().unwrap_or(0);
    let free = val["free_mib"].as_u64().unwrap_or(0);
    Ok((actual, target, free))
}

#[cfg(test)]
mod tests {
    use super::*;

    // === parse_mac ===

    #[test]
    fn parse_mac_valid_lowercase() {
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    fn parse_mac_valid_all_zeros() {
        assert_eq!(parse_mac("00:00:00:00:00:00").unwrap(), [0; 6]);
    }

    #[test]
    fn parse_mac_valid_uppercase() {
        assert_eq!(
            parse_mac("AA:BB:CC:DD:EE:FF").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    fn parse_mac_invalid_garbage() {
        let err = parse_mac("ZZZZ").unwrap_err();
        assert!(err.contains("expected 6"));
    }

    #[test]
    fn parse_mac_too_few_pairs() {
        let err = parse_mac("aa:bb:cc").unwrap_err();
        assert!(err.contains("expected 6"));
    }

    #[test]
    fn parse_mac_invalid_hex_byte() {
        let err = parse_mac("gg:bb:cc:dd:ee:ff").unwrap_err();
        assert!(err.contains("'gg'"));
    }

    #[test]
    fn parse_mac_too_many_pairs() {
        let err = parse_mac("aa:bb:cc:dd:ee:ff:00").unwrap_err();
        assert!(err.contains("expected 6"));
    }

    // === generate_mac ===

    #[test]
    fn generate_mac_format() {
        let mac = generate_mac();
        assert_eq!(mac.len(), 17);
        assert_eq!(mac.matches(':').count(), 5);
    }

    #[test]
    fn generate_mac_locally_administered_bit() {
        let mac = generate_mac();
        let first_byte = u8::from_str_radix(&mac[..2], 16).unwrap();
        assert_eq!(first_byte & 0x02, 0x02);
    }

    #[test]
    fn generate_mac_unicast_bit() {
        let mac = generate_mac();
        let first_byte = u8::from_str_radix(&mac[..2], 16).unwrap();
        assert_eq!(first_byte & 0x01, 0x00);
    }

    #[test]
    fn generate_mac_roundtrip() {
        let mac = generate_mac();
        assert!(parse_mac(&mac).is_ok());
    }

    // === PortPair::from_str ===

    #[test]
    fn port_pair_valid() {
        let pair: PortPair = "8080:80".parse().unwrap();
        assert_eq!(pair.host_port, "8080");
        assert_eq!(pair.guest_port, "80");
    }

    #[test]
    fn port_pair_invalid_host() {
        assert!("abc:80".parse::<PortPair>().is_err());
    }

    #[test]
    fn port_pair_too_many_separators() {
        assert!("80:80:80".parse::<PortPair>().is_err());
    }

    // === PathPair::from_str ===

    #[test]
    fn path_pair_valid() {
        let pair: PathPair = "/tmp:/guest".parse().unwrap();
        assert_eq!(pair.host_path, "/tmp");
        assert_eq!(pair.guest_path, "/guest");
    }

    #[test]
    fn path_pair_relative_host() {
        let err = "relative:/guest".parse::<PathPair>().unwrap_err();
        assert!(err.contains("not an absolute"));
    }

    #[test]
    fn path_pair_guest_too_deep() {
        let err = "/tmp:/a/b/c".parse::<PathPair>().unwrap_err();
        assert!(err.contains("single direct root"));
    }

    // === validate_capability ===

    #[test]
    fn validate_cap_uppercase_with_prefix() {
        assert_eq!(validate_capability("CAP_NET_RAW").unwrap(), "net_raw");
    }

    #[test]
    fn validate_cap_lowercase_with_prefix() {
        assert_eq!(validate_capability("cap_sys_admin").unwrap(), "sys_admin");
    }

    #[test]
    fn validate_cap_without_prefix() {
        assert_eq!(validate_capability("sys_ptrace").unwrap(), "sys_ptrace");
    }

    #[test]
    fn validate_cap_mixed_case() {
        assert_eq!(validate_capability("Cap_Net_Raw").unwrap(), "net_raw");
    }

    #[test]
    fn validate_cap_unknown() {
        let err = validate_capability("CAP_DOES_NOT_EXIST").unwrap_err();
        assert!(err.contains("Unknown capability"));
    }

    #[test]
    fn validate_cap_empty() {
        assert!(validate_capability("").is_err());
    }

    // === validate_balloon ===

    #[test]
    fn validate_balloon_valid() {
        assert_eq!(validate_balloon(64, 192).unwrap(), 64);
    }

    #[test]
    fn validate_balloon_equal_to_mem() {
        let err = validate_balloon(192, 192).unwrap_err();
        assert!(err.contains("must be less than"));
    }

    #[test]
    fn validate_balloon_exceeds_mem() {
        let err = validate_balloon(256, 192).unwrap_err();
        assert!(err.contains("must be less than"));
    }

    #[test]
    fn validate_balloon_below_minimum() {
        let err = validate_balloon(16, 192).unwrap_err();
        assert!(err.contains("at least 32 MiB"));
    }

    #[test]
    fn validate_balloon_exact_minimum() {
        assert_eq!(validate_balloon(32, 192).unwrap(), 32);
    }

    #[test]
    fn validate_balloon_one_above_minimum() {
        assert_eq!(validate_balloon(33, 192).unwrap(), 33);
    }

    #[test]
    fn validate_balloon_one_below_mem() {
        assert_eq!(validate_balloon(191, 192).unwrap(), 191);
    }

    // === balloon_pages ===

    #[test]
    fn balloon_pages_standard() {
        // 192 - 64 = 128 MiB inflated, 128 * 256 = 32768 pages
        assert_eq!(balloon_pages(192, 64), 32768);
    }

    #[test]
    fn balloon_pages_minimal_inflation() {
        // 192 - 191 = 1 MiB inflated, 1 * 256 = 256 pages
        assert_eq!(balloon_pages(192, 191), 256);
    }

    #[test]
    fn balloon_pages_large_inflation() {
        // 1024 - 32 = 992 MiB inflated, 992 * 256 = 253952 pages
        assert_eq!(balloon_pages(1024, 32), 253952);
    }

    // === control_socket_path ===

    #[test]
    fn control_socket_path_format() {
        assert_eq!(
            control_socket_path("my-vm"),
            "/tmp/krunvm-my-vm.sock"
        );
    }

    #[test]
    fn control_socket_path_with_special_chars() {
        assert_eq!(
            control_socket_path("test_vm-123"),
            "/tmp/krunvm-test_vm-123.sock"
        );
    }

    // === balloon JSON commands ===

    #[test]
    fn balloon_set_cmd_format() {
        let cmd = balloon_set_cmd(128);
        let val: serde_json::Value = serde_json::from_str(&cmd).unwrap();
        assert_eq!(val["cmd"], "balloon_set");
        assert_eq!(val["target_mib"], 128);
    }

    #[test]
    fn balloon_stats_cmd_format() {
        let cmd = balloon_stats_cmd();
        let val: serde_json::Value = serde_json::from_str(&cmd).unwrap();
        assert_eq!(val["cmd"], "balloon_stats");
    }

    // === parse_balloon_stats ===

    #[test]
    fn parse_balloon_stats_success() {
        let response = r#"{"ok":true,"actual_mib":64,"target_mib":128,"free_mib":12}"#;
        let (actual, target, free) = parse_balloon_stats(response).unwrap();
        assert_eq!(actual, 64);
        assert_eq!(target, 128);
        assert_eq!(free, 12);
    }

    #[test]
    fn parse_balloon_stats_zero_free() {
        let response = r#"{"ok":true,"actual_mib":64,"target_mib":128,"free_mib":0}"#;
        let (actual, target, free) = parse_balloon_stats(response).unwrap();
        assert_eq!(actual, 64);
        assert_eq!(target, 128);
        assert_eq!(free, 0);
    }

    #[test]
    fn parse_balloon_stats_missing_fields_default_zero() {
        let response = r#"{"ok":true}"#;
        let (actual, target, free) = parse_balloon_stats(response).unwrap();
        assert_eq!(actual, 0);
        assert_eq!(target, 0);
        assert_eq!(free, 0);
    }

    #[test]
    fn parse_balloon_stats_error_response() {
        let response = r#"{"ok":false,"error":"balloon device not configured"}"#;
        let err = parse_balloon_stats(response).unwrap_err();
        assert_eq!(err, "balloon device not configured");
    }

    #[test]
    fn parse_balloon_stats_invalid_json() {
        let err = parse_balloon_stats("not json").unwrap_err();
        assert!(err.contains("Failed to parse"));
    }

    // === parse_mac: reject non-canonical octets ===

    #[test]
    fn parse_mac_rejects_single_digit_octets() {
        assert!(parse_mac("1:2:3:4:5:6").is_err());
    }

    #[test]
    fn parse_mac_rejects_non_canonical_lowercase() {
        assert!(parse_mac("a:b:c:d:e:f").is_err());
    }

    #[test]
    fn parse_mac_accepts_canonical_zero_padded() {
        assert_eq!(
            parse_mac("01:02:03:04:05:06").unwrap(),
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
        );
    }

    #[test]
    fn parse_mac_rejects_three_digit_octet() {
        assert!(parse_mac("001:02:03:04:05:06").is_err());
    }

    // === shell_escape ===

    #[test]
    fn shell_escape_simple_path() {
        assert_eq!(shell_escape("/usr/local/bin"), "'/usr/local/bin'");
    }

    #[test]
    fn shell_escape_path_with_spaces() {
        assert_eq!(shell_escape("/my path/dir"), "'/my path/dir'");
    }

    #[test]
    fn shell_escape_path_with_single_quote() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn shell_escape_path_with_double_quote() {
        assert_eq!(shell_escape("say \"hello\""), "'say \"hello\"'");
    }

    #[test]
    fn shell_escape_path_with_dollar() {
        assert_eq!(shell_escape("/home/$USER"), "'/home/$USER'");
    }

    #[test]
    fn shell_escape_path_with_backtick() {
        assert_eq!(shell_escape("/tmp/`whoami`"), "'/tmp/`whoami`'");
    }

    #[test]
    fn shell_escape_path_with_newline() {
        assert_eq!(shell_escape("/tmp/a\nb"), "'/tmp/a\nb'");
    }

    #[test]
    fn shell_escape_empty_string() {
        assert_eq!(shell_escape(""), "''");
    }

    // === control_socket: conditional on balloon ===

    #[test]
    fn control_socket_none_without_balloon() {
        let balloon: Option<u32> = None;
        let socket = balloon.map(|_| control_socket_path("test-vm"));
        assert!(socket.is_none());
    }

    #[test]
    fn control_socket_some_with_balloon() {
        let balloon: Option<u32> = Some(64);
        let socket = balloon.map(|_| control_socket_path("test-vm"));
        assert_eq!(socket, Some("/tmp/krunvm-test-vm.sock".to_string()));
    }
}
