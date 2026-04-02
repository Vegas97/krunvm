// Copyright 2021 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;

use crate::{KrunvmConfig, VmConfig, APP_NAME};

/// Parse a MAC address string "xx:xx:xx:xx:xx:xx" into 6 bytes.
pub fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("Invalid MAC address '{}': expected 6 colon-separated hex pairs", s));
    }
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16)
            .map_err(|_| format!("Invalid MAC address '{}': '{}' is not a valid hex byte", s, part))?;
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
    f.read_exact(&mut bytes).expect("Failed to read from /dev/urandom");
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
}
