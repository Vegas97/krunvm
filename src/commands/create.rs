// Copyright 2021 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Args;
use std::fs;
use std::io::Write;
#[cfg(target_os = "macos")]
use std::path::Path;
use std::process::Command;

use crate::utils::{
    generate_mac, get_buildah_args, mount_container, parse_mac, path_pairs_to_hash_map,
    port_pairs_to_hash_map, umount_container, BuildahCommand, PathPair, PortPair,
};
use crate::{KrunvmConfig, VmConfig, APP_NAME};

#[cfg(target_os = "macos")]
const KRUNVM_ROSETTA_FILE: &str = ".krunvm-rosetta";

/// Create a new microVM
#[derive(Args, Debug)]
pub struct CreateCmd {
    /// OCI image to use as template
    image: String,

    /// Assign a name to the VM
    #[arg(long)]
    name: Option<String>,

    /// Number of vCPUs
    #[arg(long)]
    cpus: Option<u32>,

    /// Amount of RAM in MiB
    #[arg(long)]
    mem: Option<u32>,

    /// DNS server to use in the microVM
    #[arg(long)]
    dns: Option<String>,

    /// Working directory inside the microVM
    #[arg(short, long, default_value = "")]
    workdir: String,

    /// Volume(s) in form "host_path:guest_path" to be exposed to the guest
    #[arg(short, long = "volume")]
    volumes: Vec<PathPair>,

    /// Port(s) in format "host_port:guest_port" to be exposed to the host
    #[arg(long = "port")]
    ports: Vec<PortPair>,

    /// Path to gvproxy unix socket (enables virtio-net networking).
    /// Mutually exclusive with --port (TSI networking).
    #[arg(long)]
    net: Option<String>,

    /// VM MAC address (format: xx:xx:xx:xx:xx:xx). Only valid with --net.
    /// When --net is specified without --mac, a random locally-administered
    /// unicast MAC is generated. This matches krunvm's UX pattern of sensible
    /// defaults (like auto-naming VMs and defaulting CPUs/RAM/DNS).
    /// krunkit requires an explicit MAC, but krunvm targets a higher-level
    /// audience where "just works" matters more than explicit control.
    /// Users who need deterministic MACs (e.g., static DHCP leases in
    /// gvproxy) can still pass --mac explicitly.
    #[arg(long)]
    mac: Option<String>,

    /// Create a x86_64 microVM even on an Aarch64 host
    #[arg(short, long)]
    #[cfg(target_os = "macos")]
    x86: bool,
}

impl CreateCmd {
    pub fn run(self, cfg: &mut KrunvmConfig) {
        #[allow(unused_mut)]
        let mut cpus = self.cpus.unwrap_or(cfg.default_cpus);
        let mem = self.mem.unwrap_or(cfg.default_mem);
        let dns = self.dns.unwrap_or_else(|| cfg.default_dns.clone());
        let workdir = self.workdir;
        let mapped_volumes = path_pairs_to_hash_map(self.volumes);
        let mapped_ports = port_pairs_to_hash_map(self.ports);
        let image = self.image;
        let name = self.name;

        // Validate --net / --port / --mac interactions
        if self.mac.is_some() && self.net.is_none() {
            println!("--mac requires --net");
            std::process::exit(-1);
        }
        if self.net.is_some() && !mapped_ports.is_empty() {
            println!("--net and --port are mutually exclusive");
            std::process::exit(-1);
        }

        // Resolve MAC: use provided value or generate a random one
        let (net_socket, mac_address) = if let Some(ref net_path) = self.net {
            let net_path = if std::path::Path::new(net_path).is_absolute() {
                net_path.clone()
            } else {
                std::env::current_dir()
                    .unwrap_or_else(|e| {
                        println!("Error resolving current directory: {}", e);
                        std::process::exit(-1);
                    })
                    .join(net_path)
                    .to_string_lossy()
                    .into_owned()
            };
            let mac = match self.mac {
                Some(ref m) => {
                    let bytes = parse_mac(m).unwrap_or_else(|e| {
                        println!("{}", e);
                        std::process::exit(-1);
                    });
                    if bytes == [0; 6] || bytes == [0xff; 6] || (bytes[0] & 0x01) != 0 {
                        println!(
                            "Invalid MAC address '{}': expected a unicast, non-zero, non-broadcast address",
                            m
                        );
                        std::process::exit(-1);
                    }
                    m.clone()
                }
                None => generate_mac(),
            };
            (Some(net_path), Some(mac))
        } else {
            (None, None)
        };

        if let Some(ref name) = name {
            if name.is_empty() {
                println!("Invalid name for VM");
                std::process::exit(-1);
            }
            if cfg.vmconfig_map.contains_key(name) {
                println!("A VM with this name already exists");
                std::process::exit(-1);
            }
        }

        let mut args = get_buildah_args(cfg, BuildahCommand::From);

        #[cfg(target_os = "macos")]
        let force_x86 = self.x86;

        #[cfg(target_os = "macos")]
        if force_x86 {
            let home = match std::env::var("HOME") {
                Err(e) => {
                    println!("Error reading \"HOME\" enviroment variable: {}", e);
                    std::process::exit(-1);
                }
                Ok(home) => home,
            };

            let path = format!("{}/{}", home, KRUNVM_ROSETTA_FILE);
            if !Path::new(&path).is_file() {
                println!(
                    "
To use Rosetta for Linux you need to create the file...

{}

...with the contents that the \"rosetta\" binary expects to be served from
its specific ioctl.

For more information, please refer to this post:
https://threedots.ovh/blog/2022/06/quick-look-at-rosetta-on-linux/
",
                    path
                );
                std::process::exit(-1);
            }

            if cpus != 1 {
                println!("x86 microVMs on Aarch64 are restricted to 1 CPU");
                cpus = 1;
            }
            args.push("--arch".to_string());
            args.push("x86_64".to_string());
        }

        args.push(image.to_string());

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

        let container = std::str::from_utf8(&output.stdout).unwrap().trim();
        let name = if let Some(name) = name {
            name.to_string()
        } else {
            container.to_string()
        };
        let vmcfg = VmConfig {
            name: name.clone(),
            cpus,
            mem,
            dns: dns.to_string(),
            container: container.to_string(),
            workdir: workdir.to_string(),
            mapped_volumes,
            mapped_ports,
            net_socket,
            mac_address,
        };

        let rootfs = mount_container(cfg, &vmcfg).unwrap();
        export_container_config(cfg, &rootfs, &image).unwrap();
        fix_resolv_conf(&rootfs, &dns).unwrap();
        #[cfg(target_os = "macos")]
        if force_x86 {
            _ = fs::create_dir(format!("{}/.rosetta", rootfs));
        }
        umount_container(cfg, &vmcfg).unwrap();

        cfg.vmconfig_map.insert(name.clone(), vmcfg);
        confy::store(APP_NAME, cfg).unwrap();

        println!("microVM created with name: {}", name);
    }
}

fn fix_resolv_conf(rootfs: &str, dns: &str) -> Result<(), std::io::Error> {
    let resolvconf_dir = format!("{}/etc/", rootfs);
    fs::create_dir_all(resolvconf_dir)?;
    let resolvconf = format!("{}/etc/resolv.conf", rootfs);
    let mut file = fs::File::create(resolvconf)?;
    file.write_all(b"options use-vc\nnameserver ")?;
    file.write_all(dns.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

fn export_container_config(
    cfg: &KrunvmConfig,
    rootfs: &str,
    image: &str,
) -> Result<(), std::io::Error> {
    let mut args = get_buildah_args(cfg, BuildahCommand::Inspect);
    args.push(image.to_string());

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

    let mut file = fs::File::create(format!("{}/.krun_config.json", rootfs))?;
    file.write_all(&output.stdout)?;

    Ok(())
}
