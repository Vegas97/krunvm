// Copyright 2021 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Args;
use std::collections::HashMap;

use crate::utils::{
    path_pairs_to_hash_map, port_pairs_to_hash_map, validate_capability, PathPair, PortPair,
};
use crate::{KrunvmConfig, APP_NAME};

use super::list::printvm;

/// Change the configuration of a microVM
#[derive(Args, Debug)]
pub struct ChangeVmCmd {
    /// Name of the VM to be modified
    name: String,

    /// Assign a new name to the VM
    #[arg(long)]
    new_name: Option<String>,

    /// Number of vCPUs
    #[arg(long)]
    cpus: Option<u32>,

    /// Amount of RAM in MiB
    #[arg(long)]
    mem: Option<u32>,

    /// Working directory inside the microVM
    #[arg(short, long)]
    workdir: Option<String>,

    /// Remove all volume mappings
    #[arg(long)]
    remove_volumes: bool,

    /// Volume(s) in form "host_path:guest_path" to be exposed to the guest
    #[arg(short, long = "volume")]
    volumes: Vec<PathPair>,

    /// Remove all port mappings
    #[arg(long)]
    remove_ports: bool,

    /// Port(s) in format "host_port:guest_port" to be exposed to the host
    #[arg(long = "port")]
    ports: Vec<PortPair>,

    /// Mount the root filesystem as read-only
    #[arg(long)]
    rootfs_ro: bool,

    /// Remove read-only rootfs setting
    #[arg(long)]
    remove_rootfs_ro: bool,

    /// Remove all capability drop rules
    #[arg(long)]
    remove_cap_drop: bool,

    /// Linux capabilities to drop inside the guest VM
    #[arg(long = "cap-drop")]
    cap_drop: Vec<String>,
}

impl ChangeVmCmd {
    pub fn run(self, cfg: &mut KrunvmConfig) {
        let mut cfg_changed = false;

        let vmcfg = if let Some(new_name) = &self.new_name {
            if cfg.vmconfig_map.contains_key(new_name) {
                println!("A VM with name {} already exists", new_name);
                std::process::exit(-1);
            }

            let mut vmcfg = match cfg.vmconfig_map.remove(&self.name) {
                None => {
                    println!("No VM found with name {}", &self.name);
                    std::process::exit(-1);
                }
                Some(vmcfg) => vmcfg,
            };

            cfg_changed = true;
            let name = new_name.to_string();
            vmcfg.name = name.clone();
            cfg.vmconfig_map.insert(name.clone(), vmcfg);
            cfg.vmconfig_map.get_mut(&name).unwrap()
        } else {
            match cfg.vmconfig_map.get_mut(&self.name) {
                None => {
                    println!("No VM found with name {}", self.name);
                    std::process::exit(-1);
                }
                Some(vmcfg) => vmcfg,
            }
        };

        if let Some(cpus) = self.cpus {
            if cpus > 8 {
                println!("Error: the maximum number of CPUs supported is 8");
            } else {
                vmcfg.cpus = cpus;
                cfg_changed = true;
            }
        }

        if let Some(mem) = self.mem {
            if mem > 16384 {
                println!("Error: the maximum amount of RAM supported is 16384 MiB");
            } else {
                vmcfg.mem = mem;
                cfg_changed = true;
            }
        }

        if self.remove_volumes {
            vmcfg.mapped_volumes = HashMap::new();
            cfg_changed = true;
        } else {
            let mapped_volumes = path_pairs_to_hash_map(self.volumes);

            if !mapped_volumes.is_empty() {
                vmcfg.mapped_volumes = mapped_volumes;
                cfg_changed = true;
            }
        }
        // TODO: don't just silently ignore --volume args when --remove_volumes is specified

        if self.remove_ports {
            vmcfg.mapped_ports = HashMap::new();
            cfg_changed = true;
        } else {
            let mapped_ports = port_pairs_to_hash_map(self.ports);

            if !mapped_ports.is_empty() {
                vmcfg.mapped_ports = mapped_ports;
                cfg_changed = true;
            }
        }
        // TODO: don't just silently ignore --port args when --remove_ports is specified

        if let Some(workdir) = self.workdir {
            vmcfg.workdir = workdir.to_string();
            cfg_changed = true;
        }

        if self.rootfs_ro {
            vmcfg.rootfs_ro = true;
            cfg_changed = true;
        } else if self.remove_rootfs_ro {
            vmcfg.rootfs_ro = false;
            cfg_changed = true;
        }

        if self.remove_cap_drop {
            vmcfg.cap_drop = Vec::new();
            cfg_changed = true;
        } else if !self.cap_drop.is_empty() {
            let validated: Vec<String> = self
                .cap_drop
                .iter()
                .map(|c| {
                    validate_capability(c).unwrap_or_else(|e| {
                        println!("{}", e);
                        std::process::exit(-1);
                    })
                })
                .collect();
            vmcfg.cap_drop = validated;
            cfg_changed = true;
        }

        println!();
        printvm(vmcfg);
        println!();

        if cfg_changed {
            confy::store(APP_NAME, &cfg).unwrap();
        }
    }
}
