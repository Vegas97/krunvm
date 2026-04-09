// Copyright 2021 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{KrunvmConfig, VmConfig};
use clap::Args;

/// List microVMs
#[derive(Args, Debug)]
pub struct ListCmd {
    /// Print debug information verbosely
    #[arg(short)]
    pub debug: bool, //TODO: implement or remove this
}

impl ListCmd {
    pub fn run(self, cfg: &KrunvmConfig) {
        if cfg.vmconfig_map.is_empty() {
            println!("No microVMs found");
        } else {
            for (_name, vm) in cfg.vmconfig_map.iter() {
                println!();
                printvm(vm);
            }
            println!();
        }
    }
}

pub fn printvm(vm: &VmConfig) {
    println!("{}", vm.name);
    println!(" CPUs: {}", vm.cpus);
    println!(" RAM (MiB): {}", vm.mem);
    println!(" DNS server: {}", vm.dns);
    println!(" Buildah container: {}", vm.container);
    println!(" Workdir: {}", vm.workdir);
    println!(" Mapped volumes: {:?}", vm.mapped_volumes);
    println!(" Mapped ports: {:?}", vm.mapped_ports);
    if let Some(balloon) = vm.balloon_target_mb {
        println!(" Balloon target (MiB): {}", balloon);
    }
    if let Some(ref net) = vm.net_socket {
        println!(" Net socket: {}", net);
    }
    if let Some(ref mac) = vm.mac_address {
        println!(" MAC address: {}", mac);
    }
    if vm.rootfs_ro {
        println!(" Read-only rootfs: yes");
    }
    if !vm.cap_drop.is_empty() {
        let caps: Vec<String> = vm.cap_drop.iter().map(|c| format!("cap_{}", c)).collect();
        println!(" Dropped capabilities: {}", caps.join(", "));
    }
}
