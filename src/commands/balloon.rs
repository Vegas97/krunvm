// Copyright 2026 Vegas97
// SPDX-License-Identifier: Apache-2.0

use clap::Args;

use crate::KrunvmConfig;

/// Adjust or query the memory balloon of a running microVM
#[derive(Args, Debug)]
pub struct BalloonCmd {
    /// Name of the microVM
    name: String,

    /// Set balloon target in MiB (VM keeps this much resident memory)
    #[arg(long)]
    target: Option<u32>,

    /// Show current balloon statistics (actual/target/free in MiB)
    #[arg(long)]
    stats: bool,
}

impl BalloonCmd {
    pub fn run(self, cfg: &KrunvmConfig) {
        let _vmcfg = match cfg.vmconfig_map.get(&self.name) {
            None => {
                println!("No VM found with name {}", self.name);
                std::process::exit(-1);
            }
            Some(vmcfg) => vmcfg,
        };

        if !self.stats && self.target.is_none() {
            println!("Either --target or --stats must be specified");
            std::process::exit(-1);
        }

        // TODO: Runtime balloon control requires a control channel between the
        // `krunvm balloon` process and the running `krunvm start` process,
        // because krun_start_enter() replaces the process and blocks until VM
        // exit. Options to implement:
        //   1. Unix domain socket control channel (like QEMU monitor)
        //   2. Shared memory / file-based signaling
        //   3. A `krunvm manage` daemon that wraps the VM lifecycle
        //
        // The FFI bindings for krun_set_balloon_target() and
        // krun_get_balloon_stats() are already declared in bindings.rs.
        // Once a control channel exists, this subcommand will:
        //   --target <MB>: send target to running VM via control channel,
        //                  which calls krun_set_balloon_target(ctx, mb * 256)
        //   --stats:       request stats via control channel,
        //                  which calls krun_get_balloon_stats() and prints
        //                  actual/target/free in MiB (dividing pages by 256)
        println!(
            "Runtime balloon control is not yet implemented.\n\
             Use --balloon at create time to set the initial balloon target.\n\
             See: krunvm create --help"
        );
        std::process::exit(1);
    }
}
