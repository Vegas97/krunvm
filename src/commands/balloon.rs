// Copyright 2026 Vegas97
// SPDX-License-Identifier: Apache-2.0

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

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
        let vmcfg = match cfg.vmconfig_map.get(&self.name) {
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

        let socket_path = vmcfg
            .control_socket
            .clone()
            .unwrap_or_else(|| format!("/tmp/krunvm-{}.sock", self.name));

        let mut stream = match UnixStream::connect(&socket_path) {
            Ok(s) => s,
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        println!("VM is not running or control socket not available");
                    }
                    std::io::ErrorKind::ConnectionRefused => {
                        println!("VM process is not accepting connections");
                    }
                    _ => {
                        println!("Error connecting to control socket: {}", e);
                    }
                }
                std::process::exit(-1);
            }
        };

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        if let Some(target_mb) = self.target {
            send_command(
                &mut stream,
                &format!("{{\"cmd\":\"balloon_set\",\"target_mib\":{}}}", target_mb),
            );
        }

        if self.stats {
            let response = send_command(&mut stream, "{\"cmd\":\"balloon_stats\"}");
            let val: serde_json::Value = match serde_json::from_str(&response) {
                Ok(v) => v,
                Err(_) => {
                    println!("Failed to parse response: {}", response);
                    std::process::exit(-1);
                }
            };
            if val.get("ok") == Some(&serde_json::Value::Bool(true)) {
                let actual = val["actual_mib"].as_u64().unwrap_or(0);
                let target = val["target_mib"].as_u64().unwrap_or(0);
                let free = val["free_mib"].as_u64().unwrap_or(0);
                println!("actual: {} MiB, target: {} MiB, free: {} MiB", actual, target, free);
            } else {
                let err = val["error"].as_str().unwrap_or("unknown error");
                println!("Error: {}", err);
                std::process::exit(-1);
            }
        }
    }
}

fn send_command(stream: &mut UnixStream, cmd: &str) -> String {
    if let Err(e) = writeln!(stream, "{}", cmd) {
        println!("Error sending command: {}", e);
        std::process::exit(-1);
    }

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    match reader.read_line(&mut response) {
        Ok(0) => {
            println!("VM closed the connection");
            std::process::exit(-1);
        }
        Ok(_) => {}
        Err(e) => {
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
            {
                println!("VM did not respond in time");
            } else {
                println!("Error reading response: {}", e);
            }
            std::process::exit(-1);
        }
    }

    let response = response.trim().to_string();

    // For non-stats commands, check the response for errors
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&response) {
        if val.get("ok") == Some(&serde_json::Value::Bool(false)) {
            let err = val["error"].as_str().unwrap_or("unknown error");
            println!("Error: {}", err);
            std::process::exit(-1);
        }
    }

    response
}
