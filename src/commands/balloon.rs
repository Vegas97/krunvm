// Copyright 2026 Vegas97
// SPDX-License-Identifier: Apache-2.0

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use clap::Args;

use crate::utils::{balloon_set_cmd, balloon_stats_cmd, control_socket_path, parse_balloon_stats};
use crate::KrunvmConfig;

/// Adjust or query the memory balloon of a running microVM
#[derive(Args, Debug)]
pub struct BalloonCmd {
    /// Name of the microVM
    name: String,

    /// Set balloon inflation target in MiB (how much memory to reclaim from VM)
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

        let socket = vmcfg
            .control_socket
            .clone()
            .unwrap_or_else(|| control_socket_path(&self.name));

        let mut stream = match UnixStream::connect(&socket) {
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
            send_command(&mut stream, &balloon_set_cmd(target_mb));
        }

        if self.stats {
            let response = send_command(&mut stream, &balloon_stats_cmd());
            match parse_balloon_stats(&response) {
                Ok((actual, target, free)) => {
                    println!("actual: {} MiB, target: {} MiB, free: {} MiB", actual, target, free);
                }
                Err(e) => {
                    println!("Error: {}", e);
                    std::process::exit(-1);
                }
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
