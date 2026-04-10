// Copyright 2021 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Args;
use libc::c_char;
use std::ffi::CString;
use std::fs;
use std::fs::File;
use std::io::Write;
#[cfg(target_os = "linux")]
use std::io::{Error, ErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "macos")]
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

static SIGNAL_RECEIVED: AtomicBool = AtomicBool::new(false);

use crate::bindings;
use crate::utils::{balloon_pages, control_socket_path, mount_container, parse_mac, shell_escape, umount_container};
use crate::{KrunvmConfig, VmConfig};

#[derive(Args, Debug)]
/// Start an existing microVM
pub struct StartCmd {
    /// Name of the microVM
    name: String,

    /// Command to run inside the VM
    command: Option<String>,

    /// Arguments to be passed to the command executed in the VM
    args: Vec<String>,

    /// Number of vCPUs
    #[arg(long)]
    cpus: Option<u8>, // TODO: implement or remove this

    /// Amount of RAM in MiB
    #[arg(long)]
    mem: Option<usize>, // TODO: implement or remove this

    /// env(s) in format "key=value" to be exposed to the VM
    #[arg(long = "env")]
    envs: Option<Vec<String>>,

    /// Maximum time in seconds the VM is allowed to run (0 = no limit)
    #[arg(long)]
    timeout: Option<u64>,
}

impl StartCmd {
    pub fn run(self, cfg: &KrunvmConfig) {
        let vmcfg = match cfg.vmconfig_map.get(&self.name) {
            None => {
                println!("No VM found with name {}", self.name);
                std::process::exit(-1);
            }
            Some(vmcfg) => vmcfg,
        };

        umount_container(cfg, vmcfg).expect("Error unmounting container");
        let rootfs = mount_container(cfg, vmcfg).expect("Error mounting container");

        let vm_args: Vec<CString> = if self.command.is_some() {
            self.args
                .into_iter()
                .map(|val| CString::new(val).unwrap())
                .collect()
        } else {
            Vec::new()
        };

        let env_pairs: Vec<CString> = if let Some(envs) = self.envs {
            envs.into_iter()
                .map(|val| CString::new(val).unwrap())
                .collect()
        } else {
            Vec::new()
        };

        set_rlimits();
        install_signal_handlers();

        if let Some(secs) = self.timeout {
            if secs > 0 {
                spawn_watchdog(secs);
            }
        }

        let _file = set_lock(&rootfs);

        unsafe { exec_vm(vmcfg, &rootfs, self.command.as_deref(), vm_args, env_pairs) };

        umount_container(cfg, vmcfg).expect("Error unmounting container");
    }
}

#[cfg(target_os = "linux")]
fn map_volumes(_ctx: u32, vmcfg: &VmConfig, rootfs: &str) {
    for (host_path, guest_path) in vmcfg.mapped_volumes.iter() {
        let host_dir = CString::new(host_path.to_string()).unwrap();
        let guest_dir = CString::new(format!("{}{}", rootfs, guest_path)).unwrap();

        let ret = unsafe { libc::mkdir(guest_dir.as_ptr(), 0o755) };
        if ret < 0 && Error::last_os_error().kind() != ErrorKind::AlreadyExists {
            println!("Error creating directory {:?}", guest_dir);
            std::process::exit(-1);
        }
        unsafe { libc::umount(guest_dir.as_ptr()) };
        let ret = unsafe {
            libc::mount(
                host_dir.as_ptr(),
                guest_dir.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            )
        };
        if ret < 0 {
            println!("Error mounting volume {}", guest_path);
            std::process::exit(-1);
        }
    }
}

#[cfg(target_os = "macos")]
fn map_volumes(ctx: u32, vmcfg: &VmConfig, rootfs: &str) -> Vec<(String, String)> {
    let mut mounts = Vec::new();
    for (idx, (host_path, guest_path)) in vmcfg.mapped_volumes.iter().enumerate() {
        let full_guest = format!("{}{}", &rootfs, guest_path);
        let full_guest_path = Path::new(&full_guest);
        if !full_guest_path.exists() {
            std::fs::create_dir(full_guest_path)
                .expect("Couldn't create guest_path for mapped volume");
        }
        let tag = format!("krunvm{}", idx);
        let c_tag = CString::new(tag.as_str()).unwrap();
        let c_host = CString::new(host_path.as_str()).unwrap();
        let ret = unsafe { bindings::krun_add_virtiofs(ctx, c_tag.as_ptr(), c_host.as_ptr()) };
        if ret < 0 {
            println!("Error setting VM mapped volume {}", guest_path);
            std::process::exit(-1);
        }
        mounts.push((tag, guest_path.to_string()));
    }
    mounts
}

unsafe fn exec_vm(
    vmcfg: &VmConfig,
    rootfs: &str,
    cmd: Option<&str>,
    args: Vec<CString>,
    env_pairs: Vec<CString>,
) {
    // cap-drop without explicit cmd is fine — build_mount_wrapper will
    // resolve the OCI entrypoint from .krun_config.json

    //bindings::krun_set_log_level(9);

    let ctx = bindings::krun_create_ctx() as u32;

    let ret = bindings::krun_set_vm_config(ctx, vmcfg.cpus as u8, vmcfg.mem);
    if ret < 0 {
        println!("Error setting VM config");
        std::process::exit(-1);
    }

    let c_rootfs = CString::new(rootfs).unwrap();
    let ret = if vmcfg.rootfs_ro {
        bindings::krun_set_root_ro(ctx, c_rootfs.as_ptr())
    } else {
        bindings::krun_set_root(ctx, c_rootfs.as_ptr())
    };
    if ret < 0 {
        println!("Error setting VM rootfs");
        std::process::exit(-1);
    }

    #[cfg(target_os = "linux")]
    map_volumes(ctx, vmcfg, rootfs);
    #[cfg(target_os = "macos")]
    let virtiofs_mounts = map_volumes(ctx, vmcfg, rootfs);
    #[cfg(target_os = "macos")]
    let mount_wrapper = build_mount_wrapper(
        rootfs,
        cmd,
        &vmcfg.workdir,
        &args,
        &virtiofs_mounts,
        &vmcfg.cap_drop,
    );

    match (&vmcfg.net_socket, &vmcfg.mac_address) {
        (Some(_), None) | (None, Some(_)) => {
            println!(
                "VM networking config is incomplete; both net socket and MAC address must be set"
            );
            std::process::exit(-1);
        }
        (Some(_), Some(_)) if !vmcfg.mapped_ports.is_empty() => {
            println!("Port mappings are not supported when virtio-net is configured");
            std::process::exit(-1);
        }
        _ => {}
    }

    if let (Some(net_path), Some(mac_str)) = (&vmcfg.net_socket, &vmcfg.mac_address) {
        // virtio-net path: connect to gvproxy via unix socket
        let c_path = CString::new(net_path.as_str()).unwrap();
        let mac_bytes = parse_mac(mac_str).unwrap_or_else(|e| {
            println!("{}", e);
            std::process::exit(-1);
        });

        let ret = bindings::krun_add_net_unixstream(
            ctx,
            c_path.as_ptr(),
            -1,
            mac_bytes.as_ptr(),
            bindings::COMPAT_NET_FEATURES,
            0,
        );
        if ret < 0 {
            println!("Error adding virtio-net device (is gvproxy running?)");
            std::process::exit(-1);
        }
    } else {
        // TSI path: use port mapping (existing behavior)
        let mut ports = Vec::new();
        for (host_port, guest_port) in vmcfg.mapped_ports.iter() {
            let map = format!("{}:{}", host_port, guest_port);
            ports.push(CString::new(map).unwrap());
        }
        let mut ps: Vec<*const c_char> = Vec::new();
        for port in ports.iter() {
            ps.push(port.as_ptr());
        }
        ps.push(std::ptr::null());

        let ret = bindings::krun_set_port_map(ctx, ps.as_ptr());
        if ret < 0 {
            println!("Error setting VM port map");
            std::process::exit(-1);
        }
    }

    if !vmcfg.workdir.is_empty() {
        let c_workdir = CString::new(vmcfg.workdir.clone()).unwrap();
        let ret = bindings::krun_set_workdir(ctx, c_workdir.as_ptr());
        if ret < 0 {
            println!("Error setting VM workdir");
            std::process::exit(-1);
        }
    }

    let hostname = CString::new(format!("HOSTNAME={}", vmcfg.name)).unwrap();
    let home = CString::new("HOME=/root").unwrap();

    let mut env: Vec<*const c_char> = Vec::new();
    env.push(hostname.as_ptr());
    env.push(home.as_ptr());
    for value in env_pairs.iter() {
        env.push(value.as_ptr());
    }
    env.push(std::ptr::null());

    #[cfg(target_os = "macos")]
    {
        if let Some((helper_path, helper_args)) = mount_wrapper {
            let mut argv: Vec<*const c_char> = helper_args.iter().map(|a| a.as_ptr()).collect();
            argv.push(std::ptr::null());
            let ret =
                bindings::krun_set_exec(ctx, helper_path.as_ptr(), argv.as_ptr(), env.as_ptr());
            if ret < 0 {
                println!("Error setting VM config");
                std::process::exit(-1);
            }
        } else if let Some(cmd) = cmd {
            let mut argv: Vec<*const c_char> = Vec::new();
            for a in args.iter() {
                argv.push(a.as_ptr());
            }
            argv.push(std::ptr::null());

            let c_cmd = CString::new(cmd).unwrap();
            let ret = bindings::krun_set_exec(ctx, c_cmd.as_ptr(), argv.as_ptr(), env.as_ptr());
            if ret < 0 {
                println!("Error setting VM config");
                std::process::exit(-1);
            }
        } else {
            let ret = bindings::krun_set_env(ctx, env.as_ptr());
            if ret < 0 {
                println!("Error setting VM environment variables");
                std::process::exit(-1);
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        if !vmcfg.cap_drop.is_empty() {
            // Write a capsh wrapper script into the rootfs
            let wrapper =
                build_capdrop_wrapper(rootfs, cmd, &vmcfg.workdir, &args, &vmcfg.cap_drop);
            let mut wrapper_argv: Vec<*const c_char> =
                wrapper.1.iter().map(|a| a.as_ptr()).collect();
            wrapper_argv.push(std::ptr::null());
            let ret = bindings::krun_set_exec(
                ctx,
                wrapper.0.as_ptr(),
                wrapper_argv.as_ptr(),
                env.as_ptr(),
            );
            if ret < 0 {
                println!("Error setting VM config");
                std::process::exit(-1);
            }
        } else if let Some(cmd) = cmd {
            let mut argv: Vec<*const c_char> = Vec::new();
            for a in args.iter() {
                argv.push(a.as_ptr());
            }
            argv.push(std::ptr::null());

            let c_cmd = CString::new(cmd).unwrap();
            let ret = bindings::krun_set_exec(ctx, c_cmd.as_ptr(), argv.as_ptr(), env.as_ptr());
            if ret < 0 {
                println!("Error setting VM config");
                std::process::exit(-1);
            }
        } else {
            let ret = bindings::krun_set_env(ctx, env.as_ptr());
            if ret < 0 {
                println!("Error setting VM environment variables");
                std::process::exit(-1);
            }
        }
    }

    if let Some(balloon_mb) = vmcfg.balloon_target_mb {
        let initial_target = balloon_pages(vmcfg.mem, balloon_mb);
        let ret = bindings::krun_set_balloon_config(ctx, initial_target);
        if ret < 0 {
            println!("Error setting balloon config");
            std::process::exit(-1);
        }
    }

    // Register control socket only when balloon or explicit socket is configured
    if vmcfg.balloon_target_mb.is_some() || vmcfg.control_socket.is_some() {
        let socket_path = vmcfg
            .control_socket
            .clone()
            .unwrap_or_else(|| control_socket_path(&vmcfg.name));
        // Clean up stale socket from a previous run
        let _ = std::fs::remove_file(&socket_path);
        let c_socket = CString::new(socket_path.as_str()).unwrap();
        let ret = bindings::krun_set_control_socket(ctx, c_socket.as_ptr());
        if ret < 0 {
            eprintln!(
                "warning: failed to set control socket ({}), balloon commands won't work",
                ret
            );
        }
    }

    let ret = bindings::krun_start_enter(ctx);
    if ret < 0 {
        println!("Error starting VM");
        std::process::exit(-1);
    }
}

#[cfg(target_os = "macos")]
fn build_mount_wrapper(
    rootfs: &str,
    cmd: Option<&str>,
    workdir: &str,
    args: &[CString],
    mounts: &[(String, String)],
    cap_drop: &[String],
) -> Option<(CString, Vec<CString>)> {
    if mounts.is_empty() && cap_drop.is_empty() {
        return None;
    }

    let helper_path = write_mount_script(rootfs, workdir, mounts, cap_drop);

    let mut exec_args: Vec<CString> = Vec::new();
    if let Some(command) = cmd {
        exec_args.push(CString::new(command).unwrap());
        exec_args.extend(args.iter().cloned());
    } else {
        // No explicit command — resolve from OCI config
        let oci_cmd = resolve_oci_cmd_from_config(rootfs);
        if oci_cmd.is_empty() {
            exec_args.push(CString::new("/bin/sh").unwrap());
        } else {
            for part in &oci_cmd {
                exec_args.push(CString::new(part.as_str()).unwrap());
            }
        }
        exec_args.extend(args.iter().cloned());
    }

    let helper_cstr = CString::new(helper_path).unwrap();
    Some((helper_cstr, exec_args))
}

#[cfg(target_os = "macos")]
fn write_mount_script(
    rootfs: &str,
    workdir: &str,
    mounts: &[(String, String)],
    cap_drop: &[String],
) -> String {
    let host_path = format!("{}/.krunvm-mount.sh", rootfs);
    let guest_path = "/.krunvm-mount.sh".to_string();

    let mut file = File::create(&host_path).unwrap_or_else(|err| {
        println!("Error creating mount helper script: {}", err);
        std::process::exit(-1);
    });

    writeln!(file, "#!/bin/sh").unwrap();
    writeln!(file, "set -e").unwrap();
    for (tag, guest_path) in mounts {
        writeln!(file, "mount -t virtiofs {} {}", tag, shell_escape(guest_path)).unwrap();
    }
    if !workdir.is_empty() {
        writeln!(file, "cd {}", shell_escape(workdir)).unwrap();
    }
    if cap_drop.is_empty() {
        writeln!(file, "exec \"$@\"").unwrap();
    } else {
        let caps = cap_drop
            .iter()
            .map(|c| format!("cap_{}", c))
            .collect::<Vec<_>>()
            .join(",");
        // Use --shell=$1 to override capsh's default /bin/bash, then shift
        // and pass remaining args via --. This avoids a /bin/bash dependency.
        writeln!(file, "CMD=\"$1\"").unwrap();
        writeln!(file, "shift").unwrap();
        writeln!(
            file,
            "exec capsh --drop={} --shell=\"$CMD\" -- \"$@\"",
            caps
        )
        .unwrap();
    }

    let perms = fs::Permissions::from_mode(0o755);
    if let Err(err) = fs::set_permissions(&host_path, perms) {
        println!("Error setting mount helper permissions: {}", err);
        std::process::exit(-1);
    }

    guest_path
}

/// Write a shell wrapper that drops capabilities via capsh before exec'ing the command.
/// Used on Linux where there is no mount wrapper script.
#[cfg(not(target_os = "macos"))]
fn build_capdrop_wrapper(
    rootfs: &str,
    cmd: Option<&str>,
    workdir: &str,
    args: &[CString],
    cap_drop: &[String],
) -> (CString, Vec<CString>) {
    let host_path = format!("{}/.krunvm-capdrop.sh", rootfs);
    let guest_path = "/.krunvm-capdrop.sh";

    let mut file = File::create(&host_path).unwrap_or_else(|err| {
        println!("Error creating capability-drop helper script: {}", err);
        std::process::exit(-1);
    });

    let caps = cap_drop
        .iter()
        .map(|c| format!("cap_{}", c))
        .collect::<Vec<_>>()
        .join(",");

    writeln!(file, "#!/bin/sh").unwrap();
    writeln!(file, "set -e").unwrap();
    if !workdir.is_empty() {
        writeln!(file, "cd {}", shell_escape(workdir)).unwrap();
    }
    writeln!(file, "CMD=\"$1\"").unwrap();
    writeln!(file, "shift").unwrap();
    writeln!(
        file,
        "exec capsh --drop={} --shell=\"$CMD\" -- \"$@\"",
        caps
    )
    .unwrap();

    let perms = fs::Permissions::from_mode(0o755);
    if let Err(err) = fs::set_permissions(&host_path, perms) {
        println!("Error setting capability-drop helper permissions: {}", err);
        std::process::exit(-1);
    }

    let command = cmd.unwrap_or("/bin/sh");
    let mut exec_args: Vec<CString> = Vec::new();
    exec_args.push(CString::new(command).unwrap());
    exec_args.extend(args.iter().cloned());

    (CString::new(guest_path).unwrap(), exec_args)
}

extern "C" fn signal_handler(sig: libc::c_int) {
    SIGNAL_RECEIVED.store(true, Ordering::Relaxed);
    unsafe { libc::_exit(128 + sig) };
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, signal_handler as *const () as libc::sighandler_t);
    }
}

fn spawn_watchdog(timeout_secs: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(timeout_secs));
        eprintln!("krunvm: timeout after {} seconds, forcing exit", timeout_secs);
        unsafe { libc::_exit(124) };
    });
}

fn set_rlimits() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    if ret < 0 {
        panic!("Couldn't get RLIMIT_NOFILE value");
    }

    limit.rlim_cur = limit.rlim_max;
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
    if ret < 0 {
        panic!("Couldn't set RLIMIT_NOFILE value");
    }
}

fn set_lock(rootfs: &str) -> File {
    let lock_path = format!("{}/.krunvm.lock", rootfs);
    let file = File::create(lock_path).expect("Couldn't create lock file");

    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret < 0 {
        println!("Couldn't acquire lock file. Is another instance of this VM already running?");
        std::process::exit(-1);
    }

    file
}

#[cfg(target_os = "macos")]
/// Resolve the OCI command from .krun_config.json in the rootfs.
///
/// Follows the OCI runtime spec for combining Entrypoint and Cmd:
///   - Both set:        Entrypoint + Cmd (concatenated)
///   - Entrypoint only: Entrypoint
///   - Cmd only:        Cmd
///   - Neither:         empty (caller falls back to ["/bin/sh"])
///
/// This matches libkrun's init behavior (init/init.c concat_entrypoint_argv).
fn resolve_oci_cmd_from_config(rootfs: &str) -> Vec<String> {
    let config_path = format!("{}/.krun_config.json", rootfs);
    let json_str = match fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let val: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    // Try OCIv1.config first, then Docker.config as fallback
    for section in &["OCIv1", "Docker"] {
        let config = match val.get(section).and_then(|v| v.get("config")) {
            Some(c) => c,
            None => continue,
        };

        let entrypoint = parse_string_array(config.get("Entrypoint"));
        let cmd = parse_string_array(config.get("Cmd"));

        match (entrypoint.is_empty(), cmd.is_empty()) {
            (false, false) => {
                let mut result = entrypoint;
                result.extend(cmd);
                return result;
            }
            (false, true) => return entrypoint,
            (true, false) => return cmd,
            (true, true) => continue,
        }
    }

    Vec::new()
}

#[cfg(target_os = "macos")]
/// Parse a JSON value as a string array, returning empty vec for null/missing/invalid.
fn parse_string_array(val: Option<&serde_json::Value>) -> Vec<String> {
    val.and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}
