// Copyright 2021 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use libc::{c_char, c_int};

/// Virtio-net feature bits matching gvproxy/libkrun expectations.
/// See krunkit src/virtio.rs for the full set; this subset matches
/// the features enabled by krun_set_passt_fd / krun_set_gvproxy_path.
pub const COMPAT_NET_FEATURES: u32 = 0x4C83;

/// Send VFKIT magic after connection, required by gvproxy in vfkit mode.
/// Only applies to UnixGram sockets (macOS). For UnixStream, flags = 0.
pub const NET_FLAG_VFKIT: u32 = 1 << 0;

#[link(name = "krun")]
extern "C" {
    pub fn krun_set_log_level(level: u32) -> i32;
    pub fn krun_create_ctx() -> i32;
    pub fn krun_free_ctx(ctx: u32) -> i32;
    pub fn krun_set_vm_config(ctx: u32, num_vcpus: u8, ram_mib: u32) -> i32;
    pub fn krun_set_root(ctx: u32, root_path: *const c_char) -> i32;
    pub fn krun_set_port_map(ctx: u32, port_map: *const *const c_char) -> i32;
    pub fn krun_set_workdir(ctx: u32, workdir_path: *const c_char) -> i32;
    pub fn krun_add_virtiofs(ctx: u32, tag: *const c_char, path: *const c_char) -> i32;
    pub fn krun_set_exec(
        ctx: u32,
        exec_path: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> i32;
    pub fn krun_set_env(ctx: u32, envp: *const *const c_char) -> i32;
    pub fn krun_start_enter(ctx: u32) -> i32;
    pub fn krun_add_net_unixgram(
        ctx_id: u32,
        c_path: *const c_char,
        fd: c_int,
        c_mac: *const u8,
        features: u32,
        flags: u32,
    ) -> i32;
    pub fn krun_add_net_unixstream(
        ctx_id: u32,
        c_path: *const c_char,
        fd: c_int,
        c_mac: *const u8,
        features: u32,
        flags: u32,
    ) -> i32;
}
