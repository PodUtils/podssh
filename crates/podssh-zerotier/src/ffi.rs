//! The C API of ZeroTier's core (`vendor/zerotier-node/include/ZeroTierOne.h`)
//! that this crate calls, and podssh's own two calls (`src/shim.cpp`).

#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, c_long, c_uint, c_void};

use libc::sockaddr_storage;

/// The core's node, opaque.
#[repr(C)]
pub struct ZT_Node {
    _private: [u8; 0],
}

pub type StatePut =
    unsafe extern "C" fn(*mut ZT_Node, *mut c_void, *mut c_void, c_int, *const u64, *const c_void, c_int);
pub type StateGet =
    unsafe extern "C" fn(*mut ZT_Node, *mut c_void, *mut c_void, c_int, *const u64, *mut c_void, c_uint) -> c_int;
pub type WireSend = unsafe extern "C" fn(
    *mut ZT_Node,
    *mut c_void,
    *mut c_void,
    i64,
    *const sockaddr_storage,
    *const c_void,
    c_uint,
    c_uint,
) -> c_int;
pub type Frame = unsafe extern "C" fn(
    *mut ZT_Node,
    *mut c_void,
    *mut c_void,
    u64,
    *mut *mut c_void,
    u64,
    u64,
    c_uint,
    c_uint,
    *const c_void,
    c_uint,
);
pub type NetworkConfig =
    unsafe extern "C" fn(*mut ZT_Node, *mut c_void, *mut c_void, u64, *mut *mut c_void, c_int, *const c_void) -> c_int;
pub type Event = unsafe extern "C" fn(*mut ZT_Node, *mut c_void, *mut c_void, c_int, *const c_void);

/// `struct ZT_Node_Callbacks`, its version 0.
#[repr(C)]
pub struct Callbacks {
    pub version: c_long,
    pub state_put: StatePut,
    pub state_get: StateGet,
    pub wire_send: WireSend,
    pub frame: Frame,
    pub network_config: NetworkConfig,
    pub event: Event,
    pub path_check: Option<unsafe extern "C" fn()>,
    pub path_lookup: Option<unsafe extern "C" fn()>,
}

/// `struct ZT_Node_Config`.
#[repr(C)]
#[derive(Default)]
pub struct Config {
    pub enable_encrypted_hello: c_int,
    pub low_bandwidth_mode: c_int,
}

/// `ZT_RESULT_OK`, and the first fatal code.
pub const RESULT_OK: c_int = 0;
pub const RESULT_FATAL: c_int = 100;
/// The state objects that this crate keeps (`enum ZT_StateObjectType`).
pub const STATE_IDENTITY_PUBLIC: c_int = 1;
pub const STATE_IDENTITY_SECRET: c_int = 2;
pub const STATE_PLANET: c_int = 3;

unsafe extern "C" {
    pub fn ZT_version(major: *mut c_int, minor: *mut c_int, revision: *mut c_int);
    pub fn ZT_Node_new(
        node: *mut *mut ZT_Node,
        config: *const Config,
        uptr: *mut c_void,
        tptr: *mut c_void,
        callbacks: *const Callbacks,
        now: i64,
    ) -> c_int;
    pub fn ZT_Node_delete(node: *mut ZT_Node);
    pub fn ZT_Node_processWirePacket(
        node: *mut ZT_Node,
        tptr: *mut c_void,
        now: i64,
        local_socket: i64,
        remote: *const sockaddr_storage,
        data: *const c_void,
        len: c_uint,
        next_deadline: *mut i64,
    ) -> c_int;
    pub fn ZT_Node_processVirtualNetworkFrame(
        node: *mut ZT_Node,
        tptr: *mut c_void,
        now: i64,
        nwid: u64,
        source_mac: u64,
        dest_mac: u64,
        ether_type: c_uint,
        vlan: c_uint,
        data: *const c_void,
        len: c_uint,
        next_deadline: *mut i64,
    ) -> c_int;
    pub fn ZT_Node_processBackgroundTasks(node: *mut ZT_Node, tptr: *mut c_void, now: i64, next: *mut i64) -> c_int;
    pub fn ZT_Node_join(node: *mut ZT_Node, nwid: u64, uptr: *mut c_void, tptr: *mut c_void) -> c_int;
    pub fn ZT_Node_address(node: *mut ZT_Node) -> u64;
    pub fn podssh_zt_world(
        id: u64,
        ts: u64,
        identities: *const *const c_char,
        endpoints: *const *const c_char,
        count: c_uint,
        out: *mut u8,
        cap: c_uint,
    ) -> c_int;
    pub fn podssh_zt_mac(address: u64, nwid: u64) -> u64;
}
