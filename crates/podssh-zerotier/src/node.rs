//! One node of ZeroTier's core, safe to hold: what it sends goes to its
//! [`Host`], and what comes in is given to it by the caller, each call with
//! the time now. The core runs no thread and opens no socket of its own: its
//! wire is the host's, so podssh carries it where it can (the TCP relay, a
//! test's memory). Its state (the identity, the planet) is the host's too.

use std::ffi::{c_int, c_uint, c_void};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use libc::{sockaddr_in, sockaddr_in6, sockaddr_storage};

use crate::ffi;

/// What a node does outside the core.
pub trait Host: Send {
    /// A packet of the wire to `to`.
    fn wire(&mut self, to: SocketAddr, packet: &[u8]);
    /// An Ethernet frame that came for this host on the network `nwid`.
    fn frame(&mut self, nwid: u64, source: u64, dest: u64, ether_type: u16, data: &[u8]);
    /// A state object to keep (`None` deletes it).
    fn put(&mut self, kind: c_int, data: Option<&[u8]>);
    /// A state object kept, if any.
    fn get(&mut self, kind: c_int) -> Option<Vec<u8>>;
}

/// A node of the core.
pub struct Node {
    node: *mut ffi::ZT_Node,
    host: *mut Box<dyn Host>,
    /// When the core asks to be called again, in milliseconds.
    pub next: i64,
}

// Safety: the core is single-threaded by its caller; a Node moves between
// threads whole, and each call takes `&mut self`.
unsafe impl Send for Node {}

impl Node {
    /// A node with `host`, at `now` milliseconds: its identity is the host's
    /// kept one, else made now and given to the host to keep.
    pub fn new(host: Box<dyn Host>, now: i64) -> Result<Node, String> {
        let host = Box::into_raw(Box::new(host));
        let callbacks = ffi::Callbacks {
            version: 0,
            state_put,
            state_get,
            wire_send,
            frame,
            network_config,
            event,
            path_check: None,
            path_lookup: None,
        };
        let config = ffi::Config::default();
        let mut node = std::ptr::null_mut();
        // Safety: the callbacks and the config live for the call; `host`
        // lives until `Drop`, after the node.
        let code = unsafe { ffi::ZT_Node_new(&mut node, &config, host.cast(), std::ptr::null_mut(), &callbacks, now) };
        if code != ffi::RESULT_OK || node.is_null() {
            // Safety: the node did not keep `host`.
            drop(unsafe { Box::from_raw(host) });
            return Err(format!("ZeroTier's core did not start: code {code}"));
        }
        Ok(Node { node, host, next: now })
    }

    /// The node's address, 40 bits.
    pub fn address(&self) -> u64 {
        // Safety: the node is live.
        unsafe { ffi::ZT_Node_address(self.node) }
    }

    /// A packet of the wire from `from`.
    pub fn wire(&mut self, now: i64, from: SocketAddr, packet: &[u8]) -> Result<(), String> {
        let at = storage(from);
        // Safety: the address and the packet live for the call.
        let code = unsafe {
            ffi::ZT_Node_processWirePacket(
                self.node,
                std::ptr::null_mut(),
                now,
                0,
                &at,
                packet.as_ptr().cast(),
                packet.len() as c_uint,
                &mut self.next,
            )
        };
        checked(code)
    }

    /// An Ethernet frame of this host on the network `nwid`.
    pub fn frame(
        &mut self,
        now: i64,
        nwid: u64,
        source: u64,
        dest: u64,
        ether_type: u16,
        data: &[u8],
    ) -> Result<(), String> {
        // Safety: the frame lives for the call.
        let code = unsafe {
            ffi::ZT_Node_processVirtualNetworkFrame(
                self.node,
                std::ptr::null_mut(),
                now,
                nwid,
                source,
                dest,
                c_uint::from(ether_type),
                0,
                data.as_ptr().cast(),
                data.len() as c_uint,
                &mut self.next,
            )
        };
        checked(code)
    }

    /// The core's timers, at `now`.
    pub fn background(&mut self, now: i64) -> Result<(), String> {
        // Safety: the node is live.
        checked(unsafe { ffi::ZT_Node_processBackgroundTasks(self.node, std::ptr::null_mut(), now, &mut self.next) })
    }

    /// Join the network `nwid`; an ad-hoc network's configuration is made here.
    pub fn join(&mut self, nwid: u64) -> Result<(), String> {
        // Safety: the node is live.
        checked(unsafe { ffi::ZT_Node_join(self.node, nwid, std::ptr::null_mut(), std::ptr::null_mut()) })
    }

    /// This node's MAC address on `nwid`.
    pub fn mac(&self, nwid: u64) -> u64 {
        mac_of(self.address(), nwid)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // Safety: the node goes first, then the host that its callbacks used.
        unsafe {
            ffi::ZT_Node_delete(self.node);
            drop(Box::from_raw(self.host));
        }
    }
}

/// The MAC address of the member `address` on `nwid`.
pub fn mac_of(address: u64, nwid: u64) -> u64 {
    // Safety: a computation of two integers.
    unsafe { ffi::podssh_zt_mac(address, nwid) }
}

fn checked(code: c_int) -> Result<(), String> {
    match code >= ffi::RESULT_FATAL {
        true => Err(format!("ZeroTier's core failed: code {code}")),
        false => Ok(()),
    }
}

/// The host of the user pointer of a callback.
///
/// Safety: `uptr` is the `host` of a live [`Node`].
unsafe fn host<'a>(uptr: *mut c_void) -> &'a mut Box<dyn Host> {
    unsafe { &mut *uptr.cast::<Box<dyn Host>>() }
}

unsafe extern "C" fn state_put(
    _: *mut ffi::ZT_Node,
    uptr: *mut c_void,
    _: *mut c_void,
    kind: c_int,
    _: *const u64,
    data: *const c_void,
    len: c_int,
) {
    let bytes = (len >= 0).then(|| unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len as usize) });
    unsafe { host(uptr) }.put(kind, bytes);
}

unsafe extern "C" fn state_get(
    _: *mut ffi::ZT_Node,
    uptr: *mut c_void,
    _: *mut c_void,
    kind: c_int,
    _: *const u64,
    out: *mut c_void,
    cap: c_uint,
) -> c_int {
    match unsafe { host(uptr) }.get(kind) {
        Some(bytes) if bytes.len() <= cap as usize => {
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out.cast::<u8>(), bytes.len()) };
            bytes.len() as c_int
        }
        _ => -1,
    }
}

unsafe extern "C" fn wire_send(
    _: *mut ffi::ZT_Node,
    uptr: *mut c_void,
    _: *mut c_void,
    _: i64,
    to: *const sockaddr_storage,
    data: *const c_void,
    len: c_uint,
    _: c_uint,
) -> c_int {
    let Some(to) = (unsafe { address(&*to) }) else { return -1 };
    let packet = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len as usize) };
    unsafe { host(uptr) }.wire(to, packet);
    0
}

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn frame(
    _: *mut ffi::ZT_Node,
    uptr: *mut c_void,
    _: *mut c_void,
    nwid: u64,
    _: *mut *mut c_void,
    source: u64,
    dest: u64,
    ether_type: c_uint,
    _: c_uint,
    data: *const c_void,
    len: c_uint,
) {
    let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len as usize) };
    unsafe { host(uptr) }.frame(nwid, source, dest, ether_type as u16, bytes);
}

unsafe extern "C" fn network_config(
    _: *mut ffi::ZT_Node,
    _: *mut c_void,
    _: *mut c_void,
    _: u64,
    _: *mut *mut c_void,
    _: c_int,
    _: *const c_void,
) -> c_int {
    0
}

unsafe extern "C" fn event(_: *mut ffi::ZT_Node, _: *mut c_void, _: *mut c_void, _: c_int, _: *const c_void) {}

/// `at` as the core's `sockaddr_storage`.
pub fn storage(at: SocketAddr) -> sockaddr_storage {
    // Safety: an all-zero sockaddr_storage is valid, and each form fits in it.
    let mut out: sockaddr_storage = unsafe { std::mem::zeroed() };
    match at {
        SocketAddr::V4(v4) => {
            let sin = sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr { s_addr: u32::from(*v4.ip()).to_be() },
                ..unsafe { std::mem::zeroed() }
            };
            unsafe { std::ptr::write((&mut out as *mut sockaddr_storage).cast(), sin) };
        }
        SocketAddr::V6(v6) => {
            let sin6 = sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                ..unsafe { std::mem::zeroed() }
            };
            unsafe { std::ptr::write((&mut out as *mut sockaddr_storage).cast(), sin6) };
        }
    }
    out
}

/// The address of the core's `sockaddr_storage`, IPv4 or IPv6.
///
/// # Safety
///
/// `at` is a valid `sockaddr_storage`.
pub unsafe fn address(at: &sockaddr_storage) -> Option<SocketAddr> {
    match c_int::from(at.ss_family) {
        libc::AF_INET => {
            let sin = unsafe { &*(at as *const sockaddr_storage).cast::<sockaddr_in>() };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Some(SocketAddr::new(IpAddr::V4(ip), u16::from_be(sin.sin_port)))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(at as *const sockaddr_storage).cast::<sockaddr_in6>() };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::new(IpAddr::V6(ip), u16::from_be(sin6.sin6_port)))
        }
        _ => None,
    }
}
