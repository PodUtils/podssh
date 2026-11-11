//! ZeroTier's core for podssh (T-733): `vendor/zerotier-node`, MPL-2.0,
//! linked statically, with podssh's own calls of `src/shim.cpp`. The core
//! runs on the caller's wire and clock ([`node::Node`]); the road over
//! ZeroTier Inc.'s roots and TCP relay is built on it.

#![cfg(unix)]

mod ffi;
pub mod node;

use std::ffi::CString;

pub use node::{Host, Node};

/// The kinds of state that a [`Host`] keeps.
pub mod state {
    pub use crate::ffi::STATE_PLANET as PLANET;
    pub use crate::ffi::{STATE_IDENTITY_PUBLIC as IDENTITY_PUBLIC, STATE_IDENTITY_SECRET as IDENTITY_SECRET};
}

/// The version of the core that is linked.
pub fn version() -> (i32, i32, i32) {
    let (mut a, mut b, mut c) = (0, 0, 0);
    // Safety: the core writes three integers that live for the call.
    unsafe { ffi::ZT_version(&mut a, &mut b, &mut c) };
    (a, b, c)
}

/// A planet of `id` at `ts` whose roots are `roots`: each a public identity
/// as the core writes it and its endpoint `IP/PORT`. Signed by a key made
/// for it and dropped, so no later planet replaces it.
pub fn world(id: u64, ts: u64, roots: &[(&str, &str)]) -> Result<Vec<u8>, String> {
    let texts = |words: Vec<&str>| -> Result<Vec<CString>, String> {
        words.into_iter().map(|w| CString::new(w).map_err(|_| "a NUL in a root".to_string())).collect()
    };
    let identities = texts(roots.iter().map(|r| r.0).collect())?;
    let endpoints = texts(roots.iter().map(|r| r.1).collect())?;
    let ids: Vec<_> = identities.iter().map(|c| c.as_ptr()).collect();
    let ends: Vec<_> = endpoints.iter().map(|c| c.as_ptr()).collect();
    let mut out = vec![0u8; 16_384];
    // Safety: each pointer lives for the call, and `out` holds `cap` bytes.
    let len = unsafe {
        ffi::podssh_zt_world(
            id,
            ts,
            ids.as_ptr(),
            ends.as_ptr(),
            roots.len() as u32,
            out.as_mut_ptr(),
            out.len() as u32,
        )
    };
    if len < 0 {
        return Err("the world could not be made: a root's identity or endpoint is not one".into());
    }
    out.truncate(len as usize);
    Ok(out)
}

#[cfg(test)]
mod mesh_tests;

#[cfg(test)]
mod tests {
    #[test]
    fn the_core_links_and_says_its_version() {
        let (major, minor, _) = super::version();
        assert!(major >= 1 && minor >= 10, "{major}.{minor}");
    }
}
