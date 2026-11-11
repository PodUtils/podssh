//! ZeroTier's core for podssh (T-733): `vendor/zerotier-node`, MPL-2.0,
//! linked statically.

unsafe extern "C" {
    fn ZT_version(major: *mut i32, minor: *mut i32, revision: *mut i32);
}

/// The version of the core that is linked.
pub fn version() -> (i32, i32, i32) {
    let (mut a, mut b, mut c) = (0, 0, 0);
    // Safety: the core writes three integers that live for the call.
    unsafe { ZT_version(&mut a, &mut b, &mut c) };
    (a, b, c)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_core_links_and_says_its_version() {
        let (major, minor, _) = super::version();
        assert!(major >= 1 && minor >= 10, "{major}.{minor}");
    }
}
