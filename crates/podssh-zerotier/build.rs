//! ZeroTierOne's core (`vendor/zerotier-node`, MPL-2.0), compiled as C++17
//! into a static library of this crate, with no service and no OS layer but
//! `osdep/OSUtils.cpp`, as `objects.mk`'s `CORE_OBJS` lists it.

use std::path::Path;

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/zerotier-node");
    let mut build = cc::Build::new();
    build.cpp(true).std("c++17").warnings(false).define("NDEBUG", None).define("ZT_NO_PEER_METRICS", None);
    // The core reads no JSON; only the service does.
    build.define("OMIT_JSON_SUPPORT", None);
    build.include(root.join("ext/prometheus-cpp-lite-1.0/core/include"));
    build.include(root.join("ext/prometheus-cpp-lite-1.0/simpleapi/include"));
    let mut files: Vec<_> = std::fs::read_dir(root.join("node"))
        .expect("vendor/zerotier-node/node")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "cpp"))
        .collect();
    files.push(root.join("osdep/OSUtils.cpp"));
    files.sort();
    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
        build.file(file);
    }
    build.compile("zerotiercore");
}
