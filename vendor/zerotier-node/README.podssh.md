# vendor/zerotier-node

ZeroTierOne's core, as podssh links it (T-733): `node/`, `include/`, `version.h`, and from `osdep/` the
`OSUtils` that `objects.mk`'s `CORE_OBJS` names and the headers that `node/` includes, at ZeroTierOne
commit `899352e` (2026-07-22), MPL-2.0 (`LICENSE-MPL.txt`); and the header-only
`ext/prometheus-cpp-lite-1.0` (MIT, its `LICENSE`) that `node/Metrics` includes. No file is changed.
`nonfree/` (the controller) and `service/` are not taken. `crates/podssh-zerotier/build.rs` builds it.
It is outside the workspace's rules of length, as `vendor/tailscale-rs` is.
