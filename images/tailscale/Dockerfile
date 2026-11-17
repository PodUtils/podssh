# Tailscale's own image, for the tailscaled nodes of scripts/ts-headscale.sh
# (T-334): the target, with Tailscale SSH, and the peer of OpenSSH's path.
# Pinned to the digest of its index (tailscale/tailscale:v1.104.4, Dependabot's
# GitHub #78 of 2026-11-01). headscale 0.29.7's table of client versions ends
# at an older release, but this one joins its tailnet: the harness's 14 runs
# passed on it in Actions (T-386).
FROM docker.io/tailscale/tailscale:v1.104.7@sha256:72c1e19e0aedca96b8533bbb0b4368564410ff20b17e53b804eb6c1f04a31be4
