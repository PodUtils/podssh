#!/bin/sh
# The host behind the proxy, as the fork's integration/server/run.sh sets
# it: each route but the default one, through the proxy, removed, so that
# a reply to the tunnel's address goes back through the tunnel alone; and
# checksums filled before a packet leaves.
set -eu
ethtool -K eth0 tx off
ip route replace default via "$GATEWAY" dev eth0
for route in $(ip route show | grep -v '^default' | awk '{print $1}'); do
    ip route del "$route"
done
ip route
/usr/sbin/sshd -e
exec socat TCP-LISTEN:7,fork,reuseaddr EXEC:cat
