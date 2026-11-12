#!/bin/sh
# The proxy's start, as the fork's integration/proxy/run.sh does it, in
# POSIX sh: the interface that faces the server is the one that holds
# GATEWAY_IPV4; checksums are filled before a packet leaves (a raw socket
# reads what a veth's offload leaves unfilled); nothing is forwarded by the
# kernel, so each packet to the server went through the tunnel.
set -eu
SERVER_INTERFACE=eth1
if ip -4 addr show eth0 | grep -q "inet $GATEWAY_IPV4/"; then
    SERVER_INTERFACE=eth0
fi
export SERVER_INTERFACE
echo "the interface that faces the server: $SERVER_INTERFACE"
ethtool -K eth0 tx off
ethtool -K eth1 tx off
iptables -A FORWARD -i eth0 -o eth1 -j DROP
iptables -A FORWARD -i eth1 -o eth0 -j DROP
exec /proxy
