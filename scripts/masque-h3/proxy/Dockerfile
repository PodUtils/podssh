# connect-ip-go's integration proxy (Diniboy1123's fork, MIT) for
# scripts/masque-h3/interop.sh: its binary, built from the pinned commit in
# images/derper's Go, on images/box's Alpine (BASE, pinned to a digest),
# with the tools of its run.sh in place of the fork's Ubuntu.
ARG BASE
FROM ${BASE}
RUN apk add --no-cache iproute2 iptables ethtool
COPY proxy cert.pem key.pem run.sh /
WORKDIR /
ENTRYPOINT ["/bin/sh", "/run.sh"]
