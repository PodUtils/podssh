# The host behind the proxy for scripts/masque-h3/interop.sh: OpenSSH's sshd
# on port 22 and an echo of socat on port 7, on images/box's Alpine (BASE,
# pinned to a digest).
ARG BASE
FROM ${BASE}
RUN apk add --no-cache openssh-server socat iproute2 ethtool && ssh-keygen -A
COPY run.sh /
ENTRYPOINT ["/bin/sh", "/run.sh"]
