# The image of podssh (the owner's ruling "ghcr.io", T-847): the static binary
# of a release on an empty base. release.yml builds it for each Linux
# architecture from the files of the release, and pushes
# ghcr.io/<owner>/podssh:<tag> as one multi-arch index (call C789 of
# podcrates, COORD-142). It is not under images/, which holds the pinned
# base images alone.
#
# The context has: podssh and the empty directories home/ and tmp/. There is
# no shell and no CA file: podssh uses its compiled-in roots.
FROM scratch
COPY --chmod=0755 podssh /usr/local/bin/
COPY --chown=65534:65534 home/ /home/podssh/
COPY --chown=65534:65534 tmp/ /tmp/
ENV HOME=/home/podssh \
    TMPDIR=/tmp
USER 65534:65534
WORKDIR /home/podssh
ENTRYPOINT ["/usr/local/bin/podssh"]
CMD ["--help"]
