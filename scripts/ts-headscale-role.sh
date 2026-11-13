# scripts/ts-headscale-role.sh - the stage of scripts/ts-headscale.sh whose
# DERP server is podssh's own relay role (T-106): `podssh relay serve
# --derp-keys FILE`, which admits the node keys of FILE alone, as the only
# DERP server of a second headscale; a target of tailscaled with Tailscale
# SSH, whose DERP home is that role, over derper's HTTP upgrade; and OpenSSH
# over `podssh ts -W`, in relay mode pinned to the role over a WebSocket,
# 1 MiB each way. Sourced by the harness; alone it runs nothing.
#
# The stage runs in a subshell, with a work directory, ports and container
# names of its own, so that the first stage's stay as they were: headscale
# on PORT+10 to PORT+13, the role on PORT+16. It reuses the first stage's
# CA, headscale's certificate for the role's TLS, the binary beside it and
# the input of 1 MiB. It writes two exit codes for the harness to read,
# 0 for each check that passed: $W/role-refused.rc (a node key that the
# role does not list: 1008, exit 77, and the role's line names the key) and
# $W/role-ssh.rc (1 MiB each way once the owner listed it). The role's file
# starts empty: the target's key comes from its own status, podssh's from
# the role's line of its refusal, as an owner would list each.

# role_derp_map RPORT: headscale's DERP map, the role on 127.0.0.1:RPORT as
# region 999 and the only one, written beside the configuration; and the
# configuration of hs_config made to take it, with no embedded DERP server.
role_derp_map() {
    cat >"$W/hs/derp.yaml" <<EOF
regions:
  999:
    regionid: 999
    regioncode: podssh-role
    regionname: podssh relay serve
    nodes:
      - name: 999a
        regionid: 999
        hostname: 127.0.0.1
        ipv4: 127.0.0.1
        stunport: -1
        stunonly: false
        derpport: $1
EOF
    sed -e 's/^    enabled: true$/    enabled: false/' \
        -e 's/automatically_add_embedded_derp_region: true/automatically_add_embedded_derp_region: false/' \
        -e 's|^  paths: \[\]$|  paths: [/etc/headscale/derp.yaml]|' "$W/hs/config.yaml" >"$W/hs/config.new" || return 1
    mv "$W/hs/config.new" "$W/hs/config.yaml"
    grep -q 'paths: \[/etc/headscale/derp.yaml\]' "$W/hs/config.yaml"
}

# role_refused_keys: each node key that the role refused, as its lines on
# stdout name them, once each.
role_refused_keys() {
    LC_ALL=C sed -n 's/^derp: refused the node key \(nodekey:[0-9a-f]\{64\}\).*/\1/p' "$W/out/role.log" | sort -u
}

# role_stage: the stage, in a subshell; see above.
role_stage() (
    P=$W
    W=$P/role
    PORT=$((PORT + 10))
    RPORT=$((PORT + 6))
    URL=https://127.0.0.1:$PORT
    HS_NAME=podssh-hs-role
    TARGET_NAME=podssh-hs-role-target
    OSSH_RELAY=127.0.0.1:$RPORT
    # Each check fails unless the stage reaches its pass.
    echo 1 >"$P/role-refused.rc"
    echo 1 >"$P/role-ssh.rc"
    mkdir -p "$W/hs" "$W/keys" "$W/state" "$W/in" "$W/out" || exit 1
    cp "$P/ca.pem" "$W/ca.pem" && cp "$P/hs/tls.crt" "$P/hs/tls.key" "$W/hs/" && cp "$P/in/up.bin" "$W/in/up.bin" ||
        exit 1
    : >"$W/derp-keys"
    noproxy "$BIN" relay serve --listen "127.0.0.1:$RPORT" --cert "$W/hs/tls.crt" --key "$W/hs/tls.key" \
        --derp-keys "$W/derp-keys" </dev/null >"$W/out/role.log" 2>"$W/out/role.err" &
    ROLE=$!
    trap 'kill "$ROLE" 2>/dev/null; timeout 60 "$ENGINE" rm -f "$HS_NAME" "$TARGET_NAME" >/dev/null 2>&1' EXIT
    wait_port "$RPORT"
    hs_config
    role_derp_map "$RPORT" || { echo "ts-headscale: the DERP map of the role was not written" >&2 && exit 1; }
    hs_start || { "$ENGINE" logs "$HS_NAME" 2>&1 | tail -20 && exit 1; }
    hs_keys || { cat "$W/hs-cli.log" && exit 1; }
    PKEY=$W/keys/a.key
    ts_node "$TARGET_NAME" target --ssh || { tail -20 "$W/$TARGET_NAME-up.log" && exit 1; }
    TARGET_IP=$(ts_cli "$TARGET_NAME" ip -4) || exit 1
    # The target's node key, from its own status: public, as each key here.
    ts_cli "$TARGET_NAME" status --json >"$W/target.json" || exit 1
    python3 -I -c 'import json, sys
print(json.load(open(sys.argv[1]))["Self"]["PublicKey"])' "$W/target.json" >>"$W/derp-keys" || exit 1
    # podssh's node, its key not listed yet: the role refuses it, and names it.
    pts role-refused "$PKEY" pipe-relay --ts-mode relay --ts-relay "$OSSH_RELAY" --timeout 60s
    keys=$(role_refused_keys)
    if [ "$rc" = 77 ] && [ -n "$keys" ] && grep -q 1008 "$W/out/role-refused.err"; then
        echo 0 >"$P/role-refused.rc"
    fi
    # Listed, as the owner lists a key that the role named; read at the next login.
    printf '%s\n' "$keys" >>"$W/derp-keys"
    if both role-ssh relay; then
        echo 0 >"$P/role-ssh.rc"
    fi
)
