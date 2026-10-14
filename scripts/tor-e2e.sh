#!/usr/bin/env bash
# Starts a real Tor bridge and a real Tor client that reach each other through
# reality-pt, then fetches a page through the client.
#
#   BIN=/path/to/binaries scripts/tor-e2e.sh
#
# BIN must hold reality-client, reality-server and reality-keygen. The cover
# site (COVER_HOST, default www.cloudflare.com) must be reachable and speak
# TLS 1.3. Logs end up in $WORK (default: a fresh temp directory).
set -euo pipefail

: "${BIN:?set BIN to the directory with the reality binaries}"
COVER_HOST="${COVER_HOST:-www.cloudflare.com}"
WORK="${WORK:-$(mktemp -d)}"
BRIDGE_PT_PORT=9443
CLIENT_SOCKS_PORT=19050

mkdir -p -m 700 "$WORK/bridge" "$WORK/client"
echo "work directory: $WORK"

# Copy tor so a distribution AppArmor profile keyed on /usr/bin/tor does not
# stop it from starting the transports.
cp "$(command -v tor)" "$WORK/tor"
TOR="$WORK/tor"

pids=()
cleanup() {
  for pid in "${pids[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

dump_logs() {
  for f in "$WORK"/bridge.log "$WORK"/client.log; do
    echo "::group::$f"
    cat "$f" 2>/dev/null || true
    echo "::endgroup::"
  done
}

# wait_for FILE PATTERN SECONDS
wait_for() {
  local file=$1 pattern=$2 limit=$3 waited=0
  until grep -q -- "$pattern" "$file" 2>/dev/null; do
    if [ "$waited" -ge "$limit" ]; then
      echo "timed out after ${limit}s waiting for '$pattern' in $file"
      dump_logs
      exit 1
    fi
    sleep 2
    waited=$((waited + 2))
  done
}

keys="$("$BIN/reality-keygen")"
private_key="$(awk '/^private-key:/ {print $2}' <<<"$keys")"
public_key="$(awk '/^public-key:/ {print $2}' <<<"$keys")"
short_id="$(awk '/^short-id:/ {print $2}' <<<"$keys")"

cat >"$WORK/bridge.torrc" <<EOF
DataDirectory $WORK/bridge
Log notice file $WORK/bridge.log
SocksPort 0
BridgeRelay 1
PublishServerDescriptor 0
AssumeReachable 1
ORPort 127.0.0.1:auto
ExtORPort auto
ExitRelay 0
ExitPolicy reject *:*
Nickname RealityCI
ServerTransportPlugin reality exec $BIN/reality-server
ServerTransportListenAddr reality 127.0.0.1:$BRIDGE_PT_PORT
ServerTransportOptions reality private-key=$private_key dest=$COVER_HOST:443 server-names=$COVER_HOST short-ids=$short_id
EOF

"$TOR" -f "$WORK/bridge.torrc" >"$WORK/bridge.stdout" 2>&1 &
pids+=($!)

wait_for "$WORK/bridge.log" "Registered server transport 'reality'" 120
wait_for "$WORK/bridge/fingerprint" "RealityCI" 60
fingerprint="$(awk '{print $2}' "$WORK/bridge/fingerprint")"
echo "bridge fingerprint: $fingerprint"

cat >"$WORK/client.torrc" <<EOF
DataDirectory $WORK/client
Log notice file $WORK/client.log
SocksPort 127.0.0.1:$CLIENT_SOCKS_PORT
UseBridges 1
ClientTransportPlugin reality exec $BIN/reality-client
Bridge reality 127.0.0.1:$BRIDGE_PT_PORT $fingerprint public-key=$public_key short-id=$short_id sni=$COVER_HOST
EOF

"$TOR" -f "$WORK/client.torrc" >"$WORK/client.stdout" 2>&1 &
pids+=($!)

wait_for "$WORK/client.log" "Bootstrapped 100%" 300
echo "client bootstrapped through the transport"

answer="$(curl --fail --silent --show-error --max-time 90 \
  --socks5-hostname "127.0.0.1:$CLIENT_SOCKS_PORT" \
  https://check.torproject.org/api/ip)"
echo "check.torproject.org says: $answer"
grep -q '"IsTor":true' <<<"$answer"
echo "OK: traffic left through the Tor network via reality-pt"
