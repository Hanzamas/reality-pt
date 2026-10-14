#!/usr/bin/env bash
# Starts a real Tor bridge that uses reality-server, then checks it with a real
# Tor client (scripts/tor-client-check.sh).
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
HERE="$(cd "$(dirname "$0")" && pwd)"

mkdir -p -m 700 "$WORK/bridge"
echo "work directory: $WORK"

# Copy tor so a distribution AppArmor profile keyed on /usr/bin/tor does not
# stop it from starting the transport.
cp "$(command -v tor)" "$WORK/tor-bridge"

bridge_pid=
cleanup() {
  [ -n "$bridge_pid" ] && kill "$bridge_pid" 2>/dev/null || true
}
trap cleanup EXIT

# wait_for FILE PATTERN SECONDS
wait_for() {
  local file=$1 pattern=$2 limit=$3 waited=0
  until grep -q -- "$pattern" "$file" 2>/dev/null; do
    if [ "$waited" -ge "$limit" ]; then
      echo "timed out after ${limit}s waiting for '$pattern' in $file"
      cat "$WORK/bridge.log" 2>/dev/null || true
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

"$WORK/tor-bridge" -f "$WORK/bridge.torrc" >"$WORK/bridge.stdout" 2>&1 &
bridge_pid=$!

wait_for "$WORK/bridge.log" "Registered server transport 'reality'" 120
wait_for "$WORK/bridge/fingerprint" "RealityCI" 60
# A client fetches the consensus through the bridge, so the bridge must have it
# first. Without this wait the client gets 404 from a bridge that is still starting.
wait_for "$WORK/bridge.log" "Bootstrapped 100%" 240
fingerprint="$(awk '{print $2}' "$WORK/bridge/fingerprint")"
echo "bridge fingerprint: $fingerprint"

# The server also writes the line for the operator. Check that it matches.
line_file="$WORK/bridge/pt_state/reality_bridge_line.txt"
test -s "$line_file"
bridge_line="$(sed -e "s|<IP ADDRESS>|127.0.0.1|" -e "s|<FINGERPRINT>|$fingerprint|" "$line_file")"
echo "bridge line from the server: $bridge_line"
grep -q "public-key=$public_key" <<<"$bridge_line"

BIN="$BIN" WORK="$WORK" BRIDGE_LINE="$bridge_line" bash "$HERE/tor-client-check.sh"
