#!/usr/bin/env bash
# Starts a real Tor client that uses reality-client to reach one bridge, waits
# for it to bootstrap, and fetches a page through it.
#
#   BIN=/path/to/binaries BRIDGE_LINE='Bridge reality 1.2.3.4:443 FPR public-key=... short-id=... sni=...' \
#     scripts/tor-client-check.sh
#
# BIN must hold reality-client. Logs end up in $WORK (default: a fresh temp
# directory).
set -euo pipefail

: "${BIN:?set BIN to the directory with reality-client}"
: "${BRIDGE_LINE:?set BRIDGE_LINE to a full Bridge line}"
WORK="${WORK:-$(mktemp -d)}"
SOCKS_PORT="${SOCKS_PORT:-19050}"

mkdir -p -m 700 "$WORK/client"

# Copy tor so a distribution AppArmor profile keyed on /usr/bin/tor does not
# stop it from starting the transport.
cp "$(command -v tor)" "$WORK/tor-client"

cat >"$WORK/client.torrc" <<EOF
DataDirectory $WORK/client
Log notice file $WORK/client.log
SocksPort 127.0.0.1:$SOCKS_PORT
UseBridges 1
ClientTransportPlugin reality exec $BIN/reality-client
$BRIDGE_LINE
EOF

"$WORK/tor-client" -f "$WORK/client.torrc" >"$WORK/client.stdout" 2>&1 &
tor_pid=$!
trap 'kill "$tor_pid" 2>/dev/null || true' EXIT

waited=0
until grep -q "Bootstrapped 100%" "$WORK/client.log" 2>/dev/null; do
  if [ "$waited" -ge 300 ]; then
    echo "client did not bootstrap within 300s"
    cat "$WORK/client.log" 2>/dev/null || true
    exit 1
  fi
  sleep 2
  waited=$((waited + 2))
done
echo "client bootstrapped through the transport"

answer="$(curl --fail --silent --show-error --max-time 90 \
  --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
  https://check.torproject.org/api/ip)"
echo "check.torproject.org says: $answer"
grep -q '"IsTor":true' <<<"$answer"
echo "OK: traffic left through the Tor network via reality-pt"
