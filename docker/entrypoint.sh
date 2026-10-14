#!/bin/sh
# Starts a private Tor bridge that serves the reality transport and prints the
# bridge line to give to users.
#
# Required:
#   REALITY_DEST          cover site as host:port, for example www.microsoft.com:443
# Optional:
#   REALITY_SERVER_NAMES  comma-separated SNI values (default: host of REALITY_DEST)
#   REALITY_PRIVATE_KEY   with REALITY_SHORT_IDS, use these instead of generating keys
#   REALITY_SHORT_IDS     comma-separated short IDs
#   PT_PORT               port the transport listens on (default 443)
#   PUBLIC_IP             address to put in the printed bridge line
#   NICKNAME, CONTACT     Tor nickname and contact info
set -eu

state=/var/lib/tor
: "${REALITY_DEST:?set REALITY_DEST to the cover site as host:port, for example www.microsoft.com:443}"
cover_host="${REALITY_DEST%:*}"
server_names="${REALITY_SERVER_NAMES:-$cover_host}"
pt_port="${PT_PORT:-443}"
keys_file="$state/reality-keys"

if [ -n "${REALITY_PRIVATE_KEY:-}" ] && [ -n "${REALITY_SHORT_IDS:-}" ]; then
  private_key="$REALITY_PRIVATE_KEY"
  short_ids="$REALITY_SHORT_IDS"
elif [ -s "$keys_file" ]; then
  # Keys made on an earlier start, kept in the volume. Read them as data.
  private_key="$(sed -n 's/^private-key=//p' "$keys_file")"
  short_ids="$(sed -n 's/^short-ids=//p' "$keys_file")"
else
  generated="$(reality-keygen)"
  private_key="$(echo "$generated" | awk '/^private-key:/ {print $2}')"
  short_ids="$(echo "$generated" | awk '/^short-id:/ {print $2}')"
  (umask 077 && printf 'private-key=%s\nshort-ids=%s\n' "$private_key" "$short_ids" >"$keys_file")
  echo "generated new keys, stored in the volume"
fi

cat >"$state/torrc" <<EOF
DataDirectory $state
SocksPort 0
BridgeRelay 1
PublishServerDescriptor 0
AssumeReachable 1
ORPort 127.0.0.1:auto
ExtORPort auto
ExitRelay 0
ExitPolicy reject *:*
Nickname ${NICKNAME:-RealityBridge}
ContactInfo ${CONTACT:-none}
Log notice stdout
ServerTransportPlugin reality exec /usr/local/bin/reality-server
ServerTransportListenAddr reality 0.0.0.0:$pt_port
ServerTransportOptions reality private-key=$private_key dest=$REALITY_DEST server-names=$server_names short-ids=$short_ids
EOF

tor -f "$state/torrc" &
tor_pid=$!
trap 'kill "$tor_pid" 2>/dev/null || true' TERM INT

line_file="$state/pt_state/reality_bridge_line.txt"
waited=0
until [ -s "$line_file" ] && [ -s "$state/fingerprint" ]; do
  if ! kill -0 "$tor_pid" 2>/dev/null; then
    echo "tor exited before the bridge was ready" >&2
    wait "$tor_pid" || true
    exit 1
  fi
  if [ "$waited" -ge 120 ]; then
    echo "the bridge was not ready after 120 seconds" >&2
    exit 1
  fi
  sleep 1
  waited=$((waited + 1))
done

fingerprint="$(awk '{print $2}' "$state/fingerprint")"
line="$(sed -e "s|<IP ADDRESS>|${PUBLIC_IP:-<IP ADDRESS>}|" -e "s|<FINGERPRINT>|$fingerprint|" "$line_file")"
echo
echo "=============================================================="
echo "Give this line to your users:"
echo
echo "$line"
echo "=============================================================="
echo

wait "$tor_pid"
