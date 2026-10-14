#!/usr/bin/env bash
# Records the traffic of four scenarios and replays it through two censor
# emulators built on CensorLab (https://censorlab.cs.umass.edu/).
#
#   CENSORLAB=/path/to/censorlab test/censor/run.sh
#
# The censors are stand-ins written for this project, so the result says how the
# traffic fares against these rules and not against a real censor. Each censor
# also runs on a scenario it must catch. A censor that misses its own control
# means the setup is broken, and the run fails.
#
# Needs sudo for tcpdump. Output goes to $WORK (default: a fresh temp dir).
set -euo pipefail

: "${CENSORLAB:?set CENSORLAB to the censorlab binary}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="${WORK:-$(mktemp -d)}"
CLIENT_IP=127.0.0.1
echo "work directory: $WORK"

# Scenario name -> loopback address of its server. Keep in step with
# internal/measure/lab/capture_test.go.
SCENARIOS=(reality:127.0.0.2 browsing:127.0.0.3 random:127.0.0.4 listed-sni:127.0.0.5)
CENSORS=(fully_encrypted sni_allowlist)

# expected CENSOR:SCENARIO -> 1 if the censor must act on that traffic.
declare -A EXPECT=(
  [fully_encrypted:reality]=0 [fully_encrypted:browsing]=0 [fully_encrypted:random]=1 [fully_encrypted:listed-sni]=0
  [sni_allowlist:reality]=0 [sni_allowlist:browsing]=0 [sni_allowlist:random]=0 [sni_allowlist:listed-sni]=1
)

echo "--- recording"
sudo tcpdump -i lo -U -w "$WORK/all.pcap" tcp >"$WORK/tcpdump.log" 2>&1 &
tcpdump_pid=$!
sleep 2
(cd "$ROOT" && REALITY_PT_CAPTURE=1 go test ./internal/measure/lab -run '^TestCaptureScenarios$' -count=1)
sleep 2
sudo kill "$tcpdump_pid" || true
wait "$tcpdump_pid" 2>/dev/null || true
sudo chown "$(id -u):$(id -g)" "$WORK/all.pcap"

for entry in "${SCENARIOS[@]}"; do
  name="${entry%%:*}"
  addr="${entry##*:}"
  tcpdump -r "$WORK/all.pcap" -w "$WORK/$name.pcap" "host $CLIENT_IP and host $addr" 2>/dev/null
  packets="$(tcpdump -r "$WORK/$name.pcap" -nn 2>/dev/null | wc -l)"
  echo "$name: $packets packets between $CLIENT_IP and $addr"
  if [ "$packets" -eq 0 ]; then
    echo "no packets captured for $name"
    exit 1
  fi
done

echo "--- censors"
failed=0
printf '%-18s' "censor"
for entry in "${SCENARIOS[@]}"; do printf '%-12s' "${entry%%:*}"; done
echo
for censor in "${CENSORS[@]}"; do
  printf '%-18s' "$censor"
  for entry in "${SCENARIOS[@]}"; do
    name="${entry%%:*}"
    log="$WORK/$censor.$name.log"
    "$CENSORLAB" -c "$HERE/$censor/censor.toml" pcap "$WORK/$name.pcap" "$CLIENT_IP" >"$log" 2>&1 || true
    acted="$(grep -cE '^[0-9]+:[[:space:]]+Ok\((Drop|Reset)' "$log" || true)"
    verdict=pass
    [ "$acted" -gt 0 ] && verdict=ACTED
    printf '%-12s' "$verdict($acted)"
    want="${EXPECT[$censor:$name]}"
    if { [ "$want" = 1 ] && [ "$acted" -eq 0 ]; } || { [ "$want" = 0 ] && [ "$acted" -gt 0 ]; }; then
      failed=1
      echo
      echo "unexpected: $censor on $name acted $acted times, expected $([ "$want" = 1 ] && echo some || echo none)"
      head -20 "$log"
    fi
  done
  echo
done

if [ "$failed" -ne 0 ]; then
  echo "FAILED: see the lines above and the logs in $WORK"
  exit 1
fi
echo "OK: each censor caught its control, and left the reality traffic and the browsing alone"
