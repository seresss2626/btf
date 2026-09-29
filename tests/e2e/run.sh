#!/usr/bin/env bash
# TEST-ONLY: runs the real cloud function (in a local API Gateway simulator),
# the real adapter and three helpers (direct, relay, wrong e2eKey) and then
# functional + attack checks. Requires: node, go, and `npm install` in tests/e2e.
#
#   ./tests/e2e/run.sh            (set GO=/path/to/go-wrapper to override go)
set -euo pipefail
cd "$(dirname "$0")"
E2E=$(pwd)
ROOT=$(cd ../.. && pwd)
GO=${GO:-go}
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; wait 2>/dev/null || true; echo "logs: $WORK"' EXIT

AUTH=$(openssl rand -hex 24)
E2EKEY=$(openssl rand -hex 24)
export SIM_IAM_TOKEN="IAM-SECRET-TOKEN-SIM"
WS=18080 CTL=18081 GRPC=18082 ECHO=18095 AHTTP=18090 H1=18100 H2=18101 H3=18102

(cd "$ROOT/adapter-and-helper" && $GO build -o "$WORK/adapter" ./cmd/adapter && $GO build -o "$WORK/helper" ./cmd/helper && $GO build -o "$WORK/fakeyc" ./tests/fakeyc)

AUTH_TOKEN=$AUTH HTTP_URL="http://127.0.0.1:$AHTTP/secret-path" node "$E2E/sim.js" $WS $CTL >"$WORK/sim.log" 2>&1 &
"$WORK/fakeyc" 127.0.0.1:$GRPC "http://127.0.0.1:$CTL" >"$WORK/fakeyc.log" 2>&1 &
sleep 1
export BTF_TEST_WSAPI_ENDPOINT=127.0.0.1:$GRPC

cat >"$WORK/adapter.yaml" <<EOF
bridge: { url: "ws://127.0.0.1:$WS/_adapter", authToken: "$AUTH", e2eKey: "$E2EKEY", pingIntervalMs: 5000 }
target: { address: "127.0.0.1:$ECHO" }
http: { listenPort: $AHTTP, path: "/secret-path" }
writeCoalescing: { enabled: true, delayMs: 10 }
EOF
helper_cfg() { # port relay e2ekey
cat <<EOF
bridge: { url: "ws://127.0.0.1:$WS/_helper", authToken: "$AUTH", e2eKey: "$3", pingIntervalMs: 5000 }
listen: { address: "127.0.0.1:$1" }
wsApi: { relay: $2 }
writeCoalescing: { enabled: true, delayMs: 10 }
EOF
}
helper_cfg $H1 false "$E2EKEY" >"$WORK/h1.yaml"
helper_cfg $H2 true  "$E2EKEY" >"$WORK/h2.yaml"
helper_cfg $H3 false "$(openssl rand -hex 24)" >"$WORK/h3.yaml"

start_adapter() { "$WORK/adapter" "$WORK/adapter.yaml" >"$WORK/adapter.log" 2>&1 & }
start_helpers() {
  "$WORK/helper" "$WORK/h1.yaml" >"$WORK/h1.log" 2>&1 &
  "$WORK/helper" "$WORK/h2.yaml" >"$WORK/h2.log" 2>&1 &
  "$WORK/helper" "$WORK/h3.yaml" >"$WORK/h3.log" 2>&1 &
}
# START_ORDER=helpers-first simulates helpers connecting while the adapter is
# down (e.g. VPS reboot) — the case where shortIds used to collide.
if [ "${START_ORDER:-adapter-first}" = helpers-first ]; then
  start_helpers; sleep 4; start_adapter; sleep 2
else
  start_adapter; sleep 1; start_helpers; sleep 2
fi

set +e
node "$E2E/e2e.js" $ECHO $WS $CTL $H1 $H2 $H3 $AHTTP "$AUTH"
RC=$?
# MAUI client services (plain .NET build of maui-client/Services), if dotnet exists.
if command -v dotnet >/dev/null && [ "${SKIP_MAUI:-0}" != 1 ]; then
  export BTF_TEST_WSAPI_REST="http://127.0.0.1:$CTL"
  MAUI="$ROOT/tests/maui-services"
  dotnet build -c Release "$MAUI" >"$WORK/maui-build.log" 2>&1 || { echo "FAIL  MAUI build (see $WORK/maui-build.log)"; RC=1; }
  for relay in false true; do
    dotnet "$MAUI/bin/Release/net10.0/MauiServicesTests.dll" e2e "ws://127.0.0.1:$WS/_helper" 18110 $relay "$AUTH" "$E2EKEY" $ECHO || RC=1
  done
fi
echo "--- probe results ---"
grep -h "probe: " "$WORK"/h*.log | sed 's/^/  /'
echo "--- adapter: dropped unauthenticated messages ---"
grep -c "dropped unauthenticated" "$WORK/adapter.log" | sed 's/^/  /'
exit $RC
