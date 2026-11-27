#!/bin/sh
# Runs the as-pect unit tests against @koinos/mock-vm with the real ML-DSA verifier linked in.
set -eu
cd "$(dirname "$0")/.."
# --no-compare: only the generated sources are needed here; comparing with dist/ is `npm run build:contract`
[ -f assembly/proto/pqwallet.ts ] || sh scripts/build.sh release --no-compare >/dev/null
[ -f ../wasm/dilithium.wasm ] || sh ../wasm/build.sh >/dev/null
[ -f assembly/__tests__/fixtures.ts ] || (cd .. && node contract/scripts/fixtures.mjs)
node node_modules/@as-pect/cli/bin/asp.js --config as-pect.config.js "$@"
