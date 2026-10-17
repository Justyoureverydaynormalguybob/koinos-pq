#!/bin/sh
# Runs the as-pect unit tests against @koinos/mock-vm with the real ML-DSA verifier linked in.
set -eu
cd "$(dirname "$0")/.."
[ -f assembly/proto/pqwallet.ts ] || sh scripts/build.sh release >/dev/null
[ -f ../wasm/dilithium.wasm ] || sh ../wasm/build.sh >/dev/null
[ -f assembly/__tests__/fixtures.ts ] || (cd .. && node contract/scripts/fixtures.mjs)
node node_modules/@as-pect/cli/bin/asp.js --config as-pect.config.js "$@"
