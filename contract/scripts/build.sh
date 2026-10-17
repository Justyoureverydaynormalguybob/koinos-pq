#!/bin/sh
# Builds the Pqwallet contract: protobuf -> AssemblyScript -> contract.wasm, then links in the
# ML-DSA-44 verifier (../wasm/dilithium.wasm) with wasm-merge and validates pure-MVP WebAssembly.
# Usage: scripts/build.sh [debug|release]
set -eu
cd "$(dirname "$0")/.."
MODE="${1:-release}"
STUBS="$PWD/.stubs"
mkdir -p "$STUBS" abi "build/$MODE"

# protoc plugins ship with a `#!/usr/bin/env node` shebang; wrap them in plain sh stubs (Termux).
for p in koinos-abi-proto-gen as-proto-gen koinos-as-gen; do
  real="$(node -e "console.log(require('fs').realpathSync('node_modules/.bin/$p'))")"
  printf '#!%s\nt="$(mktemp)"\ncat > "$t"\nnode "%s" "$@" < "$t"\nrc=$?\nrm -f "$t"\nexit $rc\n' "$(command -v sh)" "$real" > "$STUBS/$p"
  chmod +x "$STUBS/$p"
done
command -v protoc >/dev/null || { echo "protoc not found (pkg install protobuf)"; exit 1; }
[ -f ../wasm/dilithium.wasm ] || sh ../wasm/build.sh

echo "[1/5] ABI"
protoc --plugin=protoc-gen-abi="$STUBS/koinos-abi-proto-gen" --abi_out=abi/ assembly/proto/pqwallet.proto
echo "[2/5] proto -> AssemblyScript"
protoc --plugin=protoc-gen-as="$STUBS/as-proto-gen" --as_out=. assembly/proto/*.proto
echo "[3/5] dispatcher (index.ts) with authorize entry point"
GENERATE_AUTHORIZE_ENTRY_POINT=1 RETURN_BUFFER_SIZE=8192 protoc --plugin=protoc-gen-as="$STUBS/koinos-as-gen" --as_out=assembly/ assembly/proto/pqwallet.proto
echo "[4/5] asc ($MODE)"
node ./node_modules/assemblyscript/bin/asc assembly/index.ts --target "$MODE" --use abort= \
  --disable sign-extension --disable bulk-memory --config asconfig.json
echo "[5/5] wasm-merge contract + dilithium -> pqwallet.wasm"
# The AS module is named "env" so the verifier's `env.memory` import binds to the contract's memory.
wasm-merge "build/$MODE/contract.wasm" env ../wasm/dilithium.wasm dilithium -o "build/$MODE/pqwallet.wasm" \
  --disable-bulk-memory --disable-sign-ext --disable-mutable-globals --disable-nontrapping-float-to-int \
  --disable-multivalue --disable-reference-types --disable-simd
wasm-validate --disable-bulk-memory --disable-sign-ext --disable-mutable-globals \
  --disable-saturating-float-to-int --disable-multi-value --disable-reference-types --disable-simd \
  "build/$MODE/pqwallet.wasm"
echo "imports/exports of the merged module:"
wasm-objdump -x "build/$MODE/pqwallet.wasm" | grep -E "<- |-> " | grep -v -E "func\[[0-9]+\] <" | head -20
wasm-objdump -x "build/$MODE/pqwallet.wasm" | grep -E "^ - memory\[" | head -3
ls -la "build/$MODE/pqwallet.wasm" abi/pqwallet.abi
mkdir -p ../dist
cp "build/$MODE/pqwallet.wasm" ../dist/pqwallet.wasm
cp abi/pqwallet.abi ../dist/pqwallet.abi
cp ../wasm/dilithium.wasm ../dist/dilithium.wasm
(cd ../dist && sha256sum pqwallet.wasm pqwallet.abi dilithium.wasm > SHA256SUMS)
echo "dist/: $(cat ../dist/SHA256SUMS | cut -c1-16 | tr '\n' ' ')"
