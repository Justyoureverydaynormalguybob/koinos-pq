#!/bin/sh
# Builds the Pqwallet contract: protobuf -> AssemblyScript -> contract.wasm, then links in the
# ML-DSA-44 verifier (../wasm/dilithium.wasm) with wasm-merge and validates pure-MVP WebAssembly.
#
# Usage: scripts/build.sh [debug|release] [--no-compare | --update-dist]
#
#   (no flag)       Build into build/<mode>/. For release, then compare the result with the committed
#                   ../dist/ and FAIL if a single byte differs. dist/ is never written.
#   --no-compare    Build only. The mock-VM tests use this to get the generated sources.
#   --update-dist   Build, then copy the result into ../dist/ and rewrite ../dist/SHA256SUMS.
#                   This is the ONLY way dist/ changes, and it is a deliberate act: dist/pqwallet.wasm
#                   is the file the CLI uploads and the file koinos-pq-core embeds. Review the diff
#                   and say in the commit why the bytes changed.
#
# Before this, every build copied its output into dist/ and wrote the sums again, so
# `npm run build && sha256sum -c dist/SHA256SUMS` passed whatever had been built.
set -eu
cd "$(dirname "$0")/.."
MODE=release
AFTER=compare
for a in "$@"; do
  case "$a" in
    debug|release) MODE="$a" ;;
    --no-compare) AFTER=none ;;
    --update-dist) AFTER=update ;;
    *) echo "usage: scripts/build.sh [debug|release] [--no-compare | --update-dist]"; exit 2 ;;
  esac
done
if [ "$MODE" != release ] && [ "$AFTER" = update ]; then echo "only a release build can update dist/"; exit 2; fi
STUBS="$PWD/.stubs"
# koinos/*.proto and google/protobuf/*.proto imports come from @koinos/proto-as. The sdk-as-cli template
# copies them into a project as koinos/ and google/ (both gitignored here); a clean checkout has neither.
PROTO_I="-I . -I node_modules/@koinos/proto-as/assembly"
# The abi plugin runs its own `protoc assembly/proto/pqwallet.proto` from this directory with no -I, so the
# imports must exist here too, laid out as the sdk-as-cli template does (koinos/, google/; both gitignored).
[ -d koinos ] || (cd node_modules/@koinos/proto-as/assembly && find koinos google -name '*.proto') | while read -r p; do
  mkdir -p "$(dirname "$p")" && cp "node_modules/@koinos/proto-as/assembly/$p" "$p"
done
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
protoc $PROTO_I --plugin=protoc-gen-abi="$STUBS/koinos-abi-proto-gen" --abi_out=abi/ assembly/proto/pqwallet.proto
echo "[2/5] proto -> AssemblyScript"
protoc $PROTO_I --plugin=protoc-gen-as="$STUBS/as-proto-gen" --as_out=. assembly/proto/*.proto
echo "[3/5] dispatcher (index.ts) with authorize entry point"
GENERATE_AUTHORIZE_ENTRY_POINT=1 RETURN_BUFFER_SIZE=8192 protoc $PROTO_I --plugin=protoc-gen-as="$STUBS/koinos-as-gen" --as_out=assembly/ assembly/proto/pqwallet.proto
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

# ---- the result against the committed dist/ ----
sum_of() { sha256sum "$1" | cut -d' ' -f1; }
committed() { awk -v f="$1" '{ n = $2; sub(/^\*/, "", n); sub(/\r$/, "", n); if (n == f) print $1 }' ../dist/SHA256SUMS; }
compare_one() { # <name in dist/> <file just built>
  built="$(sum_of "$2")"; want="$(committed "$1")"; indist="$(sum_of "../dist/$1")"
  if [ "$built" = "$want" ] && [ "$indist" = "$want" ]; then
    echo "  same   $1  $built"
  else
    echo "  DIFFERENT  $1"
    echo "    built now         $built  ($2)"
    echo "    dist/SHA256SUMS   ${want:-(no entry)}"
    echo "    dist/$1 on disk   $indist"
    DIFF=1
  fi
}
if [ "$MODE" = release ] && [ "$AFTER" = compare ]; then
  echo "comparing this build with the committed dist/:"
  DIFF=0
  compare_one pqwallet.wasm "build/$MODE/pqwallet.wasm"
  compare_one pqwallet.abi abi/pqwallet.abi
  compare_one dilithium.wasm ../wasm/dilithium.wasm
  if [ "$DIFF" != 0 ]; then
    echo "The build does NOT reproduce dist/. dist/ was left as it is."
    echo "If the source was changed on purpose, run: sh scripts/build.sh release --update-dist"
    echo "Otherwise find out why (toolchain versions are listed in docs/SECURITY.md) before uploading anything."
    exit 1
  fi
  echo "this build reproduces dist/ byte for byte"
elif [ "$AFTER" = update ]; then
  mkdir -p ../dist
  cp "build/$MODE/pqwallet.wasm" ../dist/pqwallet.wasm
  cp abi/pqwallet.abi ../dist/pqwallet.abi
  cp ../wasm/dilithium.wasm ../dist/dilithium.wasm
  (cd ../dist && sha256sum pqwallet.wasm pqwallet.abi dilithium.wasm > SHA256SUMS)
  echo "dist/ UPDATED: $(cut -c1-16 ../dist/SHA256SUMS | tr '\n' ' ')"
  echo "Check 'git diff --stat dist/': deployed accounts and koinos-pq-core carry the previous pqwallet.wasm."
fi
