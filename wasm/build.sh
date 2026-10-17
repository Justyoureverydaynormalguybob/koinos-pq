#!/bin/sh
# Builds dilithium.wasm: ML-DSA-44 verify only, WebAssembly MVP, imported memory.
# Layout: this module's data and 256 KiB stack occupy 64 KiB..~330 KiB of the importing module's memory.
# The AssemblyScript contract is compiled with --memoryBase 393216 so its data and heap start above that.
set -eu
cd "$(dirname "$0")/.."
OUT=wasm/dilithium.wasm
SRC="dilithium/sign.c dilithium/packing.c dilithium/poly.c dilithium/polyvec.c dilithium/ntt.c dilithium/reduce.c dilithium/rounding.c dilithium/fips202.c dilithium/symmetric-shake.c dilithium/mldsa44_wasm.c"
CFLAGS="--target=wasm32 -mcpu=mvp -O2 -DDILITHIUM_MODE=2 -ffreestanding -nostdlib -fno-builtin -Wall -Wextra -Wno-unused-parameter"
clang $CFLAGS -c dilithium/support.c -o wasm/support.o
clang $CFLAGS $SRC wasm/support.o -o "$OUT" \
  -Wl,--no-entry -Wl,--import-memory -Wl,--global-base=65536 -Wl,-z,stack-size=262144 \
  -Wl,--export=mldsa44_verify -Wl,--export=mldsa44_sizes -Wl,--strip-all
rm -f wasm/support.o
# Must validate as pure MVP: the Koinos VM (Fizzy) supports nothing newer.
wasm-validate --disable-bulk-memory --disable-sign-ext --disable-mutable-globals \
  --disable-saturating-float-to-int --disable-multi-value --disable-reference-types \
  --disable-simd "$OUT"
wasm-objdump -x "$OUT" | grep -E "^ - (memory|func|global)\[|import|export" | head -20
ls -l "$OUT"
