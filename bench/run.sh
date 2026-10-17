#!/bin/sh
# Native signature benchmark behind docs/THROUGHPUT.md section 3. Runs inside debian:bookworm-slim:
#
#   docker run --rm --cpus=4 -v "$PWD/bench:/bench:ro" -v "$PWD/dilithium:/pq:ro" debian:bookworm-slim sh /bench/run.sh
#
# (on Windows Git Bash prefix with MSYS_NO_PATHCONV=1 and use backslash paths). Builds libsecp256k1 v0.6.0
# with the recovery module, PQClean's clean/AVX2 ML-DSA, Falcon and SPHINCS+, and the verifier vendored
# in dilithium/, then times keygen / sign / verify single-threaded, median of N operations.
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends gcc make cmake git ca-certificates libc6-dev >/dev/null 2>&1
echo "== toolchain: $(gcc --version | head -1); cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2); flags: $(grep -m1 -o 'avx2\|avx512f' /proc/cpuinfo | sort -u | tr '\n' ' ')"
cd /tmp
git clone -q --depth 1 --branch v0.6.0 https://github.com/bitcoin-core/secp256k1.git >/dev/null 2>&1
git clone -q --depth 1 https://github.com/PQClean/PQClean.git >/dev/null 2>&1
cd secp256k1 && cmake -S . -B build -DSECP256K1_ENABLE_MODULE_RECOVERY=ON -DSECP256K1_BUILD_TESTS=OFF -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF -DSECP256K1_BUILD_BENCHMARK=OFF -DSECP256K1_BUILD_CTIME_TESTS=OFF -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build build --parallel >/dev/null && cd ..
CF="-O3 -march=native -DNDEBUG -w"
gcc $CF -I secp256k1/include /bench/bench_secp.c $(find secp256k1/build -name "libsecp256k1.a" | head -1) -o b_secp
P=PQClean; C="$P/common/fips202.c $P/common/randombytes.c $P/common/sha2.c $P/common/aes.c $P/common/sp800-185.c $P/common/nistseedexpander.c"
build() { d=$P/crypto_sign/$2; ns=$3; gcc $CF -I $P/common -I $d -DAPI_H="\"api.h\"" -DNS=$ns -DSTR="\"$1\"" /bench/bench_pqclean.c $d/*.c $(ls $d/*.S 2>/dev/null) $C -o "b_$1" 2>/tmp/err_$1.txt || { echo "build failed: $1"; head -5 /tmp/err_$1.txt; }; }
build ml-dsa-44-ref          ml-dsa-44/clean          PQCLEAN_MLDSA44_CLEAN_
build ml-dsa-44-avx2         ml-dsa-44/avx2           PQCLEAN_MLDSA44_AVX2_
build ml-dsa-65-avx2         ml-dsa-65/avx2           PQCLEAN_MLDSA65_AVX2_
build falcon-512-ref         falcon-512/clean         PQCLEAN_FALCON512_CLEAN_
build falcon-padded-512-avx2 falcon-padded-512/avx2   PQCLEAN_FALCONPADDED512_AVX2_
build sphincs-128s-avx2      sphincs-sha2-128s-simple/avx2 PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_
# The exact code NATIVE-PLAN.md vendors into the node: dilithium/ (upstream pq-crystals ref, MODE=2). Needs a randombytes for keygen/sign in the bench only.
cat > /tmp/rb.c <<'RB'
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
void randombytes(uint8_t *out, size_t outlen){ static FILE *f; if(!f) f=fopen("/dev/urandom","rb"); fread(out,1,outlen,f); }
RB
cp -r /pq /tmp/pqref && rm -f /tmp/pqref/support.c /tmp/pqref/mldsa44_wasm.c
gcc $CF -DDILITHIUM_MODE=2 -DCTXAPI -I /tmp/pqref -DAPI_H="\"sign.h\"" -DNS= -DSTR="\"koinos-pq vendored ref\"" /bench/bench_pqclean.c /tmp/pqref/*.c /tmp/rb.c -o b_vendored 2>/tmp/err_v.txt || { echo "vendored build failed"; head -20 /tmp/err_v.txt; }
echo "== results (single thread, median, microseconds; N is 500, or 256 for the vendored build where params.h defines N)"
for b in b_secp b_vendored b_ml-dsa-44-ref b_ml-dsa-44-avx2 b_ml-dsa-65-avx2 b_falcon-512-ref b_falcon-padded-512-avx2 b_sphincs-128s-avx2; do [ -x "$b" ] && ./$b; done
echo "== done"
