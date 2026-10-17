# bench

Native signature timings behind `docs/THROUGHPUT.md` (section 3) and the compute charge proposed for
the native ML-DSA-44 thunk in `docs/NATIVE-PLAN.md`. Everything runs in a throwaway Debian container,
so no compiler is needed on the host:

```sh
docker run --rm --cpus=4 -v "$PWD/bench:/bench:ro" -v "$PWD/dilithium:/pq:ro" debian:bookworm-slim sh /bench/run.sh
```

On Windows Git Bash: `MSYS_NO_PATHCONV=1 docker run ... -v "C:\path\to\koinos-pq\bench:/bench:ro" ...`.
Takes about eight minutes the first time (the SPHINCS+ signing loop is most of it).

- `bench_secp.c`: libsecp256k1 recoverable sign and `secp256k1_ecdsa_recover`, the operation behind
  Koinos's `recover_public_key` thunk (29,630 compute ticks).
- `bench_pqclean.c`: generic keygen / sign / verify timer, compiled once per scheme against PQClean's
  `api.h` or, with `-DCTXAPI`, against the upstream PQ-Crystals `sign.h` used by `dilithium/`.

Result recorded 2026-10-17 (Ryzen 7 7730U, gcc 12, `-O3 -march=native`): secp256k1 recovery 70 µs,
ML-DSA-44 reference verify 183 µs, ML-DSA-44 AVX2 verify 45 µs, Falcon-512 verify 78 µs.
