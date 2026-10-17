# Phase B plan: native ML-DSA-44 in koinos-chain

*Start here on the laptop. Written 2026-10-17 on the phone session that built and tested the
contract route (see HANDOVER.md, docs/TESTING.md). This file is the handoff: it holds every fact
the next session needs, because the phone's notes do not travel.*

## Goal
Make the Koinos node itself verify ML-DSA-44 (FIPS 204) transaction signatures, so any account can
be post-quantum with no contract, at native speed and roughly normal cost. Deliver a reviewed fork
plus a pull request to koinos/koinos-chain; the Foundation decides adoption. Block signatures and
the proof-of-burn lottery are phase B2/B3 (design first, see docs/NATIVE-PROPOSAL.md).

## Forks (all under github.com/Justyoureverydaynormalguybob, created 2026-10-17)
- koinos-chain      (the node; the work happens here)
- koinos-proto      (.proto sources; only needed in B2 for the `dsa` enum / new system calls)
- koinos-proto-cpp  (generated C++ for the protos; B2)
- koinos-crypto-cpp (secp256k1 wrappers, multihash; a natural home for an `mldsa` helper, optional)

## Design for B1 (minimal, no protobuf change)
A second kind of entry in `transaction.signatures`:

    0x01 || public_key (1312 bytes) || signature (2420 bytes)      = 3733 bytes

The node's default authority check verifies `signature` with ML-DSA-44 (pure mode, FIPS 204) over
the 34-byte transaction id multihash, with an empty context (native path) — NOTE: the contract
route uses context "koinos/pqwallet/1"; the native path should use its own fixed context, e.g.
"koinos/tx/1", so the two can never be confused. Then it derives the signer address from the public
key exactly as it does for secp256k1 keys: address = version 0x00 || ripemd160(sha256(pk)) ||
4-byte checksum. A post-quantum account is therefore just an address whose key is ML-DSA; wallets
display it like any other. Moving over = send KOIN to the new address. 65-byte entries keep
working unchanged. No registry, no new state, no new system call. Later optimisation: an on-chain
key registry so steady-state transactions carry 2420 bytes instead of 3733.

Why this and not the `dsa` enum first: the enum lives in koinos-proto, which koinos-chain consumes
as a prebuilt Hunter package, so touching it means rebuilding three repos before the first test.
B1 is one repo and proves the whole path. B2 adds the enum, a `verify_signature(ml_dsa_44)` thunk
for contracts, block signatures, and the koilib/Kondor signer.

## Where the code goes (koinos-chain, master @ 2026-07-09, src/koinos/chain/system_calls.cpp)
- `THUNK_DEFINE( check_authority_result, ...` at ~line 1439; the default loop over
  `trx->signatures()` is ~lines 1505-1520: `recover_public_key(ecdsa_secp256k1, sig, trx->id())`
  → `.to_address_bytes()` → compare with `account`. Add: if `sig.size() == 3733 && sig[0] == 0x01`
  → ML-DSA verify over `trx->id()` → address from pk → compare. Keep the 65-byte branch first and
  unchanged. Any other size: skip (today the thunk asserts "unexpected signature length"; decide
  whether to keep asserting for sizes other than 65/3733 — keeping the assert is the conservative
  choice).
- `recover_public_key` thunk ~line 1197 (asserts 65 bytes) and `verify_signature` ~1271: unchanged
  in B1. `process_block_signature` ~826 (genesis default) unchanged.
- Also used by the PoB contract and governance: `check_system_authority` (~line 962) has its own
  signature loop against the genesis key; mirror the change there or leave for B2.
- Vendor the verifier: copy `dilithium/` from this repo (verify-only subset of upstream PQ-Crystals
  ref, DILITHIUM_MODE=2, byte-identical to upstream; see dilithium/PROVENANCE.md) into
  `koinos-chain/src/koinos/chain/pq/` and add it to `src/koinos/chain/CMakeLists.txt` as a static
  C library (`-DDILITHIUM_MODE=2`). `randombytes.c` is not needed for verify; keep the trapping
  stub pattern from `dilithium/support.c` or simply do not link it.
- Address derivation: see how `crypto::public_key::to_address_bytes()` is built in koinos-crypto-cpp
  (`src/koinos/crypto/elliptic.cpp`); reproduce the same bytes for an arbitrary byte string
  (sha256 → ripemd160 → version byte 0x00 → double-sha256 checksum). Put it next to the verify
  call as a small helper; it must produce the identical address that koilib/the JS side computes
  (see "JS side" below).
- Resource accounting: the thunk's compute cost comes from the `compute_bandwidth_registry`
  (execution_context.cpp ~229-341). The new branch runs native code outside the metered VM, so add
  an explicit `use_compute_bandwidth(...)` charge sized from a benchmark (measured 2026-10-17, see
  docs/THROUGHPUT.md section 3: the vendored reference verifier takes 2.6x a secp256k1 recovery, so charge
  90,000 ticks, about three recoveries, not the ten first guessed; an AVX2 build would justify ~20,000).

## Tests
1. Unit tests in `tests/thunk_test.cpp` next to the existing `recover_public_key` (~2750) and
   `verify_signature` (~2811) cases: build a transaction with a 3733-byte entry, call
   `check_authority`, expect true; flipped bit → false; wrong address → false; 65-byte entry still
   works; mixed list works in either order. Vectors: generate with `@noble/post-quantum` using
   `cli/lib.mjs` helpers (keygen from a 32-byte seed, sign the 34-byte id with the chosen context),
   and the NIST ACVP sigVer vectors in `wasm/test/acvp-mldsa44-sigver.json` for the raw verify
   function (all 15 must agree, 12 are must-reject).
2. Devnet: build the chain image from the fork (`docker build -t koinos-chain-pq .` in the fork,
   Alpine + Hunter, 30-60 min first time), run the standard koinos docker-compose
   (github.com/koinos/koinos) with the chain service swapped for the image and a private genesis
   whose genesis key you hold, then: fund a PQ address, send a transfer signed only with a
   3733-byte entry (extend `cli/send.mjs` with a `--native` mode that emits
   `0x01||pk||sig` instead of calling the contract route), see it mined; negative cases as in
   docs/TESTING.md. The koilib side needs no changes: `signatures` is already an opaque list.
3. Keep the contract route's tests green; nothing in koinos-pq changes except the CLI gaining
   `--native`.

## Building on the laptop
- Easiest: Docker. The fork's Dockerfile builds with gcc on Alpine; Hunter fetches and compiles
  Boost, RocksDB, gRPC, Protobuf, fizzy, secp256k1-vrf etc. (slow once, cached after). For tests,
  run an interactive builder container from the same base and `cmake -DBUILD_TESTING=ON`.
- Native (Ubuntu/Debian): `apt install build-essential cmake ccache git libgmp-dev`; then
  `cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON . && cmake --build . --parallel`.
- Dependency pins: `koinos-cmake` v1.0.10 → `Hunter/config.cmake`. Koinos packages can be
  overridden with local submodules at `external/proto` and `external/crypto`
  (`hunter_config(koinos_proto GIT_SUBMODULE "external/proto")`), which is how B2 would wire the
  forked proto/crypto repos in.
- Tooling we already have: `cli/lib.mjs` (ML-DSA keygen/sign/verify in JS, tx building, submit),
  `dilithium/` (vendored verifier), `wasm/test/*.json` (vectors).

## Acceptance for B1
- `tests/thunk_test.cpp` passes with the new cases; all existing tests still pass.
- Devnet: a transfer authorised only by a 3733-byte entry is mined; secp256k1 entries unaffected;
  measured compute cost recorded.
- A PR to koinos/koinos-chain with: the vendored verifier and its provenance, the thunk change,
  the tests, a `docs/` note describing the signature entry format and address derivation, and the
  benchmark behind the compute charge.
- Update docs/NATIVE-PROPOSAL.md and HANDOVER.md in this repo with the result.

## B2 / B3 (design now, build with the core developers)
- B2: `ml_dsa_44 = 1` in `koinos/chain/chain.proto` (koinos-proto → koinos-proto-cpp), a
  `verify_signature` thunk branch so contracts can verify ML-DSA natively, block signatures via the
  PoB contract's `process_block_signature` (koinos-contracts-as, `contracts/pob/assembly/Pob.ts`)
  and the koinos-block-producer signer, koilib `Signer` variant, Kondor.
- B3: replace the secp256k1 ECVRF lottery in PoB with a hash-chain commitment lottery (each producer
  registers a hash-chain head, reveals the next preimage per block, eligibility =
  H(seed || preimage) / VHP < target). Design document with security argument first; this is a
  consensus change and needs a governance vote.

## Throughput
Read docs/THROUGHPUT.md before touching the entry format or the compute charge. Summary: verification CPU
is a few percent of a transaction; bytes grow 6-13x; today's chain is compute-bound so transactions per
block do not fall; reserve a type-tag byte in the signature entry (0x01 key+sig now, 0x02 sig-only with a
stored key and a Falcon-512 tag later), add a per-node verification cache, and take a bandwidth-budget
proposal to governance with the dsa enum in B2.

## Reality checks
- The default authority thunk runs for every transaction on the network; a bug there halts the
  chain. Keep the 65-byte path byte-for-byte unchanged and gate the new branch on exact length.
- No one should run this fork as a mainnet validator; it is for a devnet and a PR.
- ML-DSA verify is native here, so the compute charge is a policy number, not a measurement of
  interpreted ticks; document how it was chosen.
