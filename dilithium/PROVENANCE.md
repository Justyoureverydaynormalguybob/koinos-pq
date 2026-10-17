# Provenance

This directory vendors the **reference implementation of CRYSTALS-Dilithium / ML-DSA (FIPS 204)**
from the PQ-Crystals project, https://github.com/pq-crystals/dilithium, `ref/` subdirectory,
upstream commit d35ba3fe5449bee3e6d43e1f296c3ca818bd36be (2026-06-03).
Licence: Public Domain (CC0) or Apache-2.0 or GPL-2.0 (see LICENSE). Keccak code is public domain.

Only the files needed for **signature verification** are vendored. Key generation and signing
are deliberately absent from the on-chain module; `randombytes.c` is not included and
`support.c` provides a trapping stub so the symbol can never be reached.

Why upstream and not Soqucoin's copy: Soqucoin (https://github.com/soqucoin/soqucoin, commit 35b38fcea458dbad37048a12112a93ec6043420a (2026-10-12),
`src/crypto/dilithium/ref`) was diffed against upstream on 2026-10-17. The only differences are in
`sign.c`: a `soqucoin_memcleanse` zeroisation of secret material in keypair/sign (Halborn FIND-028),
a deterministic `crypto_sign_seed_keypair`, and a `crypto_sign_check_keypair` helper. None of these
touch the verification path, and none are needed in a verify-only WASM build. Secret keys never
enter the contract. The Soqucoin design is credited for the integration approach.

Parameter set: DILITHIUM_MODE=2, i.e. ML-DSA-44: public key 1312 bytes, signature 2420 bytes.
