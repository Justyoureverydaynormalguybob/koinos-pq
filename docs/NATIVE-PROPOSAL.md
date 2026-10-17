# Proposal: native ML-DSA-44 in koinos-chain

Status: draft for discussion with the Koinos Foundation / Koinos Fund System. Written 2026-10-17.

## Why
`pqwallet` proves a post-quantum account works inside the current protocol, but it verifies in
interpreted WASM and needs a contract per account. A native digital-signature type lets *every*
account go post-quantum with no contract, at native speed, and is a prerequisite for post-quantum
block production.

## Change set (all in the open repos)
1. **koinos-proto** `koinos/chain/chain.proto`: `enum dsa { ecdsa_secp256k1 = 0; ml_dsa_44 = 1; }`.
2. **koinos-chain** `system_calls.cpp`:
   - `verify_signature`: when `type == ml_dsa_44`, call the vendored FIPS 204 reference
     (`crypto_sign_verify`, `DILITHIUM_MODE=2`) with `digest` as the message and an empty or
     chain-defined context; `compressed` ignored. Register a compute cost in the
     `compute_bandwidth_registry` for the new thunk path (measure, then set).
   - `recover_public_key`: ML-DSA has no recovery; return `unknown_dsa` for `ml_dsa_44`.
   - Default authority (`_check_authority`): for each signature, if length 65 keep the current
     recovery path; if length 2420, look up the signer's registered ML-DSA key (see 3) and verify.
3. **Key registration**: a system-space map `address -> ml_dsa_44 public key`, set by a new
   `register_public_key`-style system contract entry, authorised under the account's current
   rule. Alternative: a new address version byte whose preimage is the hash of the ML-DSA key and
   whose transactions carry the key inline (3.7 KB/tx). Registration is the cheaper steady state.
4. **koilib / Kondor**: `Signer` variant producing 2420-byte signatures from a 32-byte seed
   (`@noble/post-quantum` `ml_dsa44`); JSON encoding unchanged (base64url in `signatures`).
5. **Governance**: node release first, then a proposal flipping the `verify_signature` system
   call to the new thunk (60% of blocks over the two-week vote).

## Later: consensus
Proof-of-burn eligibility uses a secp256k1 ECVRF and blocks are ECDSA-signed. No standard
post-quantum VRF exists. The workable replacement is a hash-chain lottery: each producer
registers the head of a hash chain, reveals the next preimage with each block, and eligibility
is `H(seed || preimage) / VHP < target`, exactly today's inequality. Block signatures become
ML-DSA-44 (or Falcon-512 when FIPS 206 is final: 666-byte signatures, cheaper verify).

## Sizes
| scheme | public key | signature |
|---|---|---|
| secp256k1 (today) | 33 | 65 |
| ML-DSA-44 | 1312 | 2420 |
| Falcon-512 | 897 | 666 |
