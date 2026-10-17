# koinos-pq

A post-quantum account for the Koinos blockchain, working today, with no change to the chain.

Upload the `pqwallet` contract to your own address, register an **ML-DSA-44** (NIST FIPS 204)
public key, and from then on the account is authorised only by an ML-DSA-44 signature over the
transaction id. The secp256k1 key that a quantum computer could one day break stops mattering.

```
wasm/        FIPS 204 reference verifier (C, vendored from PQ-Crystals) compiled to MVP WebAssembly
contract/    AssemblyScript account contract; wasm-merge links the verifier in
cli/         testnet tooling: keys, fund, deploy, register, send, lock, status
dist/        built artefacts with SHA256SUMS
docs/        SPEC.md (contract spec), NATIVE-PROPOSAL.md (chain-level follow-up), TESTING.md
HANDOVER.md  start here
```

`npm test` runs the NIST ACVP vectors and a noble cross-check against the WASM verifier, then the
contract tests in the Koinos mock VM with the real verifier linked.
