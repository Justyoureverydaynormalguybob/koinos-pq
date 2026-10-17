# Testing record

## Offline (reproducible with `npm test`)
- `wasm/test/verify.test.mjs`: NIST ACVP ML-DSA-44 sigVer (external interface, pure):
  15/15 agree, 12 of them must-reject (wrong key, modified message, modified signature,
  invalid hint encoding, out-of-range z, etc.). Noble cross-check: 25 keypairs, 7 assertions each.
- `contract/scripts/test.sh`: 7/7 as-pect tests against `@koinos/mock-vm` with `dilithium.wasm`
  sharing the test module's memory, the same layout as on chain.

## Testnet (Harbinger)
*Pending: waiting on faucet funds. This section is filled in from the CLI output when it runs.*
