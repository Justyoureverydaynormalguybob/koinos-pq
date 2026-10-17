# pqwallet contract specification (v1)

## Purpose
Replace an account's authority rule with ML-DSA-44 (FIPS 204) signature verification, using
Koinos's per-address `authorize` override. No chain change.

## Deployment
`upload_contract` to the account's own address with
`authorizes_call_contract = true`, `authorizes_transaction_application = true`,
and (after bootstrap) `authorizes_upload_contract = true`. ABI: `dist/pqwallet.abi`.

## State
Space 0, object `config_object { bytes public_key = 1; uint64 verifications = 2; }`.

## Entry points
| name | id | args | result | auth |
|---|---|---|---|---|
| `authorize` | `0x4a2dbd90` (reserved) | `koinos.chain.authorize_arguments` | `authorize_result{value}` | kernel only |
| `set_public_key` | sha256("set_public_key")[0:4] | `{bytes public_key}` 1312 B | `{}` | rule below |
| `get_public_key` | | `{}` | `{bytes value}` | read-only |
| `get_info` | | `{}` | scheme, sizes, context, key_registered, verifications | read-only |

## The rule (`authorizedByTransaction`)
Let `tx = get_transaction()`, `id = tx.id` (34-byte sha2-256 multihash), `pk = config.public_key`.
- If `pk` is not exactly 1312 bytes (no key yet): authorised iff some `tx.signatures[i]` of length 65
  recovers (secp256k1, over `id`) to a public key whose address equals the contract id. This is the
  chain's default rule, re-implemented, so bootstrap transactions keep working.
- Otherwise: authorised iff some `tx.signatures[i]` of length 2420 satisfies
  `ML-DSA-44.Verify(pk, M = id, sig, ctx = "koinos/pqwallet/1")` (pure mode, FIPS 204 §5.3 with
  the context prefix `0x00 || len(ctx) || ctx`). On success `verifications += 1`.
All three authorization types use the same rule.

`set_public_key` requires the rule to pass and the new key to be 1312 bytes; emits
`pqwallet.key_set { account, public_key_hash = sha2-256 multihash of the key }`.

## Signature wire format
Raw 2420-byte ML-DSA-44 signature as one element of `transaction.signatures` (base64url in JSON).
No prefix byte: the contract distinguishes by length (65 vs 2420). Other elements are ignored.

## Verifier
`wasm/dilithium.wasm`: PQ-Crystals reference, `DILITHIUM_MODE=2`, verify path only, exported
`mldsa44_verify(sig, siglen, msg, msglen, ctx, ctxlen, pk, pklen) -> i32` and `mldsa44_sizes()`.
Freestanding (own memcpy/memset/memcmp), `randombytes` traps. MVP features only (`-mcpu=mvp`),
validated with `wasm-validate` with every post-MVP feature disabled. Imports `env.memory`; data
and a 256 KiB stack at 64 KiB..~330 KiB. The AssemblyScript module is built with
`--memoryBase 393216` so the two never overlap; `wasm-merge` fuses them into one module whose only
import is `env.invoke_system_call`.

## Resource notes
- SDK system-call buffer raised to 16 KiB (`System.setSystemBufferSize`) and dispatcher return
  buffer to 8 KiB: a transaction with one ML-DSA signature does not fit the 1 KiB defaults.
- Per-transaction network bandwidth: ~2.5 KB plus operations. Compute: see `docs/TESTING.md`
  for measured `compute_bandwidth_used` on testnet (the chain limit is 287,500,000 per tx).

## Threat notes
- Replay: the signed message is the tx id, which commits to chain id, nonce, payer, rc_limit and
  the operation Merkle root. The context string separates these signatures from any other use
  of the same key.
- Lockout: a wrong `public_key` registered by mistake locks the account unless upload authority
  is still secp256k1. Hence `lock` is a separate, last step.
- Key reuse: the ML-DSA public key is published on first registration, which is fine for a
  post-quantum scheme (that is the point).
- Verifier provenance: upstream commit recorded in `dilithium/PROVENANCE.md`; ACVP vectors in
  `wasm/test/acvp-mldsa44-sigver.json`.
