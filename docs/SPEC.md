# pqwallet contract specification (v1)

## Purpose
Replace an account's authority rule with ML-DSA-44 (FIPS 204) signature verification, using
Koinos's per-address `authorize` override. No chain change.

## Deployment
`upload_contract` to the account's own address with
`authorizes_call_contract = true`, `authorizes_transaction_application = true`,
and (after bootstrap) `authorizes_upload_contract = true`. ABI: `dist/pqwallet.abi`.

## State
Space 0, object `config_object { bytes public_key = 1; }`.
Space 1, map contract address → `allowed_object { bool value = 1; }` (nested-call allow-list).

## Entry points
| name | id | args | result | auth |
|---|---|---|---|---|
| `authorize` | `0x4a2dbd90` (reserved) | `koinos.chain.authorize_arguments` | `authorize_result{value}` | kernel only |
| `set_public_key` | `0x4cc6c61b` | `{bytes public_key (1312), bytes proof (2420)}` | `{}` | direct op + rule below + proof |
| `get_public_key` | `0x96634f68` | `{}` | `{bytes value}` | read-only |
| `get_info` | `0xbd7f6850` | `{}` | scheme, sizes, context, key_registered | read-only |
| `set_allowed_caller` | | `{bytes contract, bool allowed}` | `{}` | direct op + rule below |
| `get_allowed_caller` | | `{bytes contract}` | `{bool value}` | read-only |

"Direct op" means `System.getCaller().caller` is empty: the entry point was invoked by a
transaction operation, not by another contract. `proof` is an ML-DSA-44 signature by the NEW key
over the account's 25-byte address with context `koinos/pqwallet/1/pop` (proof of possession).

## The rule (`authorizedByTransaction`)
Let `tx = get_transaction()`, `id = tx.id` (34-byte sha2-256 multihash), `pk = config.public_key`.
- If `pk` is not exactly 1312 bytes (no key yet): authorised iff some `tx.signatures[i]` of length 65
  recovers (secp256k1, over `id`) to a public key whose address equals the contract id. This is the
  chain's default rule, re-implemented, so bootstrap transactions keep working.
- Otherwise: authorised iff some `tx.signatures[i]` of length 2420 satisfies
  `ML-DSA-44.Verify(pk, M = id, sig, ctx = "koinos/pqwallet/1")` (pure mode, FIPS 204 §5.3 with
  the context prefix `0x00 || len(ctx) || ctx`). On success `verifications += 1`.
`authorize` is pure (no state writes). For `transaction_application` and `contract_upload` the
rule above decides. For `contract_call` the chain supplies `call = {contract_id, entry_point,
caller, data}` where `contract_id` is the contract asking (e.g. the token) and `caller` is who
called it: empty for a direct operation. If `caller` is non-empty and is not this account, the
request is refused unless `caller` is in the allow-list; otherwise the rule above decides. This
mirrors the AssemblyScript SDK's `checkAccountAuthority` for plain accounts, which refuses nested
callers outright, while letting the holder opt specific contracts in.

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

## Transaction access
The contract never calls `get_transaction()`. It reads `get_transaction_field("id")` and
`get_transaction_field("signatures")` (a repeated field comes back as
`message_value = Any(koinos.chain.list_type{values})`). Loading the whole transaction broke on a
58 KB contract re-upload, which is itself a transaction this contract must authorise.

## Resource notes
- SDK system-call buffer raised to 16 KiB at module start (`System.setSystemBufferSize`, before
  the dispatcher's `getArguments`) and dispatcher return buffer to 8 KiB: 1312-byte arguments and
  2420-byte signatures do not fit the 1 KiB defaults. Found on testnet, not in the mock VM.
- Each transfer triggers two `authorize` calls (payer check + the token contract's
  `require_authority`), i.e. two ML-DSA verifications. Measured on testnet: compute 6.11M of the
  287.5M limit (2.1%), rc_used 39.5M (0.39 KOIN of mana), network 2,668 bytes. A legacy
  (secp256k1) bootstrap call measured compute 1.07M.
- Mixed signature lists: when a transaction also triggers the chain's *default* secp256k1 rule
  (only the final `lock` does), the 65-byte signature must come first: the default loop stops at
  the first match but aborts with "unexpected signature length" on a 2420-byte entry.
- Mana limit: do not set `rc_limit` to the whole available mana; the mempool reserves each pending
  transaction's limit and refuses the next one with "insufficient pending account resources".

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
