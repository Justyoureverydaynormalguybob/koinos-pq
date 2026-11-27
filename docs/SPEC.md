# pqwallet contract specification (v1)

## Purpose
Replace an account's authority rule with ML-DSA-44 (FIPS 204) signature verification, using
Koinos's per-address `authorize` override. No chain change.

## Deployment
`upload_contract` to the account's own address with `authorizes_call_contract = true`,
`authorizes_transaction_application = true` and `authorizes_upload_contract = true`, all three in
that one upload. This is the production path (`npm run deploy -- --lock`, and what the wallet's
activation does). ABI: `dist/pqwallet.abi`.

A two-step variant exists for testing only: upload with `authorizes_upload_contract = false`
(`npm run deploy`), and set it later (`npm run lock`). In between, the account's secp256k1 key can
still replace the contract, and with it the registered ML-DSA-44 key. That key's public key is on
the chain from the upload transaction on, so an account left in this state is not post-quantum.
`register` and `status` say so for as long as it lasts.

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
Let `id = get_transaction_field("id")` (34-byte sha2-256 multihash), `sigs =
get_transaction_field("signatures")`, `pk = config.public_key`. A missing or malformed `id` is a
refusal.
- If `pk` is not exactly 1312 bytes (no key yet): authorised iff some `sigs[i]` of length 65
  recovers (secp256k1, over `id`) to a public key whose address equals the contract id. This is the
  chain's default rule, re-implemented, so bootstrap transactions keep working.
- Otherwise: authorised iff some `sigs[i]` of length 2420 satisfies
  `ML-DSA-44.Verify(pk, M = id, sig, ctx = "koinos/pqwallet/1")` (pure mode, FIPS 204 §5.3 with
  the context prefix `0x00 || len(ctx) || ctx`).
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
- **What the 16 KiB buffer rules out** (`SYSTEM_BUFFER_BYTES = 16384` in `Pqwallet.ts`). Every
  system call the contract makes returns its answer into this one buffer, and a call whose answer
  does not fit fails with "return buffer is not large enough", which ends `authorize` with a
  refusal. It fails closed: no funds are at risk, but some valid transactions can never be
  authorised by a `pqwallet` account.
  - *Signatures.* `authorize` reads the whole `signatures` list of the transaction, everybody's
    entries, not only this account's. Six ML-DSA-44 signatures are 14,520 bytes and fit, with
    about 1,800 bytes to spare for other entries (roughly 25 secp256k1 signatures). Seven are
    16,940 bytes and do not. So a transaction co-signed by seven or more ML-DSA-44 accounts, or
    one whose signatures add up to more than about 16,300 bytes, cannot be authorised by any
    `pqwallet` account in it. The pen-test's case 8b relies on exactly this.
  - *Arguments of an authority check.* For a `contract_call` check the chain passes `authorize`
    the `data` that the asking contract handed to `check_authority`. With `@koinos/sdk-as` 1.5.1
    `requireAuthority` passes that contract's own call arguments by default. If they are larger
    than about 16 KB, `authorize` cannot read its arguments and the check fails every time. A
    token transfer's arguments are under 100 bytes; this matters only for a contract that asks for
    the account's authority inside a call with very large arguments.
  - *Why it is not simply raised.* The value is compiled into `dist/pqwallet.wasm`, which accounts
    on chain already run, and the buffer is allocated on every call, so a larger one costs every
    transaction something. It has not been measured. Raising it is a new contract version: measure
    the cost per call on testnet first, then re-upload account by account.
- Mixed signature lists: when a transaction also triggers the chain's *default* secp256k1 rule
  (only the final `lock` does), the 65-byte signature must come first: the default loop stops at
  the first match but aborts with "unexpected signature length" on a 2420-byte entry.
- Mana limit: do not set `rc_limit` to the whole available mana; the mempool reserves each pending
  transaction's limit and refuses the next one with "insufficient pending account resources".

## Threat notes
- Replay: the signed message is the tx id, which commits to chain id, nonce, payer, rc_limit and
  the operation Merkle root. The context string separates these signatures from any other use
  of the same key.
- Lockout: `set_public_key` demands a proof of possession, so a key nobody holds cannot be
  registered. What can still lock an account for good is losing the seed after upload authority
  is the contract's; no secp256k1 fallback exists then, by design. The seed backup is the only
  recovery. The CLI never deletes a seed from the key file (`cli/rotation.mjs`).
- The window before `lock`: in the two-step testing path the secp256k1 key can replace the
  contract until `lock`. Production uses the one-step upload above, where that window does not
  exist.
- Key reuse: the ML-DSA public key is published on first registration, which is fine for a
  post-quantum scheme (that is the point).
- Verifier provenance: upstream commit recorded in `dilithium/PROVENANCE.md`; ACVP vectors in
  `wasm/test/acvp-mldsa44-sigver.json`.
