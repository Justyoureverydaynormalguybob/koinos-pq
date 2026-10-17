# Security review and resolutions

Reviewed 2026-10-17: (a) an independent adversarial review by a separate agent given only the code
and the chain documentation, (b) a verification pass against the koinos-chain source, the built
binaries and the testnet state. This file records every finding and what was done about it.

## Resolved

| id | finding | resolution |
|---|---|---|
| H1 | `set_public_key` could be called by any contract reached by a transaction the holder signed (a dapp could rotate the key to its own, or brick the account with random bytes). | `set_public_key` and `set_allowed_caller` now require `System.getCaller().caller` to be empty, i.e. a direct transaction operation. Mock VM test "refuses nested calls from another contract". |
| H2 | `authorize` ignored the authorization type and the calling contract, so for `contract_call` any nested contract (DEX, dapp) in a signed transaction could exercise the account's authority. Plain accounts under the AssemblyScript SDK's token rule are refused in that case. | For `contract_call`, a nested caller (`call.caller` non-empty and not the account itself) is refused unless the holder has allow-listed that contract with `set_allowed_caller`. Direct operations, `transaction_application` and `contract_upload` keep the signature rule. Tested. |
| M1 | No proof of possession: a wrong or unknown key could be registered and, after lock, the account is gone. | `set_public_key` requires `proof`: an ML-DSA-44 signature by the new key over the account's 25-byte address with context `koinos/pqwallet/1/pop`. Tested (missing, wrong-key and wrong-context proofs fail). Exercised on testnet by `register --rotate`. |
| M2 | The CLI uploaded whatever was in the build directory, unhashed, and `lock` makes that irreversible. | All uploads read `dist/pqwallet.wasm` and refuse to proceed unless its sha256 matches `dist/SHA256SUMS`. The digest is printed. |
| M3 | Between deploy and lock the secp256k1 key could replace the contract. | `deploy --lock` is the documented production path: upload authority is governed by the contract from the first block. The secp256k1 key then matters only until `register`, which is inherent (something has to authorise the bootstrap). The two-step path remains for testing. |
| L2 | `authorize` wrote state (a counter), which costs mana on every call and fails in read-only contexts. | Counter removed; `authorize` is pure. |
| L4 | Key file written then chmod'ed (brief window); sponsored-operation scripts silently used another project's issuer key on any network. | File created with mode 0600 in one call; the fallback funding key is only used on testnet, mainnet requires `FUND_WIF` explicitly. |
| L5 | ACVP vector file not hashed; toolchain versions not recorded. | Versions recorded below; vectors are a smoke test, the formal evidence is the byte-identical upstream reference code plus the noble cross-check. |

## Verified, no change needed

- **Replay.** The signed message is the transaction id. The chain asserts the id equals the hash of
  the header (`system_calls.cpp`, "transaction contains an invalid transaction id") and that
  `header.chain_id` matches the chain, so a signature cannot be moved to another header, nonce or
  chain. The context string separates these signatures from any other use of the key.
- **Direct calls to `authorize`.** The chain refuses calls to entry point `0x4a2dbd90` unless the
  caller is kernel mode (`system_calls.cpp`, `entry_point != authorize_entrypoint || kernel_mode`).
- **Length confusion.** 65-byte entries are only honoured before a key exists; 2420-byte entries
  only after. The C wrapper enforces exact signature and key lengths and context ≤ 255 bytes
  before the reference code reads anything.
- **Memory layout.** From the merged binary: C data 65,536..66,752, C stack top 328,896 growing
  down (256 KiB), AssemblyScript data from 393,308 and its shadow stack top at 428,080. No overlap.
  Fuzzing (300 random, 346 single-bit perturbations, hint-region extremes, 8 wrong-length cases)
  found no write outside the C region; measured stack high-water mark 36,258 bytes.
- **Provenance.** Every vendored Dilithium file is byte-identical (sha256) to upstream
  pq-crystals/dilithium `ref/` at the commit recorded in `dilithium/PROVENANCE.md`. The
  `randombytes` stub is removed by the linker; `dilithium.wasm` contains no trap instruction.
- **Deployed bytecode.** The on-chain contract hash of the testnet account equals the sha256 of
  `dist/pqwallet.wasm`, and a clean rebuild reproduces the same bytes on this machine.
- **Buffers.** The SDK system-call buffer is raised to 16 KiB at module start, before the
  dispatcher reads arguments; `authorize` reads only the `id` and `signatures` fields, so a 58 KB
  re-upload transaction is handled (proven by the lock and upgrade transactions on testnet).

## Known limitations (accepted, documented)

- **Signature list griefing (L1).** Signatures are not covered by the transaction id. A relayer
  could in principle re-broadcast a copy with extra junk entries; more than six 2420-byte entries
  overflow the 16 KiB buffer and the transaction fails (availability only, retryable). Whether the
  mempool accepts a second copy of an id it already holds was not verified.
- **Co-signing with default-rule accounts.** If a transaction also triggers the chain's default
  secp256k1 rule for some other account, its 65-byte signature must precede any 2420-byte entry.
- **Legacy path aborts on a malformed 65-byte entry (L3).** Same behaviour as the chain's own
  default rule; only reachable before a key is registered.
- **Dapps that pull funds.** By design, nested callers are refused until allow-listed. Direct
  token transfers and any operation the holder places in the transaction work unchanged.
- **Reproducibility across machines.** `-O2` output can differ between clang versions. Pinned
  toolchain for `dist/`: clang 21.1.8, lld 21.1.8, binaryen 133, wabt 1.0.42, protoc 35.1,
  node 24.18.0, assemblyscript 0.27.37, @koinos/sdk-as 1.5.1, koilib 9.4.1, @noble/post-quantum 0.7.1.
- **No third-party audit.** The verifier is unmodified NIST reference code; the contract and CLI
  have had one independent review (this file) and no professional audit.
