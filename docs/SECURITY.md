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
| M2 | The CLI uploaded whatever was in the build directory, unhashed, and `lock` makes that irreversible. | Every upload of this contract (`deploy`, `lock`, `rescue-upload`) reads `dist/pqwallet.wasm` through `loadBytecode()`, which refuses to proceed unless its sha256 matches `dist/SHA256SUMS`; the digest is printed. `upload-for`, which uploads *another* contract this account governs, validates the module and needs the sha256 given or confirmed (R4 below). |
| M3 | Between deploy and lock the secp256k1 key could replace the contract. | `deploy --lock` is the documented production path: upload authority is governed by the contract from the first block. The secp256k1 key then matters only until `register`, which is inherent (something has to authorise the bootstrap). The two-step path remains for testing. |
| L2 | `authorize` wrote state (a counter), which costs mana on every call and fails in read-only contexts. | Counter removed; `authorize` is pure. |
| L4 | Key file written then chmod'ed (brief window); sponsored-operation scripts silently used another project's issuer key on any network. | File created with mode 0600 in one call (on Windows, where no such mode exists, the ACL is cut to the owner with `icacls`, see R2); the funding key always comes from `FUND_WIF`, never from a key file found on disk. |
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
- **Build-tool advisories (R8).** `contract/`'s dev tree (`@koinos/sdk-as` 1.5.1 pulls in as-pect,
  protobufjs, tar, request and a bundled npm) carries 67 npm advisories, 3 critical, as of
  2026-11-07. None of it runs on chain or in the CLI; the runtime dependencies (`koilib`,
  `@noble/post-quantum`, `@noble/hashes`) have none. It is installed with `--ignore-scripts`.

## Review 2026-11-07

A second pass over the whole repository (contract, verifier, CLI, key handling, dependencies, git
history) with live checks: the mainnet owner account's contract hash equals the sha256 of
`dist/pqwallet.wasm`, all three overrides are on, and its registered key matches the local seed.
Nothing was found that moves an account without its current key. The findings are in the tooling
around it, and all were fixed the same day.

| id | finding | resolution |
|---|---|---|
| R1 (high) | `register --rotate` broadcast the new key and wrote the new seed to disk only after the transaction was mined. A crash in between would have left the chain on a key whose seed was never saved, with no secp256k1 fallback after lock. | The new seed is saved as `pendingSeedHex` before anything is broadcast and promoted after the transaction is mined. On start, `register` finishes or discards an interrupted rotation by comparing the on-chain key with the current and pending seeds; `status` reports a pending seed. |
| R2 (medium) | The key file held the WIF and ML-DSA seed in plain text, and the documented 0600 mode is a no-op on Windows (Node's chmod only toggles the read-only bit, so the file relied on the profile folder's inherited ACL). | Encryption at rest: `keys` asks for a passphrase and `encrypt-keys` converts an existing file or changes the passphrase. The secret fields go into an scrypt (N=2^17, r=8, p=1) + AES-256-GCM blob; the address, public key and deployment notes stay readable. Commands ask for the passphrase, or read `KOINOS_PQ_PASSPHRASE`. On Windows the file's ACL is cut to the owner with `icacls`. A plain-text file still loads, with a warning. |
| R3 (medium) | `rescue-upload` referenced two identifiers it never imported (it failed with a ReferenceError before doing anything) and read the wasm directly, bypassing the M2 digest check. | Uses `loadBytecode()` like every other upload of this contract. |
| R4 (medium) | `upload-for` uploaded any file named on the command line, with all three overrides on and no confirmation; the new code's own `authorize` then decides who controls the contract, so a wrong file hands it over permanently. Its usage text advertised a `--keep-flags` option that did not exist. | The module must pass `WebAssembly.validate`, the ABI must parse with methods, and the sha256 must be given with `--sha256 <hex>` or confirmed at the prompt by typing its first 8 characters. Nothing is sent without a terminal or the flag. The phantom option is gone. |
| R5 (medium) | `send-for` retried on "AMQP" and "invalid json" errors by building and signing a fresh transaction. Such errors can arrive after the node accepted the first one; if it was mined during the 30 s wait, the second transaction had a valid nonce and the transfer went out twice. | `submitOnce()` in `lib.mjs`: a transport error means "maybe accepted", the id is looked for on chain and the same signed bytes are resubmitted, never a new transaction. A pre-acceptance refusal from a busy mempool may rebuild (fresh nonce) only while no ambiguous error has been seen. Used by `send-for`, `upload-for`, `register` and `rescue-upload`. |
| R6 (low) | `sha256sum -c dist/SHA256SUMS` failed for `pqwallet.abi` on a Windows checkout (autocrlf), and the vendored Dilithium sources were not byte-identical to upstream there for the same reason. The committed blobs were correct. | `.gitattributes`: `dist/* -text`, `dilithium/* text eol=lf`. |
| R7 (low) | `wasm/test/*.mjs` built paths from `URL.pathname`, which Node on Windows turns into `C:\C:\...`, so `npm test` could not run on the maintainer's machine, and nothing ran tests on push. | `fileURLToPath`; GitHub Actions workflow `.github/workflows/test.yml` runs the verifier tests, the dist checksums, an import check on the merged module, and the mock-VM contract tests. |
| R8 (low) | 67 npm advisories in the contract's build tooling. | Build-time only; recorded under known limitations above. |
| R9 (low) | Docs lagged the code: SPEC.md still described a verification counter and a whole-transaction read; TESTING.md said 7 mock-VM tests (there are 10); M2 above claimed every upload was digest-checked. | Fixed in SPEC.md, TESTING.md and the M2/L4 rows above. |

Verified again, no change needed: all 22 vendored Dilithium files and the LICENSE are byte-identical
to upstream at the commit in `dilithium/PROVENANCE.md`; the committed verifier passes 15/15 ACVP
vectors, the 25-keypair noble cross-check and the memory fuzz; the merged module imports only
`env.invoke_system_call`; no key material has ever been committed (`.keys.*` were never tracked);
the runtime dependencies have no advisories and the lockfiles carry integrity hashes.

Noted, no change: `FUND_WIF` passed inline lands in shell history (a testnet funding key). The
devnet WIFs in `devnet/make-genesis.mjs` are the public local-koinos dev keys. ML-DSA-44 is NIST
level 2; the versioned context string leaves room for a level-3 `koinos/pqwallet/2`. There is no
hybrid mode (secp256k1 and ML-DSA both required), which would hedge an implementation flaw at the
cost of 65 bytes and a second signature.
