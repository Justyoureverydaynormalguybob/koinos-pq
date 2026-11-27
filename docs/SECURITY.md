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
  Since 2026-11-27 the build compares its result with `dist/` instead of overwriting it, and CI
  does the same for the contract (the C verifier is taken as committed there, so clang does not
  enter into it). See "External review 2026-11-27", item 16.
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
| R1 (high) | `register --rotate` broadcast the new key and wrote the new seed to disk only after the transaction was mined. A crash in between would have left the chain on a key whose seed was never saved, with no secp256k1 fallback after lock. | The new seed is saved as `pendingSeedHex` before anything is broadcast and promoted after the transaction is mined. On start, `register` finishes or discards an interrupted rotation by comparing the on-chain key with the current and pending seeds; `status` reports a pending seed. *2026-11-27: "discards" was itself a fault, item 1 of the external review below. Nothing is discarded any more.* |
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

## Outsider pen-test 2026-11-22

Black-box attempt to break the account from the outside, with the public GitHub code but no seed and
no key. Nothing broke.

**The verifier (the one trust anchor).** 5035 adversarial checks against `wasm/dilithium.wasm` with the
independent `@noble/post-quantum` implementation as the oracle: context confusion (a proof-of-possession
signature under the transaction context `koinos/pqwallet/1` and vice versa), transaction-id substitution,
key replay across accounts, all-zero and all-0xff signatures, structured mutations across the challenge,
`z` and hint regions, and 4000 random multi-bit mutations. Zero false-accepts, zero divergences from
noble. Kept as a regression test: `wasm/test/adv-verify.test.mjs`, wired into `npm run test:wasm`.

**The deployed account, live on Harbinger.** Against the locked pen-test account
`1FqXVbjZnMo2cUNj56LNCrc8R22RWDmq1t` (ML-DSA key registered, ~67 tKOIN), an attacker with a freshly
generated ML-DSA key — one that never had the seed — tried (1) a drain (transfer to the attacker,
signed by the attacker's key over the real transaction id) and (2) a takeover (`set_public_key`
rotating the account to the attacker's key, with a valid proof of possession). The node rejected both
with `account … has not authorized transaction`. The rejections happen before mining, so nothing is
charged and no chain state changes; the balance was untouched. Kept as a repeatable negative test:
`cli/attack-outsider.mjs` (`npm run attack`), which refuses mainnet without `ALLOW_MAINNET=1`.

The one thing an outsider cannot do is forge an ML-DSA-44 signature, and every path that tries to get
around that — a verifier false-accept, context/key/message confusion, a signature with no valid key —
is closed. The wallet's own web and local-attacker surface is covered in the wallet repo's SECURITY.md.

## Outsider attack re-run and widened, 2026-11-23

`cli/attack-outsider.mjs` (`npm run attack`) now carries thirteen attacks instead of two, takes several
victim addresses, and separates three outcomes: refused (exit 0), accepted or the account changed
(exit 1), and no verdict because the node did not answer (exit 2), so a dead node can no longer read as a
pass. After the run it compares the account's balance, registered key, contract info and allowed list
with what they were before.

*Corrected 2026-11-27: two of those claims did not hold for the script as it was on this date. The
pattern that decided "refused" also matched "fetch failed" and other non-answers, and the allowed
list was read with the wrong field name, so it always read "false". Both are fixed; see "External
review 2026-11-27", item 15, which also says which case reaches which check.*

1. Drain signed with a fresh ML-DSA-44 key.
2. Takeover: `set_public_key` to the attacker's key with a valid proof of possession.
3. `set_allowed_caller` putting the attacker's address on the allowed list.
4. Drain with no signature.
5. Drain signed with a secp256k1 key.
6. Drain carrying the native-format entry (0x01, public key, signature) of the attacker's key.
7. Drain carrying a real signature of the victim's, lifted from its last transaction on the chain.
8. Drain behind five junk signatures and the attacker's (six entries), and behind six (seven entries,
   one more than the contract's buffer holds: it must fail closed, and does, with "return buffer is not
   large enough").
9. The burn sandwich: allow PoB, burn the victim's KOIN into VHP for the attacker, forbid PoB.
10. to 13. With `ATTACKER_WIF` set, the attacker pays the mana with a funded account of its own and
    signs validly for itself: transfer out of the victim, `set_public_key`, `set_allowed_caller`, and a
    burn of the victim's KOIN through PoB.

**Harbinger**, the locked account `1FqXVbjZnMo2cUNj56LNCrc8R22RWDmq1t`: cases 1 to 9, ten attempts, all
refused; 67 tKOIN, the key and the allowed list unchanged. Harbinger's head had not moved since
09:10 UTC that day, but its mempool still judged every transaction. Cases 10 to 13 need a funded
attacker and were not run there.

**Private devnet**, three accounts made from one seed (numbers 0, 1 and 2, each with its own key):
cases 1 to 12 against each, 33 attempts, all refused, nothing changed. With the attacker paying, the
token contract answered "account 'from' has not authorized transfer" and the account contract "not
authorized". Case 7 was skipped (the devnet has no history API) and 9 and 13 do not apply (no PoB
there). The wallet's own `scripts/devnet-accounts.mjs` passed beside it: account 1 cannot be moved by
the wallet's first key or by account 2's.

Not run against mainnet; the script refuses it without `ALLOW_MAINNET=1`. Read only, the mainnet account
that has burned twice has PoB off its allowed list.

A reviewer also re-ran `npm run test:wasm` (ACVP 15/15, 25 keypairs against noble, the fuzz run, 5,035
adversarial checks with no false accept) and read `Pqwallet.ts` `authorize` again for the allowed list:
with a contract on it, only calls arriving through that contract stop being refused outright, and they
still need the account's own signature on the transaction. Leaving PoB allowed for good would let any
contract reached by a transaction the owner signs burn the account's KOIN into VHP at an address of its
choosing, which is the allow-list scope already recorded above.

## External review 2026-11-27

An outside reader, GitHub user **interfecto**, read the 0.18.3 sources of all three repositories
(this one at `13b28d5`) and wrote up what they found as issue 1 on the koinos-pq-wallet repository:
https://github.com/Justyoureverydaynormalguybob/koinos-pq-wallet/issues/1. They read code only and
ran nothing. They found no way for an outsider, a contract reached inside a signed transaction, or
the old secp256k1 key to move or change an account once its key is registered and all three
overrides are on. They confirmed the vendored verifier is byte-identical to upstream and is FIPS 204
final, and that the memory regions in the shipped binary do not overlap.

What they did find in this repository is below. Each claim was checked against the code before
anything was changed. The findings about the wallet and the signing core are answered in the wallet
repository's `docs/SECURITY.md`.

| # | finding | checked | what changed | where |
|---|---|---|---|---|
| 1 (high) | An interrupted `register --rotate`, run again, deleted the pending seed as "never reached the chain" when the on-chain key was still the old one. But the signed rotation stays valid until its nonce is used and can land later, so the account could end up answering to a seed that exists nowhere. After `lock` that is permanent. A node holding the transaction back could cause it on purpose. | True. `register.mjs` lines 31 to 35 as they were. This also undid part of R1 above, which had added the pending seed. | No command deletes a seed any more. The rotation's signed transaction, id and nonce are saved next to the pending seed, and read back, before anything is sent. A later run looks at the account's nonce first, then the on-chain key: nonce not used, the same signed bytes are sent again (never a new transaction); nonce used and the key is the new one, the pending seed becomes current; nonce used and the key is the old one, the rotation can never land and its seed moves to `retiredSeeds` with a date and a reason. If the on-chain key ever belongs to a kept seed (previous or retired), `register` makes it current again, so even a node that lies about the nonce cannot cost the account. The seed before the previous one is no longer overwritten on a second rotation. `retiredSeeds` sits inside the encrypted part of the key file. A second `register --rotate` after an interrupted one finishes that rotation and stops, instead of stacking another on top. `lock` refuses while a rotation is open or when the registered key is not the current seed's. `send`, `allow` and `upload-for` warn that they would take the rotation's nonce. `status` shows the open rotation and the kept seeds. | `cli/rotation.mjs` (new, the rules as pure functions), `cli/register.mjs`, `cli/lib.mjs`, `cli/lock.mjs`, `cli/send.mjs`, `cli/allow.mjs`, `cli/upload-for.mjs`, `cli/status.mjs`; tests `cli/test/rotation.test.mjs` (the rules) and `cli/test/register-flow.test.mjs` (`register.mjs` itself against a made-up node, including the reviewed case) |
| 15 | The pen-test script did not quite test what this file says. (a) Its "refused" pattern matched `failed`, `expected`, a bare `rc` and more, so "fetch failed", an HTML 502 page and "AMQP connection is not open" counted as refusals; a node failing only some calls gave exit 0. (b) The allowed-list check sent `{ caller }` where the contract's field is `contract`, so it always read false and the before/after comparison could never fire. (c) Cases 1 to 9 all stop at the payer check; only 10 to 13 reach `set_public_key`, `set_allowed_caller` and the nested-caller rule. | All three true. Also found while testing the fix: with no node at all the script crashed with exit 1, the code for "something was accepted", and koilib turns "context deadline exceeded" into a made-up receipt, which read as "ACCEPTED". | Only the chain's own refusal texts count, each tied to the check that words it; everything else is "no verdict" and the run exits 2. A payer-check refusal counts only if it names the victim. Each case is aimed at one check; a refusal from a different check is reported as such and also gives exit 2, because the check the case was aimed at was not exercised. The allowed list is read with `{ contract }`. An unreadable account state, before or after, is "no verdict". The script prints which check refused which case. | `cli/refusals.mjs` (new), `cli/attack-outsider.mjs`; tests `cli/test/refusals.test.mjs`, `cli/test/attack-judge.test.mjs` |
| 16 | The deployed bytecode was not tied to the source. `build.sh` copied its output into `dist/` and rewrote `SHA256SUMS`, so `npm run build && sha256sum -c dist/SHA256SUMS` always passed. CI built the contract but never compared it with `dist/`. The verifier tests loaded `wasm/dilithium.wasm`, not the merged `dist/pqwallet.wasm` that is deployed. Actions were pinned by tag, and the binaryen download was not checked. | All true. | The build writes to `contract/build/` only and fails unless `pqwallet.wasm`, `pqwallet.abi` and `dilithium.wasm` are byte-identical to the committed `dist/`. `dist/` changes only through `npm run update-dist`. CI builds the contract and runs the same comparison, then `git diff --exit-code` on `dist`, `contract/abi` and `wasm/dilithium.wasm`. The ACVP, fuzz and adversarial tests run a second time against `dist/pqwallet.wasm` itself (possible because `wasm-merge` keeps the verifier's exports in the merged module). Actions are pinned by commit, the workflow has `permissions: contents: read`, and the binaryen archive is checked against its sha256. | `contract/scripts/build.sh`, `contract/scripts/test.sh`, `package.json`, `.github/workflows/test.yml`, `wasm/test/load.mjs` (new), `wasm/test/*.test.mjs` |
| 17 | The 16 KiB system buffer refuses some valid transactions: seven or more ML-DSA-44 signatures in one transaction, and an authority check whose `data` is larger than about 16 KB. No funds at risk. | True. One detail differs from the report: with `@koinos/sdk-as` 1.5.1 the default `data` is the asking contract's own call arguments, not empty. | Documented; the contract is unchanged (its bytes are what accounts on chain run). | `docs/SPEC.md`, resource notes; `README.md`, "What it costs to use" |
| small | THROUGHPUT.md put one in-contract verification at about 5 M ticks and native at 70 to 100 times cheaper. | True: it had counted a transfer's two verifications as one. From the receipts, one is about 2.3 M to 2.8 M ticks, so native is about 30 times cheaper. The case for native stands. | Numbers corrected, arithmetic shown. | `docs/THROUGHPUT.md` section 4, `docs/NATIVE-PROPOSAL.md` |
| small | SPEC.md and the command list in HANDOVER.md led with the two-step path (`deploy`, later `lock`); until `lock` the secp256k1 key can replace the contract, and `register` gave no warning. | True. | Both lead with `deploy -- --lock`. `register` warns, when it finishes, whenever the account's upload authority is not the contract's. | `docs/SPEC.md`, `HANDOVER.md`, `cli/register.mjs` |
| small | `if (pub == null) continue` in the legacy path never runs, because the SDK exits first. TESTING.md listed "wrong key" among the ACVP must-reject cases, which the vector file does not have, and still mentioned the removed counter. | True, all three. | The line stays, with a comment saying why: removing it changes the bytes of `dist/pqwallet.wasm` (tried: the hash changes). TESTING.md corrected. | `contract/assembly/Pqwallet.ts` (comment only; rebuild gives the same hash), `docs/TESTING.md` |
| note | What the account costs its user (nested callers, one verification per check, no "sign in" recovery, set-up mana, six-signature limit). | Agreed. | Written down where a newcomer reads first. | `README.md`, "What it costs to use" |
| note | The native pull-request draft said "no protocol change". It is a consensus change: today's nodes reject a 3733-byte entry, changed nodes accept it. | True; confirmed in upstream `system_calls.cpp` (`recover_public_key` asserts 65 bytes; `check_authority` is a genesis thunk). | The draft, the plan, the proposal and the handover now say it ships as a new thunk that nothing calls, switched on by a governance proposal. **The fork's code is not changed yet**: the branch still edits the rule in place and must be reworked before the pull request is opened. | `docs/PR-koinos-chain.md`, `docs/NATIVE-PLAN.md`, `docs/NATIVE-PROPOSAL.md`, `HANDOVER.md` |

### Which pen-test case reaches which check, and where it has run

"Refused" proves something only about the check that did the refusing. The script now prints this
for every run; this is the record for the runs of 2026-11-23.

| case | what the attacker tries | the check that stops it | Harbinger | devnet |
|---|---|---|---|---|
| 1 | drain, signed with a fresh ML-DSA-44 key | payer check | run | run |
| 2 | `set_public_key` to the attacker's key, victim as payer | payer check; `set_public_key` never runs | run | run |
| 3 | `set_allowed_caller`, victim as payer | payer check; `set_allowed_caller` never runs | run | run |
| 4 | drain with no signature | the chain's basic check; `authorize` is not reached | run | run |
| 5 | drain signed with a secp256k1 key | payer check | run | run |
| 6 | drain with a native-format entry | payer check | run | run |
| 7 | drain with a signature lifted from the victim's last transaction | payer check | run | skipped (no history API) |
| 8a | five junk signatures and the attacker's | payer check | run | run |
| 8b | six junk signatures and the attacker's | the contract's 16 KiB buffer, failing closed | run | run |
| 9 | allow PoB, burn, forbid PoB, victim as payer | payer check; none of the three operations runs | run | no PoB there |
| 10 | attacker pays; transfer out of the victim | the token asks the account: signature rule | not run | run |
| 11 | attacker pays; `set_public_key` on the victim | `set_public_key` itself ("not authorized") | not run | run |
| 12 | attacker pays; `set_allowed_caller` on the victim | `set_allowed_caller` itself ("not authorized") | not run | run |
| 13 | attacker pays; burn the victim's KOIN through PoB | the token, called by PoB, asks the account: nested-caller rule | not run | no PoB there |

So, plainly:

- The Harbinger run tested the payer check (and the two checks in front of and behind it, cases 4
  and 8b) and nothing else. It never reached `set_public_key`, `set_allowed_caller` or the
  nested-caller rule on a live chain.
- The devnet run reached `set_public_key`, `set_allowed_caller` and the token's signature-rule
  path, with the attacker paying.
- **Case 13 has never run anywhere.** The nested-caller rule has been exercised only in the mock VM
  (`Pqwallet.spec.ts`), not on a chain. It needs a funded attacker account on a network with PoB.
- Both runs were judged by the old, loose pattern, and their full output was not kept. The refusal
  texts quoted above in this file ("has not authorized transaction", "account 'from' has not
  authorized transfer", "not authorized", "return buffer is not large enough") are all in the strict
  list, but that is a record of what was read at the time, not a re-check. "The allowed list
  unchanged" in those records was not actually checked by the script, because of the field-name
  fault. The same goes for the read-only note that the mainnet account has PoB off its list, if it
  was read with this script rather than with `npm run allow`.
- **To do, on a network and with the owner's say-so:** repeat the Harbinger and devnet runs with the
  corrected script, with `ATTACKER_WIF` set on Harbinger so that cases 10 to 13 run there, and
  replace the two paragraphs of 2026-11-23 with the new output. The text of the refusal in case 13
  is taken from the token's wording ("account 'from' has not authorized burn") and has not been seen
  from a live PoB burn by this script; if the chain words it differently the script will say "no
  verdict" and print the text, which is then added to `cli/refusals.mjs` once read.

### What was run for this review, and what was not

Run on 2026-11-27, offline, on the phone (Termux, node 24.18.0, clang 21.1.8, binaryen 133, protoc 36.2; `dist/` was built with protoc 35.1, so the protoc version did not change the output):
`npm test` (verifier tests on both files, the CLI tests, 10/10 mock-VM tests) and a clean
`npm run build:contract`, which reproduced `dist/` byte for byte. A source change (the dead branch
removed, then restored) made the build fail with the two hashes side by side and left `dist/`
untouched, as intended.

Not run: anything against a chain. The new `register` recovery paths and the corrected attack
script were exercised against a made-up node on 127.0.0.1 (`cli/test/register-flow.test.mjs`,
`cli/test/attack-judge.test.mjs`), not against Harbinger: a live rotation with the new code, and
one interrupted on purpose, are still to do on testnet. The CI comparison of the contract with
`dist/` has not run on GitHub yet: it reproduces on the phone, and whether the Ubuntu runner (other
protoc build, x86-64 binaryen) gives the same bytes will show on the first push.

