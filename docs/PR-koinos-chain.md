<!-- Pull request text for koinos/koinos-chain, from Justyoureverydaynormalguybob:ml-dsa-44 to koinos:master.
     Follows the repository's pull_request_template.md. -->

> **Status, 2026-11-27: do not open this pull request yet.**
>
> An outside review (issue 1 on the koinos-pq-wallet repository, by GitHub user interfecto) pointed
> out that the earlier title, "no protocol change", was wrong. It is a consensus change:
>
> - Today's `check_authority` hands every entry of `transaction.signatures` to `recover_public_key`,
>   which asserts 65 bytes (`system_calls.cpp`, "unexpected signature length"). A node without this
>   change therefore rejects a transaction that carries a 3733-byte entry. A node with it accepts it.
> - The first block that contains such a transaction would split upgraded nodes from the rest.
> - `check_authority` is also a genesis thunk, and `register_thunks` says in capitals that nothing
>   may be added to or changed in that list after genesis.
>
> Koinos has a mechanism for exactly this, and the text below is now written for it: the new rule
> ships as a **new thunk that nothing calls** (registered with `THUNK_REGISTER`, the list for
> non-genesis thunks), and a **governance proposal** later points the `check_authority` system call
> at it (`set_system_call_operation` with `target.thunk_id`). Every node runs the old rule until the
> proposal takes effect, and all of them switch at the same block.
>
> **What still has to be done in the code before opening the PR.** The branch `ml-dsa-44` as pushed
> edits the existing `check_authority` thunk in place. It has to be reworked so that the genesis
> thunk is byte-for-byte untouched and the new behaviour lives in the new thunk. Thunk ids are values
> of `koinos.chain.system_call_id` in koinos-proto (`koinos/chain/system_call_ids.proto`), so the new
> thunk needs one new enum value there: the earlier claim "no protobuf change" does not hold either.
> The devnet run has to be repeated with the system call switched by a `set_system_call_operation`,
> including one run before the switch that shows the 3733-byte entry is still rejected.

# Title

feat: native ML-DSA-44 (FIPS 204) transaction signatures as a new, dormant check_authority thunk (switched on by governance)

# Body

Resolves: none (new capability; happy to open a tracking issue first if preferred)

## Brief description

**This is a consensus change, and it is built to ship dormant.** Merging and releasing it changes
nothing a node does. It adds a new thunk; the `check_authority` system call keeps pointing at the
genesis thunk until a governance proposal (`set_system_call_operation`) points it at the new one.
Until then a transaction with the new kind of entry is rejected by every node exactly as today.
After the proposal takes effect every node accepts it from the same block, so there is no height at
which upgraded and non-upgraded nodes disagree, provided node operators have upgraded before the
vote passes (a node that has not cannot follow the chain past the switch, as with any system call
override).

Adds a second kind of entry to `transaction.signatures` so that an account can be controlled by a
post-quantum key instead of a secp256k1 key, verified natively by the node:

```
0x01 || ML-DSA-44 public key (1312 bytes) || ML-DSA-44 signature (2420 bytes)     exactly 3733 bytes
```

- Signature scheme: ML-DSA-44, NIST FIPS 204 (final, August 2024), pure mode, over the 34-byte
  transaction id multihash, fixed context string `koinos/tx/1`.
- The signer's address is derived from the public key the same way `to_address_bytes()` derives it
  from a compressed secp256k1 key, so a post-quantum account is an ordinary-looking address. Moving
  an account over is a transfer to the new address. No registry, no new state, no genesis change.
- One new thunk, registered with `THUNK_REGISTER` (the non-genesis list), and one new value for it in
  `koinos.chain.system_call_id` (koinos-proto). The genesis `check_authority` thunk is not touched.
  The new thunk is the genesis one plus one branch: it recognises the entry by exact size and tag. A
  valid entry authorises the derived address and nobody else; an invalid one authorises nobody.
  65-byte entries take the same path as in the genesis thunk, and a transaction may mix both kinds
  in any order. Any other size fails exactly as before (`unexpected signature length`).
- Activation is a separate, later step and not part of this PR: a governance proposal carrying
  `set_system_call_operation { call_id: check_authority, target: { thunk_id: <the new id> } }`.
- Verifier: the PQ-Crystals reference implementation, verify-only subset, vendored byte for byte in
  `src/koinos/chain/pq/` (provenance and upstream commit in `pq/PROVENANCE.md`; public domain /
  Apache-2.0), built as the static library `koinos_pq`. `randombytes` is a trapping stub: the node
  never generates keys or signs. `src/koinos/chain/mldsa.{hpp,cpp}` is the only caller.
- Compute charge: the verifier runs outside the metered VM, so the thunk charges 3x the
  `recover_public_key` registry cost per entry (88,890 ticks on mainnet). Measured: one reference
  verification is 2.6x a libsecp256k1 recovery (183 µs vs 70 µs, Ryzen 7 7730U, gcc 12 `-O3`); an
  AVX2 build would be 0.64x. The multiplier covers the slowest allowed node and can come down later.
- `check_system_authority`, `recover_public_key`, `verify_signature` and block signatures are
  untouched. Those, a `0x02 || signature` entry with the key stored after first use, an `ml_dsa_44`
  value in the `dsa` enum for contracts, and a tag reserved for Falcon-512 once FIPS 206 is final,
  are proposed as follow-ups and deliberately not in this PR.

Why now: every secp256k1 public key that has ever signed is already on chain, and the switch to a
post-quantum key must itself be signed by the old key, so the migration path has to exist before
large quantum machines do (Google's internal readiness target is 2029; NIST deprecates these curves
from 2030). Koinos can offer the path with a small change that ships switched off and is turned on
by its own governance, without a coordinated hard fork.

Design note with the full rationale, charge derivation and devnet results:
`docs/ml-dsa-44-signatures.md` in this branch. Throughput analysis (does this slow the chain? CPU:
no; bytes: 6-13x; transactions per block today: unchanged, the chain is compute-bound) and the
benchmark harness: https://github.com/Justyoureverydaynormalguybob/koinos-pq, `docs/THROUGHPUT.md`.

## Checklist

- [x] I have built this pull request locally (Alpine/gcc via the repo Dockerfile and `Dockerfile.test`)
- [x] I have ran the unit tests locally (whole suite 50/50 cases, 2,007/2,007 assertions; new case `ml_dsa_44_signatures`)
- [x] I have manually tested this pull request (private devnet, see Demonstration)
- [x] I have reviewed my pull request (clang-format applied with the repo `.clang-format`)
- [x] I have added any relevant tests (15 NIST ACVP sigVer vectors incl. 12 must-reject; address derivation cross-checked against koilib; bit flips in signature, key and id; wrong context, tag and sizes; mixed ordering with secp256k1; the compute charge)

## Demonstration

<!-- 2026-11-27: the table and the checklist above describe the first version of the branch, where
     the rule was edited in place. Run both again on the reworked branch (new thunk, switched by
     set_system_call_operation, plus the "still rejected before the switch" case) and replace the
     numbers before opening the PR. -->

Private devnet built from this branch (own genesis, current KOIN contract as a system contract;
compose file, genesis and driver script in the koinos-pq repo under `devnet/`, log in
`docs/devnet-run.txt`):

| transaction | result | compute (ticks) | network (bytes) |
|---|---|---|---|
| KOIN transfer, one 3733-byte ML-DSA-44 entry, no secp256k1 anywhere | mined, balance moved | 527,828 | 3,979 |
| KOIN transfer, one 65-byte secp256k1 entry (unchanged path) | mined | 409,273 | 310 |
| two transfers from two accounts, one secp256k1 + one ML-DSA-44 entry | mined | 922,593 | 4,144 |

Rejected at the mempool with the expected errors: flipped signature bit, signature under a
different context, valid entry from a different ML-DSA key, secp256k1 signature for the
post-quantum address, the mixed transaction with only its secp256k1 signature (all
`has not authorized transaction`); tag `0x02` and a 3732-byte entry (`unexpected signature
length`); no signature (`missing expected field`).

Producing an entry from JavaScript (koilib needs no change, `signatures` is already opaque):

```js
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { utils } from "koilib";
const { publicKey, secretKey } = ml_dsa44.keygen(seed32);   // address = utils.bitcoinAddress(publicKey)
const sig = ml_dsa44.sign(txIdBytes34, secretKey, { context: new TextEncoder().encode("koinos/tx/1") });
tx.signatures = [utils.encodeBase64url(Uint8Array.from([0x01, ...publicKey, ...sig]))];
```

## Notes for reviewers

- The genesis `check_authority` thunk is byte-for-byte unchanged. In the new thunk the 65-byte branch
  is the same code, and the new branch is gated on `size() == 3733 && [0] == 0x01`.
- Consensus: nothing changes at merge or release. The rule changes only when governance points
  `check_authority` at the new thunk. Before that, the new entry is rejected; after it, accepted;
  the devnet run shows both. I would like guidance on the thunk's name and id.
- Context string, charge multiplier and tag byte are the three policy choices; all are isolated
  constants and I am glad to change them.
- Disclosure: I am not a professional developer. This was built with an AI coding assistant, with
  an independent adversarial review of the companion contract work and the NIST vectors and devnet
  as the evidence. Please review accordingly; I will act on every comment.
- Related, already live on Harbinger: a contract that gives one account the same property today via
  the `authorize` override (koinos-pq repo). This PR is the native, chain-wide version of that.
