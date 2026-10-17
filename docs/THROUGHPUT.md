# Will post-quantum signatures make Koinos slower?

*Evaluation written 2026-10-17 before starting phase B (docs/NATIVE-PLAN.md). Numbers are
measured, not assumed; each one says where it came from so it can be re-checked.*

## Short answer

- **Verification speed: no difference worth talking about.** Native ML-DSA-44 verification with
  the reference C code takes 2.6 times the CPU of the secp256k1 public-key recovery the chain
  does today (183 µs against 70 µs on this laptop); the AVX2 build is faster than a recovery
  (45 µs). Either way it is a few percent of what a transaction already spends.
- **Transaction size: 6 to 13 times bigger.** A plain KOIN transfer goes from 312 bytes to 2,668
  (ML-DSA-44 signature with the key held on chain) or 3,981 bytes (signature plus key inline, the
  B1 format in NATIVE-PLAN.md). Bytes are what the chain meters as network bandwidth.
- **Transactions per block: unchanged for today's chain.** Koinos's ceiling is the per-block
  *compute* budget, not bytes. A real KOIN transfer burns about 1.5 million compute ticks, so the
  budget allows roughly 35 transfers per block sustained and 190 in a burst. Even at 3,981 bytes
  each, the bandwidth budget allows more than that (64 sustained, 257 burst). Compute binds first
  in every case. Nothing anyone can see gets slower.
- **It matters later.** The day the compute side gets cheaper (a faster VM, a cheaper token
  contract, a bigger compute budget), bandwidth becomes the ceiling and the signature size then
  caps the chain at about one tenth of what secp256k1 would allow. The fixes for that are known,
  cheap, and should be designed in now (section 5).

## 1. How Koinos limits a block

Source: `koinos/koinos-contracts-cpp` `contracts/resources/resources.cpp` constants, confirmed
live with `chain.get_resource_limits` on mainnet 2026-10-17 (limits 1,048,576 / 287,500,000 /
524,288).

| resource | sustained budget per block | hard limit per block |
|---|---|---|
| network bandwidth (serialized bytes) | 256 KiB (262,144 B) | 1 MiB (1,048,576 B) |
| compute (ticks; 57.5 M is "about 0.1 s") | 57,500,000 | 287,500,000 |
| disk storage | 39,600 B | 512 KiB |
| block interval | 3 s | |

The budget is the sustainable rate (the market drains and the price rises when blocks run above
it); the limit is the burst cap. A block also spends about 5 M compute ticks and 380 bytes on its
own overhead (measured on 100 empty mainnet blocks).

What a transaction is charged:

- Network bandwidth = `trx.ByteSizeLong()`, the raw protobuf size including every signature
  (`koinos-chain` `src/koinos/chain/system_calls.cpp` around line 492).
- Compute = metered WASM ticks plus a fixed price per system call. `recover_public_key` costs
  29,630 ticks (`tests/controller_test.cpp` compute registry), which is about 51 µs at the
  0.1 s / 57.5 M calibration. A transfer pays it at least twice: once for the payer
  (`apply_transaction`, line 465) and once inside the token contract's `require_authority`.

## 2. What a transaction weighs

Measured with koilib's own protobuf module (`lib/protoModules/protocol-proto.js`): one
`call_contract` KOIN transfer, real address lengths, 34-byte multihashes.

| signature entry | 1-op transfer | 10 transfers, one signature |
|---|---|---|
| secp256k1, 65 B (today) | 312 B | 1,194 B |
| Falcon-512 signature only, 666 B (key on chain) | 914 B | 1,796 B |
| Falcon-512 key + signature inline, 1,563 B | 1,811 B | 2,693 B |
| ML-DSA-44 signature only, 2,420 B (key on chain) | 2,668 B | 3,550 B |
| ML-DSA-44 key + signature inline, 3,733 B (B1 plan) | 3,981 B | 4,863 B |
| ML-DSA-65 signature only, 3,309 B | 3,557 B | |
| SLH-DSA-128s (hash-based) signature only, 7,856 B | 8,104 B | |

Real mainnet transfers are a little heavier than the synthetic one (413 to 568 B, two operations,
see section 4), so the ratios are slightly kinder than the table: ML-DSA-44 with a registry is
about 6.5x a real transfer, inline about 9.6x.

## 3. Verification speed

Measured 2026-10-17 in a Debian 12 container (gcc 12.2, `-O3 -march=native`) on this laptop's
AMD Ryzen 7 7730U, single thread, median of 500 operations, two runs within 1% of each other.
Harness in `bench/`. Verifiers: libsecp256k1 v0.6.0 (recovery module, what
`koinos-crypto-cpp` wraps), the verifier vendored in `dilithium/` (upstream PQ-Crystals
reference, the code NATIVE-PLAN.md puts in the node), and PQClean's clean and AVX2 builds.

| scheme | public key | signature | verify (µs) | relative to secp256k1 recovery | sign (µs) |
|---|---|---|---|---|---|
| secp256k1 recovery, libsecp256k1 (today) | 33 | 65 | 70 | 1.0x | 46 |
| ML-DSA-44, vendored reference C | 1,312 | 2,420 | 183 | 2.6x | 616 |
| ML-DSA-44, PQClean clean | 1,312 | 2,420 | 170 | 2.4x | 663 |
| ML-DSA-44, AVX2 | 1,312 | 2,420 | 45 | 0.64x | 117 |
| ML-DSA-65, AVX2 | 1,952 | 3,309 | 76 | 1.1x | 179 |
| Falcon-512 (padded), reference and AVX2 | 897 | 666 | 78 | 1.1x | 432 |
| SLH-DSA-128s (SPHINCS+), AVX2 | 32 | 7,856 | 484 | 6.9x | 352,869 |

All 1,500 verifications per scheme passed and every tampered signature was rejected. The
reference ML-DSA-44 verifier is 2.6 times a recovery; the AVX2 build is faster than a recovery.
Key generation and signing happen in the wallet, never on chain, so their cost does not matter
here (Falcon key generation at 13 ms is the only slow one, and only once per account).

**What to charge.** The chain prices `recover_public_key` at 29,630 ticks for what this machine
does in 70 µs, so 1 µs here is about 424 ticks. On that scale:

| verifier | measured | fair charge in ticks | share of a 1.5 M tick transfer (two checks) |
|---|---|---|---|
| ML-DSA-44 reference C | 183 µs | ~78,000, charged as **three recoveries** (88,890) | 12% |
| ML-DSA-44 AVX2 | 45 µs | ~19,000 | 2.5% |
| Falcon-512 | 78 µs | ~33,000 | 4.4% |

Recommendation: vendor the reference code, charge three times the `recover_public_key` registry
cost (88,890 ticks on mainnet; expressed as a multiple so it follows the registry), and record this
table as the justification. The charge has to cover the slowest node allowed on the network; a later AVX2
build with runtime CPU detection can lower it. NATIVE-PLAN.md's placeholder of "about ten
recoveries" (296,000 ticks) would be more than three times too high.

Effect on a transfer's total compute: two ML-DSA checks at 88,890 replace two recoveries at
29,630, so about 1.5 M ticks becomes about 1.62 M, an 8% rise. The compute ceiling in section 4
moves from about 35 to about 32 transfers per block sustained. That is the whole speed cost.

Confirmed on the devnet the same day (`docs/devnet-run.txt`): a KOIN transfer cost 409,273 ticks and
310 bytes with secp256k1 and 527,828 ticks and 3,979 bytes with the native ML-DSA-44 entry, a difference
of 118,555 ticks (two authority checks at three recoveries instead of one) and 3,669 bytes.

## 4. What the chain actually does today

Sampled about 6,800 mainnet blocks in windows between heights 39,800,000 and 40,293,663 via
`block_store.get_blocks_by_height` on 2026-10-17:

- About 50 transactions in 6,800 blocks, under 0.01 per block. Every signature was 65 bytes.
- Per transaction: 290 to 1,687 bytes of network bandwidth (most 316 to 568), and 0.6 M to
  9.4 M compute ticks. A single contract call is typically 1.2 M to 1.7 M; the cheapest seen was
  615 k; two-operation dapp transactions run 6 M to 9 M.
- Mean block interval 2.8 to 3.2 s.

So a block's capacity, counting the 5 M ticks and 380 bytes of per-block overhead:

| | sustained (budget) | burst (limit) |
|---|---|---|
| compute allows, typical call (1.5 M ticks) | ~35 per block | ~190 per block |
| compute allows, cheapest seen (0.6 M ticks) | ~87 | ~470 |
| bandwidth allows, secp256k1 (413 B) | ~630 | ~2,500 |
| bandwidth allows, ML-DSA-44 key on chain (2,770 B) | ~95 | ~378 |
| bandwidth allows, ML-DSA-44 inline (4,080 B) | ~64 | ~257 |
| bandwidth allows, Falcon-512 key on chain (1,015 B) | ~258 | ~1,030 |

For a typical transaction compute is the ceiling in every row. Only at the very cheapest end
(about 0.6 M ticks) does the inline ML-DSA-44 format start to bind first (64 against 87), and the
stored-key format is a tie. The signature change moves the bandwidth ceiling from about 18x above
the compute ceiling to roughly level with it. It does not lower the number of transactions a
block can hold today for the transactions people actually send.

For comparison, the contract route already live on testnet (`docs/testnet-run.txt`) costs
6.11 M ticks per transfer because the verifier runs in interpreted WASM: about 5 M ticks, or
roughly 9 ms, for one verification. Native verification is about 100 times cheaper than that
(section 3), which is the whole point of phase B.

## 5. How to keep it fast (do these in the design, not later)

Ordered by value for effort.

1. **Price the ML-DSA verify from the benchmark, not from a guess.** NATIVE-PLAN.md suggests
   "about 10 secp256k1 recoveries" (296,000 ticks). That would be 40% of a transfer's compute
   across its two checks and would throttle post-quantum accounts through the compute budget for
   no reason. Measured cost of the reference verifier is 2.6 recoveries; charge three recoveries
   (section 3) and lower it if an AVX2 build ships.
2. **Keep the key off the wire after first use.** Tag the entry with its first byte
   (`0x01` = key + signature, `0x02` = signature only) and have the node store the public key
   under the account's address the first time it sees `0x01`. Steady state drops from 3,981 to
   about 2,670 bytes per transaction, a third less, with no separate registration transaction.
   B1 can ship `0x01` alone; reserving the tag byte now costs nothing.
3. **Leave a tag for Falcon-512 (FN-DSA).** 666-byte signatures and integer-only verification
   would make a post-quantum transfer about 3x today's size instead of 8.5x. FIPS 206 is still a
   draft as of 2026 and NIST changed details from the round-3 Falcon (salt sampling, public-key
   hashing), so do not vendor it yet; just make the entry format able to take a third algorithm
   without a protocol change.
4. **Verify once, not two or three times.** Each node runs the full transaction at mempool
   admission (`controller.cpp` line 1017 calls `apply_transaction`) and again when the block
   arrives, and a transfer checks the same signature twice within one application (payer, then
   `require_authority`). A small cache keyed by (transaction id, signature bytes) -> signer
   address removes all but one verification per transaction per node. This helps secp256k1 today
   as much as ML-DSA tomorrow.
5. **Batch operations under one signature.** A transaction already carries many operations; ten
   transfers under one ML-DSA-44 signature cost 355 bytes each, roughly today's single transfer.
   Dapps, exchanges and payroll-style senders lose almost nothing.
6. **Raise the bandwidth budget when it starts to bind.** It is a governance number in the
   resources contract (`block_budget`, `block_limit`). Going from 256 KiB / 1 MiB to 1 MiB / 4 MiB
   restores today's transfer count with ML-DSA-44. The cost is node bandwidth and chain growth
   (worst case 28 GB a day sustained versus 7 GB today); actual use is 380 bytes a block, so the
   budget mainly sets the price. Pruning signatures from irreversible blocks is the matching
   storage fix if that ever matters.
7. **Parallel pre-verification when blocks fill.** Block application is single-threaded.
   Verifying all signatures in a block across cores before sequential application is the standard
   answer (Bitcoin does it); at 30 µs each a full 1 MiB block of 257 post-quantum transfers checks
   in under 3 ms on four cores. Not needed at today's load.
8. **Make the compute side faster, because that is the real ceiling.** A transfer spends about
   1.5 M ticks in interpreted WASM and system calls, 50x the signature check. Any throughput work
   on Koinos pays off there first, whatever the signature scheme.

Things that do not help: signature aggregation (ML-DSA and Falcon have no practical aggregate
form), compressing ML-DSA signatures (near-uniform bytes, 1 to 2% at best), hash-based schemes
(SLH-DSA is 7.9 KB; stateful XMSS is 2.5 KB and dangerous to manage), and the smaller NIST
round-2 candidates (HAWK, MAYO, SQIsign) which are years from a standard.

## 6. Other post-quantum chains: what is worth borrowing

Checked 2026-10-17, prompted by the question "can we copy Soqucoin's code if it would improve
Koinos?". Licences: koinos-chain, Soqucoin and Bitcoin Core are MIT; PQ-Crystals is public
domain / Apache-2.0; PQClean is public domain or MIT per scheme (Falcon is MIT). Copying from any
of them into a Koinos fork is fine. The question is whether anything there helps.

**Soqucoin** (local copy `soqucoin/soqucoin-soqucoin-genesis`, a Dogecoin/Bitcoin Core fork
with Dilithium-only script verification, Scrypt merged-mining PoW):

- Its signature verification is the same upstream PQ-Crystals reference code we already vendor
  (`dilithium/PROVENANCE.md` has the diff: only secret-key zeroisation in signing paths). Nothing
  to gain there.
- Its answer to the size problem is a 4 MB block weight (`MAX_BLOCK_WEIGHT = 4000000`, the
  Bitcoin value, with 2.4 KB signatures in the witness) plus a per-block "verification units"
  budget (`MAX_BLOCK_VERIFY_COST`), which is the same idea as Koinos's compute budget. In other
  words it accepts the byte cost and sizes the block for it. Same conclusion as section 5, item 6.
- Its advertised compression, "PAT aggregation, 1,000 signatures in 72 bytes", is not real
  compression. `src/crypto/pat/logarithmic.cpp` marks the consensus verifier `PROTOTYPE VERIFIER
  (v1.0)`; in the mode the opcode accepts without witness data it checks only that an XOR of keys
  and a message root match values inside the proof the spender supplied, and that a Merkle root is
  non-null. No Dilithium signature is checked. "Full mode" puts every signature back on the stack,
  so it saves no bytes. The LatticeFold+ range-proof verifier in `src/crypto/latticebp` is a stub
  commented "Placeholder: Always passes for development". Do not copy any of this.
- What is genuinely good in that tree is inherited from Bitcoin Core, not Soqucoin: the parallel
  script check queue (`src/checkqueue.h`) and the signature cache (`script/sigcache`). Those are
  the designs behind items 4 and 7 in section 5. They are small enough to re-implement for
  Koinos's thunk layer rather than port.

**Others, for the record** (from public designs, not re-verified line by line):

- QRL (Zond): accounts carry the Dilithium public key inline in each transaction and the address
  is a hash of the key. That is the B1 format; it confirms the approach and shows the cost.
- Nervos CKB and Solana's Winternitz vault: post-quantum authorisation inside a script or
  program, with no consensus change. That is the phase A contract route this repo already ships.
- Algorand: Falcon for state-proof certificates, not for transactions; `go-algorand` is AGPL,
  so not copyable into an MIT node in any case.
- Bitcoin's post-quantum output proposals (the BIP-360 family) spent most of their discussion on
  exactly our problem, the witness bytes of a 2 to 4 KB signature, and lean towards Falcon-sized
  schemes and a larger byte budget. Ethereum's direction is an algorithm-tagged transaction type
  plus native verifiers, which is the tag-byte design in section 5, item 2.

Net: the verifier code worth having is PQ-Crystals (vendored) and, later, PQClean's AVX2 ML-DSA
and Falcon implementations plus their test vectors. The chain integration has no analogue
elsewhere because no other chain meters compute and bandwidth the way Koinos does.

## 7. What this changes in NATIVE-PLAN.md

- B1 stays as planned (inline key + signature, one repo, no new state) because it proves the path
  and today's chain has the room. Add the type tag byte to the entry format.
- Replace "price it like ~10 secp256k1 recoveries" with the benchmarked figure.
- Add to B2: the stored-key `0x02` entry, the verification cache, and a `resources` parameter
  proposal (bandwidth budget) to go to governance alongside the `dsa` enum.
- Add to the proposal document: the throughput numbers above, so the Foundation sees the cost
  honestly and the mitigations with it.
