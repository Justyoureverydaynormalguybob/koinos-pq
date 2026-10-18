# Handover: a post-quantum account on Koinos

*Written 2026-10-17 for the owner (non-technical) and for whichever Koinos developer picks this up.*

## 1. What this is, in plain words

Every Koinos account today is controlled by a secp256k1 key, the same kind Bitcoin uses. A large
enough quantum computer could derive the private key from the public key, and the public key of
any account that has ever sent a transaction is already on chain. Nobody has such a machine yet.
Google's internal target for being ready is 2029; NIST deprecates these keys from 2030 to 2035.

Koinos has an unusual escape hatch: an account can upload a small program (a contract) to its own
address that replaces the chain's "is this signed correctly?" rule with its own. This project uses
that hatch. The program checks an **ML-DSA-44** signature instead. ML-DSA is the lattice-based
signature scheme NIST standardised in 2024 as FIPS 204; quantum computers are not known to break it.

Nothing about the chain changes. Any Koinos account can do this today. The trade-off is size:
an ML-DSA-44 signature is 2,420 bytes against 65 for secp256k1, so a transaction costs roughly
forty times more mana for bandwidth. Mana regenerates, so on Koinos this is a cost in patience,
not money.

## 2. What was built and how it was checked

| Piece | What it is | How it was verified |
|---|---|---|
| `wasm/dilithium.wasm` | The official FIPS 204 reference C code (PQ-Crystals), verify-only, compiled to plain WebAssembly MVP so the Koinos VM (Fizzy) accepts it. 10 KB. | All 15 NIST ACVP ML-DSA-44 signature-verification vectors agree (12 of them are must-reject cases). 25 random keypairs from an independent implementation (`@noble/post-quantum`) verify, and every tamper case (flipped bit, wrong key, wrong message, wrong context, truncated) is rejected. |
| `contract/` | The account contract (`Pqwallet`). Entry points: `authorize` (what the chain calls), `set_public_key`, `get_public_key`, `get_info`. | 7 tests in the Koinos mock VM with the real verifier linked in: legacy fallback before a key is set, registration, every rejection case, replay to another tx id, key rotation, counter. |
| `cli/` | Scripts that run the whole life cycle on testnet. | Live testnet run, see `docs/TESTING.md`. |

Lineage: the design is what Soqucoin did for a UTXO chain, moved to Koinos's account model.
Soqucoin's Dilithium copy was diffed against upstream; the differences were secret-key hygiene in
signing code that never runs on chain, so the upstream code is vendored directly (`dilithium/PROVENANCE.md`).

## 3. The life cycle of a post-quantum account

```
keys            -> make a fresh secp256k1 key (needed once, to upload) and an ML-DSA-44 seed
fund            -> give the address some KOIN (testnet: faucet, then cli/fund.mjs)
deploy --lock   -> upload pqwallet, all three authority types governed by the contract from block one
register        -> store the ML-DSA-44 public key with a proof of possession
                   (this last secp256k1-signed tx is the bootstrap)
send            -> from now on every tx is signed only with ML-DSA-44
register --rotate, allow <contract> on|off  -> optional housekeeping, ML-DSA-signed
```

For testing there is a two-step variant: `deploy` without `--lock` keeps upload authority with
the secp256k1 key so a broken contract can be replaced (`cli/rescue-upload.mjs`), and `lock`
closes that later. Re-running `lock` on a locked account is how you upgrade the contract.

Until `lock`, the secp256k1 key can still re-upload the contract. That is deliberate: it is the
recovery path while testing, and it was used twice on testnet (`cli/rescue-upload.mjs`, where
the issuer account pays the mana and the account key only authorises the upload). After `lock`
the secp256k1 key is dead weight and the account is post-quantum end to end. The `lock`
transaction itself carries both signatures, secp256k1 first, because it is the last transaction
the chain's default rule ever checks for this account.

Commands (testnet by default; `KOINOS_NETWORK=mainnet` switches):

```
npm run keys            # writes .keys.testnet.json (mode 0600) - back it up, it is the account
npm run fund -- 20      # moves 20 tKOIN from the koinky-kit issuer key into the account
npm run deploy
npm run register
npm run send -- <to> 0.5           # must succeed
npm run send -- <to> 0.5 --ecdsa   # must be rejected (secp256k1 no longer counts)
npm run send -- <to> 0.5 --bad-sig # must be rejected
npm run send -- <to> 0.5 --no-sig  # must be rejected
npm run lock
npm run status
```

## 4. Security review

An independent adversarial review was run on 2026-10-17 and every finding was either fixed and
re-tested on testnet or documented as an accepted limitation. Read `docs/SECURITY.md`. The two
important fixes: only a direct transaction operation can change the key or the allow-list (a
dapp inside a signed transaction cannot), and other contracts cannot spend from the account via
nested calls unless the holder allow-lists them.

## 5. Things a careful person should know

- **Back up the seed.** `.keys.<network>.json` holds a 32-byte seed; ML-DSA keys are derived
  from it deterministically. Lose it after `lock` and the account is gone for good. There is no
  secp256k1 fallback by design.
- **The last secp256k1 signature is the bootstrap.** Registering the key is itself signed by the
  old key. Do it before quantum computers exist, which is to say now.
- **Signature format.** The ML-DSA-44 signature goes in the transaction's ordinary `signatures`
  list as raw 2,420 bytes, over the 34-byte transaction id, with the FIPS 204 context string
  `koinos/pqwallet/1`. The context stops a signature made for anything else being replayed here.
- **Bandwidth.** ~2.5 KB per transaction. Fine for a person; for a high-volume dapp the native
  path in `docs/NATIVE-PROPOSAL.md` is the real fix.
- **Dapps that pull funds.** A DEX or similar contract that moves tokens out of the account from
  inside its own code is refused until you allow-list it (`npm run allow -- <contract> on`).
  Ordinary transfers and anything you place directly in a transaction need nothing.
- **Wallet support.** Kondor cannot produce ML-DSA signatures, and Kondor 2 is closed source. The
  wallet is github.com/Justyoureverydaynormalguybob/koinos-pq-wallet: a web app, and a browser
  extension that gives pages the same `window.kondor` interface (kondor-js, MIT), so existing dapps
  work with a post-quantum account unchanged. Both sit on koinos-pq-core (the signing rules).
- **Mainnet.** Deploying costs nothing beyond mana but the account is then unusual: any dapp that
  calls `require_authority` on it works (the rule is the same, the signature kind differs), but
  nothing that expects to *recover* a public key from the account's signature will.
- **Not audited.** The verifier is the NIST reference code, unmodified, with public test vectors.
  The contract around it is ~160 lines and tested, but has not had a third-party audit.
- **Two bugs only testnet found.** The SDK's 1 KiB system-call buffer, and reading the whole
  transaction (which fails on a large re-upload). Both are fixed and both are now covered by the
  live run in `docs/testnet-run.txt`. The lesson for anyone extending this: mock VM tests are
  necessary, a testnet life cycle is the real test.

**Mainnet, 2026-10-18.** The contract route is live on mainnet. Account
`1LQYsdpGuA3nwU5G1jANCnMWs3yYWfHwkQ` was set up from the browser wallet
(github.com/Justyoureverydaynormalguybob/koinos-pq-wallet): upload 44.9 KOIN of mana, registration 2.9,
then a 1 KOIN transfer authorised only by a 2,420-byte ML-DSA-44 signature, transaction
`0x12206b839a6fa5c9ac9a0a90ba4fc7a2cd3fb2786bc4927f3d59ab448a45d3726244`, block 40,318,335, succeeded
(mana 316,332,332, compute 6,071,053 ticks, 2,668 bytes). Note for anyone touching mainnet: KOIN is at
`19GYjDBVXU7keLbYvMLazsGQn3GTWHjHkK` now; the old `15DJN4a8…` address refuses state reads.

## 6. Where to go next

**Phase B1 is done (2026-10-17).** The koinos-chain fork (branch `ml-dsa-44`) verifies ML-DSA-44 natively:
a transaction signature entry `0x01 || public key || signature` (3733 bytes) authorises the address derived
from the key, with no contract. Chain tests pass (50/50) and `docs/devnet-run.txt` is the proof on a private
chain: `devnet/` holds the compose file, genesis and the script that deploys KOIN, mints, and runs the
transfer plus negative cases (`docker compose -f devnet/docker-compose.yml up -d`, `node devnet/run.mjs`).
The branch is committed locally and not yet pushed; the next step is the pull request.

Before starting the native work read `docs/THROUGHPUT.md`: it measures whether post-quantum signatures
slow the chain down (verification: no; bytes: 6-13x bigger; transactions per block today: unchanged,
because Koinos is compute-bound) and lists what to design in so it stays fast.

1. Run the mainnet life cycle on a small dedicated account first, not the main holdings.
2. Propose `docs/NATIVE-PROPOSAL.md` to the Koinos Foundation / Koinos Fund System: a native
   `ml_dsa_44` entry in the chain's `dsa` enum would make every account able to go post-quantum
   with no contract, at native speed, and is a prerequisite for post-quantum block production.
3. Done: the koinos-pq-wallet extension signs for dapps through `window.kondor` (proven end to end
   on the devnet, 2026-10-18). Next for it: icons and a store listing, per-site permissions.

## 7. Reproducing from a clean machine

Needs: node 20+, clang with the wasm32 target, lld, binaryen (`wasm-merge`), wabt
(`wasm-validate`, `wasm-objdump`), protoc.

```
npm install
(cd contract && npm install --ignore-scripts)
npm run build && npm test
sha256sum -c dist/SHA256SUMS
```
