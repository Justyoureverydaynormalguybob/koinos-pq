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
keys      -> make a fresh secp256k1 key (needed once, to upload) and an ML-DSA-44 seed
fund      -> give the address some KOIN (testnet: faucet, then cli/fund.mjs)
deploy    -> upload pqwallet to the address, overriding call + transaction authority
register  -> store the ML-DSA-44 public key (this last secp256k1-signed tx is the bootstrap)
send      -> from now on every tx is signed only with ML-DSA-44
lock      -> finally, also override upload authority so even replacing the contract needs ML-DSA
```

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

## 4. Things a careful person should know

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
- **Wallet support.** Kondor and other wallets cannot produce ML-DSA signatures yet. The CLI is
  the wallet for now. A browser signer is a small job: `@noble/post-quantum` runs in browsers.
- **Mainnet.** Deploying costs nothing beyond mana but the account is then unusual: any dapp that
  calls `require_authority` on it works (the rule is the same, the signature kind differs), but
  nothing that expects to *recover* a public key from the account's signature will.
- **Not audited.** The verifier is the NIST reference code, unmodified, with public test vectors.
  The contract around it is ~160 lines and tested, but has not had a third-party audit.
- **Two bugs only testnet found.** The SDK's 1 KiB system-call buffer, and reading the whole
  transaction (which fails on a large re-upload). Both are fixed and both are now covered by the
  live run in `docs/testnet-run.txt`. The lesson for anyone extending this: mock VM tests are
  necessary, a testnet life cycle is the real test.

## 5. Where to go next

1. Run the mainnet life cycle on a small dedicated account first, not the main holdings.
2. Propose `docs/NATIVE-PROPOSAL.md` to the Koinos Foundation / Koinos Fund System: a native
   `ml_dsa_44` entry in the chain's `dsa` enum would make every account able to go post-quantum
   with no contract, at native speed, and is a prerequisite for post-quantum block production.
3. A Kondor or passkey-style signer using the same seed format.

## 6. Reproducing from a clean machine

Needs: node 20+, clang with the wasm32 target, lld, binaryen (`wasm-merge`), wabt
(`wasm-validate`, `wasm-objdump`), protoc.

```
npm install
(cd contract && npm install --ignore-scripts)
npm run build && npm test
sha256sum -c dist/SHA256SUMS
```
