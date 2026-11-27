# koinos-pq

A post-quantum account for the Koinos blockchain, working today, with no change to the chain.

Upload the `pqwallet` contract to your own address, register an **ML-DSA-44** (NIST FIPS 204)
public key, and from then on the account is authorised only by an ML-DSA-44 signature over the
transaction id. The secp256k1 key that a quantum computer could one day break stops mattering.

```
wasm/        FIPS 204 reference verifier (C, vendored from PQ-Crystals) compiled to MVP WebAssembly
contract/    AssemblyScript account contract; wasm-merge links the verifier in
cli/         testnet tooling: keys, fund, deploy, register, send, lock, status
dist/        built artefacts with SHA256SUMS
docs/        SPEC.md (contract spec), SECURITY.md (review + resolutions), NATIVE-PROPOSAL.md, NATIVE-PLAN.md,
             TESTING.md, THROUGHPUT.md (does post-quantum make the chain slower? measured answer)
bench/       native verify timings behind THROUGHPUT.md and the proposed compute charge (runs in Docker)
devnet/      private devnet for the koinos-chain fork (native ML-DSA-44): compose, genesis, KOIN, run.mjs
HANDOVER.md  start here
```

`npm test` runs the NIST ACVP vectors, a noble cross-check, a memory-safety fuzz and an adversarial
false-accept run against the WASM verifier, once on `wasm/dilithium.wasm` and once on
`dist/pqwallet.wasm` (the merged file that is uploaded); then the CLI's offline tests; then the
contract tests in the Koinos mock VM with the real verifier linked. `npm run build` rebuilds the
contract and fails unless the result is byte-identical to the committed `dist/`.

## What it costs to use

A `pqwallet` account is not a drop-in replacement for an ordinary one. These are the prices, so
nobody finds them out afterwards. None of them puts funds at risk.

- **Contracts that act for you from inside another call are refused until you allow them.** That
  covers a multisig you are a member of, routers, vaults, anything that moves your tokens from
  inside its own code. Allow one with `npm run allow -- <contract> on`. Flows where you first
  approve an amount and the contract then spends that allowance work without it, and so does
  anything you place directly in a transaction.
- **If the account is a member of another account contract** (a multisig, say), the contract that
  ends up asking for your authority is the token being moved, with that other contract's call in
  between. As the code reads, the account then sees the token as the caller and you would have to
  allow-list the token. This has not been tried on a chain.
- **Every authority check runs one full signature verification**, about 2.3 M to 2.8 M compute
  ticks, in interpreted WebAssembly. Nothing is remembered within a transaction, so a transfer
  pays twice (6.1 M ticks, about 0.4 KOIN of mana on testnet) and a transaction that asks five
  times pays five times. The native route in `docs/NATIVE-PROPOSAL.md` would be about 30 times
  cheaper.
- **Every transaction is about 2.5 KB bigger**: the signature is 2,420 bytes against 65.
- **"Sign in with Kondor" style checks cannot verify a message signed by this account.** They work
  by recovering a public key from the signature, and an ML-DSA signature has no key to recover. A
  site has to read the account's registered key from the contract and verify against that.
- **Setting an account up costs mana from the account itself.** On mainnet on 2026-10-18 the upload
  used 44.9 KOIN of mana and the key registration 2.9, about 48 in all. The wallet asks for more
  than that to be in the account before it starts (about 66 KOIN at the prices seen in November
  2026), because the network holds a transaction's whole limit until its block is final. Mana
  comes back over five days. In the wallet nobody else can pay for the set-up; there is no
  sponsored route there (the CLI's `rescue-upload` lets another account pay for an upload).
- **A transaction can carry at most six ML-DSA-44 signatures** (the contract's 16 KiB buffer; see
  `docs/SPEC.md`, resource notes). A seventh makes every `pqwallet` account in it refuse.
- **In the wallet, tokens with more than 18 decimals are refused.**

And what it does not do: it makes one account's own authority post-quantum. The chain is not.
Blocks are still produced and signed with secp256k1 keys, and every account that has not moved to
a post-quantum key stays exposed. That is what the native proposal is for.
