# Testing record

## Offline (reproducible with `npm test`)
- `wasm/test/verify.test.mjs`: NIST ACVP ML-DSA-44 sigVer (external interface, pure):
  15/15 agree, 12 of them must-reject. The file's own reasons for those 12 are: modified message
  (3), modified signature, commitment (3), modified signature, z (3), modified signature, hint (3).
  It has no "wrong key" vector; an earlier version of this line said it had. The wrong-key case is
  covered by the noble cross-check instead: 25 keypairs, 7 assertions each (valid, flipped
  signature bit, changed message, wrong context, wrong key, short signature, short key).
- `wasm/test/fuzz.test.mjs` (memory safety, canaries around the C region) and
  `wasm/test/adv-verify.test.mjs` (5,035 false-accept checks against noble).
- **All three verifier tests run twice**: against `wasm/dilithium.wasm`, and with `--merged`
  against `dist/pqwallet.wasm`, the merged file that is actually uploaded (`npm run
  test:wasm:merged`, part of `npm run test:wasm`). `wasm-merge` keeps the verifier's exports in
  the merged module, so the same vectors reach the function as it sits in the deployed bytes, at
  the same memory addresses. The loader (`wasm/test/load.mjs`) refuses a `dist/pqwallet.wasm`
  that is not the one `dist/SHA256SUMS` names, and fails the test if the verifier ever reaches
  the module's one import, the system call. Until 2026-11-27 these tests loaded only
  `wasm/dilithium.wasm`.
- `contract/scripts/test.sh`: 10/10 as-pect tests against `@koinos/mock-vm` with `dilithium.wasm`
  sharing the test module's memory, the same layout as on chain.
- `npm run test:cli`, offline: `cli/test/rotation.test.mjs` (no sequence of events removes a seed
  from the key file; the interrupted-rotation case from the 2026-11-27 review),
  `cli/test/register-flow.test.mjs` (`register.mjs` itself against a made-up node on 127.0.0.1
  with a key file in a temporary folder: a rotation the node holds back and the user runs again,
  one it refuses and later accepts, one whose nonce another transaction took, a key on chain that
  no seed in the file belongs to),
  `cli/test/refusals.test.mjs` (only the chain's own refusal texts count as "refused") and
  `cli/test/attack-judge.test.mjs` (the attack script against a made-up node on 127.0.0.1: a
  node that answers with an error page, drops the connection or says "AMQP connection is not
  open" gives exit 2, never a pass).
- `npm run build:contract` builds the contract into `contract/build/` and fails unless the result
  is byte-identical to the committed `dist/`. It never writes to `dist/`; only `npm run
  update-dist` does. On 2026-11-27 a clean rebuild on the phone (Termux, clang 21.1.8, binaryen
  133, protoc 36.2, node 24.18.0) reproduced all three files: `pqwallet.wasm` `8b1175cd…3861a`,
  `pqwallet.abi` `0cdd1b59…0566`, `dilithium.wasm` `82ac3b06…1c74`.
- All of it runs on every push in GitHub Actions (`.github/workflows/test.yml`), together with
  `sha256sum -c dist/SHA256SUMS`, a check that the merged module imports only
  `env.invoke_system_call`, and (contract job) the same byte-for-byte comparison of the contract
  built on the runner with the committed `dist/`. The runner does not rebuild `dilithium.wasm`
  from C, because `-O2` output depends on the clang version; the committed file is used, so the
  merged module depends only on the pinned AssemblyScript compiler and binaryen 133.

## Testnet (Harbinger), 2026-10-17
Full log with every command and receipt: `docs/testnet-run.txt`. Account
`1FqXVbjZnMo2cUNj56LNCrc8R22RWDmq1t`, explorer https://harbinger.koinosblocks.com.

| step | tx | block | result |
|---|---|---|---|
| fund 50 tKOIN from a funded key | `0x1220adf2…4f07` | | ok |
| deploy v1 (call+tx overrides) | `0x122054ef…f198` | 9288854 | ok, rc_used 470M |
| register (v1) | | | **reverted**: "return buffer is not large enough" (SDK 1 KiB buffer vs 1312-byte args) |
| re-deploy v2 from own account | | | **rejected**: same error from v1's `authorize` reading a 58 KB tx |
| sponsored re-upload v3 (funded key pays, account key authorises) | `0x1220c50a…9b4e` | 9288985 | ok, rc_used 50.7M |
| register ML-DSA-44 key (secp256k1 bootstrap) | `0x1220a9ee…dd18` | 9288987 | ok, compute 1.07M, network 1,571 B |
| **send 1 tKOIN, ML-DSA-44 signature only** | `0x1220196d…92c0` | 9288994 | **mined**; compute 6.11M (2.1% of limit), rc_used 39.5M, network 2,668 B |
| send with secp256k1 only | | | rejected: "has not authorized transaction" |
| send with one flipped bit in the ML-DSA signature | | | rejected: "has not authorized transaction" |
| send with no signature | | | rejected by the chain's basic check |
| lock, ML-DSA signature only | | | rejected: "unexpected signature length" (default upload rule still secp256k1) |
| lock, [secp256k1, ML-DSA-44] | `0x12201f55…24f3` | 9289020 | ok, compute 3.27M; overrides call+tx+upload all true |
| send 0.5 tKOIN after lock, ML-DSA-44 only | | 9289024 | mined |
| send with secp256k1 after lock | | | rejected: "has not authorized transaction" |

End state: `get_info` reports key registered (the contract of that first day also kept a count of
successful verifications, 7 at this point; the counter was removed in the security review the same
day, L2, so `get_info` no longer reports one); the on-chain key hash
`4f4583ba0afdbbe67409ea6ff4a8dd8f9bf0e18cf933b0d4d7ecbd6401d71709` matches the local seed.
The secp256k1 key for this account can no longer do anything.

### Round 2 (after the security review, same day)
The account was already locked, so every step below was authorised by the ML-DSA-44 key alone.

| step | tx | block | result |
|---|---|---|---|
| upgrade to the reviewed contract (upload authority is the contract's) | `0x12204556…40e0` | 9290249 | mined, compute 6.03M |
| send 0.5 tKOIN, ML-DSA only | `0x12204789…e090` | 9290253 | mined, compute 6.08M |
| send with secp256k1 | | | rejected: "has not authorized transaction" |
| rotate to a fresh key (proof of possession by the new key) | | 9290255 | mined; new key `d1a8aaf5…6364` |
| send 0.5 tKOIN with the new key | `0x1220228c…aa15` | 9290258 | mined |
| allow-list a contract for nested calls | `0x1220e20d…b055` | 9290260 | mined, reads back "allowed" |
| revoke it | | | mined, reads back "not allowed" |

Not exercised on testnet (covered by mock VM tests): a nested contract calling `set_public_key`
(refused), a nested caller spending without being allow-listed (refused). Exercising those live
needs an attacker contract deployed on testnet; see `docs/SECURITY.md` H1/H2.

### What testnet taught that the mock VM did not
1. The SDK system-call buffer (1 KiB) must be enlarged before the dispatcher reads arguments.
2. `authorize` must not load the whole transaction; a contract re-upload is 58 KB.
3. In a transaction that also hits the chain's default secp256k1 rule (only `lock`), the 65-byte
   signature must precede the 2420-byte one.
4. Never set `rc_limit` to all available mana; the mempool reserves pending limits.
