# Testing record

## Offline (reproducible with `npm test`)
- `wasm/test/verify.test.mjs`: NIST ACVP ML-DSA-44 sigVer (external interface, pure):
  15/15 agree, 12 of them must-reject (wrong key, modified message, modified signature,
  invalid hint encoding, out-of-range z, etc.). Noble cross-check: 25 keypairs, 7 assertions each.
- `contract/scripts/test.sh`: 7/7 as-pect tests against `@koinos/mock-vm` with `dilithium.wasm`
  sharing the test module's memory, the same layout as on chain.

## Testnet (Harbinger), 2026-10-17
Full log with every command and receipt: `docs/testnet-run.txt`. Account
`1FqXVbjZnMo2cUNj56LNCrc8R22RWDmq1t`, explorer https://harbinger.koinosblocks.com.

| step | tx | block | result |
|---|---|---|---|
| fund 50 tKOIN from issuer | `0x1220adf2…4f07` | | ok |
| deploy v1 (call+tx overrides) | `0x122054ef…f198` | 9288854 | ok, rc_used 470M |
| register (v1) | | | **reverted**: "return buffer is not large enough" (SDK 1 KiB buffer vs 1312-byte args) |
| re-deploy v2 from own account | | | **rejected**: same error from v1's `authorize` reading a 58 KB tx |
| sponsored re-upload v3 (issuer pays, account key authorises) | `0x1220c50a…9b4e` | 9288985 | ok, rc_used 50.7M |
| register ML-DSA-44 key (secp256k1 bootstrap) | `0x1220a9ee…dd18` | 9288987 | ok, compute 1.07M, network 1,571 B |
| **send 1 tKOIN, ML-DSA-44 signature only** | `0x1220196d…92c0` | 9288994 | **mined**; compute 6.11M (2.1% of limit), rc_used 39.5M, network 2,668 B |
| send with secp256k1 only | | | rejected: "has not authorized transaction" |
| send with one flipped bit in the ML-DSA signature | | | rejected: "has not authorized transaction" |
| send with no signature | | | rejected by the chain's basic check |
| lock, ML-DSA signature only | | | rejected: "unexpected signature length" (default upload rule still secp256k1) |
| lock, [secp256k1, ML-DSA-44] | `0x12201f55…24f3` | 9289020 | ok, compute 3.27M; overrides call+tx+upload all true |
| send 0.5 tKOIN after lock, ML-DSA-44 only | | 9289024 | mined |
| send with secp256k1 after lock | | | rejected: "has not authorized transaction" |

End state: `get_info` reports key registered, 7 successful verifications; the on-chain key hash
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
