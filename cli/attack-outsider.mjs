// Negative test: an OUTSIDER with no seed and no key tries to move a locked pqwallet account, and the
// chain must refuse. Mirrors the 2026-11-22 pen-test. The attacker reads only the public address; it
// generates its own fresh ML-DSA-44 key and attempts (1) a drain and (2) a key-rotation takeover with a
// valid proof-of-possession. If the node accepts either, this script FAILS (exit 1).
//
//   node cli/attack-outsider.mjs [victim-address]           # Harbinger testnet (default)
//   KOINOS_NETWORK=mainnet ALLOW_MAINNET=1 node cli/attack-outsider.mjs <addr>
//
// Default victim is the Harbinger account used in the pen-test. Rejected transactions are refused before
// mining, so nothing is charged and no chain state changes.
import { randomBytes, createHash } from "node:crypto";
import {
  network, koinContract, pqContract, pqKeysFromSeed, pqProofOfPossession,
  buildTransaction, submit, pqSignTxId, b64url, Signer, balance, fmtKoin, hex,
} from "./lib.mjs";

const net = network();
if (net.name === "mainnet" && process.env.ALLOW_MAINNET !== "1") {
  console.error("refusing to run against mainnet without ALLOW_MAINNET=1");
  process.exit(2);
}
const VICTIM = process.argv[2] || "1FqXVbjZnMo2cUNj56LNCrc8R22RWDmq1t";
const attacker = pqKeysFromSeed(hex(randomBytes(32)));            // a key that never had the seed
const sink = Signer.fromSeed(hex(randomBytes(32))).getAddress();  // where the attacker wants the money
const pkHash = createHash("sha256").update(attacker.publicKey).digest("hex").slice(0, 16);

console.log(`network  ${net.name}`);
console.log(`victim   ${VICTIM}  balance ${fmtKoin(await balance(net, VICTIM))}`);
console.log(`attacker fresh ML-DSA key pk sha256 ${pkHash}…\n`);

let anyAccepted = false;
async function attempt(label, operation) {
  const tx = await buildTransaction(net, VICTIM, [operation], process.env.RC_LIMIT);
  tx.signatures = [b64url(pqSignTxId(tx.id, attacker.secretKey))];
  try {
    await submit(net, tx);
    anyAccepted = true;
    console.log(`[${label}] !!! ACCEPTED — the chain let an attacker tx through. BROKEN.`);
  } catch (e) {
    console.log(`[${label}] rejected as expected: ${String((e && e.message) || e).split("\n")[0].slice(0, 160)}`);
  }
}

// 1) drain: transfer victim -> sink
{
  const { operation } = await koinContract(net).functions.transfer(
    { from: VICTIM, to: sink, value: String(10 * 1e8) }, { onlyOperation: true });
  await attempt("drain", operation);
}
// 2) takeover: rotate the account's registered key to the attacker's, with a valid proof-of-possession
{
  const proof = pqProofOfPossession(VICTIM, attacker.secretKey);
  const { operation } = await pqContract(net, VICTIM).functions.set_public_key(
    { public_key: b64url(attacker.publicKey), proof: b64url(proof) }, { onlyOperation: true });
  await attempt("takeover", operation);
}

console.log(`\nbalance after ${fmtKoin(await balance(net, VICTIM))}`);
console.log(anyAccepted ? "RESULT: BROKEN" : "RESULT: HELD — every attacker transaction was rejected");
process.exit(anyAccepted ? 1 : 0);
