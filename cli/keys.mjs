// Creates the key file for the chosen network: a fresh secp256k1 account key (needed once, to
// upload the contract) and an ML-DSA-44 seed. Never overwrites an existing file.
// Asks for a passphrase: with one, the WIF and seed are stored encrypted (scrypt + AES-256-GCM)
// and only the address and public key stay readable. KOINOS_PQ_PASSPHRASE sets it without a
// prompt; an empty passphrase writes plain text, which every later command warns about.
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { network, keyFile, saveKeys, usePassphrase, askPassphrase, pqKeysFromSeed, hex, Signer, sha256 } from "./lib.mjs";

const net = network();
if (existsSync(keyFile(net.name))) {
  console.error(`refusing to overwrite ${keyFile(net.name)}`);
  process.exit(1);
}
const pw = await choosePassphrase();
usePassphrase(net.name, pw);
const account = Signer.fromSeed(hex(randomBytes(32)));
const seedHex = hex(randomBytes(32));
const pq = pqKeysFromSeed(seedHex);
const f = saveKeys(net.name, {
  network: net.name,
  createdAt: new Date().toISOString(),
  account: { address: account.getAddress(), wif: account.getPrivateKey("wif") },
  pq: { scheme: "ML-DSA-44", seedHex, publicKeyHex: hex(pq.publicKey), publicKeySha256: hex(sha256(pq.publicKey)) },
});
console.log(`wrote ${f} (${pw ? "encrypted" : "PLAIN TEXT"}, owner-only); back it up, it is the account`);
console.log(`account address (fund this with ${net.name === "testnet" ? "tKOIN" : "KOIN"}): ${account.getAddress()}`);
console.log(`ML-DSA-44 public key sha256: ${hex(sha256(pq.publicKey))}`);

async function choosePassphrase() {
  if (process.env.KOINOS_PQ_PASSPHRASE !== undefined) return process.env.KOINOS_PQ_PASSPHRASE;
  if (!process.stdin.isTTY) {
    console.warn("no terminal and no KOINOS_PQ_PASSPHRASE: writing the key file in plain text");
    return "";
  }
  for (;;) {
    const a = await askPassphrase("passphrase for the key file (empty = plain text, not recommended): ");
    if (a === "") return "";
    const b = await askPassphrase("again: ");
    if (a === b) return a;
    console.error("the two passphrases differ; try again");
  }
}
