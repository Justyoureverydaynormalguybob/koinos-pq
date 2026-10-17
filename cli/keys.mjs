// Creates the key file for the chosen network: a fresh secp256k1 account key (needed once, to
// upload the contract) and an ML-DSA-44 seed. Never overwrites an existing file.
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { network, keyFile, saveKeys, pqKeysFromSeed, hex, Signer, sha256 } from "./lib.mjs";

const net = network();
if (existsSync(keyFile(net.name))) {
  console.error(`refusing to overwrite ${keyFile(net.name)}`);
  process.exit(1);
}
const account = Signer.fromSeed(hex(randomBytes(32)));
const seedHex = hex(randomBytes(32));
const pq = pqKeysFromSeed(seedHex);
const f = saveKeys(net.name, {
  network: net.name,
  createdAt: new Date().toISOString(),
  account: { address: account.getAddress(), wif: account.getPrivateKey("wif") },
  pq: { scheme: "ML-DSA-44", seedHex, publicKeyHex: hex(pq.publicKey), publicKeySha256: hex(sha256(pq.publicKey)) },
});
console.log(`wrote ${f} (mode 0600)`);
console.log(`account address (fund this with ${net.name === "testnet" ? "tKOIN" : "KOIN"}): ${account.getAddress()}`);
console.log(`ML-DSA-44 public key sha256: ${hex(sha256(pq.publicKey))}`);
