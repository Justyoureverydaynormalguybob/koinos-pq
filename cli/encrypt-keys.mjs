// Encrypts an existing key file, or changes its passphrase. The WIF and ML-DSA-44 seed move into
// an scrypt + AES-256-GCM blob; the address, public key and deployment notes stay readable. The
// file is read back with the new passphrase before success is reported.
//
//   node cli/encrypt-keys.mjs              # KOINOS_NETWORK picks the file (testnet by default)
//   node cli/encrypt-keys.mjs --plaintext  # the reverse, for an export; not recommended
import { network, loadKeys, saveKeys, usePassphrase, askPassphrase, pqKeysFromSeed, hex, sha256 } from "./lib.mjs";

const net = network();
const k = await loadKeys(net.name); // asks for the current passphrase if the file has one
const keyHash = hex(sha256(pqKeysFromSeed(k.pq.seedHex).publicKey));

if (process.argv.includes("--plaintext")) {
  usePassphrase(net.name, "");
  console.log(`wrote ${saveKeys(net.name, k)} in PLAIN TEXT; address ${k.account.address}, key sha256 ${keyHash}`);
} else {
  let pw;
  for (;;) {
    pw = await askPassphrase("new passphrase: ");
    if (!pw) { console.error("empty passphrase; use --plaintext if that is really what you want"); process.exit(1); }
    if (process.env.KOINOS_PQ_PASSPHRASE !== undefined || pw === await askPassphrase("again: ")) break;
    console.error("the two passphrases differ; try again");
  }
  usePassphrase(net.name, pw);
  const f = saveKeys(net.name, k);
  const back = await loadKeys(net.name);
  if (back.pq.seedHex !== k.pq.seedHex || back.account.wif !== k.account.wif) throw new Error("read-back mismatch; do not trust the written file");
  console.log(`wrote ${f}: encrypted (scrypt N=2^17, AES-256-GCM), read back ok; address ${k.account.address}, key sha256 ${keyHash}`);
}
