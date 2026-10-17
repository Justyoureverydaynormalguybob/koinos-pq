// Final step: re-upload with upload authority also governed by the contract. Until this moment
// upload authority is still the chain's default secp256k1 rule, so this one transaction needs BOTH
// signatures: the secp256k1 one FIRST (the default rule stops at the first matching 65-byte
// signature and would abort on a 2420-byte one), and the ML-DSA-44 one for the payer check that our
// contract performs. After this, no secp256k1 key can touch the account at all.
import { network, loadKeys, saveKeys, pqContract, pqKeysFromSeed, loadBytecode, loadAbi, buildTransaction, submit, pqSignTxId, b64url, waitMined, utils, Signer } from "./lib.mjs";

const net = network();
const k = loadKeys(net.name);
const address = k.account.address;
const pq = pqKeysFromSeed(k.pq.seedHex);
const c = pqContract(net, address);
const info = (await c.functions.get_info()).result;
if (!info.key_registered) { console.error("register the ML-DSA key first"); process.exit(1); }
const { bytes: bytecode, sha256: digest } = loadBytecode();
console.log(`bytecode sha256 ${digest} (verified against dist/SHA256SUMS)`);
const operation = {
  upload_contract: {
    contract_id: address,
    bytecode: utils.encodeBase64url(bytecode),
    abi: JSON.stringify(loadAbi()),
    authorizes_call_contract: true,
    authorizes_transaction_application: true,
    authorizes_upload_contract: true,
  },
};
const tx = await buildTransaction(net, address, [operation], process.env.RC_LIMIT);
const legacy = Signer.fromWif(k.account.wif);
const withLegacy = await legacy.signTransaction({ ...tx, signatures: [] });
tx.signatures = [...withLegacy.signatures, b64url(pqSignTxId(tx.id, pq.secretKey))];
console.log(`lock tx ${tx.id}: ${tx.signatures.length} signatures (secp256k1 for the last default upload check, ML-DSA-44 for the payer)`);
const { receipt } = await submit(net, tx);
console.log(`tx ${tx.id} submitted; rc_used ${receipt.rc_used}; compute ${receipt.compute_bandwidth_used}`);
console.log(`mined in block ${await waitMined(net, tx.id)}`);
saveKeys(net.name, { ...k, lockedUpload: true, lockTx: tx.id });
console.log("done: call, transaction and upload authority are all governed by the ML-DSA-44 key");
