// Uploads the Pqwallet contract to the account address, signed by the account's secp256k1 key.
// Overrides call-contract and transaction-application authority. With --lock (use it for a real
// account) upload authority is overridden too, from the start; the secp256k1 key then only matters
// until the ML-DSA key is registered. Without --lock the secp256k1 key can still replace the
// contract until lock.mjs runs: that is the testing / recovery mode.
import { network, loadKeys, saveKeys, pqContract, loadBytecode, loadAbi, Signer, waitMined, balance, fmtKoin } from "./lib.mjs";

const net = network();
const k = loadKeys(net.name);
const signer = Signer.fromWif(k.account.wif);
signer.provider = net.provider;
const address = signer.getAddress();
const lock = process.argv.includes("--lock");
console.log(`uploading pqwallet to ${address} on ${net.name} (balance ${fmtKoin(await balance(net, address))})`);
const contract = pqContract(net, address, signer);
const { bytes, sha256: digest } = loadBytecode();
contract.bytecode = bytes;
console.log(`bytecode sha256 ${digest} (verified against dist/SHA256SUMS)`);
const { transaction, receipt } = await contract.deploy({
  abi: JSON.stringify(loadAbi()),
  authorizesCallContract: true,
  authorizesTransactionApplication: true,
  authorizesUploadContract: lock,
  rcLimit: process.env.RC_LIMIT || undefined,
});
console.log(`tx ${transaction.id} submitted; rc_used ${receipt.rc_used}`);
const block = await waitMined(net, transaction.id);
console.log(`mined in block ${block}`);
saveKeys(net.name, { ...k, contractId: address, deployedTx: transaction.id, lockedUpload: lock });
console.log(lock ? "upload authority is now also governed by the contract" : "upload authority still secp256k1 (run lock.mjs after testing)");
