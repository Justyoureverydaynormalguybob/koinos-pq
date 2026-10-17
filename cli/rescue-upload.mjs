// Re-uploads the contract with ANOTHER account paying the mana. Used when the account's own
// authorize contract cannot process a large transaction (the upload bytecode is ~58 KB).
// The upload itself is still authorised by the account's secp256k1 key (upload authority not
// yet overridden), so the transaction carries two signatures: payer's and the account's.
// Usage: FUND_WIF=<payer wif> node cli/rescue-upload.mjs   (defaults to the koinky-kit issuer key)
import { network, loadKeys, saveKeys, loadBytecode, loadAbi, Signer, Transaction, utils, waitMined, submit, fundingWif } from "./lib.mjs";

const net = network();
const k = loadKeys(net.name);
const payer = Signer.fromWif(fundingWif(net)); payer.provider = net.provider;
const account = Signer.fromWif(k.account.wif); account.provider = net.provider;
const lock = process.argv.includes("--lock");
const operation = { upload_contract: {
  contract_id: account.getAddress(),
  bytecode: utils.encodeBase64url(new Uint8Array(readFileSync(wasmPath))),
  abi: JSON.stringify(loadAbi()),
  authorizes_call_contract: true,
  authorizes_transaction_application: true,
  authorizes_upload_contract: lock,
} };
const tx = { header: { payer: payer.getAddress(), rc_limit: process.env.RC_LIMIT || "1500000000" }, operations: [operation], signatures: [] };
await Transaction.prepareTransaction(tx, net.provider, payer.getAddress());
const s1 = await payer.signTransaction(tx);
const s2 = await account.signTransaction({ ...tx, signatures: [] });
tx.signatures = [...s1.signatures, ...s2.signatures];
console.log(`re-upload of pqwallet to ${account.getAddress()} paid by ${payer.getAddress()}; tx ${tx.id}; ${tx.signatures.length} signatures`);
const { receipt } = await submit(net, tx);
console.log(`submitted; rc_used ${receipt.rc_used}; mined in block ${await waitMined(net, tx.id)}`);
saveKeys(net.name, { ...k, contractId: account.getAddress(), deployedTx: tx.id, lockedUpload: lock });
