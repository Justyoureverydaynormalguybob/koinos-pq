// Sends KOIN out of an address whose authority this post-quantum account holds (its
// authorize() delegates here, e.g. the KoinosProof contract after its handover). This account
// pays and signs with ML-DSA-44 only.
//
//   node cli/send-for.mjs <from address> <to address> <amount in KOIN | all>
import {
  network, loadKeys, pqKeysFromSeed, buildTransaction, submit, pqSignTxId, b64url, waitMined,
  koinContract, balance, mana, fmtKoin,
} from "./lib.mjs";

const [from, to, amountArg] = process.argv.slice(2);
if (!from || !to || !amountArg) {
  console.error("usage: node cli/send-for.mjs <from address> <to address> <amount KOIN | all>");
  process.exit(1);
}
const net = network();
const k = loadKeys(net.name);
const pq = pqKeysFromSeed(k.pq.seedHex);
const have = await balance(net, from);
const value = amountArg === "all" ? have : BigInt(Math.round(Number(amountArg) * 1e8));
if (value <= 0n || value > have) {
  console.error(`${from} has ${fmtKoin(have)}; cannot send ${fmtKoin(value)}`);
  process.exit(1);
}
console.log(`${net.name}: ${fmtKoin(value)} from ${from} to ${to}, authorised and paid by ${k.account.address} (mana ${fmtKoin(await mana(net, k.account.address))})`);

const { operation } = await koinContract(net).functions.transfer(
  { from, to, value: value.toString() },
  { onlyOperation: true },
);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let txId;
for (let attempt = 0; ; attempt++) {
  try {
    const avail = BigInt(await net.provider.getAccountRc(k.account.address));
    const rc = process.env.RC_LIMIT || String(avail * 9n / 10n < 10n * 100000000n ? avail * 9n / 10n : 10n * 100000000n);
    const tx = await buildTransaction(net, k.account.address, [operation], rc);
    tx.signatures = [b64url(pqSignTxId(tx.id, pq.secretKey))];
    const { receipt } = await submit(net, tx);
    txId = tx.id;
    console.log(`tx ${tx.id} accepted; rc_used ${receipt.rc_used}; compute ${receipt.compute_bandwidth_used}`);
    break;
  } catch (e) {
    if (/insufficient pending account resources|AMQP|invalid json/i.test(e.message) && attempt < 16) {
      console.log(`  ${e.message.slice(0, 60)}; retrying in 30 s`);
      await sleep(30000);
      continue;
    }
    console.error("refused:", e.message);
    process.exit(1);
  }
}
try { console.log(`mined in block ${await waitMined(net, txId, 180000)}`); } catch { console.log("not seen within 3 minutes; checking balances"); }
for (let i = 0; i < 12; i++) {
  const left = await balance(net, from);
  if (left === have - value) {
    console.log(`done: ${from} now ${fmtKoin(left)}, ${to} now ${fmtKoin(await balance(net, to))}`);
    process.exit(0);
  }
  await sleep(15000);
}
console.error("balances have not changed yet; check the transaction before retrying");
process.exit(1);
