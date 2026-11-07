// Sends KOIN out of an address whose authority this post-quantum account holds (its
// authorize() delegates here, e.g. the KoinosProof contract after its handover). This account
// pays and signs with ML-DSA-44 only.
//
//   node cli/send-for.mjs <from address> <to address> <amount in KOIN | all>
import {
  network, loadKeys, pqKeysFromSeed, buildTransaction, submitOnce, pqSignTxId, b64url, waitMined,
  koinContract, balance, mana, fmtKoin, sleep,
} from "./lib.mjs";

const [from, to, amountArg] = process.argv.slice(2);
if (!from || !to || !amountArg) {
  console.error("usage: node cli/send-for.mjs <from address> <to address> <amount KOIN | all>");
  process.exit(1);
}
const net = network();
const k = await loadKeys(net.name);
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
const build = async () => {
  const avail = BigInt(await net.provider.getAccountRc(k.account.address));
  const cap = 10n * 100000000n;
  const rc = process.env.RC_LIMIT || String(avail * 9n / 10n < cap ? avail * 9n / 10n : cap);
  const tx = await buildTransaction(net, k.account.address, [operation], rc);
  tx.signatures = [b64url(pqSignTxId(tx.id, pq.secretKey))];
  return tx;
};
// Signed once. submitOnce() resubmits the SAME transaction after a transport error (which can
// arrive after the node accepted it) and looks for its id on chain before anything else, so the
// transfer cannot go out twice. It rebuilds only on a clear pre-acceptance refusal (busy mempool).
let receipt, tx;
try { ({ receipt, tx } = await submitOnce(net, await build(), { rebuild: build })); }
catch (e) { console.error("refused:", e.message); process.exit(1); }
if (receipt) console.log(`tx ${tx.id} accepted; rc_used ${receipt.rc_used}; compute ${receipt.compute_bandwidth_used}`);
try { console.log(`mined in block ${await waitMined(net, tx.id, 180000)}`); } catch { console.log("not seen within 3 minutes; checking balances"); }
for (let i = 0; i < 12; i++) {
  const left = await balance(net, from);
  if (left === have - value) {
    console.log(`done: ${from} now ${fmtKoin(left)}, ${to} now ${fmtKoin(await balance(net, to))}`);
    process.exit(0);
  }
  await sleep(15000);
}
console.error(`balances have not changed yet; check transaction ${tx.id} before retrying`);
process.exit(1);
