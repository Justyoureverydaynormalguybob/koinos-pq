// Mints KOIN on the private devnet (the test build's mint is authorised by the KOIN contract's own key).
//
//   node devnet/mint.mjs <address> <amount KOIN>
// The transaction goes to the mempool; produce a block with devnet/produce-block.mjs or devnet/auto-blocks.mjs.
import { network, koinContract, Signer } from "../cli/lib.mjs";
import { KOIN_WIF } from "./make-genesis.mjs";

const [to, amount] = process.argv.slice(2);
if (!to || !amount) { console.error("usage: node devnet/mint.mjs <address> <amount KOIN>"); process.exit(2); }
const net = network("devnet");
const signer = Signer.fromWif(KOIN_WIF);
signer.provider = net.provider;
const koin = koinContract(net, signer);
const value = String(Math.round(Number(amount) * 1e8));
const { transaction } = await koin.functions.mint({ to, value }, { rcLimit: "2000000", sendTransaction: true });
console.log(`mint ${amount} KOIN -> ${to}: tx ${transaction.id} submitted`);
