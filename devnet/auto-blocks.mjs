// Keeps producing blocks on the private devnet, like a block producer would: every interval, if the
// mempool holds transactions (or always, with --always), sign a block with the genesis key.
//
//   node devnet/auto-blocks.mjs            # a block whenever something is pending, checked every 2 s
//   node devnet/auto-blocks.mjs --always   # a block every 2 s regardless
//   INTERVAL_MS=1000 node devnet/auto-blocks.mjs
import { network, Signer } from "../cli/lib.mjs";
import { GENESIS_WIF } from "./make-genesis.mjs";

const net = network("devnet");
const provider = net.provider;
const genesis = Signer.fromWif(GENESIS_WIF);
genesis.provider = provider;
const always = process.argv.includes("--always");
const interval = Number(process.env.INTERVAL_MS || 2000);

async function pending() {
  const r = await fetch(net.rpc[0], { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "mempool.get_pending_transactions", params: { limit: 500 } }) });
  const j = await r.json();
  return ((j.result && j.result.pending_transactions) || []).map((p) => p.transaction);
}

console.log(`auto-blocks: every ${interval} ms${always ? ", always" : ", when the mempool has transactions"}; Ctrl-C to stop`);
for (;;) {
  try {
    const txs = (await pending()).map((t) => ({ id: t.id, header: t.header, operations: t.operations, signatures: t.signatures }));
    if (txs.length || always) {
      const head = await provider.call("chain.get_head_info");
      const block = { header: { height: String(Number(head.head_topology.height || 0) + 1) }, transactions: txs };
      const signed = await genesis.signBlock(await genesis.prepareBlock(block));
      const res = await provider.submitBlock(signed);
      const receipts = ((res && res.receipt) || {}).transaction_receipts || [];
      console.log(`${new Date().toISOString()} block ${block.header.height}: ${txs.length} tx${receipts.map((t) => ` ${t.id.slice(0, 12)}…${t.reverted ? " REVERTED" : ""}`).join("")}`);
    }
  } catch (e) {
    console.log("auto-blocks: " + ((e && e.message) || e).toString().split("\n")[0].slice(0, 160));
  }
  await new Promise((r) => setTimeout(r, interval));
}
