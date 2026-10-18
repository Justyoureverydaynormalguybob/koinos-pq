// Produces one block on the private devnet containing whatever the mempool holds, signed by the genesis key.
// Useful after submitting a transaction from outside devnet/run.mjs (for example from the browser wallet).
//
//   node devnet/produce-block.mjs            # one block
//   node devnet/produce-block.mjs 5          # five blocks
import { network, Signer } from "../cli/lib.mjs";
import { GENESIS_WIF } from "./make-genesis.mjs";

const net = network("devnet");
const provider = net.provider;
const genesis = Signer.fromWif(GENESIS_WIF);
genesis.provider = provider;

async function pending() {
  const r = await fetch(net.rpc[0], { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "mempool.get_pending_transactions", params: { limit: 500 } }) });
  const j = await r.json();
  return ((j.result && j.result.pending_transactions) || []).map((p) => p.transaction);
}

const count = Math.max(1, Number(process.argv[2] || 1));
for (let i = 0; i < count; i++) {
  const head = await provider.call("chain.get_head_info");
  const txs = (await pending()).map((t) => ({ id: t.id, header: t.header, operations: t.operations, signatures: t.signatures }));
  const block = { header: { height: String(Number(head.head_topology.height || 0) + 1) }, transactions: txs };
  const signed = await genesis.signBlock(await genesis.prepareBlock(block));
  const res = await provider.submitBlock(signed);
  const r = (res && res.receipt) || {};
  const receipts = r.transaction_receipts || [];
  console.log(`block ${block.header.height}: ${txs.length} transaction(s)${receipts.map((t) => ` ${t.id.slice(0, 14)}… rc_used ${t.rc_used} compute ${t.compute_bandwidth_used} network ${t.network_bandwidth_used}B${t.reverted ? " REVERTED" : ""}`).join("")}`);
}
