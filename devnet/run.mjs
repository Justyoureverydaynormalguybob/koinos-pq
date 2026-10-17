// Drives the private devnet (devnet/docker-compose.yml) end to end for the native ML-DSA-44 path:
//
//   1. waits for the node, deploys the KOIN contract (local-koinos testnet build, owner-authorised mint)
//   2. mints to a post-quantum address (ML-DSA-44 key, address derived like any secp256k1 address) and
//      to an ordinary secp256k1 account
//   3. a transfer from the post-quantum address signed ONLY with a 3733-byte 0x01||pk||sig entry: mined
//   4. negative cases, all rejected at the mempool: flipped signature bit, the account contract's
//      context, wrong tag, secp256k1 signature for the post-quantum address, no signature
//   5. a plain secp256k1 transfer (unchanged path) and a mixed transaction carrying both kinds
//
// Blocks are produced here with the genesis key (no block producer service). Usage:
//
//   docker compose -f devnet/docker-compose.yml up -d
//   node devnet/run.mjs
import { readFileSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { network, keyFile, loadKeys, saveKeys, pqKeysFromSeed, pqAddress, pqSignTxIdNative, pqSignTxId, nativeEntry,
         buildTransaction, b64url, hex, sha256, Signer, Contract, utils, fmtKoin } from "../cli/lib.mjs";
import { GENESIS_WIF, KOIN_WIF } from "./make-genesis.mjs";

process.env.KOINOS_NETWORK = "devnet";
const net = network("devnet");
const provider = net.provider;
const genesis = Signer.fromWif(GENESIS_WIF); genesis.provider = provider;
const koinSigner = Signer.fromWif(KOIN_WIF); koinSigner.provider = provider;
if (koinSigner.getAddress() !== net.koin) throw new Error("devnet KOIN address in lib.mjs does not match KOIN_WIF");
// max_account_resources on this genesis is 10,000,000 per account and the default thunks never regenerate or
// release it until a block is irreversible, so each account must fit all its transactions under 10,000,000.
const RC = String(process.env.RC_LIMIT || 1_500_000);   // transfers (a KOIN transfer measured at about 0.55 M rc here)
const RC_DEPLOY = "3500000", RC_MINT = "2000000";     // deployer: 3.5 + 2 + 2 = 7.5 M
const report = [];
const log = (s) => { console.log(s); report.push(s); };

// ---------- helpers ----------
async function rpc(method, params = {}) { return provider.call(method, params); }
async function waitForNode(ms = 180000) {
  const t0 = Date.now();
  for (;;) {
    try { const h = await rpc("chain.get_head_info"); return h; }
    catch (e) { if (Date.now() - t0 > ms) throw new Error("node not reachable: " + e.message); await new Promise((r) => setTimeout(r, 2000)); }
  }
}
// Each block carries whatever the mempool holds plus the transactions handed over (deduplicated by id).
async function pendingTransactions() {
  const r = await fetch(net.rpc[0], { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "mempool.get_pending_transactions", params: { limit: 500 } }) });
  const j = await r.json();
  return ((j.result && j.result.pending_transactions) || []).map((p) => p.transaction);
}
async function produceBlock(transactions = []) {
  const head = await rpc("chain.get_head_info");
  const seen = new Set(), txs = [];
  for (const t of [...(await pendingTransactions()), ...transactions]) {
    if (seen.has(t.id)) continue;
    seen.add(t.id);
    txs.push({ id: t.id, header: t.header, operations: t.operations, signatures: t.signatures });
  }
  const block = { header: { height: String(Number(head.head_topology.height || 0) + 1) }, transactions: txs };
  const prepared = await genesis.prepareBlock(block);
  const signed = await genesis.signBlock(prepared);
  const res = await provider.submitBlock(signed);
  const receipt = res && res.receipt;
  // the mempool prunes included transactions asynchronously; wait so the next submission sees free rc
  for (let i = 0; i < 50; i++) {
    const still = (await pendingTransactions()).filter((t) => seen.has(t.id));
    if (!still.length) break;
    await new Promise((r) => setTimeout(r, 200));
  }
  return { height: block.header.height, txs: block.transactions.length, receipt };
}
async function balanceOf(address) {
  const { result } = await koin.functions.balanceOf({ owner: address });
  return BigInt((result && result.value) || "0");
}
async function submitExpectOk(tx, label) {
  const { receipt } = await provider.sendTransaction(tx);
  const b = await produceBlock([tx]);
  const txInBlock = await rpc("block_store.get_blocks_by_height", { head_block_id: (await rpc("chain.get_head_info")).head_topology.id, ancestor_start_height: b.height, num_blocks: 1, return_block: true, return_receipt: true });
  const item = txInBlock.block_items[0];
  const mined = (item.block.transactions || []).some((t) => t.id === tx.id);
  const r = ((item.receipt && item.receipt.transaction_receipts) || []).find((t) => t.id === tx.id) || receipt;
  log(`  ${label}: tx ${tx.id.slice(0, 18)}… ${mined ? "MINED" : "NOT IN BLOCK"} in block ${b.height}; rc_used ${r.rc_used}; compute ${r.compute_bandwidth_used}; network ${r.network_bandwidth_used} B; reverted ${!!r.reverted}`);
  if (!mined || r.reverted) throw new Error(`${label}: expected the transaction to be mined and applied`);
  return r;
}
async function submitExpectReject(tx, label) {
  try {
    await provider.sendTransaction(tx);
  } catch (e) {
    const msg = ((e && e.message) || String(e)).split("\n")[0].slice(0, 140);
    log(`  ${label}: rejected as expected (${msg})`);
    return;
  }
  throw new Error(`${label}: the node accepted a transaction it must reject`);
}
const transferOp = async (from, to, value) => (await koin.functions.transfer({ from, to, value }, { onlyOperation: true })).operation;
const KOIN = (n) => String(Math.round(n * 1e8));

// ---------- keys ----------
if (!existsSync(keyFile("devnet"))) {
  const account = Signer.fromSeed(hex(randomBytes(32)));
  const seedHex = hex(randomBytes(32));
  const pq = pqKeysFromSeed(seedHex);
  saveKeys("devnet", { network: "devnet", createdAt: new Date().toISOString(),
    account: { address: account.getAddress(), wif: account.getPrivateKey("wif") },
    pq: { scheme: "ML-DSA-44", seedHex, publicKeyHex: hex(pq.publicKey), publicKeySha256: hex(sha256(pq.publicKey)) } });
}
const k = loadKeys("devnet");
const pq = pqKeysFromSeed(k.pq.seedHex);
const pqAddr = pqAddress(pq.publicKey);
const secp = Signer.fromWif(k.account.wif); secp.provider = provider;
const secpAddr = secp.getAddress();
const sink = Signer.fromSeed(hex(sha256("koinos-pq devnet sink"))).getAddress();

// ---------- 1. node + KOIN ----------
log(`koinos-pq devnet run ${new Date().toISOString()}`);
const head = await waitForNode();
log(`node up: head height ${head.head_topology.height || 0}, chain id ${await rpc("chain.get_chain_id").then((r) => r.chain_id)}`);
{ const pending = await pendingTransactions(); if (pending.length) { const b = await produceBlock(); log(`drained ${pending.length} pending transaction(s) from an earlier run into block ${b.height}`); } }
const bytecode = readFileSync(fileURLToPath(new URL("./koin.wasm", import.meta.url)));
const koin = new Contract({ id: net.koin, abi: utils.tokenAbi, provider, signer: koinSigner, bytecode });
let deployed = false;
try { await koin.functions.name(); deployed = true; } catch { deployed = false; }
if (!deployed) {
  const { transaction } = await koin.deploy({ rcLimit: RC_DEPLOY, sendTransaction: true });
  const b = await produceBlock([transaction]);
  log(`KOIN deployed at ${net.koin} (tx ${transaction.id.slice(0, 18)}…, block ${b.height}, ${bytecode.length} B wasm)`);
} else {
  log(`KOIN already deployed at ${net.koin}`);
}
// The current KOIN keeps its balances in system space, so it must be a system contract (as on mainnet).
// Only the genesis key can flag it: a set_system_contract operation under system authority.
try {
  await balanceOf(sink);
} catch (e) {
  if (!/system space/.test(e.message || "")) throw e;
  const tx = await buildTransaction(net, genesis.getAddress(), [{ set_system_contract: { contract_id: net.koin, system_contract: true } }], RC);
  tx.signatures = (await genesis.signTransaction({ ...tx, signatures: [] })).signatures;
  await provider.sendTransaction(tx);
  const b = await produceBlock([tx]);
  log(`KOIN flagged as a system contract by the genesis key (block ${b.height})`);
  await balanceOf(sink); // must work now
}
log(`post-quantum address ${pqAddr} (ML-DSA-44 key, sha256 ${k.pq.publicKeySha256.slice(0, 16)}…); secp256k1 account ${secpAddr}`);

// ---------- 2. mint ----------
for (const to of [pqAddr, secpAddr]) {
  if ((await balanceOf(to)) >= 10n * 10n ** 8n) continue;
  // one block per mint: koilib reads the nonce from chain state, not from the mempool
  const { transaction } = await koin.functions.mint({ to, value: KOIN(1000) }, { rcLimit: RC_MINT, sendTransaction: true });
  const b = await produceBlock([transaction]);
  log(`minted 1000 KOIN to ${to} (block ${b.height})`);
}
log(`balances: pq ${fmtKoin(await balanceOf(pqAddr))}, secp ${fmtKoin(await balanceOf(secpAddr))}, sink ${fmtKoin(await balanceOf(sink))}`);

// ---------- 3. the native transfer ----------
log("3. transfer from the post-quantum address, signed only with a 3733-byte ML-DSA-44 entry");
{
  const tx = await buildTransaction(net, pqAddr, [await transferOp(pqAddr, sink, KOIN(1))], RC);
  const sig = pqSignTxIdNative(tx.id, pq.secretKey);
  tx.signatures = [b64url(nativeEntry(pq.publicKey, sig))];
  const before = await balanceOf(sink);
  const r = await submitExpectOk(tx, "native 0x01||pk||sig (3733 B)");
  const after = await balanceOf(sink);
  log(`  sink balance ${fmtKoin(before)} -> ${fmtKoin(after)}`);
  if (after - before !== 10n ** 8n) throw new Error("transfer did not move 1 KOIN");
  report.nativeReceipt = r;
}

// ---------- 4. negatives ----------
log("4. negative cases (each must be rejected by the node)");
{
  const mk = async () => buildTransaction(net, pqAddr, [await transferOp(pqAddr, sink, KOIN(1))], RC);
  let tx = await mk(); { const s = pqSignTxIdNative(tx.id, pq.secretKey); s[10] ^= 1; tx.signatures = [b64url(nativeEntry(pq.publicKey, s))]; }
  await submitExpectReject(tx, "flipped signature bit");
  tx = await mk(); tx.signatures = [b64url(nativeEntry(pq.publicKey, pqSignTxId(tx.id, pq.secretKey)))];
  await submitExpectReject(tx, "signed with the account contract's context koinos/pqwallet/1");
  tx = await mk(); { const e = nativeEntry(pq.publicKey, pqSignTxIdNative(tx.id, pq.secretKey)); e[0] = 0x02; tx.signatures = [b64url(e)]; }
  await submitExpectReject(tx, "tag 0x02 instead of 0x01");
  tx = await mk(); { const e = nativeEntry(pq.publicKey, pqSignTxIdNative(tx.id, pq.secretKey)); tx.signatures = [b64url(e.subarray(0, e.length - 1))]; }
  await submitExpectReject(tx, "3732 bytes");
  tx = await mk(); { const other = pqKeysFromSeed(hex(sha256("some other seed"))); tx.signatures = [b64url(nativeEntry(other.publicKey, pqSignTxIdNative(tx.id, other.secretKey)))]; }
  await submitExpectReject(tx, "valid entry from a different ML-DSA key");
  tx = await mk(); tx.signatures = (await secp.signTransaction(tx)).signatures;
  await submitExpectReject(tx, "65-byte secp256k1 signature for the post-quantum address");
  tx = await mk(); tx.signatures = [];
  await submitExpectReject(tx, "no signature");
}

// ---------- 5. secp256k1 unchanged, and a mixed transaction ----------
log("5. secp256k1 path unchanged, and a transaction carrying both kinds");
{
  const tx = await buildTransaction(net, secpAddr, [await transferOp(secpAddr, sink, KOIN(1))], RC);
  tx.signatures = (await secp.signTransaction(tx)).signatures;
  report.secpReceipt = await submitExpectOk(tx, "plain secp256k1 transfer (65 B)");
}
{
  // payer: the post-quantum address; operations move 1 KOIN from each account; signatures: secp first, then ML-DSA
  const tx = await buildTransaction(net, pqAddr, [await transferOp(pqAddr, sink, KOIN(1)), await transferOp(secpAddr, sink, KOIN(1))], RC);
  const secpSig = (await secp.signTransaction({ ...tx, signatures: [] })).signatures[0];
  tx.signatures = [secpSig, b64url(nativeEntry(pq.publicKey, pqSignTxIdNative(tx.id, pq.secretKey)))];
  const before = await balanceOf(sink);
  await submitExpectOk(tx, "mixed: secp256k1 + ML-DSA-44 entries, two accounts");
  const after = await balanceOf(sink);
  if (after - before !== 2n * 10n ** 8n) throw new Error("mixed transaction did not move 2 KOIN");
  log(`  sink balance ${fmtKoin(before)} -> ${fmtKoin(after)}`);
}
{
  // a transaction that needs the ML-DSA signer but carries only the secp256k1 one must fail
  const tx = await buildTransaction(net, pqAddr, [await transferOp(pqAddr, sink, KOIN(1)), await transferOp(secpAddr, sink, KOIN(1))], RC);
  tx.signatures = (await secp.signTransaction({ ...tx, signatures: [] })).signatures;
  await submitExpectReject(tx, "mixed operations with only the secp256k1 signature");
}

log(`final balances: pq ${fmtKoin(await balanceOf(pqAddr))}, secp ${fmtKoin(await balanceOf(secpAddr))}, sink ${fmtKoin(await balanceOf(sink))}`);
const n = report.nativeReceipt, s = report.secpReceipt;
if (n && s) log(`cost: native transfer compute ${n.compute_bandwidth_used} ticks / ${n.network_bandwidth_used} B; secp256k1 transfer compute ${s.compute_bandwidth_used} ticks / ${s.network_bandwidth_used} B; difference ${Number(n.compute_bandwidth_used) - Number(s.compute_bandwidth_used)} ticks, ${Number(n.network_bandwidth_used) - Number(s.network_bandwidth_used)} B`);
log("ALL DEVNET CHECKS PASSED");
