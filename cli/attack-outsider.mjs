// The outsider attack, as a repeatable NEGATIVE test: everything someone without the account's ML-DSA-44
// key can try against a locked pqwallet account. The attacker here never loads a key file; all it knows
// is the victim's public address (and, like anyone, what is on the chain). Every transaction below must
// be refused. Exit 0: all refused and the account is unchanged. Exit 1: something was accepted or the
// account changed. Exit 2: a case could not be judged (the node did not answer), so nothing is proven.
//
// Usage: node cli/attack-outsider.mjs [victim-address ...]      (KOINOS_NETWORK, default testnet)
//   ATTACKER_WIF=<funded key of the attacker's own>   also runs the cases where the attacker pays the mana
//   ALLOW_MAINNET=1                            needed to aim it at mainnet (refused otherwise)
// A refused transaction never reaches a block, so a clean run leaves no trace on the chain.
import { randomBytes } from "node:crypto";
import { network, koinContract, pqContract, pqKeysFromSeed, pqProofOfPossession, pqSignTxIdNative, nativeEntry,
  buildTransaction, submit, pqSignTxId, b64url, Signer, balance, fmtKoin, hex, restGet, utils } from "./lib.mjs";

const net = network();
if (net.name === "mainnet" && process.env.ALLOW_MAINNET !== "1") {
  console.error("refusing to run against mainnet: set ALLOW_MAINNET=1 if that is really what you mean");
  process.exit(2);
}
const POB = { mainnet: "159myq5YUhhoVWu3wsHKHiJYKPKGUrGiyv", testnet: "1MAbK5pYkhp9yHnfhYamC3tfSLmVRTDjd9" }[net.name] ?? null;
const victims = process.argv.slice(2).filter((a) => !a.startsWith("--"));
if (!victims.length) victims.push("1FqXVbjZnMo2cUNj56LNCrc8R22RWDmq1t"); // the long-standing locked Harbinger account
const RC = process.env.RC_LIMIT || "2000000000";

const attacker = pqKeysFromSeed(hex(randomBytes(32))); // a fresh ML-DSA-44 key: it never saw the victim's seed
const ecdsa = Signer.fromSeed(hex(randomBytes(32)));   // and a fresh secp256k1 key
const sink = ecdsa.getAddress();
const payer = process.env.ATTACKER_WIF ? Signer.fromWif(process.env.ATTACKER_WIF) : null;
if (payer) payer.provider = net.provider;

let accepted = 0, unclear = 0, refused = 0;
const first = (e) => String((e && e.message) || e).split("\n")[0].slice(0, 170);
// what a node says when it has judged the transaction and said no, as opposed to not answering at all
const JUDGED = /return buffer|authoriz|signature|insufficient|revert|invalid|failed|exception|denied|not allowed|unknown|expected|nonce|rc/i;

async function attempt(label, build) {
  let tx;
  try {
    tx = await build();
  } catch (e) {
    if (e && e.skip) { console.log(`  [--] ${label}: skipped: ${first(e)}`); return; } // not possible here: nothing to judge
    unclear++;
    console.log(`  [?] ${label}: could not build: ${first(e)}`);
    return;
  }
  try {
    const { receipt } = await submit(net, tx);
    if (receipt && receipt.reverted) {
      refused++;
      console.log(`  [ok] ${label}: reverted on the chain, nothing changed (the attacker paid the mana)`);
    } else {
      accepted++;
      console.log(`  [!!] ${label}: ACCEPTED, tx ${tx.id}. BROKEN`);
    }
  } catch (e) {
    if (JUDGED.test(first(e))) {
      refused++;
      console.log(`  [ok] ${label}: refused: ${first(e)}`);
    } else {
      unclear++;
      console.log(`  [?] ${label}: no verdict: ${first(e)}`);
    }
  }
}

// protobuf, by hand, for the two calls koilib has no ABI for here
const varint = (n) => { const out = []; let v = BigInt(n); do { let b = Number(v & 0x7fn); v >>= 7n; if (v) b |= 0x80; out.push(b); } while (v); return out; };
const bytesField = (num, u8) => [(num << 3) | 2, ...varint(u8.length), ...u8];
const addr = (a) => utils.decodeBase58(a);
const call = (contract, entry, args) => ({ call_contract: { contract_id: contract, entry_point: entry, args: b64url(Uint8Array.from(args)) } });
const allowOp = (account, who, allowed) => call(account, 0x4cb90951, [...bytesField(1, addr(who)), 0x10, allowed ? 1 : 0]);
const burnOp = (from, vhpTo, value) => call(POB, 0x859facc5, [0x08, ...varint(value), ...bytesField(2, addr(from)), ...bytesField(3, addr(vhpTo))]);

async function state(victim) {
  const pq = pqContract(net, victim);
  const [bal, key, info] = await Promise.all([
    balance(net, victim),
    pq.functions.get_public_key({}).then((r) => (r.result && r.result.value) || "", () => "unreadable"),
    pq.functions.get_info({}).then((r) => JSON.stringify(r.result || {}), () => "unreadable"),
  ]);
  let pob = "n/a";
  if (POB) pob = await pq.functions.get_allowed_caller({ caller: POB }).then((r) => String(!!(r.result && r.result.value)), () => "unreadable");
  return { bal, key, info, pob };
}

for (const victim of victims) {
  console.log(`\n${net.name}: attacking ${victim}`);
  const before = await state(victim);
  if (before.key === "unreadable" || before.key === "") {
    console.log("  [?] no pqwallet contract with a registered key answers at this address; nothing to attack");
    unclear++;
    continue;
  }
  console.log(`  before: ${fmtKoin(before.bal)}, key ${before.key.slice(0, 12)}…, PoB on its allowed list: ${before.pob}`);
  const transfer = async (from, to, value) => (await koinContract(net).functions.transfer({ from, to, value: String(value) }, { onlyOperation: true })).operation;
  const amount = before.bal > 100000000n ? 100000000n : before.bal > 0n ? before.bal : 1n;
  const asVictim = (ops) => buildTransaction(net, victim, ops, RC);
  const pqSign = (tx) => { tx.signatures = [b64url(pqSignTxId(tx.id, attacker.secretKey))]; return tx; };

  await attempt("1 drain, signed with the attacker's own ML-DSA-44 key", async () => pqSign(await asVictim([await transfer(victim, sink, amount)])));

  await attempt("2 takeover: set_public_key to the attacker's key, with a valid proof of possession", async () => {
    const { operation } = await pqContract(net, victim).functions.set_public_key(
      { public_key: b64url(attacker.publicKey), proof: b64url(pqProofOfPossession(victim, attacker.secretKey)) }, { onlyOperation: true });
    return pqSign(await asVictim([operation]));
  });

  await attempt("3 put the attacker's address on the allowed list", async () => pqSign(await asVictim([allowOp(victim, sink, true)])));

  await attempt("4 drain with no signature at all", async () => asVictim([await transfer(victim, sink, amount)]));

  await attempt("5 drain signed with a secp256k1 key (what an ordinary Koinos account would accept)", async () => {
    const tx = await asVictim([await transfer(victim, sink, amount)]);
    tx.signatures = (await ecdsa.signTransaction({ ...tx, signatures: [] })).signatures;
    return tx;
  });

  await attempt("6 drain carrying the native-format entry (0x01, public key, signature) of the attacker's key", async () => {
    const tx = await asVictim([await transfer(victim, sink, amount)]);
    tx.signatures = [b64url(nativeEntry(attacker.publicKey, pqSignTxIdNative(tx.id, attacker.secretKey)))];
    return tx;
  });

  await attempt("7 drain carrying a real signature of the victim's, lifted from its last transaction on the chain", async () => {
    const skip = (why) => Object.assign(new Error(why), { skip: true });
    if (!net.rest) throw skip("this network has no history API to lift a signature from");
    const rows = await restGet(net, `/account/${victim}/history?limit=20&ascending=false`);
    const old = rows.map((r) => r.trx && r.trx.transaction).find((t) => t && t.header && t.header.payer === victim && t.signatures && t.signatures.length);
    if (!old) throw skip("the victim has no transaction of its own on the chain yet");
    const tx = await asVictim([await transfer(victim, sink, amount)]);
    tx.signatures = [...old.signatures];
    return tx;
  });

  // the contract tries every 2,420-byte entry: six fit its buffer, a seventh overflows it and must fail closed
  for (const junk of [5, 6]) {
    await attempt(`8${junk === 5 ? "a" : "b"} drain behind ${junk} junk signatures and the attacker's (${junk + 1} entries${junk === 6 ? ", one more than the buffer holds" : ""})`, async () => {
      const tx = await asVictim([await transfer(victim, sink, amount)]);
      tx.signatures = [...Array.from({ length: junk }, () => b64url(randomBytes(2420))), b64url(pqSignTxId(tx.id, attacker.secretKey))];
      return tx;
    });
  }

  if (POB) {
    await attempt("9 burn sandwich: allow PoB, burn the victim's KOIN into VHP for the attacker, forbid PoB", async () =>
      pqSign(await asVictim([allowOp(victim, POB, true), burnOp(victim, sink, amount), allowOp(victim, POB, false)])));
  }

  if (payer) {
    const me = payer.getAddress();
    const paid = async (ops) => { const tx = await buildTransaction(net, me, ops, RC); return payer.signTransaction(tx); };
    await attempt("10 the attacker pays the mana and signs validly for itself: transfer out of the victim", async () => paid([await transfer(victim, sink, amount)]));
    await attempt("11 the attacker pays: set_public_key on the victim", async () => {
      const { operation } = await pqContract(net, victim).functions.set_public_key(
        { public_key: b64url(attacker.publicKey), proof: b64url(pqProofOfPossession(victim, attacker.secretKey)) }, { onlyOperation: true });
      return paid([operation]);
    });
    await attempt("12 the attacker pays: put itself on the victim's allowed list", async () => paid([allowOp(victim, me, true)]));
    if (POB) await attempt("13 the attacker pays: burn the victim's KOIN through PoB (PoB asks the victim, which must refuse a nested caller)", async () => paid([burnOp(victim, me, amount)]));
  } else {
    console.log("  (cases 10 to 13, where the attacker pays the mana itself, need ATTACKER_WIF)");
  }

  const after = await state(victim);
  const same = after.bal === before.bal && after.key === before.key && after.info === before.info && after.pob === before.pob;
  console.log(`  after:  ${fmtKoin(after.bal)}, key ${after.key.slice(0, 12)}…, PoB on its allowed list: ${after.pob} -> ${same ? "unchanged" : "CHANGED"}`);
  if (!same) accepted++;
  if (after.pob === "true") { accepted++; console.log("  [!!] PoB is on this account's allowed list"); }
}

console.log(`\n${refused} refused, ${accepted} accepted or changed, ${unclear} without a verdict`);
process.exit(accepted ? 1 : unclear ? 2 : 0);
