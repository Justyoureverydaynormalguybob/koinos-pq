// The outsider attack, as a repeatable NEGATIVE test: everything someone without the account's ML-DSA-44
// key can try against a locked pqwallet account. The attacker here never loads a key file; all it knows
// is the victim's public address (and, like anyone, what is on the chain). Every transaction below must
// be refused.
//   Exit 0: every case was refused BY THE CHECK IT IS AIMED AT, and the account is unchanged.
//   Exit 1: something was accepted, or the account changed.
//   Exit 2: a case got no verdict, or was refused somewhere else than the check it is aimed at, so
//           that check was not exercised and nothing is proven about it.
// Only the chain's own refusal texts count as "refused" (cli/refusals.mjs). A network error, an HTML
// error page, "AMQP connection is not open", too little mana: all "no verdict".
//
// Which case reaches which check:
//   1, 2, 3, 5, 6, 7, 8a, 9   the payer check. The victim is the payer, so the chain asks the account's
//                             authorize() first and the signature rule says no. The operations in these
//                             transactions (transfer, set_public_key, set_allowed_caller, burn) never run.
//   4                         the chain's basic check (no signature at all); authorize() is not reached.
//   8b                        the contract's 16 KiB buffer: authorize() fails closed.
//   10                        (attacker pays) the token asks the account for a direct transfer: signature rule.
//   11, 12                    (attacker pays) set_public_key and set_allowed_caller themselves run and refuse.
//   13                        (attacker pays) PoB calls the token, the token asks the account: the
//                             nested-caller rule, the only case that reaches it.
// So without ATTACKER_WIF this script tests the payer check and nothing behind it.
//
// Usage: node cli/attack-outsider.mjs [victim-address ...]      (KOINOS_NETWORK, default testnet)
//   ATTACKER_WIF=<funded key of the attacker's own>   also runs the cases where the attacker pays the mana
//   ALLOW_MAINNET=1                            needed to aim it at mainnet (refused otherwise)
// A refused transaction never reaches a block, so a clean run leaves no trace on the chain.
import { randomBytes } from "node:crypto";
import { network, koinContract, pqContract, pqKeysFromSeed, pqProofOfPossession, pqSignTxIdNative, nativeEntry,
  buildTransaction, submit, pqSignTxId, b64url, Signer, balance, fmtKoin, hex, restGet, utils } from "./lib.mjs";
import { CHECKS, refusedBy, errorText } from "./refusals.mjs";

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

let accepted = 0, unclear = 0, refused = 0, elsewhere = 0;
const first = (e) => errorText(e).split("\n")[0].slice(0, 170);
const reached = {}; // check -> case numbers refused there

/** `aim` is the key in CHECKS this case is meant to be stopped by. */
async function attempt(label, aim, victim, build) {
  const no = label.split(" ")[0];
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
    if (!receipt || receipt.rpc_error) {
      // koilib turns "rpc failed, context deadline exceeded" into a made-up receipt: the node never answered
      unclear++;
      console.log(`  [?] ${label}: no verdict: the node gave no receipt${receipt ? ` (${first(JSON.stringify(receipt.rpc_error))})` : ""}`);
    } else if (receipt.reverted) {
      // In a block but reverted: the chain did refuse, and the receipt's logs say where, if anywhere.
      const by = (receipt.logs || []).map((l) => refusedBy(l, victim)).find(Boolean) || null;
      note(label, no, aim, by, `reverted on the chain, nothing changed (the attacker paid the mana)${by ? "" : "; the receipt does not say which check"}`);
    } else {
      accepted++;
      console.log(`  [!!] ${label}: ACCEPTED, tx ${tx.id}. BROKEN`);
    }
  } catch (e) {
    const by = refusedBy(e, victim);
    if (by) note(label, no, aim, by, first(e));
    else { unclear++; console.log(`  [?] ${label}: no verdict (not one of the chain's refusal texts): ${first(e)}`); }
  }
}
function note(label, no, aim, by, text) {
  if (by === aim) {
    refused++;
    (reached[by] ??= []).push(no);
    console.log(`  [ok] ${label}: refused by the ${CHECKS[by].name}: ${text}`);
  } else {
    elsewhere++;
    if (by) (reached[by] ??= []).push(no);
    console.log(`  [~] ${label}: refused, but ${by ? `by the ${CHECKS[by].name}` : "it is not clear where"}, not by the ${CHECKS[aim].name} it is aimed at: ${text}`);
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
    balance(net, victim).catch(() => null),
    pq.functions.get_public_key({}).then((r) => (r.result && r.result.value) || "", () => "unreadable"),
    pq.functions.get_info({}).then((r) => JSON.stringify(r.result || {}), () => "unreadable"),
  ]);
  let pob = "n/a";
  if (POB) pob = await pq.functions.get_allowed_caller({ contract: POB }).then((r) => String(!!(r.result && r.result.value)), () => "unreadable");
  return { bal, key, info, pob };
}

for (const victim of victims) {
  console.log(`\n${net.name}: attacking ${victim}`);
  const before = await state(victim);
  if (before.bal === null) {
    console.log("  [?] the node did not answer; nothing was tried and nothing is proven");
    unclear++;
    continue;
  }
  if (before.key === "unreadable" || before.key === "") {
    console.log("  [?] no pqwallet contract with a registered key answers at this address; nothing to attack");
    unclear++;
    continue;
  }
  if (before.info === "unreadable" || before.pob === "unreadable") {
    console.log("  [?] the account's state could not be read before the attack; a before/after comparison would prove nothing");
    unclear++;
    continue;
  }
  console.log(`  before: ${fmtKoin(before.bal)}, key ${before.key.slice(0, 12)}…, PoB on its allowed list: ${before.pob}`);
  const transfer = async (from, to, value) => (await koinContract(net).functions.transfer({ from, to, value: String(value) }, { onlyOperation: true })).operation;
  const amount = before.bal > 100000000n ? 100000000n : before.bal > 0n ? before.bal : 1n;
  const asVictim = (ops) => buildTransaction(net, victim, ops, RC);
  const pqSign = (tx) => { tx.signatures = [b64url(pqSignTxId(tx.id, attacker.secretKey))]; return tx; };

  await attempt("1 drain, signed with the attacker's own ML-DSA-44 key", "payer", victim, async () => pqSign(await asVictim([await transfer(victim, sink, amount)])));

  await attempt("2 takeover: set_public_key to the attacker's key, with a valid proof of possession", "payer", victim, async () => {
    const { operation } = await pqContract(net, victim).functions.set_public_key(
      { public_key: b64url(attacker.publicKey), proof: b64url(pqProofOfPossession(victim, attacker.secretKey)) }, { onlyOperation: true });
    return pqSign(await asVictim([operation]));
  });

  await attempt("3 put the attacker's address on the allowed list", "payer", victim, async () => pqSign(await asVictim([allowOp(victim, sink, true)])));

  await attempt("4 drain with no signature at all", "nosig", victim, async () => asVictim([await transfer(victim, sink, amount)]));

  await attempt("5 drain signed with a secp256k1 key (what an ordinary Koinos account would accept)", "payer", victim, async () => {
    const tx = await asVictim([await transfer(victim, sink, amount)]);
    tx.signatures = (await ecdsa.signTransaction({ ...tx, signatures: [] })).signatures;
    return tx;
  });

  await attempt("6 drain carrying the native-format entry (0x01, public key, signature) of the attacker's key", "payer", victim, async () => {
    const tx = await asVictim([await transfer(victim, sink, amount)]);
    tx.signatures = [b64url(nativeEntry(attacker.publicKey, pqSignTxIdNative(tx.id, attacker.secretKey)))];
    return tx;
  });

  await attempt("7 drain carrying a real signature of the victim's, lifted from its last transaction on the chain", "payer", victim, async () => {
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
    await attempt(`8${junk === 5 ? "a" : "b"} drain behind ${junk} junk signatures and the attacker's (${junk + 1} entries${junk === 6 ? ", one more than the buffer holds" : ""})`, junk === 6 ? "buffer" : "payer", victim, async () => {
      const tx = await asVictim([await transfer(victim, sink, amount)]);
      tx.signatures = [...Array.from({ length: junk }, () => b64url(randomBytes(2420))), b64url(pqSignTxId(tx.id, attacker.secretKey))];
      return tx;
    });
  }

  if (POB) {
    await attempt("9 burn sandwich: allow PoB, burn the victim's KOIN into VHP for the attacker, forbid PoB", "payer", victim, async () =>
      pqSign(await asVictim([allowOp(victim, POB, true), burnOp(victim, sink, amount), allowOp(victim, POB, false)])));
  }

  if (payer) {
    const me = payer.getAddress();
    const paid = async (ops) => { const tx = await buildTransaction(net, me, ops, RC); return payer.signTransaction(tx); };
    await attempt("10 the attacker pays the mana and signs validly for itself: transfer out of the victim", "token", victim, async () => paid([await transfer(victim, sink, amount)]));
    await attempt("11 the attacker pays: set_public_key on the victim", "contract", victim, async () => {
      const { operation } = await pqContract(net, victim).functions.set_public_key(
        { public_key: b64url(attacker.publicKey), proof: b64url(pqProofOfPossession(victim, attacker.secretKey)) }, { onlyOperation: true });
      return paid([operation]);
    });
    await attempt("12 the attacker pays: put itself on the victim's allowed list", "contract", victim, async () => paid([allowOp(victim, me, true)]));
    if (POB) await attempt("13 the attacker pays: burn the victim's KOIN through PoB (the token asks the victim, which must refuse a nested caller)", "nested", victim, async () => paid([burnOp(victim, me, amount)]));
  } else {
    console.log("  (cases 10 to 13 need ATTACKER_WIF. Without them only the payer check was tried: set_public_key,");
    console.log("   set_allowed_caller and the nested-caller rule were NOT reached by this run)");
  }

  const after = await state(victim);
  if (after.bal === null || [after.key, after.info, after.pob].includes("unreadable")) {
    console.log("  [?] the account's state could not be read after the attack; unchanged is not proven");
    unclear++;
    continue;
  }
  const same = after.bal === before.bal && after.key === before.key && after.info === before.info && after.pob === before.pob;
  console.log(`  after:  ${fmtKoin(after.bal)}, key ${after.key.slice(0, 12)}…, PoB on its allowed list: ${after.pob} -> ${same ? "unchanged" : "CHANGED"}`);
  if (!same) accepted++;
  if (after.pob === "true") { accepted++; console.log("  [!!] PoB is on this account's allowed list"); }
}

console.log("\nwhich check refused which case:");
for (const [key, c] of Object.entries(CHECKS)) {
  console.log(`  ${c.name}: ${reached[key] ? [...new Set(reached[key])].join(", ") : "not reached in this run"}`);
}
console.log(`\n${refused} refused where aimed, ${elsewhere} refused somewhere else, ${accepted} accepted or changed, ${unclear} without a verdict`);
process.exit(accepted ? 1 : unclear || elsewhere ? 2 : 0);
