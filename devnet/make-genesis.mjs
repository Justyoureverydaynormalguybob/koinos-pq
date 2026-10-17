// Writes devnet/genesis_data.json: a private Koinos genesis whose genesis key we hold.
//
// Entries (all in the system metadata space, same keys mainnet uses):
//   genesis_key                 address of the devnet genesis key (the local-koinos dev WIF; devnet only)
//   resource_limit_data         copied from the koinos/koinos example genesis
//   max_account_resources       copied (10,000,000 rc for every account: the default get_account_rc thunk)
//   protocol_descriptor         copied
//   block_hash_code             copied (sha2-256)
//   compute_bandwidth_registry  rebuilt from the thunk cost table in koinos-chain/tests/thunk_test.cpp so
//                               every thunk the v1.5.2 node can call has a price
// The mainnet example also carries thousands of KOIN balance entries in zone 1; we leave those out.
//
//   node devnet/make-genesis.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { Signer, utils } from "koilib";

export const GENESIS_WIF = "5KYPA63Gx4MxQUqDM3PMckvX9nVYDUaLigTKAsLPesTyGmKmbR2"; // local-koinos dev key, public, devnet only
export const KOIN_WIF = "5JbxDqUqx581iL9Po1mLvHMLkxnmjvypDdnmdLQvK5TzSpCFSgH";    // local-koinos dev key for the KOIN contract

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) main();
function main() {
const keyOf = (n) => Buffer.concat([Buffer.from([0x12, 0x20]), createHash("sha256").update("object_key::" + n).digest()]).toString("base64");
const varint = (n) => { const o = []; let v = BigInt(n); do { let b = Number(v & 0x7fn); v >>= 7n; if (v) b |= 0x80; o.push(b); } while (v); return Buffer.from(o); };
const lenDelim = (field, buf) => Buffer.concat([Buffer.from([(field << 3) | 2]), varint(buf.length), buf]);

const example = JSON.parse(readFileSync(here("../../koinos-devnet/config-example/genesis_data.json"), "utf8"));
const byKey = Object.fromEntries(example.entries.filter((e) => e.space && e.space.system && !e.space.zone).map((e) => [e.key, e]));
const copied = ["resource_limit_data", "max_account_resources", "protocol_descriptor", "block_hash_code"].map((n) => {
  const e = byKey[keyOf(n)];
  if (!e) throw new Error(`example genesis lacks ${n}`);
  return { space: { system: true }, key: e.key, value: e.value };
});

// compute_bandwidth_registry { repeated compute_bandwidth_entry entries = 1 { string name = 1; uint64 compute = 2; } }
const src = readFileSync(here("../../koinos-chain/tests/thunk_test.cpp"), "utf8");
const table = src.slice(src.indexOf("std::map< std::string, uint64_t > thunk_compute{"), src.indexOf("};", src.indexOf("thunk_compute{")));
const entries = [...table.matchAll(/\{\s*"([a-z0-9_]+)",\s*([0-9']+)\s*\}/g)].map((m) => [m[1], Number(m[2].replace(/'/g, ""))]);
if (entries.length < 50) throw new Error(`only ${entries.length} thunk costs parsed`);
const registry = Buffer.concat(entries.map(([name, compute]) =>
  lenDelim(1, Buffer.concat([lenDelim(1, Buffer.from(name, "utf8")), Buffer.from([(2 << 3) | 0]), varint(compute)]))));

const genesis = Signer.fromWif(GENESIS_WIF);
const out = {
  entries: [
    { space: { system: true }, key: keyOf("genesis_key"), value: Buffer.from(utils.decodeBase58(genesis.getAddress())).toString("base64") },
    ...copied,
    { space: { system: true }, key: keyOf("compute_bandwidth_registry"), value: registry.toString("base64") },
  ],
};
writeFileSync(here("genesis_data.json"), JSON.stringify(out, null, 2) + "\n");

// resource_limit_data: disk_storage_limit=1 disk_storage_cost=2 network_bandwidth_limit=3 network_bandwidth_cost=4 compute_bandwidth_limit=5 compute_bandwidth_cost=6
const rl = Buffer.from(byKey[keyOf("resource_limit_data")].value, "base64");
const fields = {}; for (let i = 0; i < rl.length;) { const f = rl[i] >> 3; i++; let v = 0n, s = 0n; for (;;) { const b = rl[i++]; v |= BigInt(b & 0x7f) << s; s += 7n; if (b < 0x80) break; } fields[f] = v; }
console.log(`wrote devnet/genesis_data.json: genesis key ${genesis.getAddress()}, KOIN deployer ${Signer.fromWif(KOIN_WIF).getAddress()}, ${entries.length} thunk prices`);
console.log(`resource limits per block: disk ${fields[1]} (cost ${fields[2]}), network ${fields[3]} (cost ${fields[4]}), compute ${fields[5]} (cost ${fields[6]}); max_account_resources ${Buffer.from(byKey[keyOf("max_account_resources")].value, "base64").toString("hex")}`);
}
