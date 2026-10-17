// SPDX-License-Identifier: MIT
// Pqwallet: a post-quantum (ML-DSA-44 / FIPS 204) authority contract for a Koinos account.
//
// How it works
//  * Upload this contract to the account's address with authorizes_call_contract,
//    authorizes_transaction_application (and, once happy, authorizes_upload_contract) set.
//  * While no key is registered, `authorize` falls back to the chain's normal rule:
//    a secp256k1 signature in the transaction that recovers to this address.
//  * `set_public_key` registers a 1312-byte ML-DSA-44 public key. From then on a
//    transaction is authorised only if one of its signatures is a 2420-byte ML-DSA-44
//    signature over the transaction id (34-byte multihash) with context CONTEXT.
//  * Verification runs in the vendored FIPS 204 reference code (wasm/dilithium.wasm),
//    linked into this module by wasm-merge; see scripts/build.sh.

import { Arrays, Crypto, Protobuf, Storage, System, authority, protocol } from "@koinos/sdk-as";
import { pqwallet } from "./proto/pqwallet";

// Provided by wasm/dilithium.wasm after wasm-merge. Pointers are offsets in this module's memory.
// Returns 1 for a valid signature, 0 otherwise. Never traps on bad lengths.
@external("dilithium", "mldsa44_verify")
declare function mldsa44_verify(
  sig: usize, siglen: u32,
  msg: usize, msglen: u32,
  ctx: usize, ctxlen: u32,
  pk: usize, pklen: u32
): i32;

export const PK_BYTES: i32 = 1312;
export const SIG_BYTES: i32 = 2420;
export const CONTEXT: string = "koinos/pqwallet/1";
const CONFIG_SPACE_ID: u32 = 0;
/** Room for a transaction with up to ~6 ML-DSA-44 signatures plus header and operations. */
export const SYSTEM_BUFFER_BYTES: u32 = 16384;

export class Pqwallet {
  contractId: Uint8Array;
  config: Storage.Obj<pqwallet.config_object>;

  constructor() {
    // A transaction carrying ML-DSA-44 signatures (2420 bytes each) does not fit the SDK's
    // default 1 KiB system-call buffer; System.getTransaction() needs room for the whole tx.
    System.setSystemBufferSize(SYSTEM_BUFFER_BYTES);
    const contractId = System.getContractId();
    this.contractId = contractId;
    this.config = new Storage.Obj(
      contractId,
      CONFIG_SPACE_ID,
      pqwallet.config_object.decode,
      pqwallet.config_object.encode,
      () => new pqwallet.config_object()
    );
  }

  /** ML-DSA-44 check of `sig` over `msg` under `pk`. */
  static verifyMlDsa44(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array): bool {
    if (sig.length != SIG_BYTES || pk.length != PK_BYTES) return false;
    const ctx = Uint8Array.wrap(String.UTF8.encode(CONTEXT));
    const r = mldsa44_verify(
      sig.dataStart, <u32>sig.length,
      msg.dataStart, <u32>msg.length,
      ctx.dataStart, <u32>ctx.length,
      pk.dataStart, <u32>pk.length
    );
    return r == 1;
  }

  /** Legacy rule: some signature recovers (secp256k1) to this address. */
  legacyAuthorized(tx: protocol.transaction): bool {
    const id = tx.id;
    if (id == null) return false;
    for (let i = 0; i < tx.signatures.length; i++) {
      const sig = tx.signatures[i];
      if (sig.length != 65) continue;
      const pub = System.recoverPublicKey(sig, id!);
      if (pub == null) continue;
      const addr = Crypto.addressFromPublicKey(pub!);
      if (Arrays.equal(addr, this.contractId)) return true;
    }
    return false;
  }

  /** The one rule everything hangs on. */
  authorizedByTransaction(): bool {
    const cfg = this.config.get()!;
    const tx = System.getTransaction();
    const pk = cfg.public_key;
    if (pk == null || pk!.length != PK_BYTES) {
      return this.legacyAuthorized(tx);
    }
    const id = tx.id;
    if (id == null) return false;
    for (let i = 0; i < tx.signatures.length; i++) {
      if (Pqwallet.verifyMlDsa44(tx.signatures[i], id!, pk!)) {
        cfg.verifications += 1;
        this.config.put(cfg);
        return true;
      }
    }
    return false;
  }

  authorize(args: authority.authorize_arguments): authority.authorize_result {
    // Same rule for contract_call, transaction_application and contract_upload:
    // the transaction must carry a valid signature of the registered kind.
    return new authority.authorize_result(this.authorizedByTransaction());
  }

  set_public_key(args: pqwallet.set_public_key_arguments): pqwallet.set_public_key_result {
    const newKey = args.public_key;
    System.require(newKey != null && newKey!.length == PK_BYTES, "public key must be 1312 bytes (ML-DSA-44)");
    System.require(this.authorizedByTransaction(), "not authorized");
    const cfg = this.config.get()!;
    cfg.public_key = newKey!;
    this.config.put(cfg);
    const hash = System.hash(Crypto.multicodec.sha2_256, newKey!)!;
    System.event(
      "pqwallet.key_set",
      Protobuf.encode(new pqwallet.key_set_event(this.contractId, hash), pqwallet.key_set_event.encode),
      [this.contractId]
    );
    return new pqwallet.set_public_key_result();
  }

  get_public_key(args: pqwallet.get_public_key_arguments): pqwallet.get_public_key_result {
    const cfg = this.config.get()!;
    const pk = cfg.public_key;
    return new pqwallet.get_public_key_result(pk == null ? new Uint8Array(0) : pk!);
  }

  get_info(args: pqwallet.get_info_arguments): pqwallet.get_info_result {
    const cfg = this.config.get()!;
    const pk = cfg.public_key;
    return new pqwallet.get_info_result(
      "ML-DSA-44 (FIPS 204), pure mode",
      <u32>PK_BYTES,
      <u32>SIG_BYTES,
      CONTEXT,
      pk != null && pk!.length == PK_BYTES,
      cfg.verifications
    );
  }
}
