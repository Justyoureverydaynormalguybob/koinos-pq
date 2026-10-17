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

import { Arrays, Crypto, Protobuf, Storage, System, authority, value } from "@koinos/sdk-as";
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
/** Room for a transaction with up to ~6 ML-DSA-44 signatures plus header and operations. */
export const SYSTEM_BUFFER_BYTES: u32 = 16384;
// Runs when the module starts, before the dispatcher calls System.getArguments(): a
// set_public_key call carries 1312 bytes of arguments, more than the SDK's 1 KiB default.
System.setSystemBufferSize(SYSTEM_BUFFER_BYTES);
export const SIG_BYTES: i32 = 2420;
export const CONTEXT: string = "koinos/pqwallet/1";
/**
 * Proof of possession: a NEW key proves it exists by signing this account's 25-byte address under
 * this context. It cannot sign the transaction id (the proof sits inside the operation that the id
 * commits to), and it does not need to: the transaction itself is still authorised by the current
 * key, so the proof only has to stop a key nobody holds from being registered.
 */
export const CONTEXT_POP: string = "koinos/pqwallet/1/pop";
const CONFIG_SPACE_ID: u32 = 0;
const ALLOWED_SPACE_ID: u32 = 1;

export class Pqwallet {
  contractId: Uint8Array;
  config: Storage.Obj<pqwallet.config_object>;
  allowed: Storage.Map<Uint8Array, pqwallet.allowed_object>;

  constructor() {
    // Also here, in case a caller constructs the class without the module start having run.
    if (System.getSystemBufferSize() < SYSTEM_BUFFER_BYTES) System.setSystemBufferSize(SYSTEM_BUFFER_BYTES);
    const contractId = System.getContractId();
    this.contractId = contractId;
    this.config = new Storage.Obj(
      contractId,
      CONFIG_SPACE_ID,
      pqwallet.config_object.decode,
      pqwallet.config_object.encode,
      () => new pqwallet.config_object()
    );
    this.allowed = new Storage.Map(
      contractId,
      ALLOWED_SPACE_ID,
      pqwallet.allowed_object.decode,
      pqwallet.allowed_object.encode,
      () => new pqwallet.allowed_object(false)
    );
  }

  /** True when the current entry point was invoked directly by a transaction operation. */
  static calledDirectly(): bool {
    const caller = System.getCaller().caller;
    return caller == null || caller!.length == 0;
  }

  /** ML-DSA-44 check of `sig` over `msg` under `pk`, with the given context string. */
  static verifyMlDsa44(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array, context: string = CONTEXT): bool {
    if (sig.length != SIG_BYTES || pk.length != PK_BYTES) return false;
    const ctx = Uint8Array.wrap(String.UTF8.encode(context));
    const r = mldsa44_verify(
      sig.dataStart, <u32>sig.length,
      msg.dataStart, <u32>msg.length,
      ctx.dataStart, <u32>ctx.length,
      pk.dataStart, <u32>pk.length
    );
    return r == 1;
  }

  /** Transaction id (34-byte multihash) without loading the whole transaction. */
  static txId(): Uint8Array | null {
    const f = System.getTransactionField("id");
    if (f == null) return null;
    const id = f!.bytes_value;
    return id.length == 34 ? id : null;
  }

  /**
   * Transaction signatures via get_transaction_field("signatures"). Only this field is loaded, so a
   * transaction carrying large operations (for example a 58 KB contract re-upload) still fits the
   * system-call buffer. A repeated field comes back as message_value = Any(list_type{values}).
   */
  static txSignatures(): Array<Uint8Array> {
    const out = new Array<Uint8Array>();
    const f = System.getTransactionField("signatures");
    if (f == null) return out;
    const any = f!.message_value;
    if (any == null) return out;
    const packed = any!.value;
    if (packed == null) return out;
    const list = Protobuf.decode<value.list_type>(packed!, value.list_type.decode);
    for (let i = 0; i < list.values.length; i++) out.push(list.values[i].bytes_value);
    return out;
  }

  /** Legacy rule: some signature recovers (secp256k1) to this address. */
  legacyAuthorized(id: Uint8Array, sigs: Array<Uint8Array>): bool {
    for (let i = 0; i < sigs.length; i++) {
      const sig = sigs[i];
      if (sig.length != 65) continue;
      const pub = System.recoverPublicKey(sig, id);
      if (pub == null) continue;
      const addr = Crypto.addressFromPublicKey(pub!);
      if (Arrays.equal(addr, this.contractId)) return true;
    }
    return false;
  }

  /** The one rule everything hangs on. */
  authorizedByTransaction(): bool {
    const id = Pqwallet.txId();
    if (id == null) return false;
    const sigs = Pqwallet.txSignatures();
    const cfg = this.config.get()!;
    const pk = cfg.public_key;
    if (pk == null || pk!.length != PK_BYTES) {
      return this.legacyAuthorized(id!, sigs);
    }
    for (let i = 0; i < sigs.length; i++) {
      if (Pqwallet.verifyMlDsa44(sigs[i], id!, pk!)) return true;
    }
    return false;
  }

  authorize(args: authority.authorize_arguments): authority.authorize_result {
    if (args.type == authority.authorization_type.contract_call) {
      // call.contract_id is the contract asking (e.g. the token), call.caller is who called THAT
      // contract: empty for a direct transaction operation, otherwise a nested contract (a DEX,
      // a dapp). Nested callers may act for this account only if explicitly allowed; otherwise a
      // dapp reached by any signed transaction could spend from, or reconfigure, the account.
      const call = args.call;
      if (call != null) {
        const caller = call!.caller;
        if (caller != null && caller!.length > 0 && !Arrays.equal(caller!, this.contractId)) {
          if (!this.allowed.get(caller!)!.value) return new authority.authorize_result(false);
        }
      }
    }
    // transaction_application and contract_upload are never nested: signature rule only.
    return new authority.authorize_result(this.authorizedByTransaction());
  }

  set_public_key(args: pqwallet.set_public_key_arguments): pqwallet.set_public_key_result {
    System.require(Pqwallet.calledDirectly(), "set_public_key must be a direct transaction operation");
    const newKey = args.public_key;
    System.require(newKey != null && newKey!.length == PK_BYTES, "public key must be 1312 bytes (ML-DSA-44)");
    System.require(this.authorizedByTransaction(), "not authorized");
    const proof = args.proof;
    System.require(
      proof != null && Pqwallet.verifyMlDsa44(proof!, this.contractId, newKey!, CONTEXT_POP),
      "proof of possession failed: the new key must sign this account's address with context koinos/pqwallet/1/pop"
    );
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
      pk != null && pk!.length == PK_BYTES
    );
  }

  set_allowed_caller(args: pqwallet.set_allowed_caller_arguments): pqwallet.set_allowed_caller_result {
    System.require(Pqwallet.calledDirectly(), "set_allowed_caller must be a direct transaction operation");
    const contract = args.contract;
    System.require(contract != null && contract!.length == 25, "contract must be a 25-byte address");
    System.require(this.authorizedByTransaction(), "not authorized");
    if (args.allowed) this.allowed.put(contract!, new pqwallet.allowed_object(true));
    else this.allowed.remove(contract!);
    System.event(
      "pqwallet.allowed_caller",
      Protobuf.encode(new pqwallet.allowed_caller_event(this.contractId, contract!, args.allowed), pqwallet.allowed_caller_event.encode),
      [this.contractId]
    );
    return new pqwallet.set_allowed_caller_result();
  }

  get_allowed_caller(args: pqwallet.get_allowed_caller_arguments): pqwallet.get_allowed_caller_result {
    const contract = args.contract;
    if (contract == null) return new pqwallet.get_allowed_caller_result(false);
    return new pqwallet.get_allowed_caller_result(this.allowed.get(contract!)!.value);
  }
}
