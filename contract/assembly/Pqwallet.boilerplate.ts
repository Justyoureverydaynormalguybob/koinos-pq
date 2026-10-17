import { System, Protobuf, authority } from "@koinos/sdk-as";
import { pqwallet } from "./proto/pqwallet";

export class Pqwallet {
  authorize(args: authority.authorize_arguments): authority.authorize_result {
    // const call = args.call;
    // const type = args.type;

    // YOUR CODE HERE

    const res = new authority.authorize_result();
    res.value = true;

    return res;
  }

  set_public_key(
    args: pqwallet.set_public_key_arguments
  ): pqwallet.set_public_key_result {
    // const public_key = args.public_key;

    // YOUR CODE HERE

    const res = new pqwallet.set_public_key_result();

    return res;
  }

  get_public_key(
    args: pqwallet.get_public_key_arguments
  ): pqwallet.get_public_key_result {
    // YOUR CODE HERE

    const res = new pqwallet.get_public_key_result();
    // res.value = ;

    return res;
  }

  get_info(args: pqwallet.get_info_arguments): pqwallet.get_info_result {
    // YOUR CODE HERE

    const res = new pqwallet.get_info_result();
    // res.scheme = ;
    // res.public_key_bytes = ;
    // res.signature_bytes = ;
    // res.context = ;
    // res.key_registered = ;
    // res.verifications = ;

    return res;
  }
}
