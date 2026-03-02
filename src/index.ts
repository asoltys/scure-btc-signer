/*! scure-btc-signer - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  isBytes,
  concatBytes,
  compareBytes,
  pubSchnorr,
  randomPrivateKeyBytes,
  taprootTweakPubkey,
} from './utils.js';
// prettier-ignore
export {
  p2pk, p2pkh, p2sh, p2ms, p2wsh, p2wpkh, p2tr, p2tr_ns, p2tr_ms, p2tr_pk,
  multisig // => classicMultisig?
} from './payment.js';
// prettier-ignore
export {
  OP, RawTx, CompactSize,
  Script, ScriptNum, MAX_SCRIPT_BYTE_LENGTH,
} from './script.js';
export type { ScriptType, IssuanceData } from './script.js';
export { Transaction } from './transaction.js';
export { getInputType, selectUTXO } from './utxo.js';
export {
  NETWORK, TEST_NETWORK, TAPROOT_UNSPENDABLE_KEY,
  LIQUID_NETWORK, LIQUID_TEST_NETWORK, LIQUID_REGTEST_NETWORK,
  LIQUID_REGTEST_NETWORK as REGTEST_NETWORK, // backward compat
} from './utils.js';

export const utils = {
  isBytes,
  concatBytes,
  compareBytes,
  pubSchnorr,
  randomPrivateKeyBytes,
  taprootTweakPubkey,
};

// Utils
// prettier-ignore
export {
  Address, getAddress, WIF,
  taprootListToTree, OutScript, _sortPubkeys, sortedMultisig, combinations
} from './payment.js'; // remove
export type { OptScript, CustomScript } from './payment.js';

export { _DebugPSBT, TaprootControlBlock, RawPSET, _RawPSET } from './psbt.js'; // remove
export { Decimal, bip32Path, SigHash, PSBTCombine, DEFAULT_SEQUENCE } from './transaction.js'; // remove
export { amt2val, val2amt } from './utils.js';
export { _cmpBig, _Estimator } from './utxo.js';
export { toConfidential, fromConfidential, isConfidential } from './address.js';
export type { ConfidentialResult } from './address.js';
export { Confidential } from './confidential.js';
export type { UnblindOutputResult, ConfidentialOutput } from './confidential.js';
export * from './zkp.js';
