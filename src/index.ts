/*! scure-btc-signer - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  isBytes,
  concatBytes,
  compareBytes,
  pubSchnorr,
  randomPrivateKeyBytes,
  taprootTweakPubkey,
} from './utils.ts';
// prettier-ignore
export {
  p2pk, p2pkh, p2sh, p2ms, p2wsh, p2wpkh, p2tr, p2tr_ns, p2tr_ms, p2tr_pk,
  multisig // => classicMultisig?
} from './payment.ts';
// prettier-ignore
export {
  OP, RawTx, CompactSize,
  Script, ScriptNum, MAX_SCRIPT_BYTE_LENGTH,
} from './script.ts';
export type { ScriptType, IssuanceData } from './script.ts';
export { Transaction } from './transaction.ts';
export { getInputType, selectUTXO } from './utxo.ts';
export {
  NETWORK, TEST_NETWORK, TAPROOT_UNSPENDABLE_KEY,
  LIQUID_NETWORK, LIQUID_TEST_NETWORK, LIQUID_REGTEST_NETWORK,
  LIQUID_REGTEST_NETWORK as REGTEST_NETWORK, // backward compat
} from './utils.ts';

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
} from './payment.ts'; // remove
export type { OptScript, CustomScript } from './payment.ts';

export { _DebugPSBT, TaprootControlBlock, RawPSET, _RawPSET } from './psbt.ts'; // remove
export { Decimal, bip32Path, SigHash, PSBTCombine, DEFAULT_SEQUENCE } from './transaction.ts'; // remove
export { amt2val, val2amt } from './utils.ts';
export { _cmpBig, _Estimator } from './utxo.ts';
export { toConfidential, fromConfidential, isConfidential } from './address.ts';
export type { ConfidentialResult } from './address.ts';
export { Confidential } from './confidential.ts';
export type { UnblindOutputResult, ConfidentialOutput } from './confidential.ts';
export * from './zkp.ts';
