import { expect, test } from 'bun:test';
import * as btc from '../src/index.ts';
import { hex } from '@scure/base';

Error.stackTraceLimit = Infinity;

let amt2val = (n) => {
  let val = new Uint8Array(9);
  let y = n.toString(16).padStart(16, '0'); // Convert to hex and pad to 16 characters

  for (let j = 0; j < 8; j++) {
    val[j + 1] = parseInt(y.slice(j * 2, j * 2 + 2), 16);
  }

  val[0] = 1; // Version indicator for raw value
  return val;
};

let raw =
  '020000000101b2207e472f96c81eb0154fc74938cea35bfe310a298b03180b8297dec226de910000000000fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010007740758467337001600148e8b1fd4925a4d816f68a2358b3c24fa9dc820580125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000003345000160014b39b99e39b9754716527250d6811842c866f3cfe0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000001900004a00000000000247304402204e3cb663838c007ec74e299d25b64506a1ec1c1292a0cb26de6360f5389d646802205a68bb8ebb50fe88157ef09c3642cd931e3635cc8b842f75dd999ddc89c9908b0121022ccf18a3492038420bc54375bcb05ddf18508f122221326ca095c00a197b122300000000000000';

let expected =
  '02000000010137674e7017dc926f5831a18e6aa4df6abe826a8b7d8923348ac50c469b77ad190100000000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000032c1c001600140e9eff903c3f27a4cff880bb3ecd1c0efef340a30125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000083400000000000000000247304402204f3f96a6069a843f196ac3d857fbea75d5ef302fc162e1dab2fcc424a6337c7502204a02debebb1266b925d8999e06c2d843e69e043051d695878710a79fb2e5f3a801210293e20f6e2e0ff77e1b3e9c6596f5452b8b3bb844b7dac954ebd105acd8cc246c0000000000';

test('Parse tx', () => {
  let network = btc.REGTEST_NETWORK;
  let nonWitnessUtxo = hex.decode(raw);
  let pk = 'cTMgtKAELWHfmJaTh4fAhU6RutQumLnt9jz9k3EYq1x8Le8qocmy';
  let privkey = btc.WIF(network).decode(pk);
  let destination = 'ert1qp600lypu8un6fnlcszanangupml0xs9r96cgfc';
  let amount = 207900n;
  let fee = 2100;
  let tx = new btc.Transaction();
  let txid = '19ad779b460cc58a3423897d8b6a82be6adfa46a8ea131586f92dc17704e6737';
  let index = 1;

  tx.addInput({
    txid,
    index,
    nonWitnessUtxo,
  });

  tx.addOutputAddress(destination, amount, network);
  tx.addOutput({
    value: amt2val(BigInt(fee)),
    asset: hex.decode(btc.REGTEST_NETWORK.assetHash),
    nonce: new Uint8Array([]),
    script: new Uint8Array([]),
  });

  tx.signIdx(privkey, 0);
  tx.finalize();

  expect(tx.hex).toEqual(expected);
});
