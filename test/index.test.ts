import { test } from 'bun:test';
import * as btc from '../src/index.ts';
import { hex } from '@scure/base';

Error.stackTraceLimit = Infinity;

let raw =
  '020000000101b2207e472f96c81eb0154fc74938cea35bfe310a298b03180b8297dec226de910000000000fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010007740758467337001600148e8b1fd4925a4d816f68a2358b3c24fa9dc820580125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000003345000160014b39b99e39b9754716527250d6811842c866f3cfe0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000001900004a00000000000247304402204e3cb663838c007ec74e299d25b64506a1ec1c1292a0cb26de6360f5389d646802205a68bb8ebb50fe88157ef09c3642cd931e3635cc8b842f75dd999ddc89c9908b0121022ccf18a3492038420bc54375bcb05ddf18508f122221326ca095c00a197b122300000000000000';

test('Parse tx', () => {
  let nonWitnessUtxo = hex.decode(raw);
  let pk = 'cTMgtKAELWHfmJaTh4fAhU6RutQumLnt9jz9k3EYq1x8Le8qocmy';
  let privkey = btc.WIF(btc.REGTEST_NETWORK).decode(pk);
  let destination = 'ert1qp600lypu8un6fnlcszanangupml0xs9r96cgfc';
  let amount = 207900;
  let fee = 2100;
  let tx = new btc.Transaction();
  let txid = '19ad779b460cc58a3423897d8b6a82be6adfa46a8ea131586f92dc17704e6737';
  let index = 1;

  tx.addInput({
    txid,
    index,
    nonWitnessUtxo,
  });

  tx.addOutputAddress(destination, BigInt(amount), btc.REGTEST_NETWORK.assetHash, btc.REGTEST_NETWORK);
  tx.addOutput({
    amount: BigInt(fee),
    asset: hex.decode(btc.REGTEST_NETWORK.assetHash),
    nonce: new Uint8Array([]),
    script: new Uint8Array([]),
  });

  tx.signIdx(privkey, 0);
  tx.finalize();

  console.log(tx.hex);
});
