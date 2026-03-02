import { schnorr, secp256k1 as secp } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utils as packedUtils, U32LE } from 'micro-packed';

export type Hex = string | Uint8Array;
export type Bytes = Uint8Array;
const Point = secp.Point;
const Fn = Point.Fn;
const CURVE_ORDER = Point.Fn.ORDER;
export const hasEven = (y: bigint) => y % 2n === 0n;

const isBytes: (a: unknown) => a is Uint8Array = packedUtils.isBytes;
const concatBytes: (...arrays: Uint8Array[]) => Uint8Array = packedUtils.concatBytes;
const equalBytes: (a: Uint8Array, b: Uint8Array) => boolean = packedUtils.equalBytes;
export { concatBytes, equalBytes, isBytes, sha256 };

export const hash160 = (msg: Uint8Array): Uint8Array => ripemd160(sha256(msg));
export const sha256x2 = (...msgs: Uint8Array[]): Uint8Array => sha256(sha256(concatBytes(...msgs)));
export const randomPrivateKeyBytes: () => Uint8Array = schnorr.utils.randomSecretKey;
export const pubSchnorr: (priv: Uint8Array) => Uint8Array = schnorr.getPublicKey;
export const pubECDSA: (privateKey: Uint8Array, isCompressed?: boolean) => Uint8Array =
  secp.getPublicKey;

// low-r signature grinding. Used to reduce tx size by 1 byte.
// noble/secp256k1 does not support the feature: it is not used outside of BTC.
// We implement it manually, because in BTC it's common.
// Not best way, but closest to bitcoin implementation (easier to check)
const hasLowR = (sig: { r: bigint; s: bigint }) => sig.r < CURVE_ORDER / 2n;
export function signECDSA(hash: Bytes, privateKey: Bytes, lowR = false): Bytes {
  let sig = secp.Signature.fromBytes(secp.sign(hash, privateKey, { prehash: false }));
  if (lowR && !hasLowR(sig)) {
    const extraEntropy = new Uint8Array(32);
    let counter = 0;
    while (!hasLowR(sig)) {
      extraEntropy.set(U32LE.encode(counter++));
      sig = secp.Signature.fromBytes(secp.sign(hash, privateKey, { prehash: false, extraEntropy }));
      if (counter > 4294967295) throw new Error('lowR counter overflow: report the error');
    }
  }
  return sig.toBytes('der');
}

export const signSchnorr: typeof schnorr.sign = schnorr.sign;
export const tagSchnorr: typeof schnorr.utils.taggedHash = schnorr.utils.taggedHash;

export const PubT = {
  ecdsa: 0,
  schnorr: 1,
};
export type PubT = ValueOf<typeof PubT>;

export function validatePubkey(pub: Bytes, type: PubT): Bytes {
  const len = pub.length;
  if (type === PubT.ecdsa) {
    if (len === 32) throw new Error('Expected non-Schnorr key');
    Point.fromBytes(pub); // does assertValidity
    return pub;
  } else if (type === PubT.schnorr) {
    if (len !== 32) throw new Error('Expected 32-byte Schnorr key');
    schnorr.utils.lift_x(bytesToNumberBE(pub));
    return pub;
  } else {
    throw new Error('Unknown key type');
  }
}

export function tapTweak(a: Bytes, b: Bytes): bigint {
  const u = schnorr.utils;
  const t = u.taggedHash('TapTweak', a, b);
  const tn = bytesToNumberBE(t);
  if (tn >= CURVE_ORDER) throw new Error('tweak higher than curve order');
  return tn;
}

export function taprootTweakPrivKey(privKey: Bytes, merkleRoot: Bytes = Uint8Array.of()): Bytes {
  const u = schnorr.utils;
  const seckey0 = bytesToNumberBE(privKey); // seckey0 = int_from_bytes(seckey0)
  const P = Point.BASE.multiply(seckey0); // P = point_mul(G, seckey0)
  // seckey = seckey0 if has_even_y(P) else SECP256K1_ORDER - seckey0
  const seckey = hasEven(P.y) ? seckey0 : Fn.neg(seckey0);
  const xP = u.pointToBytes(P);
  // t = int_from_bytes(tagged_hash("TapTweak", bytes_from_int(x(P)) + h)); >= SECP256K1_ORDER check
  const t = tapTweak(xP, merkleRoot);
  // bytes_from_int((seckey + t) % SECP256K1_ORDER)
  return numberToBytesBE(Fn.add(seckey, t), 32);
}

export function taprootTweakPubkey(pubKey: Bytes, h: Bytes): [Bytes, number] {
  const u = schnorr.utils;
  const t = tapTweak(pubKey, h); // t = int_from_bytes(tagged_hash("TapTweak", pubkey + h))
  const P = u.lift_x(bytesToNumberBE(pubKey)); // P = lift_x(int_from_bytes(pubkey))
  const Q = P.add(Point.BASE.multiply(t)); // Q = point_add(P, point_mul(G, t))
  const parity = hasEven(Q.y) ? 0 : 1; // 0 if has_even_y(Q) else 1
  return [u.pointToBytes(Q), parity]; // bytes_from_int(x(Q))
}

// Another stupid decision, where lack of standard affects security.
// Multisig needs to be generated with some key.
// We are using approach from BIP 341/bitcoinjs-lib: SHA256(uncompressedDER(SECP256K1_GENERATOR_POINT))
// It is possible to switch SECP256K1_GENERATOR_POINT with some random point;
// but it's too complex to prove.
// Also used by bitcoin-core and bitcoinjs-lib
export const TAPROOT_UNSPENDABLE_KEY: Bytes = sha256(Point.BASE.toBytes(false));

export type BTC_NETWORK = {
  bech32: string;
  pubKeyHash: number;
  scriptHash: number;
  wif: number;
  blech32?: string;
  confidentialPrefix?: number;
  assetHash?: string;
};

export const NETWORK: BTC_NETWORK = {
  bech32: 'bc',
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  wif: 0x80,
};

export const TEST_NETWORK: BTC_NETWORK = {
  bech32: 'tb',
  pubKeyHash: 0x6f,
  scriptHash: 0xc4,
  wif: 0xef,
};

// Liquid networks
export const LIQUID_NETWORK: BTC_NETWORK = {
  bech32: 'ex',
  blech32: 'lq',
  pubKeyHash: 0x39,
  scriptHash: 0x27,
  wif: 0x80,
  confidentialPrefix: 12,
  assetHash: '6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d',
};

export const LIQUID_TEST_NETWORK: BTC_NETWORK = {
  bech32: 'tex',
  blech32: 'tlq',
  pubKeyHash: 0x24,
  scriptHash: 0x13,
  wif: 0xef,
  confidentialPrefix: 23,
  assetHash: '144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49',
};

export const LIQUID_REGTEST_NETWORK: BTC_NETWORK = {
  bech32: 'ert',
  blech32: 'el',
  pubKeyHash: 0xeb,
  scriptHash: 0x4b,
  wif: 0xef,
  confidentialPrefix: 4,
  assetHash: '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
};

// Exported for tests, internal method
export function compareBytes(a: Bytes, b: Bytes): number {
  if (!isBytes(a) || !isBytes(b)) throw new Error(`cmp: wrong type a=${typeof a} b=${typeof b}`);
  // -1 -> a<b, 0 -> a==b, 1 -> a>b
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) if (a[i] != b[i]) return Math.sign(a[i] - b[i]);
  return Math.sign(a.length - b.length);
}

// Reverses key<->values
export function reverseObject<T extends Record<string, string | number>>(
  obj: T
): { [K in T[keyof T]]: Extract<keyof T, string> } {
  const res = {} as any;
  for (const k in obj) {
    if (res[obj[k]] !== undefined) throw new Error('duplicate key');
    res[obj[k]] = k;
  }
  return res;
}

export type ValueOf<T> = T[keyof T];

export let amt2val = (n: BigInt) => {
  let val = new Uint8Array(9);
  let y = n.toString(16).padStart(16, '0');
  for (let j = 0; j < 8; j++) {
    val[j + 1] = parseInt(y.slice(j * 2, j * 2 + 2), 16);
  }
  val[0] = 1;
  return val;
};

export let val2amt = (val: Uint8Array) => {
  if (val.length !== 9 || val[0] !== 0x01) {
    throw new Error('val2amt: expected 9-byte unconfidential value (prefix 0x01). Got ' + val.length + ' bytes with prefix 0x' + (val[0] ?? 0).toString(16));
  }
  let y = '';
  for (let j = 1; j < 9; j++) {
    y += val[j].toString(16).padStart(2, '0');
  }
  return BigInt('0x' + y);
};
