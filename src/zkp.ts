// ZKP functions for Liquid confidential transactions.
// Ported from libsecp256k1-zkp via @noble/curves.

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { FpIsSquare } from '@noble/curves/abstract/modular.js';
import type { WeierstrassPoint } from '@noble/curves/abstract/weierstrass.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import {
  bytesToNumberBE,
  numberToBytesBE,
  concatBytes,
  asciiToBytes,
} from '@noble/curves/utils.js';

type PointT = WeierstrassPoint<bigint>;
const Point = secp256k1.Point;
const Fp = Point.Fp;
const N = Point.Fn.ORDER;
const numTo32b = (n: bigint) => numberToBytesBE(n, 32);

// ---- Point serialization helpers ----

// Internal serialization: 0x00/0x01 prefix (QR-based, used in rangeproof hashing)
function serializePoint(point: PointT): Uint8Array {
  const data = new Uint8Array(33);
  data[0] = FpIsSquare(Fp, point.y) ? 0x00 : 0x01;
  data.set(numberToBytesBE(point.x, 32), 1);
  return data;
}

// Generator serialization: 0x0a/0x0b prefix (QR-based)
function serializeGenerator(point: PointT): Uint8Array {
  const { x, y } = point.toAffine();
  const result = new Uint8Array(33);
  result[0] = FpIsSquare(Fp, y) ? 0x0a : 0x0b;
  result.set(numberToBytesBE(x, 32), 1);
  return result;
}

// Pedersen commitment serialization: 0x08/0x09 prefix (QR-based)
function serializePedersen(point: PointT): Uint8Array {
  const { x, y } = point.toAffine();
  const result = new Uint8Array(33);
  result[0] = FpIsSquare(Fp, y) ? 0x08 : 0x09;
  result.set(numberToBytesBE(x, 32), 1);
  return result;
}

// Parse point from bytes: handles 02/03 (standard), 08/09 (Pedersen), 0a/0b (generator)
function parsePoint(bytes: Uint8Array): PointT {
  if (bytes.length !== 33) throw new Error('Invalid point length');
  const prefix = bytes[0];
  if (prefix === 0x02 || prefix === 0x03) return Point.fromBytes(bytes);
  if (prefix === 0x08 || prefix === 0x09 || prefix === 0x0a || prefix === 0x0b) {
    const x = bytesToNumberBE(bytes.subarray(1));
    const wantQR = prefix % 2 === 0;
    const ySquared = Fp.add(Fp.mul(Fp.mul(x, x), x), 7n);
    let y = Fp.sqrt(ySquared);
    if (FpIsSquare(Fp, y) !== wantQR) y = Fp.neg(y);
    return Point.fromAffine({ x, y });
  }
  throw new Error(`Unknown point prefix: 0x${prefix.toString(16)}`);
}

// Recover point from x-coordinate, picking QR root for y
function pointFromXQuad(x: bigint): PointT | null {
  const c = Fp.add(Fp.mul(Fp.mul(x, x), x), 7n);
  try {
    let y = Fp.sqrt(c);
    if (!FpIsSquare(Fp, y)) y = Fp.neg(y);
    return Point.fromAffine({ x, y });
  } catch {
    return null;
  }
}

// ---- Scalar helpers ----

function modN(x: bigint): bigint {
  const r = x % N;
  return r < 0n ? r + N : r;
}

function negateScalar(a: bigint): bigint {
  if (a === 0n) return 0n;
  let result = N - a;
  if (result < 0n) result += N;
  else if (result >= N) result -= N;
  return result;
}

function setScalarFromB32(b32: Uint8Array): bigint {
  if (b32.length !== 32) throw new Error('Input must be a 32-byte array');
  let scalar = bytesToNumberBE(b32);
  if (scalar >= N) scalar -= N;
  return scalar;
}

function clz64(x: bigint): number {
  if (x === 0n) return 64;
  let n = 0;
  while ((x & 0x8000000000000000n) === 0n) { x <<= 1n; n++; }
  return n;
}

// ---- SvdW hash-to-curve (Elements-specific, NOT RFC 9380) ----

const SVDW_C = 0x0a2d2ba93507f1df233770c2a797962cc61f6d15da14ecd47d8d27ae1cd5f852n;
const SVDW_D = 0x851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40n;

function svdwFinalize(x: bigint, ySq: bigint, t: bigint): PointT {
  let y = Fp.sqrt(ySq);
  if (!FpIsSquare(Fp, y)) y = Fp.neg(y);
  if (t & 1n) y = Fp.neg(y);
  return Point.fromAffine({ x, y });
}

function svdw(t: bigint): PointT {
  const t2 = Fp.mul(t, t);
  const denom = Fp.add(t2, 8n);
  const w = Fp.mul(Fp.mul(SVDW_C, t), Fp.inv(denom));
  const x1 = Fp.sub(SVDW_D, Fp.mul(t, w));
  const y1sq = Fp.add(Fp.mul(Fp.mul(x1, x1), x1), 7n);
  if (FpIsSquare(Fp, y1sq)) return svdwFinalize(x1, y1sq, t);
  const x2 = Fp.neg(Fp.add(1n, x1));
  const y2sq = Fp.add(Fp.mul(Fp.mul(x2, x2), x2), 7n);
  if (FpIsSquare(Fp, y2sq)) return svdwFinalize(x2, y2sq, t);
  const x3 = Fp.add(1n, Fp.inv(Fp.mul(w, w)));
  const y3sq = Fp.add(Fp.mul(Fp.mul(x3, x3), x3), 7n);
  return svdwFinalize(x3, y3sq, t);
}

// ---- Borromean ring signatures ----

const borromeanHash = (m: Uint8Array, e: Uint8Array, ridx: number, eidx: number): Uint8Array => {
  const ring = new Uint8Array(4);
  const epos = new Uint8Array(4);
  const writeBe32 = (buffer: Uint8Array, value: number) => {
    buffer[0] = (value >> 24) & 0xff;
    buffer[1] = (value >> 16) & 0xff;
    buffer[2] = (value >> 8) & 0xff;
    buffer[3] = value & 0xff;
  };
  writeBe32(ring, ridx);
  writeBe32(epos, eidx);
  const h = sha256.create();
  h.update(e); h.update(m); h.update(ring); h.update(epos);
  return h.digest();
};

const borromeanSign = (
  e0: Uint8Array, s: bigint[], pubs: PointT[], k: bigint[], sec: bigint[],
  rsizes: number[], secidx: number[], nrings: number, m: Uint8Array
): number => {
  let rgej: PointT;
  let tmp: Uint8Array = new Uint8Array(33);
  let count = 0;

  const sha256_e0 = sha256.create();
  for (let i = 0; i < nrings; i++) {
    if (Number.MAX_SAFE_INTEGER - count < rsizes[i]) throw new Error('Integer overflow');
    rgej = Point.BASE.multiply(k[i]);
    if (rgej.is0()) return 0;
    tmp = rgej.toBytes(true);

    for (let j = secidx[i] + 1; j < rsizes[i]; j++) {
      tmp = borromeanHash(m, tmp, i, j);
      let ens = bytesToNumberBE(tmp);
      if (ens >= N) ens = ens % N;
      rgej = pubs[count + j].multiply(ens).add(Point.BASE.multiply(s[count + j]));
      if (rgej.is0()) return 0;
      tmp = rgej.toBytes(true);
    }
    sha256_e0.update(tmp);
    count += rsizes[i];
  }

  sha256_e0.update(m);
  e0.set(sha256_e0.digest());

  count = 0;
  for (let i = 0; i < nrings; i++) {
    if (Number.MAX_SAFE_INTEGER - count < rsizes[i]) throw new Error('Integer overflow');
    tmp = borromeanHash(m, e0.slice(0, 32), i, 0);
    let ens = bytesToNumberBE(tmp) % N;
    if (ens === 0n || ens >= N) return 0;

    for (let j = 0; j < secidx[i]; j++) {
      rgej = pubs[count + j].multiply(ens).add(Point.BASE.multiply(s[count + j]));
      if (rgej.is0()) return 0;
      tmp = rgej.toBytes(true);
      tmp = borromeanHash(m, tmp, i, j + 1);
      ens = bytesToNumberBE(tmp) % N;
      if (ens === 0n || ens >= N) return 0;
    }

    s[count + secidx[i]] = (N - ((ens * sec[i]) % N) + k[i]) % N;
    if (s[count + secidx[i]] === 0n) return 0;
    count += rsizes[i];
  }

  return 1;
};

const borromeanVerify = (
  e0: Uint8Array, s: bigint[], pubs: PointT[], rsizes: number[], nrings: number, m: Uint8Array
): boolean => {
  let count = 0;
  const sha256_e0 = sha256.create();

  for (let i = 0; i < nrings; i++) {
    let tmp: Uint8Array = borromeanHash(m, e0, i, 0);
    let ens = bytesToNumberBE(tmp) % N;
    for (let j = 0; j < rsizes[i]; j++) {
      if (s[count] === 0n || ens === 0n || pubs[count].is0()) return false;
      // s*G + ens*pub (Shamir's trick replaced with sequential multiply+add)
      const R = Point.BASE.multiply(s[count]).add(pubs[count].multiply(ens));
      if (R.is0()) return false;
      const serialized = R.toBytes(true);
      if (j !== rsizes[i] - 1) {
        tmp = borromeanHash(m, serialized, i, j + 1);
        ens = bytesToNumberBE(tmp) % N;
      } else {
        sha256_e0.update(serialized);
      }
      count++;
    }
  }

  sha256_e0.update(m);
  const computed = sha256_e0.digest();
  for (let i = 0; i < 32; i++) {
    if (e0[i] !== computed[i]) return false;
  }
  return true;
};

// ---- Range proof parameters ----

type ProveParams = {
  rings: number; rsizes: number[]; npub: number; secidx: number[];
  minValue: bigint; mantissa: number; scale: bigint; minBits: number; v: bigint; exp: number;
};

const rangeProveParams = (minBits: number, minValue: bigint, exp: number, value: bigint): ProveParams => {
  let i, v;
  let rsizes = new Array(32);
  let secidx = new Array(32);
  let rings = 1;
  rsizes[0] = 1;
  secidx[0] = 0;
  let scale = 1n;
  let mantissa = 0;
  let npub = 0;

  if (minValue === 0xffffffffffffffffn) exp = -1;

  if (exp >= 0) {
    let maxBits;
    let v2;
    if (
      (minValue && value > 0x7fffffffffffffffn) ||
      (value && minValue >= 0x7fffffffffffffffn)
    ) {
      throw new Error('value out of range');
    }
    maxBits = minValue ? clz64(BigInt(minValue)) : 64;
    if (minBits > maxBits) minBits = maxBits;
    if (minBits > 61 || value > 0x7fffffffffffffffn) exp = 0;
    v = value - BigInt(minValue);
    v2 = minBits ? 0xffffffffffffffffn >> BigInt(64 - minBits) : 0n;
    for (i = 0; i < exp && v2 <= 0xffffffffffffffffn / 10n; i++) {
      v /= 10n;
      v2 *= 10n;
    }
    exp = i;
    v2 = v;
    for (i = 0; i < exp; i++) {
      v2 *= 10n;
      scale *= 10n;
    }
    minValue = value - v2;
    mantissa = v ? 64 - clz64(v) : 1;
    if (minBits > mantissa) mantissa = minBits;
    rings = (mantissa + 1) >> 1;
    for (i = 0; i < rings; i++) {
      rsizes[i] = i < rings - 1 || !(mantissa & 1) ? 4 : 2;
      npub += rsizes[i];
      secidx[i] = Number((v >> BigInt(i * 2)) & 3n);
    }
    if (mantissa <= 0) throw new Error('Invalid mantissa value');
    if ((v & ~(0xffffffffffffffffn >> BigInt(64 - mantissa))) !== 0n)
      throw new Error('Did not get all the bits');
  } else {
    exp = 0;
    minValue = value;
    v = 0n;
    npub = 2;
  }

  if (v * scale + minValue !== value) throw new Error('Invalid value');
  if (rings <= 0 || rings > 32) throw new Error('Invalid number of rings');
  if (npub > 128) throw new Error('Invalid number of public keys');

  return { rings, rsizes, npub, secidx, minValue, mantissa, scale, minBits, v, exp };
};

// ---- RNG (RFC 6979-based) ----

class RNG {
  private k: Uint8Array;
  private v: Uint8Array;
  private retry: boolean;

  constructor(k: Uint8Array, v: Uint8Array, retry = false) {
    this.k = k; this.v = v; this.retry = retry;
  }

  static create(seed: Uint8Array): RNG {
    const zero = new Uint8Array([0x00]);
    const one = new Uint8Array([0x01]);
    let v: Uint8Array = new Uint8Array(32).fill(0x01);
    let k: Uint8Array = new Uint8Array(32).fill(0x00);
    k = Uint8Array.from(hmac(sha256, k, concatBytes(v, zero, seed)));
    v = Uint8Array.from(hmac(sha256, k, v));
    k = Uint8Array.from(hmac(sha256, k, concatBytes(v, one, seed)));
    v = Uint8Array.from(hmac(sha256, k, v));
    return new RNG(k, v, false);
  }

  generate(outlen: number): Uint8Array {
    const zero = new Uint8Array([0x00]);
    let out: Uint8Array = new Uint8Array(outlen);
    if (this.retry) {
      this.k = Uint8Array.from(hmac(sha256, this.k, concatBytes(this.v, zero)));
      this.v = Uint8Array.from(hmac(sha256, this.k, this.v));
    }
    let remaining = outlen;
    let offset = 0;
    while (remaining > 0) {
      const now = Math.min(remaining, 32);
      this.v = Uint8Array.from(hmac(sha256, this.k, this.v));
      out.set(this.v.slice(0, now), offset);
      remaining -= now;
      offset += now;
    }
    this.retry = true;
    return out;
  }

  finalize() {
    this.k.fill(0);
    this.v.fill(0);
    this.retry = false;
  }
}

// ---- Range proof helpers ----

function rangeproofGenrand(
  sec: bigint[], s: bigint[], message: Uint8Array,
  rsizes: number[], rings: number,
  nonce: Uint8Array, commit: Uint8Array,
  proof: Uint8Array, len: number,
  gen: Uint8Array,
) {
  let tmp: Uint8Array = new Uint8Array(32);
  let rngseed = new Uint8Array(32 + 33 + 33 + len);
  let acc = 0n;
  let ret = 1;
  let npub = 0;

  if (len > 10) throw new Error('Invalid length');

  const genP = parsePoint(gen);
  const commitP = parsePoint(commit);

  rngseed.set(nonce.subarray(0, 32), 0);
  rngseed.set(serializePoint(commitP), 32);
  rngseed.set(serializePoint(genP), 32 + 33);
  rngseed.set(proof.slice(0, len), 32 + 33 + 33);

  const rng = RNG.create(rngseed);

  for (let i = 0; i < rings; i++) {
    if (i < rings - 1) {
      tmp = rng.generate(32);
      do {
        tmp = rng.generate(32);
        sec[i] = bytesToNumberBE(tmp) % N;
      } while (bytesToNumberBE(tmp) > N || sec[i] === 0n);
      acc = (acc + sec[i]) % N;
    } else {
      sec[i] = negateScalar(acc);
    }

    for (let j = 0; j < rsizes[i]; j++) {
      tmp = rng.generate(32);
      if (message) {
        for (let b = 0; b < 32; b++) {
          tmp[b] ^= message[(i * 4 + j) * 32 + b];
          message[(i * 4 + j) * 32 + b] = tmp[b];
        }
      }
      s[npub] = bytesToNumberBE(tmp) % N;
      ret &= Number(s[npub] !== 0n);
      npub++;
    }
  }
  acc = 0n;
  return ret;
}

const rangeproofPubExpand = (pubs: PointT[], exp: number, rsizes: number[], rings: number, genp: PointT) => {
  var base = genp;
  var i, j, npub;
  if (exp < 0) exp = 0;
  base = base.negate();
  while (exp--) {
    var tmp = base.double();
    base = tmp.double().add(tmp);
  }
  npub = 0;
  for (i = 0; i < rings; i++) {
    for (j = 1; j < rsizes[i]; j++) {
      pubs[npub + j] = pubs[npub + j - 1].add(base);
    }
    if (i < rings - 1) {
      base = base.double().double();
    }
    npub += rsizes[i];
  }
};

// ---- Range proof main functions ----

export const rangeproofSign = (
  minValue: bigint,
  commit: Uint8Array,
  blind: Uint8Array,
  nonce: Uint8Array,
  exp: number,
  minBits: number,
  value: bigint,
  msg: Uint8Array,
  extraCommit: Uint8Array,
  genp: Uint8Array,
) => {
  let proof = new Uint8Array(5134);
  let pubs = new Array(128);
  let s = new Array(128);
  let sec = new Array(32);
  let k = new Array(32);
  let sha256M = sha256.create();
  let prep = new Uint8Array(4096);
  let len;
  let i;

  let genP = parsePoint(genp);

  len = 0;
  if (minValue > value || minBits > 64 || minBits < 0 || exp < -1 || exp > 18) {
    throw new Error('params out of range');
  }

  let v, rings, rsizes, npub, secidx, mantissa, scale;
  ({ v, rings, rsizes, npub, secidx, mantissa, scale, exp, minBits, minValue } = rangeProveParams(minBits, minValue, exp, value));

  if (!v) throw new Error('mising value');

  proof[len] = (rsizes[0] > 1 ? 64 | exp : 0) | (minValue ? 32 : 0);
  len++;
  if (rsizes[0] > 1) {
    if (mantissa <= 0 || mantissa > 64) throw new Error('Mantissa out of range');
    proof[len] = mantissa - 1;
    len++;
  }
  if (minValue) {
    for (i = 0; i < 8; i++) {
      proof[len + i] = Number((minValue >> BigInt((7 - i) * 8)) & BigInt(255));
    }
    len += 8;
  }
  if (msg.length > 0 && msg.length > 128 * (rings - 1)) {
    throw new Error('invalid message length');
  }

  sha256M.update(serializePoint(parsePoint(commit)));
  sha256M.update(serializePoint(genP));
  sha256M.update(proof.slice(0, len));

  prep.fill(0);
  if (msg != null && msg.length > 0) {
    prep.set(msg.subarray(0, msg.length));
  }

  if (rsizes[rings - 1] > 1) {
    let idx = rsizes[rings - 1] - 1;
    idx -= Number(secidx[rings - 1] === idx);
    idx = ((rings - 1) * 4 + idx) * 32;
    for (i = 0; i < 8; i++) {
      let n = Number((v >> BigInt(56 - i * 8)) & BigInt(255));
      prep[8 + i + idx] = prep[16 + i + idx] = prep[24 + i + idx] = n;
      prep[i + idx] = 0;
    }
    prep[idx] = 128;
  }

  if (
    !(rangeproofGenrand(
      sec, s, prep, rsizes, rings,
      nonce, commit, proof, len, genp,
    ))
  ) {
    throw new Error('failed to generate secrets');
  }

  prep.fill(0);
  for (i = 0; i < rings; i++) {
    k[i] = s[i * 4 + secidx[i]];
    s[i * 4 + secidx[i]] = 0n;
  }

  let stmp = setScalarFromB32(blind);
  sec[rings - 1] = (sec[rings - 1] + stmp) % N;

  let signs = new Uint8Array(proof.buffer, len, (rings + 6) >> 3);

  for (i = 0; i < (rings + 6) >> 3; i++) {
    signs[i] = 0;
    len++;
  }
  npub = 0;
  for (i = 0; i < rings; i++) {
    let val = (BigInt(secidx[i]) * scale) << BigInt(i * 2);
    let P1 = sec[i] ? Point.BASE.multiply(sec[i]) : Point.ZERO;
    let P2 = secidx[i] ? genP.multiply(val) : Point.ZERO;
    pubs[npub] = P1.add(P2);

    if (pubs[npub].is0()) throw new Error('Point at infinity');

    if (i < rings - 1) {
      var tmpc = serializePoint(pubs[npub]);
      var quadness = tmpc[0];
      sha256M.update(tmpc);
      signs[i >> 3] |= quadness << (i & 7);
      proof.set(tmpc.slice(1), len);
      len += 32;
    }
    npub += rsizes[i];
  }

  rangeproofPubExpand(pubs, exp, rsizes, rings, genP);
  if (extraCommit != null && extraCommit.length > 0) {
    sha256M.update(extraCommit);
  }

  let signed = borromeanSign(
    proof.subarray(len),
    s, pubs, k, sec, rsizes, secidx, rings,
    sha256M.digest(),
  );

  if (!signed) throw new Error('Signature failed');

  len += 32;
  for (let i = 0; i < npub; i++) {
    proof.set(numTo32b(s[i]), len);
    len += 32;
  }

  proof = proof.slice(0, len);
  return proof;
};

export const rangeproofVerify = (
  proof: Uint8Array,
  commit: Uint8Array,
  extraCommit: Uint8Array,
  genp: Uint8Array
): boolean => {
  // A. Parse header
  let offset = 0;
  if (proof.length < 65 || (proof[offset] & 128) !== 0) return false;
  const has_nz_range = (proof[offset] & 64) !== 0;
  const has_min = (proof[offset] & 32) !== 0;
  let exp = -1;
  let mantissa = 0;
  let max_value = 0n;
  let scale = 1n;
  let min_value = 0n;
  if (has_nz_range) {
    exp = proof[offset] & 31;
    offset++;
    if (exp > 18) return false;
    mantissa = proof[offset] + 1;
    if (mantissa > 64) return false;
    max_value = 0xffffffffffffffffn >> BigInt(64 - mantissa);
  } else {
    max_value = 0n;
  }
  offset++;
  for (let i = 0; i < exp; i++) {
    if (max_value > 0xffffffffffffffffn / 10n) return false;
    max_value *= 10n;
    scale *= 10n;
  }
  if (has_min) {
    if (proof.length - offset < 8) return false;
    for (let i = 0; i < 8; i++) {
      min_value = (min_value << 8n) | BigInt(proof[offset + i]);
    }
    offset += 8;
  }
  if (max_value > 0xffffffffffffffffn - min_value) return false;
  max_value += min_value;

  // B. Ring structure
  const rsizes: number[] = [];
  let npub = 1;
  let rings = 0;
  rsizes[0] = 1;
  if (mantissa !== 0) {
    rings = mantissa >> 1;
    for (let i = 0; i < rings; i++) rsizes[i] = 4;
    npub = (mantissa >> 1) << 2;
    if (mantissa & 1) {
      rsizes[rings] = 2;
      npub += rsizes[rings];
      rings++;
    }
  }
  if (rings === 0) { rings = 1; rsizes[0] = 1; npub = 1; }

  // C. Validate proof size
  if (proof.length - offset < 32 * (npub + rings - 1) + 32 + ((rings + 6) >> 3)) return false;

  // D. Hash initialization
  const sha256_m = sha256.create();
  const commitPoint = parsePoint(commit);
  const genP = parsePoint(genp);
  sha256_m.update(serializePoint(commitPoint));
  sha256_m.update(serializePoint(genP));
  sha256_m.update(proof.subarray(0, offset));

  // E. Extract sign bits and intermediate points
  const signs = new Uint8Array(31);
  for (let i = 0; i < rings - 1; i++) {
    signs[i] = (proof[offset + (i >> 3)] & (1 << (i & 7))) !== 0 ? 1 : 0;
  }
  offset += (rings + 6) >> 3;
  if ((rings - 1) & 7) {
    if ((proof[offset - 1] >> ((rings - 1) & 7)) !== 0) return false;
  }

  const pubs: PointT[] = new Array(128);
  npub = 0;
  let acc = Point.ZERO;
  if (min_value > 0n) {
    acc = genP.multiply(min_value);
  }

  for (let i = 0; i < rings - 1; i++) {
    const xBytes = proof.subarray(offset, offset + 32);
    const x = bytesToNumberBE(xBytes);
    const pt = pointFromXQuad(x);
    if (!pt) return false;
    let c = signs[i] ? pt.negate() : pt;
    sha256_m.update(new Uint8Array([signs[i]]));
    sha256_m.update(xBytes);
    pubs[npub] = c;
    acc = acc.add(c);
    offset += 32;
    npub += rsizes[i];
  }

  // Last ring commitment: commit - acc
  pubs[npub] = commitPoint.add(acc.negate());
  if (pubs[npub].is0()) return false;

  // F. Expand pubkeys
  rangeproofPubExpand(pubs, exp, rsizes, rings, genP);
  npub += rsizes[rings - 1];

  // G. Extract Borromean signature
  const e0 = proof.subarray(offset, offset + 32);
  offset += 32;
  const s: bigint[] = new Array(npub);
  for (let i = 0; i < npub; i++) {
    s[i] = bytesToNumberBE(proof.subarray(offset, offset + 32));
    if (s[i] >= N) return false;
    offset += 32;
  }
  if (offset !== proof.length) return false;

  // H. Finalize hash and verify
  if (extraCommit && extraCommit.length > 0) {
    sha256_m.update(extraCommit);
  }
  const m = sha256_m.digest();
  return borromeanVerify(e0, s, pubs, rsizes, rings, m);
};

// ---- Surjection proof helpers ----

class SurjectionCSPRNG {
  private state: Uint8Array;
  private bytesLeft: number;
  private stateCounter: number;

  constructor(seed: Uint8Array) {
    this.state = sha256(seed);
    this.bytesLeft = 32;
    this.stateCounter = 0;
  }

  private nextByte(): number {
    if (this.bytesLeft === 0) {
      const counterBuf = new Uint8Array(4);
      new DataView(counterBuf.buffer).setUint32(0, this.stateCounter, true);
      this.stateCounter++;
      this.state = sha256(concatBytes(counterBuf, this.state));
      this.bytesLeft = 32;
    }
    this.bytesLeft--;
    return this.state[this.bytesLeft];
  }

  next(limit: number): number {
    if (limit <= 256) {
      const mask = (1 << Math.ceil(Math.log2(limit || 1))) - 1 || 0xff;
      while (true) {
        const val = this.nextByte() & mask;
        if (val < limit) return val;
      }
    } else {
      const mask = (1 << Math.ceil(Math.log2(limit))) - 1;
      while (true) {
        const val = (this.nextByte() | (this.nextByte() << 8)) & mask;
        if (val < limit) return val;
      }
    }
  }
}

const surjBorromeanHash = (e: Uint8Array, m: Uint8Array, ridx: number, eidx: number): Uint8Array => {
  const ridxBuf = new Uint8Array(4);
  const eidxBuf = new Uint8Array(4);
  new DataView(ridxBuf.buffer).setUint32(0, ridx, false);
  new DataView(eidxBuf.buffer).setUint32(0, eidx, false);
  const h = sha256.create();
  h.update(e); h.update(m); h.update(ridxBuf); h.update(eidxBuf);
  return h.digest();
};

function surjBorromeanSign(
  m: Uint8Array, pubkeys: PointT[], sec: bigint, secIdx: number,
  nonce: bigint, sValues: bigint[]
): { e0: Uint8Array; s: bigint[] } {
  const nKeys = pubkeys.length;
  const s = sValues.slice();

  // Phase 1: Forward from secIdx+1
  let R = Point.BASE.multiply(nonce);
  let tmp: Uint8Array = R.toBytes(true);
  for (let j = secIdx + 1; j < nKeys; j++) {
    const e = surjBorromeanHash(tmp, m, 0, j);
    const eBig = bytesToNumberBE(e);
    R = pubkeys[j].is0()
      ? Point.BASE.multiply(s[j])
      : Point.BASE.multiply(s[j]).add(pubkeys[j].multiply(eBig));
    tmp = R.toBytes(true);
  }

  // e0 = SHA256(R_last || m)
  const e0 = sha256(concatBytes(tmp, m));

  // Phase 2: Forward from 0 to secIdx
  let ePrev: Uint8Array = e0;
  for (let j = 0; j < secIdx; j++) {
    const e = surjBorromeanHash(ePrev, m, 0, j);
    const eBig = bytesToNumberBE(e);
    R = pubkeys[j].is0()
      ? Point.BASE.multiply(s[j])
      : Point.BASE.multiply(s[j]).add(pubkeys[j].multiply(eBig));
    ePrev = R.toBytes(true);
  }

  // s[secIdx] = nonce - e * sec (mod N)
  const eFinal = surjBorromeanHash(ePrev, m, 0, secIdx);
  const eBig = bytesToNumberBE(eFinal);
  s[secIdx] = modN(nonce - eBig * sec);

  return { e0, s };
}

function surjBorromeanVerify(
  m: Uint8Array, pubkeys: PointT[], e0: Uint8Array, s: bigint[]
): boolean {
  const nKeys = pubkeys.length;
  let ePrev: Uint8Array = e0;
  for (let j = 0; j < nKeys; j++) {
    const e = surjBorromeanHash(ePrev, m, 0, j);
    const eBig = bytesToNumberBE(e);
    if (eBig === 0n) return false;
    if (s[j] >= N) return false;
    const R = pubkeys[j].is0()
      ? Point.BASE.multiply(s[j])
      : Point.BASE.multiply(s[j]).add(pubkeys[j].multiply(eBig));
    if (R.is0()) return false;
    ePrev = R.toBytes(true);
  }
  const e0Check = sha256(concatBytes(ePrev, m));
  for (let i = 0; i < 32; i++) {
    if (e0Check[i] !== e0[i]) return false;
  }
  return true;
}

function surjectionGenmessage(inputTags: PointT[], outputTag: PointT): Uint8Array {
  const h = sha256.create();
  for (const tag of inputTags) h.update(tag.toBytes(true));
  h.update(outputTag.toBytes(true));
  return h.digest();
}

function surjectionGenrand(key: Uint8Array, nUsed: number): Uint8Array[] {
  const scalars: Uint8Array[] = [];
  const buf = new Uint8Array(36);
  buf.set(key, 4);
  for (let i = 0; i < nUsed; i++) {
    new DataView(buf.buffer).setUint32(0, i, true);
    const h = sha256(buf);
    buf.set(h, 0);
    scalars.push(h);
  }
  return scalars;
}

function surjectionComputePublicKeys(
  inputTags: PointT[], outputTag: PointT, usedIndices: number[]
): PointT[] {
  return usedIndices.map((idx) => outputTag.add(inputTags[idx].negate()));
}

// ---- Exported functions ----

export function generatorGenerate(seed: Uint8Array): Uint8Array {
  const h1 = sha256(concatBytes(asciiToBytes('1st generation: '), seed));
  const t1 = Fp.create(bytesToNumberBE(h1));
  const p1 = svdw(t1);
  const h2 = sha256(concatBytes(asciiToBytes('2nd generation: '), seed));
  const t2 = Fp.create(bytesToNumberBE(h2));
  const p2 = svdw(t2);
  return serializeGenerator(p1.add(p2));
}

export function generatorGenerateBlinded(key: Uint8Array, blinder: Uint8Array): Uint8Array {
  const gen = parsePoint(generatorGenerate(key));
  const blindScalar = bytesToNumberBE(blinder);
  if (blindScalar === 0n) return serializeGenerator(gen);
  return serializeGenerator(gen.add(Point.BASE.multiply(blindScalar)));
}

export function pedersenCommitment(value: bigint, generator: Uint8Array, blinder: Uint8Array): Uint8Array {
  const b = bytesToNumberBE(blinder);
  const H = parsePoint(generator);
  let C: PointT;
  if (b === 0n) {
    C = H.multiply(value);
  } else if (value === 0n) {
    C = Point.BASE.multiply(b);
  } else {
    C = Point.BASE.multiply(b).add(H.multiply(value));
  }
  return serializePedersen(C);
}

export function pedersenBlindGeneratorBlindSum(
  values: bigint[],
  assetBlinders: Uint8Array[],
  valueBlinders: Uint8Array[],
  nInputs: number
): Uint8Array {
  const n = values.length;
  let sum = 0n;
  for (let i = 0; i < n - 1; i++) {
    const v = values[i];
    const ab = bytesToNumberBE(assetBlinders[i]);
    const vb = bytesToNumberBE(valueBlinders[i]);
    const term = modN(v * ab + vb);
    sum = i < nInputs ? modN(sum + term) : modN(sum - term);
  }
  const lastV = values[n - 1];
  const lastAb = bytesToNumberBE(assetBlinders[n - 1]);
  return numberToBytesBE(modN(sum - lastV * lastAb), 32);
}

export function surjectionProofInitialize(
  inputTags: Uint8Array[],
  outputTag: Uint8Array,
  maxIterations: number,
  seed: Uint8Array
): { proof: Uint8Array; inputIndex: number } {
  const nInputs = inputTags.length;
  const nToUse = Math.min(nInputs, 3);
  let matchIdx = -1;
  for (let i = 0; i < nInputs; i++) {
    let match = true;
    for (let j = 0; j < outputTag.length; j++) {
      if (inputTags[i][j] !== outputTag[j]) { match = false; break; }
    }
    if (match) { matchIdx = i; break; }
  }
  if (matchIdx === -1) throw new Error('surjectionProofInitialize: no matching input tag');

  const csprng = new SurjectionCSPRNG(seed);
  const bitmap = new Uint8Array(Math.ceil(nInputs / 8));
  let inputIndex = 0;
  for (let iter = 0; iter < maxIterations; iter++) {
    bitmap.fill(0);
    let hasMatch = false;
    for (let i = 0; i < nToUse; i++) {
      let idx: number;
      do {
        idx = csprng.next(nInputs);
      } while (bitmap[idx >> 3] & (1 << (idx & 7)));
      bitmap[idx >> 3] |= 1 << (idx & 7);
      if (idx === matchIdx) hasMatch = true;
    }
    if (hasMatch) {
      inputIndex = 0;
      for (let i = 0; i < matchIdx; i++) {
        if (bitmap[i >> 3] & (1 << (i & 7))) inputIndex++;
      }
      const bitmapLen = Math.ceil(nInputs / 8);
      const proof = new Uint8Array(2 + bitmapLen);
      proof[0] = nInputs & 0xff;
      proof[1] = (nInputs >> 8) & 0xff;
      proof.set(bitmap.subarray(0, bitmapLen), 2);
      return { proof, inputIndex };
    }
  }
  throw new Error('surjectionProofInitialize: max iterations reached');
}

export function surjectionProofGenerate(
  proof: Uint8Array,
  inputTags: Uint8Array[],
  outputTag: Uint8Array,
  inputIndex: number,
  inputBlindingKey: Uint8Array,
  outputBlindingKey: Uint8Array
): Uint8Array {
  const nInputs = proof[0] | (proof[1] << 8);
  const bitmapLen = Math.ceil(nInputs / 8);
  const bitmap = proof.subarray(2, 2 + bitmapLen);
  const usedIndices: number[] = [];
  for (let i = 0; i < nInputs; i++) {
    if (bitmap[i >> 3] & (1 << (i & 7))) usedIndices.push(i);
  }
  const nUsed = usedIndices.length;

  const inputPoints = inputTags.map((t) => parsePoint(t));
  const outputPoint = parsePoint(outputTag);
  const blindingKey = modN(bytesToNumberBE(outputBlindingKey) - bytesToNumberBE(inputBlindingKey));
  const blindKeyBytes = numberToBytesBE(blindingKey, 32);
  const pubkeys = surjectionComputePublicKeys(inputPoints, outputPoint, usedIndices);
  const m = surjectionGenmessage(inputPoints, outputPoint);
  const sScalars = surjectionGenrand(blindKeyBytes, nUsed);
  const nonce = bytesToNumberBE(sScalars[inputIndex]);
  const sBigints = sScalars.map((sc) => bytesToNumberBE(sc));
  sBigints[inputIndex] = 0n;
  const { e0, s } = surjBorromeanSign(m, pubkeys, blindingKey, inputIndex, nonce, sBigints);

  const result = new Uint8Array(2 + bitmapLen + 32 + nUsed * 32);
  result.set(proof.subarray(0, 2 + bitmapLen), 0);
  result.set(e0, 2 + bitmapLen);
  for (let i = 0; i < nUsed; i++) {
    result.set(numberToBytesBE(s[i], 32), 2 + bitmapLen + 32 + i * 32);
  }
  return result;
}

export function surjectionProofVerify(
  proof: Uint8Array,
  inputTags: Uint8Array[],
  outputTag: Uint8Array
): boolean {
  const nInputs = proof[0] | (proof[1] << 8);
  const bitmapLen = Math.ceil(nInputs / 8);
  const bitmap = proof.subarray(2, 2 + bitmapLen);
  const usedIndices: number[] = [];
  for (let i = 0; i < nInputs; i++) {
    if (bitmap[i >> 3] & (1 << (i & 7))) usedIndices.push(i);
  }
  const nUsed = usedIndices.length;
  const e0 = proof.subarray(2 + bitmapLen, 2 + bitmapLen + 32);
  const s: bigint[] = [];
  for (let i = 0; i < nUsed; i++) {
    const offset = 2 + bitmapLen + 32 + i * 32;
    s.push(bytesToNumberBE(proof.subarray(offset, offset + 32)));
  }

  const inputPoints = inputTags.map((t) => parsePoint(t));
  const outputPoint = parsePoint(outputTag);
  const pubkeys = surjectionComputePublicKeys(inputPoints, outputPoint, usedIndices);
  const m = surjectionGenmessage(inputPoints, outputPoint);
  return surjBorromeanVerify(m, pubkeys, e0, s);
}

export function ecdhUnhashedSHA256(pubkey: Uint8Array, scalar: Uint8Array): Uint8Array {
  const P = Point.fromBytes(pubkey);
  const s = bytesToNumberBE(scalar);
  return sha256(P.multiply(s).toBytes(true));
}
