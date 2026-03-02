import * as P from 'micro-packed';
import { isBytes, reverseObject, type ValueOf, type Bytes } from './utils.ts';

export const MAX_SCRIPT_BYTE_LENGTH = 520;

// prettier-ignore
export const OP = {
  OP_0: 0, PUSHDATA1: 76, PUSHDATA2: 77, PUSHDATA4: 78, '1NEGATE': 79,
  RESERVED: 80,
  OP_1: 81, OP_2: 82, OP_3: 83, OP_4: 84, OP_5: 85, OP_6: 86, OP_7: 87, OP_8: 88, OP_9: 89,
  OP_10: 90, OP_11: 91, OP_12: 92, OP_13: 93, OP_14: 94, OP_15: 95, OP_16: 96,
  // Control
  NOP: 97, VER: 98, IF: 99, NOTIF: 100, VERIF: 101, VERNOTIF: 102, ELSE: 103, ENDIF: 104, VERIFY: 105, RETURN: 106,
  // Stack
  TOALTSTACK: 107, FROMALTSTACK: 108, '2DROP': 109, '2DUP': 110, '3DUP': 111, '2OVER': 112, '2ROT': 113, '2SWAP': 114,
  IFDUP: 115, DEPTH: 116, DROP: 117, DUP: 118, NIP: 119, OVER: 120, PICK: 121, ROLL: 122, ROT: 123, SWAP: 124, TUCK: 125,
  // Splice
  CAT: 126, SUBSTR: 127, LEFT: 128, RIGHT: 129, SIZE: 130,
  // Boolean logic
  INVERT: 131, AND: 132, OR: 133, XOR: 134, EQUAL: 135, EQUALVERIFY: 136, RESERVED1: 137, RESERVED2: 138,
    // Numbers
  '1ADD': 139, '1SUB': 140, '2MUL': 141, '2DIV': 142,
  NEGATE: 143, ABS: 144, NOT: 145, '0NOTEQUAL': 146,
  ADD: 147, SUB: 148, MUL: 149, DIV: 150, MOD: 151, LSHIFT: 152, RSHIFT: 153, BOOLAND: 154, BOOLOR: 155,
  NUMEQUAL: 156, NUMEQUALVERIFY: 157, NUMNOTEQUAL: 158, LESSTHAN: 159, GREATERTHAN: 160,
  LESSTHANOREQUAL: 161, GREATERTHANOREQUAL: 162, MIN: 163, MAX: 164, WITHIN: 165,
  // Crypto
  RIPEMD160: 166, SHA1: 167, SHA256: 168, HASH160: 169, HASH256: 170, CODESEPARATOR: 171,
  CHECKSIG: 172, CHECKSIGVERIFY: 173, CHECKMULTISIG: 174, CHECKMULTISIGVERIFY: 175,
  // Expansion
  NOP1: 176, CHECKLOCKTIMEVERIFY: 177, CHECKSEQUENCEVERIFY: 178, NOP4: 179, NOP5: 180, NOP6: 181, NOP7: 182, NOP8: 183, NOP9: 184, NOP10: 185,
  // BIP 342
  CHECKSIGADD: 186,
  // Invalid
  INVALID: 255,
};

export const OPNames = reverseObject(OP);
export type OP = ValueOf<typeof OP>;

export type ScriptOP = keyof typeof OP | Uint8Array | number;
export type ScriptType = ScriptOP[];

// We can encode almost any number as ScriptNum, however, parsing will be a problem
// since we can't know if buffer is a number or something else.
export function ScriptNum(bytesLimit = 6, forceMinimal = false): P.CoderType<bigint> {
  return P.wrap({
    encodeStream: (w: P.Writer, value: bigint) => {
      if (value === 0n) return;
      const neg = value < 0;
      const val = BigInt(value);
      const nums = [];
      for (let abs = neg ? -val : val; abs; abs >>= 8n) nums.push(Number(abs & 0xffn));
      if (nums[nums.length - 1] >= 0x80) nums.push(neg ? 0x80 : 0);
      else if (neg) nums[nums.length - 1] |= 0x80;
      w.bytes(new Uint8Array(nums));
    },
    decodeStream: (r: P.Reader): bigint => {
      const len = r.leftBytes;
      if (len > bytesLimit)
        throw new Error(`ScriptNum: number (${len}) bigger than limit=${bytesLimit}`);
      if (len === 0) return 0n;
      if (forceMinimal) {
        const data = r.bytes(len, true);
        // MSB is zero (without sign bit) -> not minimally encoded
        if ((data[data.length - 1] & 0x7f) === 0) {
          // exception
          if (len <= 1 || (data[data.length - 2] & 0x80) === 0)
            throw new Error('Non-minimally encoded ScriptNum');
        }
      }
      let last = 0;
      let res = 0n;
      for (let i = 0; i < len; ++i) {
        last = r.byte();
        res |= BigInt(last) << (8n * BigInt(i));
      }
      if (last >= 0x80) {
        res &= (2n ** BigInt(len * 8) - 1n) >> 1n;
        res = -res;
      }
      return res;
    },
  });
}

export function OpToNum(op: ScriptOP, bytesLimit = 4, forceMinimal = true): number | undefined {
  if (typeof op === 'number') return op;
  if (isBytes(op)) {
    try {
      const val = ScriptNum(bytesLimit, forceMinimal).decode(op);
      if (val > Number.MAX_SAFE_INTEGER) return;
      return Number(val);
    } catch (e) {
      return;
    }
  }
  return;
}

// Converts script bytes to parsed script
// 5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae
// =>
// OP_2
//   030000000000000000000000000000000000000000000000000000000000000001
//   030000000000000000000000000000000000000000000000000000000000000002
//   030000000000000000000000000000000000000000000000000000000000000003
//   OP_3
//   CHECKMULTISIG
export const Script: P.CoderType<ScriptType> = P.wrap({
  encodeStream: (w: P.Writer, value: ScriptType) => {
    for (let o of value) {
      if (typeof o === 'string') {
        if (OP[o] === undefined) throw new Error(`Unknown opcode=${o}`);
        w.byte(OP[o]);
        continue;
      } else if (typeof o === 'number') {
        if (o === 0x00) {
          w.byte(0x00);
          continue;
        } else if (1 <= o && o <= 16) {
          w.byte(OP.OP_1 - 1 + o);
          continue;
        }
      }
      // Encode big numbers
      if (typeof o === 'number') o = ScriptNum().encode(BigInt(o));
      if (!isBytes(o)) throw new Error(`Wrong Script OP=${o} (${typeof o})`);
      // Bytes
      const len = o.length;
      if (len < OP.PUSHDATA1) w.byte(len);
      else if (len <= 0xff) {
        w.byte(OP.PUSHDATA1);
        w.byte(len);
      } else if (len <= 0xffff) {
        w.byte(OP.PUSHDATA2);
        w.bytes(P.U16LE.encode(len));
      } else {
        w.byte(OP.PUSHDATA4);
        w.bytes(P.U32LE.encode(len));
      }
      w.bytes(o);
    }
  },
  decodeStream: (r: P.Reader): ScriptType => {
    const out: ScriptType = [];
    while (!r.isEnd()) {
      const cur = r.byte();
      // if 0 < cur < 78
      if (OP.OP_0 < cur && cur <= OP.PUSHDATA4) {
        let len;
        if (cur < OP.PUSHDATA1) len = cur;
        else if (cur === OP.PUSHDATA1) len = P.U8.decodeStream(r);
        else if (cur === OP.PUSHDATA2) len = P.U16LE.decodeStream(r);
        else if (cur === OP.PUSHDATA4) len = P.U32LE.decodeStream(r);
        else throw new Error('Should be not possible');
        out.push(r.bytes(len));
      } else if (cur === 0x00) {
        out.push(0);
      } else if (OP.OP_1 <= cur && cur <= OP.OP_16) {
        out.push(cur - (OP.OP_1 - 1));
      } else {
        const op = OPNames[cur] as keyof typeof OP;
        if (op === undefined) throw new Error(`Unknown opcode=${cur.toString(16)}`);
        out.push(op);
      }
    }
    return out;
  },
});

// BTC specific variable length integer encoding
// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
const CSLimits: Record<number, [number, number, bigint, bigint]> = {
  0xfd: [0xfd, 2, 253n, 65535n],
  0xfe: [0xfe, 4, 65536n, 4294967295n],
  0xff: [0xff, 8, 4294967296n, 18446744073709551615n],
};
export const CompactSize: P.CoderType<bigint> = P.wrap({
  encodeStream: (w: P.Writer, value: bigint) => {
    if (typeof value === 'number') value = BigInt(value);
    if (0n <= value && value <= 252n) return w.byte(Number(value));
    for (const [flag, bytes, start, stop] of Object.values(CSLimits)) {
      if (start > value || value > stop) continue;
      w.byte(flag);
      for (let i = 0; i < bytes; i++) w.byte(Number((value >> (8n * BigInt(i))) & 0xffn));
      return;
    }
    throw w.err(`VarInt too big: ${value}`);
  },
  decodeStream: (r: P.Reader): bigint => {
    const b0 = r.byte();
    if (b0 <= 0xfc) return BigInt(b0);
    const [_, bytes, start] = CSLimits[b0];
    let num = 0n;
    for (let i = 0; i < bytes; i++) num |= BigInt(r.byte()) << (8n * BigInt(i));
    if (num < start) throw r.err(`Wrong CompactSize(${8 * bytes})`);
    return num;
  },
});

// Same thing, but in number instead of bigint. Checks for safe integer inside
export const CompactSizeLen: P.CoderType<number> = P.apply(CompactSize, P.coders.numberBigint);

// ui8a of size <CompactSize>
export const VarBytes: P.CoderType<Bytes> = P.bytes(CompactSize);

// SegWit v0 stack of witness buffers
export const RawWitness: P.CoderType<Bytes[]> = P.array(CompactSizeLen, VarBytes);

// Array of size <CompactSize>
export const BTCArray = <T>(t: P.CoderType<T>): P.CoderType<T[]> => P.array(CompactSize, t);

// Liquid constants
const OUTPOINT_ISSUANCE_FLAG = 0x80000000;
const OUTPOINT_PEGIN_FLAG = 0x40000000;
const OUTPOINT_INDEX_MASK = 0x3fffffff;
const MINUS_1 = 0xffffffff;

export interface IssuanceData {
  assetBlindingNonce: Uint8Array;
  assetEntropy: Uint8Array;
  assetAmount: Uint8Array;
  tokenAmount: Uint8Array;
}

export const ConfidentialAsset: P.CoderType<Uint8Array> = P.wrap({
  encodeStream: (w, value: Uint8Array) => {
    for (let i = 0; i < value.length; i++) w.byte(value[i]);
  },
  decodeStream: (r) => {
    const prefix = r.byte();
    if (prefix === 0x01 || prefix === 0x0a || prefix === 0x0b) {
      const rest = new Uint8Array(32);
      for (let i = 0; i < 32; i++) rest[i] = r.byte();
      const result = new Uint8Array(33);
      result[0] = prefix;
      result.set(rest, 1);
      return result;
    }
    return new Uint8Array([prefix]);
  },
});

export const ConfidentialValue: P.CoderType<Uint8Array> = P.wrap({
  encodeStream: (w, value: Uint8Array) => {
    for (let i = 0; i < value.length; i++) w.byte(value[i]);
  },
  decodeStream: (r) => {
    const prefix = r.byte();
    let extra = 0;
    if (prefix === 0x01) extra = 8;
    else if (prefix === 0x08 || prefix === 0x09) extra = 32;
    const result = new Uint8Array(1 + extra);
    result[0] = prefix;
    for (let i = 0; i < extra; i++) result[1 + i] = r.byte();
    return result;
  },
});

export const ConfidentialNonce: P.CoderType<Uint8Array> = P.wrap({
  encodeStream: (w, value: Uint8Array) => {
    for (let i = 0; i < value.length; i++) w.byte(value[i]);
  },
  decodeStream: (r) => {
    const prefix = r.byte();
    if (prefix === 0x01 || prefix === 0x02 || prefix === 0x03) {
      const result = new Uint8Array(33);
      result[0] = prefix;
      for (let i = 0; i < 32; i++) result[1 + i] = r.byte();
      return result;
    }
    return new Uint8Array([prefix]);
  },
});

export const SegwitFlag = P.wrap({
  encodeStream: (w: P.Writer, value: boolean) => {
    value ? w.byte(0x1) : w.byte(0x0);
  },
  decodeStream: (r: P.Reader) => {
    return !!r.byte();
  },
});

export const RawOutput = P.struct({
  asset: ConfidentialAsset,
  value: ConfidentialValue,
  nonce: ConfidentialNonce,
  script: VarBytes,
});

export const RawInput: P.CoderType<{
  txid: Uint8Array;
  index: number;
  finalScriptSig: Uint8Array;
  sequence: number;
  issuance?: IssuanceData;
  isPegin?: boolean;
}> = P.wrap({
  encodeStream: (w, value) => {
    // txid (32 bytes, reversed)
    const txid = value.txid;
    for (let i = txid.length - 1; i >= 0; i--) w.byte(txid[i]);
    // index with flags
    let idx = value.index;
    if (value.issuance) idx = (idx | OUTPOINT_ISSUANCE_FLAG) >>> 0;
    if (value.isPegin) idx = (idx | OUTPOINT_PEGIN_FLAG) >>> 0;
    w.byte(idx & 0xff);
    w.byte((idx >>> 8) & 0xff);
    w.byte((idx >>> 16) & 0xff);
    w.byte((idx >>> 24) & 0xff);
    // scriptSig
    const ss = VarBytes.encode(value.finalScriptSig);
    for (let i = 0; i < ss.length; i++) w.byte(ss[i]);
    // sequence
    const seq = value.sequence;
    w.byte(seq & 0xff);
    w.byte((seq >>> 8) & 0xff);
    w.byte((seq >>> 16) & 0xff);
    w.byte((seq >>> 24) & 0xff);
    // issuance
    if (value.issuance) {
      const iss = value.issuance;
      for (let i = 0; i < iss.assetBlindingNonce.length; i++) w.byte(iss.assetBlindingNonce[i]);
      for (let i = 0; i < iss.assetEntropy.length; i++) w.byte(iss.assetEntropy[i]);
      const am = ConfidentialValue.encode(iss.assetAmount);
      for (let i = 0; i < am.length; i++) w.byte(am[i]);
      const tm = ConfidentialValue.encode(iss.tokenAmount);
      for (let i = 0; i < tm.length; i++) w.byte(tm[i]);
    }
  },
  decodeStream: (r) => {
    // txid (32 bytes, reversed)
    const raw = new Uint8Array(32);
    for (let i = 0; i < 32; i++) raw[i] = r.byte();
    const txid = new Uint8Array(32);
    for (let i = 0; i < 32; i++) txid[i] = raw[31 - i];
    // index
    let index = r.byte() | (r.byte() << 8) | (r.byte() << 16) | (r.byte() << 24);
    index = index >>> 0; // unsigned
    // scriptSig
    const finalScriptSig = VarBytes.decodeStream(r);
    // sequence
    let sequence = r.byte() | (r.byte() << 8) | (r.byte() << 16) | (r.byte() << 24);
    sequence = sequence >>> 0;
    // check for issuance/pegin flags
    let issuance: IssuanceData | undefined;
    let isPegin = false;
    if (index !== MINUS_1) {
      if (index & OUTPOINT_ISSUANCE_FLAG) {
        const assetBlindingNonce = new Uint8Array(32);
        for (let i = 0; i < 32; i++) assetBlindingNonce[i] = r.byte();
        const assetEntropy = new Uint8Array(32);
        for (let i = 0; i < 32; i++) assetEntropy[i] = r.byte();
        const assetAmount = ConfidentialValue.decodeStream(r);
        const tokenAmount = ConfidentialValue.decodeStream(r);
        issuance = { assetBlindingNonce, assetEntropy, assetAmount, tokenAmount };
      }
      if (index & OUTPOINT_PEGIN_FLAG) isPegin = true;
      index = index & OUTPOINT_INDEX_MASK;
    }
    const result: any = { txid, index, finalScriptSig, sequence };
    if (issuance) result.issuance = issuance;
    if (isPegin) result.isPegin = isPegin;
    return result;
  },
});

const ConfidentialInputFields = P.struct({
  issuanceRangeProof: VarBytes,
  inflationRangeProof: VarBytes,
  witness: RawWitness,
  pegInWitness: RawWitness,
});

const ConfidentialOutputFields = P.struct({
  surjectionProof: VarBytes,
  rangeProof: VarBytes,
});

// https://en.bitcoin.it/wiki/Protocol_documentation#tx
const _RawTx = P.struct({
  version: P.I32LE,
  segwitFlag: SegwitFlag,
  inputs: BTCArray(RawInput),
  outputs: BTCArray(RawOutput),
  lockTime: P.U32LE,
  witnesses: P.flagged('segwitFlag', P.array('inputs/length', ConfidentialInputFields)),
  outs: P.flagged('segwitFlag', P.array('outputs/length', ConfidentialOutputFields)),
});

function validateRawTx(tx: P.UnwrapCoder<typeof _RawTx>) {
  if (tx.segwitFlag && tx.witnesses && !tx.witnesses.length)
    throw new Error('Segwit flag with empty witnesses array');
  return tx;
}
export const RawTx = P.validate(_RawTx, validateRawTx);
