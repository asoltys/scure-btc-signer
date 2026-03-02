// Blech32/Blech32m encoding for Liquid confidential segwit addresses.
// Identical to bech32 but uses 60-bit checksums (12 characters) instead of 30-bit (6 characters).
// Uses native BigInt instead of Long dependency.

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

const GENERATORS: bigint[] = [
  0x7d52fba40bd886n,
  0x5e8dbf1a03950cn,
  0x1c3a3c74072a18n,
  0x385d72fa0e5139n,
  0x7093e5a608865bn,
];

export const BLECH32 = 'blech32';
export const BLECH32M = 'blech32m';
export type Blech32Encoding = typeof BLECH32 | typeof BLECH32M;

function getEncodingConst(enc: Blech32Encoding): bigint {
  if (enc === BLECH32) return 1n;
  if (enc === BLECH32M) return 0x455972a3350f7a1n;
  throw new Error('Invalid blech32 encoding type');
}

function polymod(values: ArrayLike<number>): bigint {
  let chk = 1n;
  for (let p = 0; p < values.length; p++) {
    const top = chk >> 55n;
    chk = ((chk & 0x7fffffffffffffn) << 5n) ^ BigInt(values[p]);
    for (let i = 0; i < 5; i++) {
      if ((top >> BigInt(i)) & 1n) {
        chk ^= GENERATORS[i];
      }
    }
  }
  return chk;
}

function hrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (let p = 0; p < hrp.length; p++) ret.push(hrp.charCodeAt(p) >> 5);
  ret.push(0);
  for (let p = 0; p < hrp.length; p++) ret.push(hrp.charCodeAt(p) & 31);
  return ret;
}

function verifyChecksum(hrp: string, data: number[], enc: Blech32Encoding): boolean {
  const values = hrpExpand(hrp).concat(data);
  return polymod(values) === getEncodingConst(enc);
}

function createChecksum(hrp: string, data: number[], enc: Blech32Encoding): number[] {
  const values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  const mod = polymod(values) ^ getEncodingConst(enc);
  const ret: number[] = [];
  for (let p = 0; p < 12; p++) {
    ret.push(Number((mod >> BigInt(5 * (11 - p))) & 31n));
  }
  return ret;
}

export function encode(hrp: string, data: number[], enc: Blech32Encoding): string {
  const checksum = createChecksum(hrp, data, enc);
  const combined = data.concat(checksum);
  let ret = hrp + '1';
  for (let p = 0; p < combined.length; p++) {
    ret += CHARSET.charAt(combined[p]);
  }
  return ret;
}

export function decode(
  str: string,
  enc: Blech32Encoding
): { hrp: string; data: number[] } {
  let hasLower = false;
  let hasUpper = false;
  for (let p = 0; p < str.length; p++) {
    const c = str.charCodeAt(p);
    if (c < 33 || c > 126) throw new Error('Invalid character in blech32 string');
    if (c >= 97 && c <= 122) hasLower = true;
    if (c >= 65 && c <= 90) hasUpper = true;
  }
  if (hasLower && hasUpper) throw new Error('Mixed case in blech32 string');

  str = str.toLowerCase();
  const pos = str.lastIndexOf('1');
  if (pos < 1 || pos + 13 > str.length) throw new Error('Invalid separator position in blech32 string');

  const hrp = str.substring(0, pos);
  const data: number[] = [];
  for (let p = pos + 1; p < str.length; p++) {
    const d = CHARSET.indexOf(str.charAt(p));
    if (d === -1) throw new Error(`Invalid character "${str.charAt(p)}" in blech32 string`);
    data.push(d);
  }

  if (!verifyChecksum(hrp, data, enc)) {
    throw new Error(`Invalid ${enc} checksum`);
  }

  return { hrp, data: data.slice(0, data.length - 12) };
}

// Convert between bit groups (same as bech32 convertBits)
function convertBits(
  data: number[],
  fromBits: number,
  toBits: number,
  pad: boolean
): number[] {
  let acc = 0;
  let bits = 0;
  const ret: number[] = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    if (value < 0 || value >> fromBits !== 0) throw new Error('Invalid value for convertBits');
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  } else {
    if (bits >= fromBits) throw new Error('Excess padding');
    if ((acc << (toBits - bits)) & maxv) throw new Error('Non-zero padding bits');
  }
  return ret;
}

function getEncodingType(witnessVersion: number): Blech32Encoding {
  if (witnessVersion === 0) return BLECH32;
  if (witnessVersion === 1) return BLECH32M;
  throw new Error(`Unsupported witness version (${witnessVersion}) for blech32`);
}

/**
 * Encode a confidential segwit address.
 * witnessProgram = blindingKey(33) || witnessData(20|32)
 */
export function encodeAddress(
  witnessProgram: Uint8Array,
  blindingKey: Uint8Array,
  hrp: string,
  witnessVersion: number
): string {
  const combined = new Uint8Array(blindingKey.length + witnessProgram.length);
  combined.set(blindingKey);
  combined.set(witnessProgram, blindingKey.length);

  const progLen = combined.length;
  if (witnessVersion === 0 && progLen !== 53 && progLen !== 65)
    throw new Error('Witness version 0 needs program length 53 or 65');
  if (progLen < 2 || progLen > 65)
    throw new Error('Witness program length must be 2-65');

  const data = [witnessVersion].concat(
    convertBits(Array.from(combined), 8, 5, true)
  );
  return encode(hrp, data, getEncodingType(witnessVersion));
}

/**
 * Decode a confidential segwit address.
 * Returns the blinding public key, witness program, and witness version.
 */
export function decodeAddress(
  addr: string
): { witness: Uint8Array; blindingPublicKey: Uint8Array; witnessVersion: number; hrp: string } {
  let result: { hrp: string; data: number[] };
  try {
    result = decode(addr, BLECH32);
  } catch {
    result = decode(addr, BLECH32M);
  }

  const witnessVersion = result.data[0];
  if (witnessVersion < 0 || witnessVersion > 16)
    throw new Error('Invalid witness version');

  const program = convertBits(result.data.slice(1), 5, 8, false);
  if (program.length < 2 || program.length > 65)
    throw new Error('Invalid witness program length');
  if (witnessVersion === 0 && program.length !== 53 && program.length !== 65)
    throw new Error('Invalid witness program length for version 0');

  const blindingPublicKey = Uint8Array.from(program.slice(0, 33));
  const witness = Uint8Array.from(program.slice(33));

  return { witness, blindingPublicKey, witnessVersion, hrp: result.hrp };
}
