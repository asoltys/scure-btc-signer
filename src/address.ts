// Confidential address encoding/decoding for Liquid.
// Supports both segwit (blech32) and legacy (base58check) confidential addresses.

import { bech32, bech32m, createBase58check } from '@scure/base';
import { encodeAddress, decodeAddress } from './blech32.ts';
import { NETWORK, sha256 } from './utils.ts';
import { OutScript } from './payment.ts';

const base58check = createBase58check(sha256);

export interface ConfidentialResult {
  blindingKey: Uint8Array;
  unconfidentialAddress: string;
  scriptPubKey: Uint8Array;
}

/**
 * Convert an unconfidential Liquid address to a confidential address.
 * - Segwit addresses (bech32/bech32m prefix) → blech32 output
 * - Legacy base58 addresses → base58check with confidentialPrefix
 */
export function toConfidential(
  address: string,
  blindingKey: Uint8Array,
  network = NETWORK
): string {
  if (blindingKey.length !== 33) throw new Error('Blinding key must be 33 bytes');

  // Segwit path
  if (address.toLowerCase().startsWith(network.bech32)) {
    return toConfidentialSegwit(address, blindingKey, network);
  }

  // Legacy base58 path
  return toConfidentialLegacy(address, blindingKey, network);
}

/**
 * Decode a confidential address into its blinding key, unconfidential address, and scriptPubKey.
 */
export function fromConfidential(
  address: string,
  network = NETWORK
): ConfidentialResult {
  // Check segwit (blech32) first
  if (network.blech32 && address.toLowerCase().startsWith(network.blech32)) {
    return fromConfidentialSegwit(address, network);
  }

  // Legacy base58 confidential
  return fromConfidentialLegacy(address, network);
}

/**
 * Quick check if an address is confidential (blech32 prefix or confidential base58 prefix).
 */
export function isConfidential(address: string, network = NETWORK): boolean {
  if (network.blech32 && address.toLowerCase().startsWith(network.blech32)) return true;
  try {
    const data = base58check.decode(address);
    return data[0] === network.confidentialPrefix;
  } catch {
    return false;
  }
}

// --- Segwit helpers ---

function toConfidentialSegwit(
  address: string,
  blindingKey: Uint8Array,
  network: typeof NETWORK
): string {
  // Decode unconfidential bech32/bech32m address to get version + program
  let res;
  let version: number;
  try {
    res = bech32.decode(address as `${string}1${string}`);
    version = res.words[0];
    if (version !== 0) throw new Error('wrong version for bech32');
  } catch {
    res = bech32m.decode(address as `${string}1${string}`);
    version = res.words[0];
  }
  const program = Uint8Array.from(bech32.fromWords(res.words.slice(1)));
  return encodeAddress(program, blindingKey, network.blech32!, version);
}

function fromConfidentialSegwit(
  address: string,
  network: typeof NETWORK
): ConfidentialResult {
  const result = decodeAddress(address);
  const { blindingPublicKey, witness, witnessVersion } = result;

  // Reconstruct unconfidential bech32/bech32m address
  const coder = witnessVersion === 0 ? bech32 : bech32m;
  const words = [witnessVersion].concat(coder.toWords(witness));
  const unconfidentialAddress = coder.encode(network.bech32, words);

  // Build scriptPubKey from witness version + program
  let scriptPubKey: Uint8Array;
  if (witnessVersion === 0 && witness.length === 20) {
    scriptPubKey = OutScript.encode({ type: 'wpkh', hash: witness });
  } else if (witnessVersion === 0 && witness.length === 32) {
    scriptPubKey = OutScript.encode({ type: 'wsh', hash: witness });
  } else if (witnessVersion === 1 && witness.length === 32) {
    scriptPubKey = OutScript.encode({ type: 'tr', pubkey: witness });
  } else {
    throw new Error('Unknown witness program');
  }

  return { blindingKey: blindingPublicKey, unconfidentialAddress, scriptPubKey };
}

// --- Legacy base58 helpers ---

function toConfidentialLegacy(
  address: string,
  blindingKey: Uint8Array,
  network: typeof NETWORK
): string {
  const payload = base58check.decode(address);
  if (payload.length !== 21) throw new Error('Invalid base58 address length');
  const prefix = payload[0];
  if (prefix !== network.pubKeyHash && prefix !== network.scriptHash)
    throw new Error('Invalid base58 address prefix');

  // Format: [confidentialPrefix, addrPrefix, blindingKey(33), hash(20)]
  const result = new Uint8Array(2 + 33 + 20);
  result[0] = network.confidentialPrefix!;
  result[1] = prefix;
  result.set(blindingKey, 2);
  result.set(payload.subarray(1), 35);
  return base58check.encode(result);
}

function fromConfidentialLegacy(
  address: string,
  network: typeof NETWORK
): ConfidentialResult {
  const payload = base58check.decode(address);
  if (payload[0] !== network.confidentialPrefix)
    throw new Error('Invalid confidential address prefix');
  if (payload.length !== 55)
    throw new Error('Invalid confidential base58 address length');

  const addrPrefix = payload[1];
  if (addrPrefix !== network.pubKeyHash && addrPrefix !== network.scriptHash)
    throw new Error('Invalid address prefix in confidential address');

  const blindingKey = payload.slice(2, 35);
  const hash = payload.slice(35);

  // Reconstruct unconfidential base58 address
  const unconfPayload = new Uint8Array(21);
  unconfPayload[0] = addrPrefix;
  unconfPayload.set(hash, 1);
  const unconfidentialAddress = base58check.encode(unconfPayload);

  // Build scriptPubKey
  const scriptPubKey = OutScript.encode(
    addrPrefix === network.pubKeyHash
      ? { type: 'pkh', hash }
      : { type: 'sh', hash }
  );

  return { blindingKey, unconfidentialAddress, scriptPubKey };
}
