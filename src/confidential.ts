// Confidential transaction blinding/unblinding for Liquid.

import { sha256, concatBytes } from './utils.ts';
import {
  generatorGenerate,
  generatorGenerateBlinded,
  pedersenCommitment,
  pedersenBlindGeneratorBlindSum,
  rangeproofSign,
  rangeproofVerify,
  surjectionProofInitialize,
  surjectionProofGenerate,
  surjectionProofVerify,
  ecdhUnhashedSHA256,
} from './zkp.ts';

const ZERO = new Uint8Array(32);

// --- Output shape for unblinding ---

export interface UnblindOutputResult {
  value: string;
  valueBlindingFactor: Uint8Array;
  asset: Uint8Array;
  assetBlindingFactor: Uint8Array;
}

// --- Minimal output type for unblinding ---

export interface ConfidentialOutput {
  nonce: Uint8Array;
  value: Uint8Array;
  asset: Uint8Array;
  script: Uint8Array;
  rangeProof?: Uint8Array;
}

// --- Confidential class ---

export class Confidential {
  /** Derive shared nonce: sha256(ecdh(pubkey, privkey)) */
  nonceHash(pubkey: Uint8Array, privkey: Uint8Array): Uint8Array {
    return sha256(Uint8Array.from(ecdhUnhashedSHA256(pubkey, privkey)));
  }

  /** Pedersen commitment on value */
  valueCommitment(value: string, generator: Uint8Array, blinder: Uint8Array): Uint8Array {
    return Uint8Array.from(pedersenCommitment(BigInt(value), generator, blinder));
  }

  /** Blinded asset generator */
  assetCommitment(asset: Uint8Array, factor: Uint8Array): Uint8Array {
    return Uint8Array.from(generatorGenerateBlinded(asset, factor));
  }

  /** Compute the balancing value blinding factor */
  valueBlindingFactor(
    inValues: string[],
    outValues: string[],
    inAssetBlinders: Uint8Array[],
    outAssetBlinders: Uint8Array[],
    inValueBlinders: Uint8Array[],
    outValueBlinders: Uint8Array[]
  ): Uint8Array {
    const values = inValues.concat(outValues).map(BigInt);
    const nInputs = inValues.length;
    const assetBlinders = inAssetBlinders.concat(outAssetBlinders);
    const valueBlinders = inValueBlinders.concat(outValueBlinders);
    return Uint8Array.from(
      pedersenBlindGeneratorBlindSum(values, assetBlinders, valueBlinders, nInputs)
    );
  }

  /** Unblind output using blinding private key (derives nonce via ECDH) */
  unblindOutputWithKey(out: ConfidentialOutput, blindingPrivKey: Uint8Array): UnblindOutputResult {
    const nonce = this.nonceHash(out.nonce, blindingPrivKey);
    return this.unblindOutputWithNonce(out, nonce);
  }

  /** Unblind output using precomputed nonce (rewind rangeproof) */
  unblindOutputWithNonce(_out: ConfidentialOutput, _nonce: Uint8Array): UnblindOutputResult {
    throw new Error('unblindOutputWithNonce: rangeproof.rewind not implemented');
  }

  /** Sign a rangeproof (asset + assetBlinder encoded in message) */
  rangeProof(
    value: string,
    asset: Uint8Array,
    valueCommitment: Uint8Array,
    assetCommitment: Uint8Array,
    valueBlinder: Uint8Array,
    assetBlinder: Uint8Array,
    nonce: Uint8Array,
    scriptPubkey: Uint8Array,
    minValue: string = '1',
    exp: string = '0',
    minBits: string = '52'
  ): Uint8Array {
    const message = concatBytes(asset, assetBlinder);
    return Uint8Array.from(
      rangeproofSign(
        BigInt(parseInt(value, 10) === 0 ? '0' : minValue),
        valueCommitment,
        valueBlinder,
        nonce,
        parseInt(exp, 10),
        parseInt(minBits, 10),
        BigInt(value),
        message,
        scriptPubkey,
        assetCommitment
      )
    );
  }

  /** Rangeproof with ECDH nonce derivation */
  rangeProofWithNonceHash(
    blindingPubkey: Uint8Array,
    ephemeralPrivkey: Uint8Array,
    value: string,
    asset: Uint8Array,
    valueCommitment: Uint8Array,
    assetCommitment: Uint8Array,
    valueBlinder: Uint8Array,
    assetBlinder: Uint8Array,
    scriptPubkey: Uint8Array,
    minValue?: string,
    exp?: string,
    minBits?: string
  ): Uint8Array {
    const nonce = this.nonceHash(blindingPubkey, ephemeralPrivkey);
    return this.rangeProof(
      value, asset, valueCommitment, assetCommitment,
      valueBlinder, assetBlinder, nonce, scriptPubkey,
      minValue, exp, minBits
    );
  }

  /** Verify a rangeproof */
  rangeProofVerify(
    proof: Uint8Array,
    valueCommitment: Uint8Array,
    assetCommitment: Uint8Array,
    script?: Uint8Array
  ): boolean {
    return rangeproofVerify(proof, valueCommitment, script ?? new Uint8Array(), assetCommitment);
  }

  /** Generate surjection proof: prove output asset belongs to input set */
  surjectionProof(
    outputAsset: Uint8Array,
    outputAssetBlindingFactor: Uint8Array,
    inputAssets: Uint8Array[],
    inputAssetBlindingFactors: Uint8Array[],
    seed: Uint8Array
  ): Uint8Array {
    const outputGenerator = generatorGenerateBlinded(outputAsset, outputAssetBlindingFactor);
    const inputGenerators = inputAssets.map((v, i) =>
      generatorGenerateBlinded(v, inputAssetBlindingFactors[i])
    );
    const init = surjectionProofInitialize(inputAssets, outputAsset, 100, seed);
    return Uint8Array.from(
      surjectionProofGenerate(
        init.proof,
        inputGenerators,
        outputGenerator,
        init.inputIndex,
        inputAssetBlindingFactors[init.inputIndex],
        outputAssetBlindingFactor
      )
    );
  }

  /** Verify a surjection proof */
  surjectionProofVerify(
    inAssets: Uint8Array[],
    inAssetBlinders: Uint8Array[],
    outAsset: Uint8Array,
    outAssetBlinder: Uint8Array,
    proof: Uint8Array
  ): boolean {
    const inGenerators = inAssets.map((v, i) =>
      generatorGenerateBlinded(v, inAssetBlinders[i])
    );
    const outGenerator = generatorGenerateBlinded(outAsset, outAssetBlinder);
    return surjectionProofVerify(proof, inGenerators, outGenerator);
  }

  /** Special rangeproof for blinding values (exp=-1) */
  blindValueProof(
    value: string,
    valueCommitment: Uint8Array,
    assetCommitment: Uint8Array,
    valueBlinder: Uint8Array,
    nonce: Uint8Array
  ): Uint8Array {
    return Uint8Array.from(
      rangeproofSign(
        BigInt(value),
        valueCommitment,
        valueBlinder,
        nonce,
        -1,
        0,
        BigInt(value),
        new Uint8Array(),
        new Uint8Array(),
        assetCommitment
      )
    );
  }

  /** Single-asset surjection proof for asset blinding */
  blindAssetProof(
    asset: Uint8Array,
    assetCommitment: Uint8Array,
    assetBlinder: Uint8Array
  ): Uint8Array {
    const gen = generatorGenerate(asset);
    const init = surjectionProofInitialize([asset], asset, 100, ZERO);
    return Uint8Array.from(
      surjectionProofGenerate(
        init.proof,
        [gen],
        assetCommitment,
        init.inputIndex,
        ZERO,
        assetBlinder
      )
    );
  }

  /** Verify an asset blind proof */
  assetBlindProofVerify(
    asset: Uint8Array,
    assetCommitment: Uint8Array,
    proof: Uint8Array
  ): boolean {
    const inGenerators = [generatorGenerate(asset)];
    return surjectionProofVerify(proof, inGenerators, assetCommitment);
  }
}
