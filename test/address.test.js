import { expect, test, describe } from 'bun:test';
import { hex } from '@scure/base';
import * as btc from '../src/index.ts';
import {
  encode as blech32Encode,
  decode as blech32Decode,
  encodeAddress as blech32EncodeAddress,
  decodeAddress as blech32DecodeAddress,
  BLECH32,
  BLECH32M,
} from '../src/blech32.ts';

// ---- Test fixtures from liquidjs-lib ----

// Blech32 segwit confidential addresses (regtest)
const blech32Fixtures = [
  {
    address:
      'el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd',
    version: 0,
    prefix: 'el',
    data: 'e6a10b7bd8aeb56444c5734ea682cd2f1ad692c4', // 20-byte witness (P2WPKH)
    blindkey:
      '03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800',
  },
  {
    address:
      'el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqqfxftvrt6mm8ee4u7cj8x9uhz0tqwsc6hxuxl9sccxuqa682k2p34j69q77djwvn',
    version: 0,
    prefix: 'el',
    data: '24c95b06bd6f67ce6bcf62473179713d607431ab9b86f9618c1b80ee8eab2831', // 32-byte witness (P2WSH)
    blindkey:
      '03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800',
  },
];

// Standard confidential addresses (combined segwit + legacy, from liquidjs-lib fixtures)
const standardFixtures = [
  // Liquid mainnet P2PKH confidential (legacy base58)
  {
    network: 'liquid',
    version: 57, // pubKeyHash
    blindkey:
      '02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623',
    hash: '73fa580ea148bf5a520e21a9e6a875d38603df96',
    unconfidential: 'Q7qcjTLsYGoMA7TjUp97R6E6AM5VKqBik6',
    confidentialAddress:
      'VTpz1bNuCALgavJKgbAw9Lpp9A72rJy64XPqgqfnaLpMjRcPh5UHBqyRUE4WMZ3asjqu7YEPVAnWw2EK',
  },
  {
    network: 'liquid',
    version: 57,
    blindkey:
      '02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623',
    hash: '1f4133bed29660d80240ab1a4cb5b09ddefd1b87',
    unconfidential: 'Pz7eBTfLoVaisE57DLn6rZhEtFNa7SnZ2Z',
    confidentialAddress:
      'VTpz1bNuCALgavJKgbAw9Lpp9A72rJy64XPqgqfnaLpMjRcFy6vHWKEeFbmcxvn7WjHNagxHnFaRcVuS',
  },
  // Regtest P2SH confidential (legacy base58)
  {
    network: 'regtest',
    version: 75, // scriptHash
    blindkey:
      '02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623',
    hash: '2b919bfc040faed8de5469dfa0241a3c1e5681be',
    unconfidential: 'XFKcLWJmPuToz62uc2sgCBUddmH6yopoxE',
    confidentialAddress:
      'AzppxC5RDs8yB8mabhwS13y4WbsWoS41fLV8GKM4woLUJB5RxNBVfK6wdVX4QVoubRXFKKfbPhEKKTKc',
  },
  // Regtest P2PKH confidential (legacy base58)
  {
    network: 'regtest',
    version: 235, // pubKeyHash
    blindkey:
      '02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623',
    hash: '5104186b6dc2bd280b7a82b89c7b0f174adacbe4',
    unconfidential: '2dgp82cKUqN7pesBxcK6smvFSzCjyqqv1wL',
    confidentialAddress:
      'CTEqfbuwRjMKaivrrNqMSZahNuqitEMLabLzfxsyNPpPD2DvPGn9SW3Hp4RTEbgQgHtckwd8ons8vHcg',
  },
  // Regtest P2WPKH confidential (blech32)
  {
    network: 'regtest',
    blindkey:
      '03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800',
    data: 'e6a10b7bd8aeb56444c5734ea682cd2f1ad692c4',
    unconfidential: 'ert1qu6ssk77c466kg3x9wd82dqkd9udddykyfykm9k',
    confidentialAddress:
      'el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd',
  },
  // Regtest P2WSH confidential (blech32)
  {
    network: 'regtest',
    blindkey:
      '03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800',
    data: '24c95b06bd6f67ce6bcf62473179713d607431ab9b86f9618c1b80ee8eab2831',
    unconfidential:
      'ert1qyny4kp4adanuu670vfrnz7t384s8gvdtnwr0jcvvrwqwar4t9qcs2m7c20',
    confidentialAddress:
      'el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqqfxftvrt6mm8ee4u7cj8x9uhz0tqwsc6hxuxl9sccxuqa682k2p34j69q77djwvn',
  },
  // Testnet P2WPKH confidential (blech32)
  {
    network: 'testnet',
    blindkey:
      '0339b93f60bf024de61e56a0d0be0df864b952f4c82d2ed725fdb5d5991d5c4352',
    data: 'e45427947dd5a21ee6678f10f22b10eaa26e5a5d',
    unconfidential: 'tex1qu32z09ra6k3paen83ug0y2csa23xukja3fyeyx',
    confidentialAddress:
      'tlq1qqvumj0mqhupymes726sdp0sdlpjtj5h5eqkja4e9lk6atxgat3p49ez5y728m4dzrmnx0rcs7g43p64zded96r7etwq8lmd2e',
  },
];

// Liquid mainnet segwit addresses from integration tests
const integrationFixtures = [
  // P2WPKH — pubkey from KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
  {
    network: 'liquid',
    unconfidential: 'ex1qw508d6qejxtdg4y5r3zarvary0c5xw7kxw5fx4',
    blindkey:
      '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    confidentialAddress:
      'lq1qqfumuen7l8wthtz45p3ftn58pvrs9xlumvkuu2xet8egzkcklqtesag7wm5pnyvk632fg8z96xe6xgl3gvaavrxls8dj42vva',
  },
  // P2WSH 3-of-4 multisig
  {
    network: 'liquid',
    unconfidential:
      'ex1q75f6dv4q8ug7zhujrsp5t0hzf33lllnr3fe7e2pra3v24mzl8rrqhw64ue',
    blindkey:
      '026477115981fe981a6918a6297d9803c4dc04f328f22041bedff886bbc2962e01',
    confidentialAddress:
      'lq1qqfj8wy2es8lfsxnfrznzjlvcq0zdcp8n9rezqsd7mlugdw7zjchqragn56e2q0c3u90ey8qrgklwynrrlllx8znnaj5z8mzc4tk97wxxu2pwz4u8lcxz',
  },
];

function getNetwork(name) {
  if (name === 'liquid') return btc.LIQUID_NETWORK;
  if (name === 'testnet') return btc.LIQUID_TEST_NETWORK;
  if (name === 'regtest') return btc.LIQUID_REGTEST_NETWORK;
  throw new Error(`Unknown network: ${name}`);
}

// ===========================================================================
// Blech32 low-level tests
// ===========================================================================

describe('blech32', () => {
  test('encode/decode round-trip (BLECH32)', () => {
    const hrp = 'el';
    const data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const encoded = blech32Encode(hrp, data, BLECH32);
    const decoded = blech32Decode(encoded, BLECH32);
    expect(decoded.hrp).toBe(hrp);
    expect(decoded.data).toEqual(data);
  });

  test('encode/decode round-trip (BLECH32M)', () => {
    const hrp = 'lq';
    const data = [0, 15, 20, 31, 0, 10, 5, 25];
    const encoded = blech32Encode(hrp, data, BLECH32M);
    const decoded = blech32Decode(encoded, BLECH32M);
    expect(decoded.hrp).toBe(hrp);
    expect(decoded.data).toEqual(data);
  });

  test('decode rejects wrong encoding', () => {
    const hrp = 'el';
    const data = [0, 1, 2, 3];
    const encoded = blech32Encode(hrp, data, BLECH32);
    expect(() => blech32Decode(encoded, BLECH32M)).toThrow();
  });

  test('decode rejects mixed case', () => {
    expect(() => blech32Decode('El1qqqqqqqqqqqq', BLECH32)).toThrow('Mixed case');
  });

  test('decode rejects invalid characters', () => {
    expect(() => blech32Decode('el1!invalid', BLECH32)).toThrow();
  });

  for (const f of blech32Fixtures) {
    test(`decode known blech32 address: ${f.data.slice(0, 16)}...`, () => {
      const result = blech32DecodeAddress(f.address);
      expect(result.witnessVersion).toBe(f.version);
      expect(result.hrp).toBe(f.prefix);
      expect(hex.encode(result.blindingPublicKey)).toBe(f.blindkey);
      expect(hex.encode(result.witness)).toBe(f.data);
    });

    test(`encode/decode round-trip for known address: ${f.data.slice(0, 16)}...`, () => {
      const witness = hex.decode(f.data);
      const blindingKey = hex.decode(f.blindkey);
      const encoded = blech32EncodeAddress(witness, blindingKey, f.prefix, f.version);
      expect(encoded).toBe(f.address);
      const decoded = blech32DecodeAddress(encoded);
      expect(hex.encode(decoded.witness)).toBe(f.data);
      expect(hex.encode(decoded.blindingPublicKey)).toBe(f.blindkey);
      expect(decoded.witnessVersion).toBe(f.version);
    });
  }

  test('encodeAddress rejects invalid blinding key length', () => {
    const witness = hex.decode('e6a10b7bd8aeb56444c5734ea682cd2f1ad692c4');
    const shortKey = new Uint8Array(32);
    // Combined length 52 != 53 for v0, should fail
    expect(() => blech32EncodeAddress(witness, shortKey, 'el', 0)).toThrow();
  });

  test('encodeAddress rejects wrong program length for v0', () => {
    const witness = new Uint8Array(15); // not 20 or 32
    const blindingKey = new Uint8Array(33);
    // Combined = 33 + 15 = 48, not 53 or 65
    expect(() => blech32EncodeAddress(witness, blindingKey, 'el', 0)).toThrow();
  });
});

// ===========================================================================
// Confidential address tests
// ===========================================================================

describe('confidential addresses', () => {
  // --- Segwit confidential (blech32) ---

  describe('segwit (blech32)', () => {
    for (const f of standardFixtures.filter((f) => f.data)) {
      const network = getNetwork(f.network);
      const label = `${f.network} ${f.data.length === 40 ? 'P2WPKH' : 'P2WSH'}`;

      test(`toConfidential: ${label}`, () => {
        const result = btc.toConfidential(
          f.unconfidential,
          hex.decode(f.blindkey),
          network
        );
        expect(result).toBe(f.confidentialAddress);
      });

      test(`fromConfidential: ${label}`, () => {
        const result = btc.fromConfidential(f.confidentialAddress, network);
        expect(hex.encode(result.blindingKey)).toBe(f.blindkey);
        expect(result.unconfidentialAddress).toBe(f.unconfidential);
        expect(result.scriptPubKey.length).toBeGreaterThan(0);
      });

      test(`round-trip: ${label}`, () => {
        const blindingKey = hex.decode(f.blindkey);
        const conf = btc.toConfidential(f.unconfidential, blindingKey, network);
        const decoded = btc.fromConfidential(conf, network);
        expect(decoded.unconfidentialAddress).toBe(f.unconfidential);
        expect(hex.encode(decoded.blindingKey)).toBe(f.blindkey);
      });

      test(`isConfidential: ${label}`, () => {
        expect(btc.isConfidential(f.confidentialAddress, network)).toBe(true);
        expect(btc.isConfidential(f.unconfidential, network)).toBe(false);
      });
    }

    // Integration test vectors (liquid mainnet segwit)
    for (const f of integrationFixtures) {
      const network = getNetwork(f.network);
      const label = f.unconfidential.includes('ex1qw508') ? 'P2WPKH' : 'P2WSH';

      test(`toConfidential integration: ${label}`, () => {
        const result = btc.toConfidential(
          f.unconfidential,
          hex.decode(f.blindkey),
          network
        );
        expect(result).toBe(f.confidentialAddress);
      });

      test(`fromConfidential integration: ${label}`, () => {
        const result = btc.fromConfidential(f.confidentialAddress, network);
        expect(hex.encode(result.blindingKey)).toBe(f.blindkey);
        expect(result.unconfidentialAddress).toBe(f.unconfidential);
      });
    }
  });

  // --- Legacy confidential (base58) ---

  describe('legacy (base58)', () => {
    for (const f of standardFixtures.filter((f) => f.hash)) {
      const network = getNetwork(f.network);
      const isPKH = f.version === network.pubKeyHash;
      const label = `${f.network} ${isPKH ? 'P2PKH' : 'P2SH'}`;

      test(`toConfidential: ${label} (${f.hash.slice(0, 12)}...)`, () => {
        const result = btc.toConfidential(
          f.unconfidential,
          hex.decode(f.blindkey),
          network
        );
        expect(result).toBe(f.confidentialAddress);
      });

      test(`fromConfidential: ${label} (${f.hash.slice(0, 12)}...)`, () => {
        const result = btc.fromConfidential(f.confidentialAddress, network);
        expect(hex.encode(result.blindingKey)).toBe(f.blindkey);
        expect(result.unconfidentialAddress).toBe(f.unconfidential);
        expect(result.scriptPubKey.length).toBeGreaterThan(0);
      });

      test(`round-trip: ${label} (${f.hash.slice(0, 12)}...)`, () => {
        const blindingKey = hex.decode(f.blindkey);
        const conf = btc.toConfidential(f.unconfidential, blindingKey, network);
        const decoded = btc.fromConfidential(conf, network);
        expect(decoded.unconfidentialAddress).toBe(f.unconfidential);
        expect(hex.encode(decoded.blindingKey)).toBe(f.blindkey);
      });

      test(`isConfidential: ${label} (${f.hash.slice(0, 12)}...)`, () => {
        expect(btc.isConfidential(f.confidentialAddress, network)).toBe(true);
        expect(btc.isConfidential(f.unconfidential, network)).toBe(false);
      });
    }
  });

  // --- Error cases ---

  describe('error handling', () => {
    test('toConfidential rejects wrong blinding key length', () => {
      expect(() =>
        btc.toConfidential(
          'ert1qu6ssk77c466kg3x9wd82dqkd9udddykyfykm9k',
          new Uint8Array(32), // should be 33
          btc.REGTEST_NETWORK
        )
      ).toThrow('33 bytes');
    });

    test('fromConfidential rejects invalid base58 confidential prefix', () => {
      // A valid unconfidential address should fail fromConfidential
      expect(() =>
        btc.fromConfidential(
          'ert1qu6ssk77c466kg3x9wd82dqkd9udddykyfykm9k',
          btc.REGTEST_NETWORK
        )
      ).toThrow();
    });

    test('isConfidential returns false for unconfidential addresses', () => {
      expect(
        btc.isConfidential(
          'ert1qu6ssk77c466kg3x9wd82dqkd9udddykyfykm9k',
          btc.REGTEST_NETWORK
        )
      ).toBe(false);
      expect(
        btc.isConfidential('2dgp82cKUqN7pesBxcK6smvFSzCjyqqv1wL', btc.REGTEST_NETWORK)
      ).toBe(false);
    });

    test('isConfidential returns false for garbage', () => {
      expect(btc.isConfidential('notanaddress', btc.REGTEST_NETWORK)).toBe(false);
    });
  });
});

// ===========================================================================
// Address() decode with confidential addresses
// ===========================================================================

describe('Address().decode confidential', () => {
  // Blech32 confidential addresses should decode to the same OutScript as unconfidential
  for (const f of standardFixtures.filter((f) => f.data)) {
    const network = getNetwork(f.network);
    const label = `${f.network} blech32 ${f.data.length === 40 ? 'P2WPKH' : 'P2WSH'}`;

    test(`${label}: same OutScript as unconfidential`, () => {
      const confDecoded = btc.Address(network).decode(f.confidentialAddress);
      const unconfDecoded = btc.Address(network).decode(f.unconfidential);
      expect(confDecoded.type).toBe(unconfDecoded.type);
      if (confDecoded.hash) {
        expect(hex.encode(confDecoded.hash)).toBe(hex.encode(unconfDecoded.hash));
      }
      if (confDecoded.pubkey) {
        expect(hex.encode(confDecoded.pubkey)).toBe(hex.encode(unconfDecoded.pubkey));
      }
    });
  }

  // Legacy confidential base58 addresses
  for (const f of standardFixtures.filter((f) => f.hash)) {
    const network = getNetwork(f.network);
    const isPKH = f.version === network.pubKeyHash;
    const label = `${f.network} base58 ${isPKH ? 'P2PKH' : 'P2SH'}`;

    test(`${label}: same OutScript as unconfidential`, () => {
      const confDecoded = btc.Address(network).decode(f.confidentialAddress);
      const unconfDecoded = btc.Address(network).decode(f.unconfidential);
      expect(confDecoded.type).toBe(unconfDecoded.type);
      expect(hex.encode(confDecoded.hash)).toBe(hex.encode(unconfDecoded.hash));
    });
  }

  // Integration fixtures (mainnet segwit)
  for (const f of integrationFixtures) {
    const network = getNetwork(f.network);
    const label = f.unconfidential.includes('ex1qw508') ? 'P2WPKH' : 'P2WSH';

    test(`liquid ${label}: same OutScript as unconfidential`, () => {
      const confDecoded = btc.Address(network).decode(f.confidentialAddress);
      const unconfDecoded = btc.Address(network).decode(f.unconfidential);
      expect(confDecoded.type).toBe(unconfDecoded.type);
    });
  }

  // Verify OutScript round-trip: decode confidential -> encode script -> decode script matches
  test('OutScript encode/decode consistency for blech32 P2WPKH', () => {
    const network = btc.REGTEST_NETWORK;
    const addr =
      'el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd';
    const decoded = btc.Address(network).decode(addr);
    expect(decoded.type).toBe('wpkh');
    const script = btc.OutScript.encode(decoded);
    const redecoded = btc.OutScript.decode(script);
    expect(redecoded.type).toBe('wpkh');
    expect(hex.encode(redecoded.hash)).toBe(
      'e6a10b7bd8aeb56444c5734ea682cd2f1ad692c4'
    );
  });

  test('OutScript encode/decode consistency for blech32 P2WSH', () => {
    const network = btc.REGTEST_NETWORK;
    const addr =
      'el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqqfxftvrt6mm8ee4u7cj8x9uhz0tqwsc6hxuxl9sccxuqa682k2p34j69q77djwvn';
    const decoded = btc.Address(network).decode(addr);
    expect(decoded.type).toBe('wsh');
    const script = btc.OutScript.encode(decoded);
    const redecoded = btc.OutScript.decode(script);
    expect(redecoded.type).toBe('wsh');
    expect(hex.encode(redecoded.hash)).toBe(
      '24c95b06bd6f67ce6bcf62473179713d607431ab9b86f9618c1b80ee8eab2831'
    );
  });
});
