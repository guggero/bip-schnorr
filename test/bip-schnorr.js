/* global describe, it, beforeEach */

const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const bipSchnorr = require('../src/bip-schnorr');

const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');
const G = curve.G;
const p = curve.p;
const n = curve.n;

const testVectors = require('./test-vectors.json');

describe('test vectors', () => {
  describe('sign', () => {
    testVectors
      .filter(vec => vec.d !== null)
      .forEach(vec => {
        it('sign ' + vec.d, () => {
          // given
          const d = BigInteger.fromHex(vec.d);
          const m = Buffer.from(vec.m, 'hex');

          // when
          const result = bipSchnorr.sign(d, m);

          // then
          assert.strictEqual(result.toString('hex'), vec.sig.toLowerCase());
        });
      });
  });

  describe('verify', () => {
    testVectors
      .forEach(vec => {
        it('verify ' + (vec.comment || vec.d), () => {
          // given
          const pk = Buffer.from(vec.pk, 'hex');
          const m = Buffer.from(vec.m, 'hex');
          const sig = Buffer.from(vec.sig, 'hex');
          const expectedResult = vec.result;

          // when
          let result = true;
          let error = null;
          try {
            bipSchnorr.verify(pk, m, sig);
          } catch (e) {
            result = false;
            error = e;
          }

          // then
          assert.strictEqual(result, expectedResult, error);
          if (!expectedResult) {
            assert.strictEqual(error.message, vec.expectedError);
          }
        });
      });
  });

  describe('aggregate demo', () => {
    const vec1 = testVectors[1];
    const vec2 = testVectors[2];
    const vec3 = testVectors[3];
    const pk1 = BigInteger.fromHex(vec1.pk);
    const pk2 = BigInteger.fromHex(vec2.pk);
    const pk3 = BigInteger.fromHex(vec3.pk);
    const P1 = G.multiply(pk1);
    const P2 = G.multiply(pk2);
    const P3 = G.multiply(pk3);
    const P = P1.add(P2).add(P3);

    it('can sign and verify aggregated signatures over same message', () => {
      // given
      const m = Buffer.from(vec1.m, 'hex');
      const sigSum2 = bipSchnorr.aggregateSignatures([pk1, pk2, pk3], m);

      // when
      bipSchnorr.verify(P.getEncoded(true), m, sigSum2);
    });
  });
});
