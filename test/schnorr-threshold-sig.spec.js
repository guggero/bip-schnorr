/* global describe, it, beforeEach */
const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const convert = require('../src/convert');
const muSig = require('../src/mu-sig');
const thresholdSig = require('../src/threshold-sig');
const schnorr = require('../src/schnorr');
const randomBytes = require('random-bytes');

const testVectors = require('./test-vectors-threshold-sig.json');
const testVectorsLagrange = require('./test-vectors-lagrange.json');

describe('thresholdSig', () => {
  describe('keySplit', () => {
    testVectors.forEach((vec, index) => {
      it('can split private keys into shards ' + index, () => {
        // given
        const privateKeys = vec.privKeys.map(d => BigInteger.fromHex(d));
        const numSigners = vec.pubCoefficients[0].length;
        const numSignersTotal = privateKeys.length;

        // when
        const results = privateKeys.map(d => thresholdSig.keySplit(d, numSigners, numSignersTotal));

        // then
        results.forEach((result, resultIndex) => {
          result.shards.forEach((shard, shardIndex) => {
            assert.strictEqual(convert.intToBuffer(shard).toString('hex'), vec.shards[resultIndex][shardIndex], `shard[${resultIndex}][${shardIndex}]`);
          });

          result.pubCoefficients.forEach((coefficient, coefficientIndex) => {
            assert.strictEqual(coefficient.toString('hex'), vec.pubCoefficients[resultIndex][coefficientIndex], `pubCoefficient[${resultIndex}][${coefficientIndex}]`);
          });
        });
      });
    });
  });

  describe('verifyShard', () => {
    testVectors.forEach((vec, index) => {
      it('can verify shard ' + index, () => {
        // given
        const privateKeys = vec.privKeys.map(d => BigInteger.fromHex(d));
        const pubKeys = vec.pubKeys.map(pk => Buffer.from(pk, 'hex'));
        const pubKeyCombined = Buffer.from(vec.pubKeyCombined, 'hex');
        const ell = muSig.computeEll(pubKeys);
        const numSigners = vec.pubCoefficients[0].length;
        const numSignersTotal = privateKeys.length;
        const parts = privateKeys.map(d => thresholdSig.keySplit(d, numSigners, numSignersTotal));

        privateKeys.forEach((privKey, index) => {
          const signingPubkey = Buffer.alloc(33, 0);
          for (let j = 0; j < numSigners; j++) {

            // when
            let result = false;
            try {
              thresholdSig.verifyShard(privKey, signingPubkey, numSignersTotal, ell, j > 0, parts[index].shards[j], index, j, parts[index].pubCoefficients, numSigners);
              result = true;
            } catch (e) {
              result = false;
            }

            // then
            assert.strictEqual(result, true);
          }
        });
      });
    });
  });

  describe('lagrangeCoefficient', () => {
    testVectorsLagrange.forEach((vec, index) => {
      it('can calculate lagrange coefficient ' + vec.coefficient, () => {
        // when
        const result = thresholdSig.lagrangeCoefficient(vec.indices, vec.numSigners, vec.myIndex);

        // then
        assert.strictEqual(convert.intToBuffer(result).toString('hex'), vec.coefficient);
      });
    });
  })
});
