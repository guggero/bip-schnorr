/* global describe, it, beforeEach */
const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const schnorr = require('../src/schnorr');
const ecurve = require('ecurve');

const testVectors = require('./test-vectors-schnorr.json');

describe('test vectors', () => {
  describe('sign', () => {
    testVectors
      .filter(vec => vec.d !== "")
      .forEach(vec => {
        it('can sign ' + vec.d, () => {
          // given
          const d = BigInteger.fromHex(vec.d);
          const m = Buffer.from(vec.m, 'hex');
          const a = Buffer.from(vec.aux, 'hex');

          // when
          const result = schnorr.sign(d, m, a);

          // then
          assert.strictEqual(result.toString('hex'), vec.sig.toLowerCase());
        });
      });
  });

  describe('verify', () => {
    testVectors
      .forEach(vec => {
        it('can verify ' + (vec.comment || vec.d), () => {
          // given
          const pk = Buffer.from(vec.pk, 'hex');
          const m = Buffer.from(vec.m, 'hex');
          const sig = Buffer.from(vec.sig, 'hex');
          const expectedResult = vec.result;

          // when
          let result = true;
          let error = null;
          try {
            schnorr.verify(pk, m, sig);
          } catch (e) {
            result = false;
            error = e;
          }

          // then
          assert.strictEqual(result, expectedResult, error);
        });
      });
  });

  describe('batchVerify', () => {
    it('can batch verify all positive test cases', () => {
      // given
      const positiveVectors = testVectors.filter(vec => vec.result);
      const pubKeys = positiveVectors.map(vec => Buffer.from(vec.pk, 'hex'));
      const messages = positiveVectors.map(vec => Buffer.from(vec.m, 'hex'));
      const signatures = positiveVectors.map(vec => Buffer.from(vec.sig, 'hex'));

      // when
      let result = true;
      let error = null;
      try {
        schnorr.batchVerify(pubKeys, messages, signatures);
      } catch (e) {
        result = false;
        error = e;
      }

      // then
      assert.strictEqual(result, true, error);
      assert.strictEqual(error, null);
    });

    it('fails on one invalid signature', () => {
      // given
      const positiveVectors = testVectors.filter(vec => vec.result);
      const pubKeys = positiveVectors.map(vec => Buffer.from(vec.pk, 'hex'));
      const messages = positiveVectors.map(vec => Buffer.from(vec.m, 'hex'));
      const signatures = positiveVectors.map(vec => Buffer.from(vec.sig, 'hex'));
      const nagativeVector = testVectors.filter(vec => !vec.result)[0];
      pubKeys.push(Buffer.from(nagativeVector.pk, 'hex'));
      messages.push(Buffer.from(nagativeVector.m, 'hex'));
      signatures.push(Buffer.from(nagativeVector.sig, 'hex'));

      // when
      let result = true;
      let error = null;
      try {
        schnorr.batchVerify(pubKeys, messages, signatures);
      } catch (e) {
        result = false;
        error = e;
      }

      // then
      assert.strictEqual(result, false, error);
      assert.strictEqual(error.message, 'c is not equal to y^2');
    });
  });
});
