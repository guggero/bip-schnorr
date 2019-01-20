/* global describe, it, beforeEach */
const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const bipSchnorr = require('../src/bip-schnorr');
const randomBytes = require('random-bytes');
const ecurve = require('ecurve');

const curve = ecurve.getCurveByName('secp256k1');
const G = curve.G;
const n = curve.n;

const NUM_RANDOM_TESTS = 64;
const RANDOM_TEST_TIMEOUT = 20000;

describe('random tests', () => {
  describe('verify', () => {
    it('can verify ' + NUM_RANDOM_TESTS + ' random messages with random keys', (done) => {
      // given
      const privateKeys = [];
      const pubKeys = [];
      const messages = [];
      for (let i = 0; i < NUM_RANDOM_TESTS; i++) {
        const d = BigInteger.fromBuffer(Buffer.from(randomBytes.sync(32))).mod(n);
        const pubKey = G.multiply(d).getEncoded(true);
        const message = Buffer.from(randomBytes.sync(32));
        privateKeys.push(d);
        pubKeys.push(pubKey);
        messages.push(message);
      }

      // when / then
      for (let i = 0; i < NUM_RANDOM_TESTS; i++) {
        let result = true;
        let error = null;
        const signature = bipSchnorr.sign(privateKeys[i], messages[i]);
        try {
          bipSchnorr.verify(pubKeys[i], messages[i], signature);
        } catch (e) {
          result = false;
          error = e;
        }

        // then
        assert.strictEqual(result, true, error);
        assert.strictEqual(error, null);
      }
      done();
    }).timeout(RANDOM_TEST_TIMEOUT);
  });

  describe('batchVerify', () => {
    it('can batch verify ' + NUM_RANDOM_TESTS + ' random messages and signatures', (done) => {
      // given
      const pubKeys = [];
      const messages = [];
      const signatures = [];
      for (let i = 0; i < NUM_RANDOM_TESTS; i++) {
        const d = BigInteger.fromBuffer(Buffer.from(randomBytes.sync(32))).mod(n);
        const pubKey = G.multiply(d).getEncoded(true);
        const message = Buffer.from(randomBytes.sync(32));
        const signature = bipSchnorr.sign(d, message);
        pubKeys.push(pubKey);
        messages.push(message);
        signatures.push(signature);
      }

      // when
      let result = true;
      let error = null;
      try {
        bipSchnorr.batchVerify(pubKeys, messages, signatures);
      } catch (e) {
        result = false;
        error = e;
      }

      // then
      assert.strictEqual(result, true, error);
      assert.strictEqual(error, null);
      done();
    }).timeout(RANDOM_TEST_TIMEOUT);
  });

  describe('aggregateSignatures', () => {
    for (let i = 1; i <= NUM_RANDOM_TESTS / 2; i++) {
      it('can aggregate signatures of two random private keys over same message, run #' + i, () => {
        // given
        const d1 = BigInteger.fromBuffer(Buffer.from(randomBytes.sync(32))).mod(n);
        const d2 = BigInteger.fromBuffer(Buffer.from(randomBytes.sync(32))).mod(n);
        const pubKey1 = G.multiply(d1);
        const pubKey2 = G.multiply(d2);
        const message = Buffer.from(randomBytes.sync(32));
        const signature = bipSchnorr.aggregateSignatures([d1, d2], message);

        // when
        let result = true;
        let error = null;
        try {
          bipSchnorr.verify(pubKey1.add(pubKey2).getEncoded(true), message, signature);
        } catch (e) {
          result = false;
          error = e;
        }

        // then
        assert.strictEqual(result, true, error);
        assert.strictEqual(error, null);
      });
    }

    for (let i = 1; i <= NUM_RANDOM_TESTS / 8; i++) {
      const message = Buffer.from(randomBytes.sync(32));

      it('can aggregate signatures of ' + NUM_RANDOM_TESTS + ' random private keys over the same message, run #' + i, (done) => {
        // given
        const privateKeys = [];
        let sumPubKey = null;
        for (let i = 0; i < NUM_RANDOM_TESTS; i++) {
          const d = BigInteger.fromBuffer(Buffer.from(randomBytes.sync(32))).mod(n);
          const P = G.multiply(d);
          if (i === 0) {
            sumPubKey = P;
          } else {
            sumPubKey = sumPubKey.add(P);
          }
          privateKeys.push(d);
        }
        const signature = bipSchnorr.aggregateSignatures(privateKeys, message);

        // when
        let result = true;
        let error = null;
        try {
          bipSchnorr.verify(sumPubKey.getEncoded(true), message, signature);
        } catch (e) {
          result = false;
          error = e;
        }

        // then
        assert.strictEqual(result, true, error);
        assert.strictEqual(error, null);

        done();
      }).timeout(RANDOM_TEST_TIMEOUT);
    }
  });
});
