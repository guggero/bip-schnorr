/* global describe, it, beforeEach */
const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const schnorr = require('../src/schnorr');
const convert = require('../src/convert');
const randomBytes = require('randombytes');
const ecurve = require('ecurve');

const curve = ecurve.getCurveByName('secp256k1');
const G = curve.G;
const n = curve.n;

const NUM_RANDOM_TESTS = 64;
const RANDOM_TEST_TIMEOUT = 20000;

const randomInt = (len) => BigInteger.fromBuffer(Buffer.from(randomBytes(len))).mod(n);
const randomBuffer = (len) => Buffer.from(randomBytes(len));

describe('random tests', () => {
  describe('verify', () => {
    it('can verify ' + NUM_RANDOM_TESTS + ' random messages with random keys', (done) => {
      // given
      const privateKeys = [];
      const pubKeys = [];
      const messages = [];
      for (let i = 0; i < NUM_RANDOM_TESTS; i++) {
        const d = randomInt(32);
        const pubKey = convert.intToBuffer(G.multiply(d).affineX);
        const message = randomBuffer(32);
        privateKeys.push(d);
        pubKeys.push(pubKey);
        messages.push(message);
      }

      // when / then
      for (let i = 0; i < NUM_RANDOM_TESTS; i++) {
        let result = true;
        let error = null;
        const signature = schnorr.sign(privateKeys[i], messages[i]);
        try {
          schnorr.verify(pubKeys[i], messages[i], signature);
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
        const d = randomInt(32);
        const pubKey = convert.intToBuffer(G.multiply(d).affineX);
        const message = randomBuffer(32);
        const signature = schnorr.sign(d, message);
        pubKeys.push(pubKey);
        messages.push(message);
        signatures.push(signature);
      }

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
      done();
    }).timeout(RANDOM_TEST_TIMEOUT);
  });
});
