/* global describe, it, beforeEach */
const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const convert = require('../src/convert');
const muSig = require('../src/mu-sig');
const ecurve = require('ecurve');

const curve = ecurve.getCurveByName('secp256k1');
const G = curve.G;

const testVectors = require('./test-vectors-mu-sig.json');

describe('muSig', () => {
  describe('pubKeyCombine', () => {
    testVectors.forEach(vec => {
      it('can combine public keys into ' + vec.combined, () => {
        // given
        const pubKeys = vec.pubKeys.map(pk => Buffer.from(pk, 'hex'));

        // when
        const result = muSig.pubKeyCombine(pubKeys);

        // then
        assert.strictEqual(convert.pointToBuffer(result).toString('hex'), vec.combined);
      });
    });
  });

  describe('sessionInitialize', () => {
    testVectors
      .filter(vec => vec.privKeys)
      .forEach(vec => {
        it('can initialize session for combined key ' + vec.combined, () => {
          // given
          const combined = Buffer.from(vec.combined, 'hex');
          const pubKeys = vec.pubKeys.map(pk => Buffer.from(pk, 'hex'));
          const ell = muSig.computeEll(pubKeys);
          const message = Buffer.from(vec.message, 'hex');

          // when / then
          for (let i = 0; i < vec.privKeys.length; i++) {
            const sessionId = Buffer.from(vec.sessionIds[i], 'hex');
            const privateKey = BigInteger.fromHex(vec.privKeys[i]);
            const session = muSig.sessionInitialize(sessionId, privateKey, message, combined, ell, i);

            assert.strictEqual(session.commitment.toString('hex'), vec.commitments[i]);
          }
        });
      });
  });
});
