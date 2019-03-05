/* global describe, it, beforeEach */
const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const schnorr = require('../src/schnorr');
const muSig = require('../src/mu-sig');
const ecurve = require('ecurve');

const curve = ecurve.getCurveByName('secp256k1');
const n = curve.n;

const testVectors = require('./test-vectors-schnorr.json');

function assertError(error, expectedMessage) {
  assert.strictEqual(error.message, expectedMessage);
}

describe('edge cases', () => {
  const positiveTestVectors = testVectors.filter(vec => vec.result);
  const vec = positiveTestVectors[0];
  const pubKey = Buffer.from(vec.pk, 'hex');
  const m = Buffer.from(vec.m, 'hex');
  const sig = Buffer.from(vec.sig, 'hex');

  describe('sign', () => {
    it('can check sign params', () => {
      try { schnorr.sign('foo', m); } catch (e) { assertError(e, 'privateKey must be a BigInteger'); }
      try { schnorr.sign(BigInteger.valueOf(1), 'foo'); } catch (e) { assertError(e, 'message must be a Buffer'); }
      try { schnorr.sign(BigInteger.valueOf(1), Buffer.from([])); } catch (e) { assertError(e, 'message must be 32 bytes long'); }
      try { schnorr.sign(BigInteger.valueOf(0), m); } catch (e) { assertError(e, 'privateKey must be an integer in the range 1..n-1'); }
      try { schnorr.sign(BigInteger.valueOf(0), m); } catch (e) { assertError(e, 'privateKey must be an integer in the range 1..n-1'); }
      try { schnorr.sign(n, m); } catch (e) { assertError(e, 'privateKey must be an integer in the range 1..n-1'); }
    });
  });

  describe('verify', () => {
    it('can check verify params', () => {
      // when / then
      try { schnorr.verify('foo', m, sig); } catch (e) { assertError(e, 'pubKey must be a Buffer'); }
      try { schnorr.verify(Buffer.from([]), m, sig); } catch (e) { assertError(e, 'pubKey must be 33 bytes long'); }
      try { schnorr.verify(pubKey, 'foo', sig); } catch (e) { assertError(e, 'message must be a Buffer'); }
      try { schnorr.verify(pubKey, m, 'foo'); } catch (e) { assertError(e, 'signature must be a Buffer'); }
      try { schnorr.verify(pubKey, m.slice(0, 16), sig); } catch (e) { assertError(e, 'message must be 32 bytes long'); }
      try { schnorr.verify(pubKey, m, sig.slice(32)); } catch (e) { assertError(e, 'signature must be 64 bytes long'); }
      try { schnorr.verify(pubKey.slice(16), m, sig); } catch (e) { assertError(e, 'pubKey must be 33 bytes long'); }
    });
  });

  describe('batchVerify', () => {
    it('can check batch verify params', () => {
      // when / then
      try { schnorr.batchVerify([], [m], [sig]); } catch (e) { assertError(e, 'pubKeys must be an array with one or more elements'); }
      try { schnorr.batchVerify([pubKey], [], [sig]); } catch (e) { assertError(e, 'messages must be an array with one or more elements'); }
      try { schnorr.batchVerify([pubKey], [m], []); } catch (e) { assertError(e, 'signatures must be an array with one or more elements'); }
      try { schnorr.batchVerify([pubKey], [m], [sig, sig]); } catch (e) { assertError(e, 'all parameters must be an array with the same length'); }
      try { schnorr.batchVerify([pubKey], [m, m], [sig, sig]); } catch (e) { assertError(e, 'all parameters must be an array with the same length'); }
      try { schnorr.batchVerify([pubKey, pubKey], [m, m], [sig]); } catch (e) { assertError(e, 'all parameters must be an array with the same length'); }

      try { schnorr.batchVerify(['foo'], [m], [sig]); } catch (e) { assertError(e, 'pubKey[0] must be a Buffer'); }
      try { schnorr.batchVerify([pubKey], ['foo'], [sig]); } catch (e) { assertError(e, 'message[0] must be a Buffer'); }
      try { schnorr.batchVerify([pubKey], [m], ['foo']); } catch (e) { assertError(e, 'signature[0] must be a Buffer'); }
      try { schnorr.batchVerify([pubKey], [m.slice(0, 16)], [sig]); } catch (e) { assertError(e, 'message[0] must be 32 bytes long'); }
      try { schnorr.batchVerify([pubKey], [m], [sig.slice(32)]); } catch (e) { assertError(e, 'signature[0] must be 64 bytes long'); }
    });
  });

  describe('naiveKeyAggregation', () => {
    it('can check parameters', () => {
      // when / then
      try { schnorr.naiveKeyAggregation(null, m); } catch (e) { assertError(e, 'privateKeys must be an array with one or more elements'); }
      try { schnorr.naiveKeyAggregation([], m); } catch (e) { assertError(e, 'privateKeys must be an array with one or more elements'); }
    });
  });

  describe('muSig.nonInteractive', () => {
    it('can check parameters', () => {
      // when / then
      try { muSig.nonInteractive(null, m); } catch (e) { assertError(e, 'privateKeys must be an array with one or more elements'); }
      try { muSig.nonInteractive([], m); } catch (e) { assertError(e, 'privateKeys must be an array with one or more elements'); }
    });
  });
});
