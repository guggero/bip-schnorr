/* global describe, it, beforeEach */
const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const bipSchnorr = require('../src/bip-schnorr');
const ecurve = require('ecurve');

const curve = ecurve.getCurveByName('secp256k1');
const n = curve.n;

const testVectors = require('./test-vectors.json');

function assertError(error, expectedMessage) {
  assert.strictEqual(error.message, expectedMessage);
}

describe('edge cases', () => {
  const positiveTestVectors = testVectors.filter(vec => vec.result);
  const vec = positiveTestVectors[0];
  const pk = Buffer.from(vec.pk, 'hex');
  const m = Buffer.from(vec.m, 'hex');
  const sig = Buffer.from(vec.sig, 'hex');

  describe('sign', () => {
    it('can check sign params', () => {
      try { bipSchnorr.sign(BigInteger.valueOf(0), m); } catch (e) { assertError(e, 'privateKey must be an integer in the range 1..n-1'); }
      try { bipSchnorr.sign(n, m); } catch (e) { assertError(e, 'privateKey must be an integer in the range 1..n-1'); }
    });
  });

  describe('verify', () => {
    it('can check verify params', () => {
      // when / then
      try { bipSchnorr.verify('foo', m, sig); } catch (e) { assertError(e, 'pubKey must be a Buffer'); }
      try { bipSchnorr.verify(pk, 'foo', sig); } catch (e) { assertError(e, 'message must be a Buffer'); }
      try { bipSchnorr.verify(pk, m, 'foo'); } catch (e) { assertError(e, 'signature must be a Buffer'); }
      try { bipSchnorr.verify(pk, m.slice(0, 16), sig); } catch (e) { assertError(e, 'message must be 32 bytes long'); }
      try { bipSchnorr.verify(pk, m, sig.slice(32)); } catch (e) { assertError(e, 'signature must be 64 bytes long'); }
      try { bipSchnorr.verify(pk.slice(16), m, sig); } catch (e) { assertError(e, 'pubKey must be 33 bytes long'); }
    });
  });

  describe('batchVerify', () => {
    it('can check batch verify params', () => {
      // when / then
      try { bipSchnorr.batchVerify([], [m], [sig]); } catch (e) { assertError(e, 'pubKeys must be an array with one or more elements'); }
      try { bipSchnorr.batchVerify([pk], [], [sig]); } catch (e) { assertError(e, 'messages must be an array with one or more elements'); }
      try { bipSchnorr.batchVerify([pk], [m], []); } catch (e) { assertError(e, 'signatures must be an array with one or more elements'); }
      try { bipSchnorr.batchVerify([pk], [m], [sig, sig]); } catch (e) { assertError(e, 'all parameters must be an array with the same length'); }
      try { bipSchnorr.batchVerify([pk], [m, m], [sig, sig]); } catch (e) { assertError(e, 'all parameters must be an array with the same length'); }
      try { bipSchnorr.batchVerify([pk, pk], [m, m], [sig]); } catch (e) { assertError(e, 'all parameters must be an array with the same length'); }

      try { bipSchnorr.batchVerify(['foo'], [m], [sig]); } catch (e) { assertError(e, 'pubKey[0] must be a Buffer'); }
      try { bipSchnorr.batchVerify([pk], ['foo'], [sig]); } catch (e) { assertError(e, 'message[0] must be a Buffer'); }
      try { bipSchnorr.batchVerify([pk], [m], ['foo']); } catch (e) { assertError(e, 'signature[0] must be a Buffer'); }
      try { bipSchnorr.batchVerify([pk], [m.slice(0, 16)], [sig]); } catch (e) { assertError(e, 'message[0] must be 32 bytes long'); }
      try { bipSchnorr.batchVerify([pk], [m], [sig.slice(32)]); } catch (e) { assertError(e, 'signature[0] must be 64 bytes long'); }
    });
  });

  describe('naiveKeyAggregation', () => {
    it('can check parameters', () => {
      // when / then
      try { bipSchnorr.naiveKeyAggregation(null, m); } catch (e) { assertError(e, 'privateKeys must be an array with one or more elements'); }
      try { bipSchnorr.naiveKeyAggregation([], m); } catch (e) { assertError(e, 'privateKeys must be an array with one or more elements'); }
    });
  });

  describe('muSigNonInteractive', () => {
    it('can check parameters', () => {
      // when / then
      try { bipSchnorr.muSigNonInteractive(null, m); } catch (e) { assertError(e, 'privateKeys must be an array with one or more elements'); }
      try { bipSchnorr.muSigNonInteractive([], m); } catch (e) { assertError(e, 'privateKeys must be an array with one or more elements'); }
    });
  });
});
