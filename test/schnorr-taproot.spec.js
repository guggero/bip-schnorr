/* global describe, it, beforeEach */
const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const ecurve = require('ecurve');
const taproot = require('../src/taproot');

const curve = ecurve.getCurveByName('secp256k1');
const n = curve.n;

function assertError(error, expectedMessage) {
  assert.strictEqual(error.message, expectedMessage);
}

describe('taproot', () => {
  describe('taprootConstruct', () => {
    it('can create a tweaked taproot key BIP86 test vector 1', () => {
      // given
      const pubKeyBuffer = Buffer.from('03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115', 'hex');
      const pubKey = ecurve.Point.decodeFrom(curve, pubKeyBuffer);

      // when
      const result = taproot.taprootConstruct(pubKey);

      // then
      assert.strictEqual(result.toString('hex'), 'a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c');
    });
    it('can create a tweaked taproot key BIP86 test vector 2', () => {
      // given
      const pubKeyBuffer = Buffer.from('0283dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145', 'hex');
      const pubKey = ecurve.Point.decodeFrom(curve, pubKeyBuffer);

      // when
      const result = taproot.taprootConstruct(pubKey);

      // then
      assert.strictEqual(result.toString('hex'), 'a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb');
    });
    it('can create a tweaked taproot key BIP86 test vector 3', () => {
      // given
      const pubKeyBuffer = Buffer.from('02399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef', 'hex');
      const pubKey = ecurve.Point.decodeFrom(curve, pubKeyBuffer);

      // when
      const result = taproot.taprootConstruct(pubKey);

      // then
      assert.strictEqual(result.toString('hex'), '882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc');
    });
  });
});
