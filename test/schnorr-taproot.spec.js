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
    it('can create a tweaked taproot key', () => {
      // given
      const pubKeyBuffer = Buffer.from('03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115', 'hex');
      const pubKey = ecurve.Point.decodeFrom(curve, pubKeyBuffer);

      // when
      const result = taproot.taprootConstruct(pubKey);

      // then
      assert.strictEqual(result.toString('hex'), '7f82c3db962c880194eac332057b4e78d290e19d887e11e600ac846696666e05');
    });
  });
});
