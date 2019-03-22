const assert = require('assert');
const convert = require('../src/convert');
const Buffer = require('safe-buffer').Buffer;
const chacha20 = require('../src/scalar-chacha20');

const testVectors = require('./test-vectors-scalar-chacha20.json');

describe('scalarChacha20', () => {
  testVectors.forEach(vec => {
    it('should get expected value for seed ' + vec.seed + ' and index ' + vec.index, () => {
      // given
      const seed = Buffer.from(vec.seed, 'hex');

      // when
      const result = chacha20.seedToScalarValues(seed, vec.index);

      // then
      assert.strictEqual(Buffer.concat(result.map(convert.intToBuffer)).toString('hex'), vec.result);
    });
  });
});
