const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const sha256 = require('js-sha256');

function bufferToInt(buffer) {
  return BigInteger.fromBuffer(buffer);
}

function intToBuffer(bigInteger) {
  return bigInteger.toBuffer(32);
}

function hash(buffer) {
  return Buffer.from(sha256.create().update(buffer).array());
}

module.exports = {
  bufferToInt,
  intToBuffer,
  hash,
};
