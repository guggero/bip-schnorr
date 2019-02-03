const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const sha256 = require('js-sha256');
const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');
const check = require('./check');

function bufferToInt(buffer) {
  return BigInteger.fromBuffer(buffer);
}

function intToBuffer(bigInteger) {
  return bigInteger.toBuffer(32);
}

function hash(buffer) {
  return Buffer.from(sha256.create().update(buffer).array());
}

function pointToBuffer(point) {
  return point.getEncoded(true);
}

function pubKeyToPoint(pubKey) {
  const pubKeyEven = (pubKey[0] - 0x02) === 0;
  const x = bufferToInt(pubKey.slice(1, 33));
  const P = curve.pointFromX(!pubKeyEven, x);
  check.checkPointExists(pubKeyEven, P);
  return P;
}

module.exports = {
  bufferToInt,
  intToBuffer,
  hash,
  pointToBuffer,
  pubKeyToPoint,
};
