const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const sha256 = require('js-sha256');
const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');
const check = require('./check');

const G = curve.G;

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
  return point.getEncoded(true).slice(1);
}

function pubKeyToPoint(pubKey) {
  const x = bufferToInt(pubKey);
  const P = curve.pointFromX(false, x);
  check.checkPointExists(true, P);
  return P;
}

function pubKeyFromPrivate(privateKey) {
  return pointToBuffer(G.multiply(privateKey));
}

module.exports = {
  bufferToInt,
  intToBuffer,
  hash,
  pointToBuffer,
  pubKeyToPoint,
  pubKeyFromPrivate
};
