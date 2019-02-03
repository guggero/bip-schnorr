const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const sha256 = require('js-sha256');
const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');

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
  if (pubKey.length !== 33) {
    throw new Error('pubKey must be 33 bytes long');
  }
  const pubKeyEven = (pubKey[0] - 0x02) === 0;
  const x = bufferToInt(pubKey.slice(1, 33));
  const P = curve.pointFromX(!pubKeyEven, x);
  if (curve.isInfinity(P)) {
    throw new Error('point is at infinity');
  }
  const pEven = P.affineY.isEven();
  if (pubKeyEven !== pEven) {
    throw new Error('point does not exist');
  }
  return P;
}

module.exports = {
  bufferToInt,
  intToBuffer,
  hash,
  pointToBuffer,
  pubKeyToPoint,
};
