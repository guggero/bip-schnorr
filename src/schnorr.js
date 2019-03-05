const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');
const math = require('./math');
const check = require('./check');
const convert = require('./convert');

const concat = Buffer.concat;
const G = curve.G;
const p = curve.p;
const n = curve.n;
const zero = BigInteger.ZERO;
const one = BigInteger.ONE;
const two = BigInteger.valueOf(2);
const three = BigInteger.valueOf(3);
const four = BigInteger.valueOf(4);
const seven = BigInteger.valueOf(7);

function sign(privateKey, message) {
  // https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#signing
  const k0 = math.deterministicGetK0(privateKey, message);
  const R = G.multiply(k0);
  const k = math.getK(R, k0);
  const P = G.multiply(privateKey);
  const Rx = convert.intToBuffer(R.affineX);
  const e = math.getE(Rx, P, message);
  return concat([Rx, convert.intToBuffer(k.add(e.multiply(privateKey)).mod(n))]);
}

function verify(pubKey, message, signature) {
  check.checkVerifyParams(pubKey, message, signature);

  // https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#verification
  const P = convert.pubKeyToPoint(pubKey);
  const r = convert.bufferToInt(signature.slice(0, 32));
  const s = convert.bufferToInt(signature.slice(32, 64));
  check.checkSignatureInput(r, s);
  const e = math.getE(convert.intToBuffer(r), P, message);
  const R = math.getR(s, e, P);
  if (R.curve.isInfinity(R) || math.jacobi(R.affineY) !== 1 || !R.affineX.equals(r)) {
    throw new Error('signature verification failed');
  }
}

function batchVerify(pubKeys, messages, signatures) {
  check.checkBatchVerifyParams(pubKeys, messages, signatures);

  // https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#Batch_Verification
  let leftSide = zero;
  let rightSide = null;
  for (let i = 0; i < pubKeys.length; i++) {
    const P = convert.pubKeyToPoint(pubKeys[i]);
    const r = convert.bufferToInt(signatures[i].slice(0, 32));
    const s = convert.bufferToInt(signatures[i].slice(32, 64));
    check.checkSignatureInput(r, s);
    const e = math.getE(convert.intToBuffer(r), P, messages[i]);
    const c = r.pow(three).add(seven).mod(p);
    const y = c.modPow(p.add(one).divide(four), p);
    if (c.compareTo(y.modPow(two, p)) !== 0) {
      throw new Error('c is not equal to y^2');
    }
    const R = ecurve.Point.fromAffine(curve, r, y);

    if (i === 0) {
      leftSide = leftSide.add(s);
      rightSide = R.add(P.multiply(e));
    } else {
      const a = math.randomA();
      leftSide = leftSide.add(a.multiply(s));
      rightSide = rightSide.add(R.multiply(a)).add(P.multiply(a.multiply(e)));
    }
  }

  if (!G.multiply(leftSide.mod(n)).equals(rightSide)) {
    throw new Error('signature verification failed');
  }
}

function naiveKeyAggregation(privateKeys, message) {
  if (!privateKeys || !privateKeys.length) {
    throw new Error('privateKeys must be an array with one or more elements');
  }
  const k0s = [];
  let P = null;
  let R = null;
  for (let privateKey of privateKeys) {
    const k0i = math.deterministicGetK0(privateKey, message);
    const Ri = G.multiply(k0i);
    const Pi = G.multiply(privateKey);
    k0s.push(k0i);
    if (R === null) {
      R = Ri;
      P = Pi;
    } else {
      R = R.add(Ri);
      P = P.add(Pi);
    }
  }
  const Rx = convert.intToBuffer(R.affineX);
  let e = math.getE(Rx, P, message);
  let s = zero;
  for (let i = 0; i < k0s.length; i++) {
    const k = math.getK(R, k0s[i]);
    s = s.add(k.add(e.multiply(privateKeys[i])));
  }
  return concat([Rx, convert.intToBuffer(s.mod(n))]);
}

module.exports = {
  sign,
  verify,
  batchVerify,
  naiveKeyAggregation,
};
