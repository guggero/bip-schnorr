const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const ecurve = require('ecurve');
const sha256 = require('js-sha256');
const randomBytes = require('random-bytes');

const curve = ecurve.getCurveByName('secp256k1');
const G = curve.G;
const p = curve.p;
const n = curve.n;
const VERSION = 'v0.1.0';
const zero = BigInteger.ZERO;
const one = BigInteger.ONE;
const two = BigInteger.valueOf(2);
const three = BigInteger.valueOf(3);
const four = BigInteger.valueOf(4);
const seven = BigInteger.valueOf(7);

function sign(privateKey, message) {
  // https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#signing
  const k0 = deterministicGetK0(privateKey, message);
  const R = G.multiply(k0);
  const k = getK(R, k0);
  const P = G.multiply(privateKey);
  const rX = intToBuffer(R.affineX);
  const e = getE(rX, P, message);
  return Buffer.concat([rX, intToBuffer(k.add(e.multiply(privateKey)).mod(n))]);
}

function verify(pubKey, message, signature) {
  checkVerifyParams(pubKey, message, signature);

  // https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#verification
  const P = pubKeyToPoint(pubKey);
  const r = bufferToInt(signature.slice(0, 32));
  if (r.compareTo(p) >= 0) {
    throw new Error('r is larger than or equal to field size');
  }
  const s = bufferToInt(signature.slice(32, 64));
  if (s.compareTo(n) >= 0) {
    throw new Error('s is larger than or equal to curve order');
  }
  const e = bufferToInt(hash(Buffer.concat([intToBuffer(r), pointToBuffer(P), message]))).mod(n);
  const sG = G.multiply(s);
  const eP = P.multiply(e);
  const R = sG.add(eP.negate());
  if (curve.isInfinity(R) || jacobi(R.affineY) !== 1 || !R.affineX.equals(r)) {
    throw new Error('signature verification failed');
  }
}

function batchVerify(pubKeys, messages, signatures) {
  checkBatchVerifyParams(pubKeys, messages, signatures);

  // https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#Batch_Verification
  let leftSide = zero;
  let rightSide = null;
  for (let i = 0; i < pubKeys.length; i++) {
    const P = pubKeyToPoint(pubKeys[i]);
    const r = bufferToInt(signatures[i].slice(0, 32));
    if (r.compareTo(p) >= 0) {
      throw new Error('r is larger than or equal to field size');
    }
    const s = bufferToInt(signatures[i].slice(32, 64));
    if (s.compareTo(n) >= 0) {
      throw new Error('s is larger than or equal to curve order');
    }
    const e = getE(intToBuffer(r), P, messages[i]);
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
      const a = randomA();
      leftSide = leftSide.add(a.multiply(s));
      rightSide = rightSide.add(R.multiply(a)).add(P.multiply(a.multiply(e)));
    }
  }

  if (!G.multiply(leftSide.mod(n)).equals(rightSide)) {
    throw new Error('signature verification failed');
  }
}

function aggregateSignatures(privateKeys, message) {
  if (!privateKeys || !privateKeys.length) {
    throw new Error('privateKeys must be an array with one or more elements');
  }
  const k0s = [];
  let P = null;
  let R = null;
  for (let privateKey of privateKeys) {
    const k0i = deterministicGetK0(privateKey, message);
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
  const rX = intToBuffer(R.affineX);
  let e = getE(rX, P, message);
  let s = zero;
  for (let i = 0; i < k0s.length; i++) {
    const k = getK(R, k0s[i]);
    s = s.add(k.add(e.multiply(privateKeys[i])));
  }
  return Buffer.concat([rX, intToBuffer(s.mod(n))]);
}

function deterministicGetK0(privateKey, message) {
  if (!BigInteger.isBigInteger(privateKey)) {
    throw new Error('privateKey must be a BigInteger');
  }
  if (!Buffer.isBuffer(message)) {
    throw new Error('message must be a Buffer');
  }
  if (message.length !== 32) {
    throw new Error('message must be 32 bytes long');
  }
  checkRange(privateKey);

  const concat = Buffer.concat([intToBuffer(privateKey), message]);
  const h = hash(concat);
  const i = bufferToInt(h);
  const k0 = i.mod(n);
  if (k0.signum() === 0) {
    throw new Error('k0 is zero');
  }
  return k0;
}

function jacobi(num) {
  return num.modPow(p.subtract(one).divide(two), p).intValue();
}

function getK(R, k0) {
  return jacobi(R.affineY) === 1 ? k0 : n.subtract(k0);
}

function getE(rX, P, m) {
  return bufferToInt(hash(Buffer.concat([rX, pointToBuffer(P), m]))).mod(n);
}

function checkVerifyParams(pubKey, message, signature, idx) {
  const idxStr = (idx !== undefined ? '[' + idx + ']' : '');
  if (!Buffer.isBuffer(pubKey)) {
    throw new Error('pubKey' + idxStr + ' must be a Buffer');
  }
  if (!Buffer.isBuffer(message)) {
    throw new Error('message' + idxStr + ' must be a Buffer');
  }
  if (!Buffer.isBuffer(signature)) {
    throw new Error('signature' + idxStr + ' must be a Buffer');
  }
  if (pubKey.length !== 33) {
    throw new Error('pubKey' + idxStr + ' must be 33 bytes long');
  }
  if (message.length !== 32) {
    throw new Error('message' + idxStr + ' must be 32 bytes long');
  }
  if (signature.length !== 64) {
    throw new Error('signature' + idxStr + ' must be 64 bytes long');
  }
}

function checkBatchVerifyParams(pubKeys, messages, signatures) {
  if (!pubKeys || !pubKeys.length) {
    throw new Error('pubKeys must be an array with one or more elements');
  }
  if (!messages || !messages.length) {
    throw new Error('messages must be an array with one or more elements');
  }
  if (!signatures || !signatures.length) {
    throw new Error('signatures must be an array with one or more elements');
  }
  if (pubKeys.length !== messages.length || messages.length !== signatures.length) {
    throw new Error('all parameters must be an array with the same length')
  }
  for (let i = 0; i < pubKeys.length; i++) {
    checkVerifyParams(pubKeys[i], messages[i], signatures[i], i);
  }
}

function checkRange(privateKey) {
  if (privateKey.compareTo(one) < 0 || privateKey.compareTo(n.subtract(one)) > 0) {
    throw new Error('privateKey must be an integer in the range 1..n-1')
  }
}

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

function randomA() {
  let a = null;
  for (; ;) {
    a = bufferToInt(Buffer.from(randomBytes.sync(32)));
    try {
      checkRange(a);
      return a;
    } catch (e) {
      // out of range, generate another one
    }
  }
}

module.exports = {
  VERSION,
  sign,
  verify,
  batchVerify,
  aggregateSignatures,
  pubKeyToPoint,
};
