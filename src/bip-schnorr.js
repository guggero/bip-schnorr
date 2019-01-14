const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const ecurve = require('ecurve');
const sha256 = require('js-sha256');
const jacobi = require('./jacobi');

const curve = ecurve.getCurveByName('secp256k1');
const G = curve.G;
const p = curve.p;
const n = curve.n;
const VERSION = 'v0.0.3';

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
  if (privateKey.compareTo(BigInteger.ONE) < 0 || privateKey.compareTo(n.subtract(BigInteger.ONE)) > 0) {
    throw new Error("the private key must be an integer in the range 1..n-1")
  }

  const concat = Buffer.concat([intToBuffer(privateKey), message]);
  const h = hash(concat);
  const i = bufferToInt(h);
  const k0 = i.mod(n);
  if (k0.signum() === 0) {
    throw new Error('k0 is zero');
  }
  return k0;
}

function getK(R, k0) {
  return jacobi(R.affineY, p) === 1 ? k0 : n.subtract(k0);
}

function getE(rX, P, m) {
  return bufferToInt(hash(Buffer.concat([rX, P.getEncoded(true), m]))).mod(n);
}

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
  if (!Buffer.isBuffer(pubKey)) {
    throw new Error('pubKey must be a Buffer');
  }
  if (!Buffer.isBuffer(message)) {
    throw new Error('message must be a Buffer');
  }
  if (!Buffer.isBuffer(signature)) {
    throw new Error('signature must be a Buffer');
  }
  if (pubKey.length !== 33) {
    throw new Error('public key must be 33 bytes long');
  }
  if (message.length !== 32) {
    throw new Error('message must be 32 bytes long');
  }
  if (signature.length !== 64) {
    throw new Error('signature must be 64 bytes long');
  }

  // https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#verification
  const P = pubKeyToPoint(pubKey);
  const r = BigInteger.fromBuffer(signature.slice(0, 32));
  if (r.compareTo(p) >= 0) {
    throw new Error('r is larger than or equal to field size');
  }
  const s = BigInteger.fromBuffer(signature.slice(32, 64));
  if (s.compareTo(n) >= 0) {
    throw new Error('s is larger than or equal to curve order');
  }
  const e = bufferToInt(hash(Buffer.concat([intToBuffer(r), P.getEncoded(true), message]))).mod(n);
  const sG = G.multiply(s);
  const eP = P.multiply(e);
  const R = sG.add(eP.negate());
  if (curve.isInfinity(R) || jacobi(R.affineY, p) !== 1 || !R.affineX.equals(r)) {
    throw new Error('signature verification failed');
  }
}

function aggregateSignatures(privateKeys, message) {
  if (!privateKeys || !privateKeys.length) {
    throw new Error('privateKeys must be an array with one or more elements');
  }
  const k0s = [];
  const Rs = [];
  let P = null;
  let R = null;
  for (let privateKey of privateKeys) {
    const k0i = deterministicGetK0(privateKey, message);
    const Ri = G.multiply(k0i);
    const Pi = G.multiply(privateKey);
    k0s.push(k0i);
    Rs.push(Ri);
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
  let s = BigInteger.ZERO;
  for (let i = 0; i < k0s.length; i++) {
    s = s.add(getK(Rs[i], k0s[i]).add(e.multiply(privateKeys[i]))).mod(n);
  }
  return Buffer.concat([rX, intToBuffer(s)]);
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

function pubKeyToPoint(pubKey) {
  if (pubKey.length !== 33) {
    throw new Error('pubKey must be 33 bytes long');
  }
  const pubKeyEven = (pubKey[0] - 0x02) === 0;
  const x = BigInteger.fromBuffer(pubKey.slice(1, 33));
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
  VERSION,
  sign,
  verify,
  aggregateSignatures,
  pubKeyToPoint,
};
