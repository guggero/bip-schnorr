const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const ecurve = require('ecurve');
const randomBytes = require('randombytes');
const curve = ecurve.getCurveByName('secp256k1');
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

function deterministicGetK0(privateKey, message) {
  check.checkSignParams(privateKey, message);

  const h = convert.hash(concat([convert.intToBuffer(privateKey), message]));
  const i = convert.bufferToInt(h);
  return i.mod(n);
}

function isEven(pubKey) {
  return pubKey.affineY.mod(two).equals(zero);
}

function getEvenKey(pubKey, privateKey) {
  if (isEven(pubKey)) {
    return privateKey.clone();
  }

  return n.subtract(privateKey);
}

function jacobi(num) {
  return num.modPow(p.subtract(one).divide(two), p).intValue();
}

function jacobiPoint(point) {
  const jacobiCheckInt = point.y.multiply(point.z).mod(p); // optimization over point.affineY
  return jacobi(jacobiCheckInt);
}

function getK(R, k0) {
  return jacobiPoint(R) === 1 ? k0 : n.subtract(k0);
}

function getE(Rx, P, m) {
  const hash = convert.hash(concat([Rx, convert.pointToBuffer(P), m]));
  return convert.bufferToInt(hash).mod(n);
}

function bip340GetE(Rx, Px, m) {
  const hash = taggedHash('BIP0340/challenge', concat([Rx, Px, m]));
  return convert.bufferToInt(hash).mod(n);
}

function getR(s, e, P) {
  const sG = G.multiply(s);
  const eP = P.multiply(e);
  return sG.add(eP.negate());
}

function taggedHash(tag, msg) {
  const tagHash = convert.hash(tag);
  return convert.hash(concat([tagHash, tagHash, Buffer.from(msg)]));
}

function liftX(Px) {
  const x = convert.bufferToInt(Px);

  const c = x.pow(three).add(seven).mod(p);
  const y = c.modPow(p.add(one).divide(four), p);
  if (c.compareTo(y.modPow(two, p)) !== 0) {
    throw new Error('c is not equal to y^2');
  }
  let P = ecurve.Point.fromAffine(curve, x, y);
  if (!isEven(P)) {
    P = ecurve.Point.fromAffine(curve, x, p.subtract(y));
  }

  check.checkPointExists(true, P);
  return P;
}

function randomA() {
  let a = null;
  for (; ;) {
    a = convert.bufferToInt(Buffer.from(randomBytes(32)));
    try {
      check.checkRange('a', a);
      return a;
    } catch (e) {
      // out of range, generate another one
    }
  }
}

module.exports = {
  deterministicGetK0,
  isEven,
  getEvenKey,
  jacobi,
  getK,
  getE,
  bip340GetE,
  getR,
  taggedHash,
  liftX,
  randomA,
};
