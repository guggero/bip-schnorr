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

function deterministicGetK0(privateKey, message) {
  check.checkSignParams(privateKey, message);

  const h = convert.hash(concat([convert.intToBuffer(privateKey), message]));
  const i = convert.bufferToInt(h);
  const k0 = i.mod(n);
  return k0;
}

function getK(R, k0) {
  if (R.affineY.and(one).equals(zero)) {
    return k0;
  } else {
    return n.subtract(k0);
  }
}

function getE(Rx, P, m) {
  return convert.bufferToInt(
    taggedHash('BIP0340/challenge', concat([Rx, convert.pointToBuffer(P), m]))
  ).mod(n);
}

function getR(s, e, P) {
  const sG = G.multiply(s);
  const eP = P.multiply(e);
  return sG.add(eP.negate());
}

function taggedHash (tag, msg) {
  let tagHash = convert.hash(tag);
  return convert.hash(concat([tagHash, tagHash, Buffer.from(msg)]));
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
  getK,
  getE,
  getR,
  taggedHash,
  randomA,
};
