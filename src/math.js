const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const ecurve = require('ecurve');
const randomBytes = require('random-bytes');
const curve = ecurve.getCurveByName('secp256k1');
const check = require('./check');
const convert = require('./convert');

const concat = Buffer.concat;
const G = curve.G;
const p = curve.p;
const n = curve.n;
const one = BigInteger.ONE;
const two = BigInteger.valueOf(2);

function deterministicGetK0(privateKey, message) {
  check.checkSignParams(privateKey, message);

  const h = convert.hash(concat([convert.intToBuffer(privateKey), message]));
  const i = convert.bufferToInt(h);
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

function getE(Rx, P, m) {
  return convert.bufferToInt(convert.hash(concat([Rx, convert.pointToBuffer(P), m]))).mod(n);
}

function getR(s, e, P) {
  const sG = G.multiply(s);
  const eP = P.multiply(e);
  return sG.add(eP.negate());
}

function randomA() {
  let a = null;
  for (; ;) {
    a = convert.bufferToInt(Buffer.from(randomBytes.sync(32)));
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
  jacobi,
  getK,
  getE,
  getR,
  randomA,
};
