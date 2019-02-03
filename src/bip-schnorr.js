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
  const Rx = convert.intToBuffer(R.affineX);
  const e = getE(Rx, P, message);
  return concat([Rx, convert.intToBuffer(k.add(e.multiply(privateKey)).mod(n))]);
}

function verify(pubKey, message, signature) {
  check.checkVerifyParams(pubKey, message, signature);

  // https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#verification
  const P = convert.pubKeyToPoint(pubKey);
  const r = convert.bufferToInt(signature.slice(0, 32));
  const s = convert.bufferToInt(signature.slice(32, 64));
  check.checkSignatureInput(r, s);
  const e = convert.bufferToInt(convert.hash(concat([convert.intToBuffer(r), convert.pointToBuffer(P), message]))).mod(n);
  const sG = G.multiply(s);
  const eP = P.multiply(e);
  const R = sG.add(eP.negate());
  if (curve.isInfinity(R) || jacobi(R.affineY) !== 1 || !R.affineX.equals(r)) {
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
    const e = getE(convert.intToBuffer(r), P, messages[i]);
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

function naiveKeyAggregation(privateKeys, message) {
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
  const Rx = convert.intToBuffer(R.affineX);
  let e = getE(Rx, P, message);
  let s = zero;
  for (let i = 0; i < k0s.length; i++) {
    const k = getK(R, k0s[i]);
    s = s.add(k.add(e.multiply(privateKeys[i])));
  }
  return concat([Rx, convert.intToBuffer(s.mod(n))]);
}

function muSigNonInteractive(privateKeys, message) {
  if (!privateKeys || !privateKeys.length) {
    throw new Error('privateKeys must be an array with one or more elements');
  }

  // https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures/
  const rs = [];
  const Xs = [];
  let R = null;
  for (let privateKey of privateKeys) {
    const ri = deterministicGetK0(privateKey, message);
    const Ri = G.multiply(ri);
    const Xi = G.multiply(privateKey);
    rs.push(ri);
    Xs.push(Xi);
    if (R === null) {
      R = Ri;
    } else {
      R = R.add(Ri);
    }
  }
  const L = convert.hash(concat(Xs.map(convert.pointToBuffer)));
  const as = [];
  let X = null;
  for (let Xi of Xs) {
    const a = convert.bufferToInt(convert.hash(concat([L, convert.pointToBuffer(Xi)])));
    const summand = Xi.multiply(a);
    as.push(a);
    if (X === null) {
      X = summand;
    } else {
      X = X.add(summand);
    }
  }

  let Rx = convert.intToBuffer(R.affineX);
  let e = getE(Rx, X, message);
  let s = zero;
  for (let i = 0; i < rs.length; i++) {
    const ri = getK(R, rs[i]);
    s = s.add(ri.add(e.multiply(as[i]).multiply(privateKeys[i])).mod(n));
  }
  return concat([Rx, convert.intToBuffer(s.mod(n))]);
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
  check.checkRange(privateKey);

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

function randomA() {
  let a = null;
  for (; ;) {
    a = convert.bufferToInt(Buffer.from(randomBytes.sync(32)));
    try {
      check.checkRange(a);
      return a;
    } catch (e) {
      // out of range, generate another one
    }
  }
}

module.exports = {
  sign,
  verify,
  batchVerify,
  naiveKeyAggregation,
  muSigNonInteractive,
};
