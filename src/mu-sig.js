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
const MUSIG_TAG = convert.hash(Buffer.from('MuSig coefficient'));

// Computes ell = SHA256(pubKeys[0], ..., pubKeys[pubKeys.length-1]) with
// pubKeys serialized in compressed form.
function computeEll(pubKeys) {
  check.checkPubKeyArr(pubKeys);
  return convert.hash(concat(pubKeys))
}

function computeCoefficient(ell, idx) {
  const idxBuf = Buffer.alloc(4);
  idxBuf.writeUInt32LE(idx);
  const data = concat([MUSIG_TAG, MUSIG_TAG, ell, idxBuf]);
  return convert.bufferToInt(convert.hash(data)).mod(n);
}

function pubKeyCombine(pubKeys, pubKeyHash) {
  const ell = pubKeyHash || computeEll(pubKeys);
  let X = null;
  for (let i = 0; i < pubKeys.length; i++) {
    const Xi = convert.pubKeyToPoint(pubKeys[i]);
    const coefficient = computeCoefficient(ell, i);
    const summand = Xi.multiply(coefficient);
    if (X === null) {
      X = summand;
    } else {
      X = X.add(summand);
    }
  }
  return X;
}

function nonInteractive(privateKeys, message) {
  if (!privateKeys || !privateKeys.length) {
    throw new Error('privateKeys must be an array with one or more elements');
  }

  // https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures/
  const rs = [];
  const Xs = [];
  let R = null;
  for (let privateKey of privateKeys) {
    const ri = math.deterministicGetK0(privateKey, message);
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
  check.checkPubKeysUnique(Xs);
  const ell = computeEll(Xs.map(convert.pointToBuffer));
  const coefficients = [];
  let X = null;
  for (let i = 0; i < Xs.length; i++) {
    const Xi = Xs[i];
    const coefficient = computeCoefficient(ell, i);
    const summand = Xi.multiply(coefficient);
    coefficients.push(coefficient);
    if (X === null) {
      X = summand;
    } else {
      X = X.add(summand);
    }
  }

  let Rx = convert.intToBuffer(R.affineX);
  let e = math.getE(Rx, X, message);
  let s = zero;
  for (let i = 0; i < rs.length; i++) {
    const ri = math.getK(R, rs[i]);
    s = s.add(ri.add(e.multiply(coefficients[i]).multiply(privateKeys[i])).mod(n));
  }
  return concat([Rx, convert.intToBuffer(s.mod(n))]);
}

function sessionInitialize(sessionId, privateKey, message, pubKeyCombined, ell, idx) {
  check.checkSessionParams(sessionId, privateKey, message, pubKeyCombined, ell);
  const signers = [];
  signers[idx] = {};

  const session = {
    sessionId,
    message,
    pubKeyCombined,
    ell,
    idx,
    signers
  };
  const coefficient = computeCoefficient(ell, idx);
  session.secretKey = privateKey.multiply(coefficient).mod(n);
  const nonceData = concat([sessionId, message, pubKeyCombined, convert.intToBuffer(privateKey)]);
  session.secretNonce = convert.bufferToInt(convert.hash(nonceData));
  check.checkRange('secNonce', session.secretNonce);
  const R = G.multiply(session.secretNonce);
  session.nonce = convert.pointToBuffer(R);
  session.commitment = convert.hash(session.nonce);
  signers[idx].nonce = session.nonce;
  signers[idx].commitment = session.commitment;
  return session;
}

function sessionCombineNonces(nonces) {
  check.checkNonceArr(nonces);
  let R = convert.pubKeyToPoint(nonces[0]);
  for (let i = 1; i < nonces.length; i++) {
    R = R.add(convert.pubKeyToPoint(nonces[i]));
  }
  return R;
}

function partialSign() {

}

function partialSigCombine() {

}

module.exports = {
  nonInteractive,
  computeEll,
  pubKeyCombine,
  sessionInitialize,
  sessionCombineNonces,
};
