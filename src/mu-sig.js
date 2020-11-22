const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');
const math = require('./math');
const check = require('./check');
const convert = require('./convert');

const concat = Buffer.concat;
const G = curve.G;
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
  return convert.pointToBuffer(X);
}

function sessionInitialize(sessionId, privateKey, message, pubKeyCombined, ell, idx) {
  check.checkSessionParams(sessionId, privateKey, message, pubKeyCombined, ell);

  const session = {
    sessionId,
    message,
    pubKeyCombined,
    ell,
    idx,
  };
  const coefficient = computeCoefficient(ell, idx);
  session.secretKey = privateKey.multiply(coefficient).mod(n);
  const nonceData = concat([sessionId, message, pubKeyCombined, convert.intToBuffer(privateKey)]);
  session.secretNonce = convert.bufferToInt(convert.hash(nonceData));
  check.checkRange('secretNonce', session.secretNonce);
  const R = G.multiply(session.secretNonce);
  session.nonce = convert.pointToBuffer(R);
  session.commitment = convert.hash(session.nonce);
  return session;
}

function sessionNonceCombine(session, nonces) {
  check.checkNonceArr(nonces);
  let R = convert.pubKeyToPoint(nonces[0]);
  for (let i = 1; i < nonces.length; i++) {
    R = R.add(convert.pubKeyToPoint(nonces[i]));
  }
  if (math.jacobi(R.affineY) !== 1) {
    session.nonceIsNegated = true;
    R = R.negate();
  }
  return convert.pointToBuffer(R);
}

function partialSign(session, message, nonceCombined, pubKeyCombined) {
  const R = convert.pubKeyToPoint(nonceCombined);
  const Rx = convert.intToBuffer(R.affineX);
  const e = math.getE(Rx, convert.pubKeyToPoint(pubKeyCombined), message);
  const sk = session.secretKey;
  let k = session.secretNonce;
  if (session.nonceIsNegated) {
    k = k.negate();
  }
  return sk.multiply(e).mod(n).add(k).mod(n);
}

function partialSigVerify(session, partialSig, nonceCombined, idx, pubKey, nonce) {
  const R = convert.pubKeyToPoint(nonceCombined);
  const Rx = convert.intToBuffer(R.affineX);
  const e = math.getE(Rx, convert.pubKeyToPoint(session.pubKeyCombined), session.message);
  const coefficient = computeCoefficient(session.ell, idx);
  const Ri = convert.pubKeyToPoint(nonce);
  let RP = math.getR(partialSig, e.multiply(coefficient).mod(n), convert.pubKeyToPoint(pubKey));
  if (!session.nonceIsNegated) {
    RP = RP.negate();
  }
  const sum = RP.add(Ri);
  if (!sum.curve.isInfinity(sum)) {
    throw new Error('partial signature verification failed');
  }
}

function partialSigCombine(nonceCombined, partialSigs) {
  const R = convert.pubKeyToPoint(nonceCombined);
  check.checkArray('partialSigs', partialSigs);
  const Rx = convert.intToBuffer(R.affineX);
  let s = partialSigs[0];
  for (let i = 1; i < partialSigs.length; i++) {
    s = s.add(partialSigs[i]).mod(n);
  }
  return concat([Rx, convert.intToBuffer(s)]);
}

module.exports = {
  nonInteractive,
  computeEll,
  pubKeyCombine,
  sessionInitialize,
  sessionNonceCombine,
  partialSign,
  partialSigVerify,
  partialSigCombine,
};
