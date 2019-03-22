const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');
const math = require('./math');
const check = require('./check');
const convert = require('./convert');
const muSig = require('./mu-sig');
const scalarChacha20 = require('./scalar-chacha20');

const concat = Buffer.concat;
const G = curve.G;
const zero = BigInteger.ZERO;
const one = BigInteger.ONE;

function keySplit(privateKey, k, n) {
  check.checkPrivateKey(privateKey);

  const result = {
    shards: [],
    pubCoefficients: []
  };

  const constantTerm = privateKey;
  const rp = G.multiply(constantTerm);
  result.pubCoefficients[0] = convert.pointToBuffer(rp);

  let rngSeed = Buffer.alloc(16, 0);
  for (let i = 0; i < 8; i++) {
    const x = one.shiftLeft(i * 8);
    rngSeed[i] = BigInteger.valueOf(k).divide(x).byteValue();
    rngSeed[i + 8] = BigInteger.valueOf(n).divide(x).byteValue();
  }
  rngSeed = convert.hash(concat([convert.intToBuffer(privateKey), rngSeed]));
  for (let i = 0; i < n; i++) {
    let shard = zero;
    for (let j = 0; j < k - 1; j++) {
      let randomScalars = [];
      if (j % 2 === 0) {
        randomScalars = scalarChacha20.seedToScalarValues(rngSeed, j);
      }
      shard = shard.add(randomScalars[j % 2]).mod(curve.n);
      shard = shard.multiply(BigInteger.valueOf(i + 1)).mod(curve.n);
    }
    result.shards[i] = shard.add(constantTerm).mod(curve.n);
  }
  for (let i = 0; i < k - 1; i++) {
    let randomScalars = [];
    if (i % 2 === 0) {
      randomScalars = scalarChacha20.seedToScalarValues(rngSeed, i);
    }
    result.pubCoefficients[k - i - 1] = convert.pointToBuffer(G.multiply(randomScalars[i % 2]));
  }
  return result;
}

function verifyShard(privKey, signingPubkey, numSignersTotal, ell, continuing, shard, myIndex, otherIndex, pubCoefficients, numSigners) {
  const coefficient = muSig.computeCoefficient(ell, otherIndex);
  // TODO implement
}

function lagrangeCoefficient(indices, numSigners, coefficientIndex) {
  let num = one;
  let den = one;
  let indexs = BigInteger.valueOf(coefficientIndex + 1);
  for (let i = 0; i < numSigners; i++) {
    if (indices[i] === coefficientIndex) {
      continue;
    }

    let mul = BigInteger.valueOf(indices[i] + 1).negate();
    num = num.multiply(mul).mod(curve.n);
    mul = mul.add(indexs).mod(curve.n);
    den = den.multiply(mul).mod(curve.n);
  }
  den = den.modInverse(curve.n);
  return num.multiply(den).mod(curve.n);
}

function sessionInitialize(sessionId, privateKey, message, pubKeyCombined, ell, idx, numSigners, indices) {
  check.checkSessionParams(sessionId, privateKey, message, pubKeyCombined, ell);

  const session = {
    sessionId,
    message,
    pubKeyCombined,
    ell,
    idx,
  };
  const coefficient = lagrangeCoefficient(indices, numSigners, idx);
  session.secretKey = privateKey.multiply(coefficient).mod(n);
  const nonceData = concat([convert.intToBuffer(privateKey), sessionId, message, pubKeyCombined]);
  session.secretNonce = convert.bufferToInt(convert.hash(nonceData));
  check.checkRange('secretNonce', session.secretNonce);
  const R = G.multiply(session.secretNonce);
  session.nonce = convert.pointToBuffer(R);
  session.commitment = convert.hash(session.nonce);
  return session;
}

module.exports = {
  keySplit,
  verifyShard,
  lagrangeCoefficient,
  sessionInitialize,
};
