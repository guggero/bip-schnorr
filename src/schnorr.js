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

function sign(privateKey, message, aux) {
  // https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#signing
  check.checkSignParams(privateKey, message);
  privateKey = typeof (privateKey) == 'string' ? BigInteger.fromHex(privateKey) : privateKey;

  const P = G.multiply(privateKey);
  const Px = convert.intToBuffer(P.affineX);

  const d = math.getEvenKey(P, privateKey);
  let kPrime
  if (aux) {
    check.checkAux(aux);

    const t = convert.intToBuffer(d.xor(convert.bufferToInt(math.taggedHash('BIP0340/aux', aux))));
    const rand = math.taggedHash('BIP0340/nonce', concat([t, Px, message]))
    kPrime = convert.bufferToInt(rand).mod(n);
  } else {
    kPrime = math.deterministicGetK0(d, Px, message);
  }

  if (kPrime.signum() === 0) {
    throw new Error('kPrime is zero');
  }

  const R = G.multiply(kPrime);
  const k = math.getEvenKey(R, kPrime);
  const Rx = convert.intToBuffer(R.affineX);
  const e = math.getE(Rx, Px, message);
  return concat([Rx, convert.intToBuffer(k.add(e.multiply(d)).mod(n))]);
}

function verify(pubKey, message, signature) {
  check.checkVerifyParams(pubKey, message, signature);

  // https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#verification
  const P = math.liftX(pubKey);
  const Px = convert.intToBuffer(P.affineX);
  const r = convert.bufferToInt(signature.slice(0, 32));
  const s = convert.bufferToInt(signature.slice(32, 64));
  check.checkSignatureInput(r, s);
  const e = math.getE(convert.intToBuffer(r), Px, message);
  const R = math.getR(s, e, P);
  if (R.curve.isInfinity(R) || !math.isEven(R) || !R.affineX.equals(r)) {
    throw new Error('signature verification failed');
  }
}

function batchVerify(pubKeys, messages, signatures) {
  check.checkBatchVerifyParams(pubKeys, messages, signatures);

  // https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#Batch_Verification
  let leftSide = zero;
  let rightSide = null;
  for (let i = 0; i < pubKeys.length; i++) {
    const P = math.liftX(pubKeys[i]);
    const Px = convert.intToBuffer(P.affineX);
    const r = convert.bufferToInt(signatures[i].slice(0, 32));
    const s = convert.bufferToInt(signatures[i].slice(32, 64));
    check.checkSignatureInput(r, s);
    const e = math.getE(convert.intToBuffer(r), Px, messages[i]);
    const R = math.liftX(signatures[i].slice(0, 32));

    if (i === 0) {
      leftSide = leftSide.add(s);
      rightSide = R;
      rightSide = rightSide.add(P.multiply(e));
    } else {
      const a = math.randomA();
      leftSide = leftSide.add(a.multiply(s));
      rightSide = rightSide.add(R.multiply(a));
      rightSide = rightSide.add(P.multiply(a.multiply(e)));
    }
  }

  if (!G.multiply(leftSide).equals(rightSide)) {
    throw new Error('signature verification failed');
  }
}

module.exports = {
  sign,
  verify,
  batchVerify,
};
