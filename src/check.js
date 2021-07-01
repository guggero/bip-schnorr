const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');

const one = BigInteger.ONE;
const n = curve.n;
const p = curve.p;

function checkBuffer(name, buf, len, idx) {
  const idxStr = (idx !== undefined ? '[' + idx + ']' : '');
  if (!Buffer.isBuffer(buf)) {
    throw new Error(name + idxStr + ' must be a Buffer');
  }
  if (buf.length !== len) {
    throw new Error(name + idxStr + ' must be ' + len + ' bytes long');
  }
}

function checkArray(name, arr) {
  if (!arr || !arr.length) {
    throw new Error(name + ' must be an array with one or more elements');
  }
}

function checkPubKeyArr(pubKeys) {
  checkArray('pubKeys', pubKeys);
  for (let i = 0; i < pubKeys.length; i++) {
    checkBuffer('pubKey', pubKeys[i], 32, i);
  }
}

function checkMessageArr(messages) {
  checkArray('messages', messages);
  for (let i = 0; i < messages.length; i++) {
    checkBuffer('message', messages[i], 32, i);
  }
}

function checkSignatureArr(signatures) {
  checkArray('signatures', signatures);
  for (let i = 0; i < signatures.length; i++) {
    checkBuffer('signature', signatures[i], 64, i);
  }
}

function checkNonceArr(nonces) {
  checkArray('nonces', nonces);
  for (let i = 0; i < nonces.length; i++) {
    checkBuffer('nonce', nonces[i], 32, i);
  }
}

function checkPrivateKey(privateKey, idx) {
  const idxStr = (idx !== undefined ? '[' + idx + ']' : '');
  if (!BigInteger.isBigInteger(privateKey) && !(typeof privateKey == 'string')) {
    throw new Error('privateKey' + idxStr + ' must be a BigInteger or valid hex string');
  }

  if (typeof(privateKey) == 'string') {
    if (privateKey.match(/[^a-f^A-F^0-9]+/)) {
      throw new Error('privateKey must be a BigInteger or valid hex string');
    }

    checkRange('privateKey', BigInteger.fromHex(privateKey));
    return
  }

  checkRange('privateKey', privateKey);
}

function checkSignParams(privateKey, message) {
  checkPrivateKey(privateKey);
  checkBuffer('message', message, 32);
}

function checkVerifyParams(pubKey, message, signature) {
  checkBuffer('pubKey', pubKey, 32);
  checkBuffer('message', message, 32);
  checkBuffer('signature', signature, 64);
}

function checkBatchVerifyParams(pubKeys, messages, signatures) {
  checkPubKeyArr(pubKeys);
  checkMessageArr(messages);
  checkSignatureArr(signatures);
  if (pubKeys.length !== messages.length || messages.length !== signatures.length) {
    throw new Error('all parameters must be an array with the same length')
  }
}

function checkSessionParams(sessionId, privateKey, message, pubKeyCombined, ell) {
  checkSignParams(privateKey, message);
  checkBuffer('sessionId', sessionId, 32);
  checkBuffer('pubKeyCombined', pubKeyCombined, 32);
  checkBuffer('ell', ell, 32);
}

function checkRange(name, scalar) {
  if (scalar.compareTo(one) < 0 || scalar.compareTo(n.subtract(one)) > 0) {
    throw new Error(name + ' must be an integer in the range 1..n-1')
  }
}

function checkSignatureInput(r, s) {
  if (r.compareTo(p) >= 0) {
    throw new Error('r is larger than or equal to field size');
  }
  if (s.compareTo(n) >= 0) {
    throw new Error('s is larger than or equal to curve order');
  }
}

function checkPointExists(pubKeyEven, P) {
  if (P.curve.isInfinity(P)) {
    throw new Error('point is at infinity');
  }
  const pEven = P.affineY.isEven();
  if (pubKeyEven !== pEven) {
    throw new Error('point does not exist');
  }
}

function checkAux(aux) {
  if (aux.length !== 32) {
    throw new Error('aux must be 32 bytes');
  }
}

module.exports = {
  checkSessionParams,
  checkSignParams,
  checkVerifyParams,
  checkBatchVerifyParams,
  checkRange,
  checkSignatureInput,
  checkPointExists,
  checkPubKeyArr,
  checkArray,
  checkNonceArr,
  checkAux,
};
