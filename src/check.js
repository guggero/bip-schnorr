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

function checkPubKeyArr(pubKeys) {
  if (!pubKeys || !pubKeys.length) {
    throw new Error('pubKeys must be an array with one or more elements');
  }
  for (let i = 0; i < pubKeys.length; i++) {
    checkBuffer('pubKey', pubKeys[i], 33, i);
  }
}

function checkMessageArr(messages) {
  if (!messages || !messages.length) {
    throw new Error('messages must be an array with one or more elements');
  }
  for (let i = 0; i < messages.length; i++) {
    checkBuffer('message', messages[i], 32, i);
  }
}

function checkSignatureArr(signatures) {
  if (!signatures || !signatures.length) {
    throw new Error('signatures must be an array with one or more elements');
  }
  for (let i = 0; i < signatures.length; i++) {
    checkBuffer('signature', signatures[i], 64, i);
  }
}

function checkPrivateKey(privateKey, idx) {
  const idxStr = (idx !== undefined ? '[' + idx + ']' : '');
  if (!BigInteger.isBigInteger(privateKey)) {
    throw new Error('privateKey' + idxStr + ' must be a BigInteger');
  }
  checkRange(privateKey);
}

function checkPubKeysUnique(pubKeys) {
  const serialized = pubKeys.map(pk => pk.toString('hex'));
  const distinct = (value, index, self) => {
    return self.indexOf(value) === index;
  };
  if (pubKeys.length !== serialized.filter(distinct).length) {
    throw new Error('pubKeys must be an array with unique elements');
  }
}

function checkSignParams(privateKey, message) {
  checkPrivateKey(privateKey);
  checkBuffer('message', message, 32);
}

function checkVerifyParams(pubKey, message, signature) {
  checkBuffer('pubKey', pubKey, 33);
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
  checkBuffer('pubKeyCombined', pubKeyCombined, 33);
  checkBuffer('ell', ell, 32);
}

function checkRange(privateKey) {
  if (privateKey.compareTo(one) < 0 || privateKey.compareTo(n.subtract(one)) > 0) {
    throw new Error('privateKey must be an integer in the range 1..n-1')
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
  if (curve.isInfinity(P)) {
    throw new Error('point is at infinity');
  }
  const pEven = P.affineY.isEven();
  if (pubKeyEven !== pEven) {
    throw new Error('point does not exist');
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
  checkPubKeysUnique
};
