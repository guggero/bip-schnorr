const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');

const one = BigInteger.ONE;
const n = curve.n;
const p = curve.p;

function checkVerifyParams(pubKey, message, signature, idx) {
  const idxStr = (idx !== undefined ? '[' + idx + ']' : '');
  if (!Buffer.isBuffer(pubKey)) {
    throw new Error('pubKey' + idxStr + ' must be a Buffer');
  }
  if (!Buffer.isBuffer(message)) {
    throw new Error('message' + idxStr + ' must be a Buffer');
  }
  if (!Buffer.isBuffer(signature)) {
    throw new Error('signature' + idxStr + ' must be a Buffer');
  }
  if (pubKey.length !== 33) {
    throw new Error('pubKey' + idxStr + ' must be 33 bytes long');
  }
  if (message.length !== 32) {
    throw new Error('message' + idxStr + ' must be 32 bytes long');
  }
  if (signature.length !== 64) {
    throw new Error('signature' + idxStr + ' must be 64 bytes long');
  }
}

function checkBatchVerifyParams(pubKeys, messages, signatures) {
  if (!pubKeys || !pubKeys.length) {
    throw new Error('pubKeys must be an array with one or more elements');
  }
  if (!messages || !messages.length) {
    throw new Error('messages must be an array with one or more elements');
  }
  if (!signatures || !signatures.length) {
    throw new Error('signatures must be an array with one or more elements');
  }
  if (pubKeys.length !== messages.length || messages.length !== signatures.length) {
    throw new Error('all parameters must be an array with the same length')
  }
  for (let i = 0; i < pubKeys.length; i++) {
    checkVerifyParams(pubKeys[i], messages[i], signatures[i], i);
  }
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

module.exports = {
  checkVerifyParams,
  checkBatchVerifyParams,
  checkRange,
  checkSignatureInput,
};
