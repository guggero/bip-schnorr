/* chacha20 - 256 bits */

// Written in 2014 by Devi Mandiri. Public domain.
//
// Implementation derived from chacha-ref.c version 20080118
// See for details: http://cr.yp.to/chacha/chacha-20080128.pdf
//
// copied from https://github.com/quartzjer/chacha20
// adapted for use cases in secp256k1.
const check = require('./check');
const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;

function uint8to32littleEndian(x, i) {
  return x[i] | (x[i + 1] << 8) | (x[i + 2] << 16) | (x[i + 3] << 24);
}

function rotate(v, c) {
  return (v << c) | (v >>> (32 - c));
}

function quarterRound(x, a, b, c, d) {
  x[a] += x[b];
  x[d] = rotate(x[d] ^ x[a], 16);
  x[c] += x[d];
  x[b] = rotate(x[b] ^ x[c], 12);
  x[a] += x[b];
  x[d] = rotate(x[d] ^ x[a], 8);
  x[c] += x[d];
  x[b] = rotate(x[b] ^ x[c], 7);
}

function seedToScalarValues(seed, idx) {
  const input = new Uint32Array(16);
  const output = Buffer.alloc(64, 0);
  let overflowCount = 0;
  let overflow = false;
  const result = [];

  do {
    // https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01#section-2.3
    input[0] = 0x61707865;
    input[1] = 0x3320646e;
    input[2] = 0x79622d32;
    input[3] = 0x6b206574;
    input[4] = uint8to32littleEndian(seed, 0);
    input[5] = uint8to32littleEndian(seed, 4);
    input[6] = uint8to32littleEndian(seed, 8);
    input[7] = uint8to32littleEndian(seed, 12);
    input[8] = uint8to32littleEndian(seed, 16);
    input[9] = uint8to32littleEndian(seed, 20);
    input[10] = uint8to32littleEndian(seed, 24);
    input[11] = uint8to32littleEndian(seed, 28);
    input[12] = idx;
    input[13] = 0; // only 32bit idx supported currently
    input[14] = 0;
    input[15] = overflowCount;

    const x = new Uint32Array(16);
    for (let i = 16; i--;) {
      x[i] = input[i];
    }
    for (let i = 0; i < 10; i++) {
      quarterRound(x, 0, 4, 8, 12);
      quarterRound(x, 1, 5, 9, 13);
      quarterRound(x, 2, 6, 10, 14);
      quarterRound(x, 3, 7, 11, 15);
      quarterRound(x, 0, 5, 10, 15);
      quarterRound(x, 1, 6, 11, 12);
      quarterRound(x, 2, 7, 8, 13);
      quarterRound(x, 3, 4, 9, 14);
    }
    for (let i = 16; i--;) {
      x[i] += input[i];
    }
    for (let i = 16; i--;) {
      output.writeUInt32BE(x[i], i * 4);
    }
    result[0] = BigInteger.fromHex(output.slice(0, 32).toString('hex'));
    result[1] = BigInteger.fromHex(output.slice(32, 64).toString('hex'));
    overflowCount++;
    try {
      overflow = false;
      check.checkRange('result[0]', result[0]);
      check.checkRange('result[1]', result[1]);
    } catch (e) {
      overflow = true;
    }
  } while (overflow);
  return result;
}

module.exports = {
  seedToScalarValues,
};
