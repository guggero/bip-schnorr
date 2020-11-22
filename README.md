# Pure JavaScript implementation of the Schnorr BIP

[![Build Status](https://travis-ci.org/guggero/bip-schnorr.svg?branch=master)](https://travis-ci.org/guggero/bip-schnorr)
[![Coverage Status](https://coveralls.io/repos/github/guggero/bip-schnorr/badge.svg?branch=master)](https://coveralls.io/github/guggero/bip-schnorr?branch=master)
[![Open Source Love](https://badges.frapsoft.com/os/mit/mit.svg?v=102)](https://github.com/ellerbrock/open-source-badge/)

[![npm version](https://badge.fury.io/js/bip-schnorr.svg)](https://badge.fury.io/js/bip-schnorr)

This is a pure JavaScript implementation of the standard 64-byte Schnorr signature
scheme over the elliptic curve *secp256k1* and its application in the
`MuSig` [multi-signature scheme proposed by Blockstream](https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures/).

The code is based upon the [BIP340 proposal](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).

The current version passes all test vectors provided
[here](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv).

I am by no means an expert in high performance JavaScript or the underlying cryptography.
This library is slow, not peer reviewed at all, not tested (outside of passing the official test vectors) against
other, real implementations and should therefore **only be used for educational purposes!**
Please do not use for production setups!


## How to install

**NPM**:
```bash
npm install --save bip-schnorr
```

**yarn**:
```bash
yarn add bip-schnorr
```


## How to use

NOTE: All parameters are either of type `BigInteger` or `Buffer` (or an array of those).

### Schnorr

```javascript
const Buffer = require('safe-buffer').Buffer; 
const BigInteger = require('bigi');
const schnorr = require('bip-schnorr');
const convert = schnorr.convert;

// signing
const privateKey = BigInteger.fromHex('B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF');
const message = Buffer.from('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', 'hex');
const createdSignature = schnorr.sign(privateKey, message);
console.log('The signature is: ' + createdSignature.toString('hex'));

// verifying
const publicKey = Buffer.from('02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659', 'hex');
const signatureToVerify = Buffer.from('2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD', 'hex');
try {
  schnorr.verify(publicKey, message, signatureToVerify);
  console.log('The signature is valid.');
} catch (e) {
  console.error('The signature verification failed: ' + e);
}

// batch verifying
const publicKeys = [
  Buffer.from('02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659', 'hex'),
  Buffer.from('03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B', 'hex'),
  Buffer.from('026D7F1D87AB3BBC8BC01F95D9AECE1E659D6E33C880F8EFA65FACF83E698BBBF7', 'hex'),
];
const messages = [
  Buffer.from('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', 'hex'),
  Buffer.from('5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C', 'hex'),
  Buffer.from('B2F0CD8ECB23C1710903F872C31B0FD37E15224AF457722A87C5E0C7F50FFFB3', 'hex'),
];
const signatures = [
  Buffer.from('2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD', 'hex'),
  Buffer.from('00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380', 'hex'),
  Buffer.from('68CA1CC46F291A385E7C255562068357F964532300BEADFFB72DD93668C0C1CAC8D26132EB3200B86D66DE9C661A464C6B2293BB9A9F5B966E53CA736C7E504F', 'hex'),
];
try {
  schnorr.batchVerify(publicKeys, messages, signatures);
  console.log('The signatures are valid.');
} catch (e) {
  console.error('The signature verification failed: ' + e);
}
````

## API

### schnorr.sign(privateKey : BigInteger, message : Buffer) : Buffer
Sign a 32-byte message with the private key, returning a 64-byte signature.

### schnorr.verify(pubKey : Buffer, message : Buffer, signature : Buffer) : void
Verify a 64-byte signature of a 32-byte message against the public key. Throws an `Error` if verification fails.

### schnorr.batchVerify(pubKeys : Buffer[], messages : Buffer[], signatures : Buffer[]) : void
Verify a list of 64-byte signatures as a batch operation. Throws an `Error` if verification fails.

## Implementations in different languages
* [Go implementation](https://github.com/hbakhtiyor/schnorr/)

## Performance

The code is not yet optimized for performance.

The following results were achieved on an Intel Core i7-6500U running on linux/amd64 with node v10.23.0:

```text
$ node test/schnorr.benchmark.js
Sign (batch size: 1) x 26.12 ops/sec ±2.68% (47 runs sampled) 40291 us/op 25 sig/s
Sign (batch size: 2) x 13.36 ops/sec ±0.88% (37 runs sampled) 77550 us/op 26 sig/s
Sign (batch size: 4) x 6.78 ops/sec ±1.33% (21 runs sampled) 149622 us/op 27 sig/s
Sign (batch size: 8) x 3.38 ops/sec ±0.93% (13 runs sampled) 297823 us/op 27 sig/s
Sign (batch size: 16) x 1.69 ops/sec ±0.51% (9 runs sampled) 591927 us/op 27 sig/s
Sign (batch size: 32) x 0.85 ops/sec ±0.27% (7 runs sampled) 1177938 us/op 27 sig/s
Sign (batch size: 64) x 0.42 ops/sec ±0.63% (6 runs sampled) 2383795 us/op 27 sig/s
Verify (batch size: 1) x 26.22 ops/sec ±0.76% (47 runs sampled) 39417 us/op 25 sig/s
Verify (batch size: 2) x 13.04 ops/sec ±0.57% (36 runs sampled) 78548 us/op 25 sig/s
Verify (batch size: 4) x 6.57 ops/sec ±0.83% (21 runs sampled) 153775 us/op 26 sig/s
Verify (batch size: 8) x 3.28 ops/sec ±0.60% (13 runs sampled) 305802 us/op 26 sig/s
Verify (batch size: 16) x 1.65 ops/sec ±0.58% (9 runs sampled) 605158 us/op 26 sig/s
Verify (batch size: 32) x 0.83 ops/sec ±0.70% (7 runs sampled) 1214640 us/op 26 sig/s
Verify (batch size: 64) x 0.41 ops/sec ±0.45% (6 runs sampled) 2428993 us/op 26 sig/s
Batch Verify (batch size: 1) x 25.84 ops/sec ±0.82% (47 runs sampled) 39838 us/op 25 sig/s
Batch Verify (batch size: 2) x 8.80 ops/sec ±1.02% (26 runs sampled) 115088 us/op 17 sig/s
Batch Verify (batch size: 4) x 4.39 ops/sec ±0.64% (15 runs sampled) 231074 us/op 17 sig/s
Batch Verify (batch size: 8) x 2.20 ops/sec ±0.36% (10 runs sampled) 457815 us/op 17 sig/s
Batch Verify (batch size: 16) x 1.10 ops/sec ±0.56% (7 runs sampled) 909321 us/op 18 sig/s
Batch Verify (batch size: 32) x 0.55 ops/sec ±0.28% (6 runs sampled) 1825425 us/op 18 sig/s
Batch Verify (batch size: 64) x 0.26 ops/sec ±7.04% (5 runs sampled) 3832114 us/op 17 sig/s
Done in 279.18s.
```
