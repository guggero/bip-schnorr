# Pure JavaScript implementation of BIP340 Schnorr Signatures for secp256k1

[![Build Status](https://travis-ci.org/guggero/bip-schnorr.svg?branch=master)](https://travis-ci.org/guggero/bip-schnorr)
[![Coverage Status](https://coveralls.io/repos/github/guggero/bip-schnorr/badge.svg?branch=master)](https://coveralls.io/github/guggero/bip-schnorr?branch=master)
[![Open Source Love](https://badges.frapsoft.com/os/mit/mit.svg?v=102)](https://github.com/ellerbrock/open-source-badge/)

[![npm version](https://badge.fury.io/js/bip-schnorr.svg)](https://badge.fury.io/js/bip-schnorr)

This is a pure JavaScript implementation of the standard 64-byte Schnorr signature
scheme over the elliptic curve *secp256k1*.

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
const publicKey = Buffer.from('DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659', 'hex');
const signatureToVerify = Buffer.from('2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D96EF2BE1AF1CAE22BF6736FA9650DE69E7DA1D37F92C4A92FBC93CC28FDBDB84', 'hex');
try {
  schnorr.verify(publicKey, message, signatureToVerify);
  console.log('The signature is valid.');
} catch (e) {
  console.error('The signature verification failed: ' + e);
}

// batch verifying
const publicKeys = [
  Buffer.from('9D03B28781BD34C3250E4250FEB4543AF02AC6529398EBF776AAA5C3BDA10CFD', 'hex'),
  Buffer.from('141F9A1B6360A717A7C71CB67E98D57513A84101192DC048F4382B5DF1B3C756', 'hex'),
  Buffer.from('F986619C277577317E362101E08F8ACF63B34623B6A4758C2254398F70564D5A', 'hex'),
];
const messages = [
  Buffer.from('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', 'hex'),
  Buffer.from('5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C', 'hex'),
  Buffer.from('B2F0CD8ECB23C1710903F872C31B0FD37E15224AF457722A87C5E0C7F50FFFB3', 'hex'),
];
const signatures = [
  Buffer.from('1C621A42A3397988B63FC8F6F5EA81F8C88A71E2D30B1D7F3681CC9CB99E5AC022E52FC927DCA01B3BD3A16793F06996A5FE8A9B3FA7A91EC8934AF15F12FCF8', 'hex'),
  Buffer.from('E94ECF2B0446171E44D62311EBDB631612B8AC5C4A5974033C61B924BD11B24AFC118CB661C18B0C94FDCD3F10C6F8B3F8DDA44A20DC4308430F0396EE9F477C', 'hex'),
  Buffer.from('F25929B90A93130BF85EC6ABA70DA6B26FDFC37F71C7E268342873575CA0C01375F372B31E5C218E30CAE08DEAEF47F37096C7E11D506EC8DC9221109B79FB2D', 'hex'),
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
