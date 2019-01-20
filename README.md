# Pure JavaScript implementation of the Schnorr BIP

[![Build Status](https://travis-ci.org/guggero/bip-schnorr.svg?branch=master)](https://travis-ci.org/guggero/bip-schnorr)
[![Coverage Status](https://coveralls.io/repos/github/guggero/bip-schnorr/badge.svg?branch=master)](https://coveralls.io/github/guggero/bip-schnorr?branch=master)
[![Open Source Love](https://badges.frapsoft.com/os/mit/mit.svg?v=102)](https://github.com/ellerbrock/open-source-badge/)

[![npm version](https://badge.fury.io/js/bip-schnorr.svg)](https://badge.fury.io/js/bip-schnorr)
[![Dependency Status](https://david-dm.org/guggero/bip-schnorr.svg)](https://david-dm.org/guggero/bip-schnorr)
[![devDependency Status](https://david-dm.org/guggero/bip-schnorr/dev-status.svg)](https://david-dm.org/guggero/bip-schnorr#info=devDependencies)

This is a pure JavaScript implementation of the standard 64-byte Schnorr signature
scheme over the elliptic curve *secp256k1*.

The code is based upon the
[initial proposal of Pieter Wuille](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki)
when it didn't have a BIP number assigned yet.

I am by no means an expert in high performance JavaScript or the underlying cryptography.
So this library is probably really slow.

The current version passes all test vectors provided
[here](https://raw.githubusercontent.com/sipa/bips/bip-schnorr/bip-schnorr/test-vectors.csv).  
**But the author does not give any guarantees that the algorithm is implemented
correctly for every edge case!**

Please use for educational purposes only.

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

```javascript
const bipSchnorr = require('bip-schnorr');

// signing
const privateKey = BigInteger.fromHex('B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF');
const message = Buffer.from('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', 'hex');
const createdSignature = bipSchnorr.sign(privateKey, message);
console.log('The signature is: ' + createdSignature.toString('hex'));

// verifying
const publicKey = Buffer.from('02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659', 'hex');
const signatureToVerify = Buffer.from('2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD', 'hex');
try {
  bipSchnorr.verify(publicKey, message, signatureToVerify);
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
  bipSchnorr.batchVerify(publicKeys, messages, signatures);
  console.log('The signatures are valid.');
} catch (e) {
  console.error('The signature verification failed: ' + e);
}

// aggregating signatures (not part of BIP!)
const privateKey1 = BigInteger.fromHex('B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF');
const privateKey2 = BigInteger.fromHex('C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7');
const message = Buffer.from('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', 'hex');
const aggregatedSignature = bipSchnorr.aggregateSignatures([privateKey1, privateKey2], message);

// verifying an aggregated signature
const publicKey1 = Buffer.from('02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659', 'hex');
const publicKey2 = Buffer.from('03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B', 'hex');
const sumOfPublicKeys = bipSchnorr.pubKeyToPoint(publicKey1).add(bipSchnorr.publicKeyToPoint(publicKey2));
try {
  bipSchnorr.verify(sumOfPublicKeys.getEncoded(true), message, aggregatedSignature);
  console.log('The signature is valid.');
} catch (e) {
  console.error('The signature verification failed: ' + e);
}
```

## API

### bipSchnorr.sign(privateKey : BigInteger, message : Buffer) : Buffer
Sign a 32-byte message with the private key, returning a 64-byte signature.

### bipSchnorr.verify(pubKey : Buffer, message : Buffer, signature : Buffer) : void
Verify a 64-byte signature of a 32-byte message against the public key. Throws an `Error` if verification fails.

### bipSchnorr.batchVerify(pubKeys : Buffer[], messages : Buffer[], signatures : Buffer[]) : void
Verify a list of 64-byte signatures as a batch operation. Throws an `Error` if verification fails.

### bipSchnorr.aggregateSignatures(privateKeys : BigInteger[], message : Buffer) : Buffer
Aggregates multiple signatures of different private keys over the same message into a single 64-byte signature.

### bipSchnorr.pubKeyToPoint(pubKey : Buffer) : Point
Returns the point on the `secp256k1` curve that corresponds to the given 33-byte public key.

## Implementations in different languages
* [Go implementation](https://github.com/hbakhtiyor/schnorr/)

## Performance

The code is not yet optimized for performance.

The following results were achieved on an Intel Core i7-6500U running on linux/amd64 with node v10.15.0:

```text
$ node test/schnorr.benchmark.js
Sign (batch size: 1) x 29.70 ops/sec ±3.19% (53 runs sampled) 35769 us/op 28 sig/s
Sign (batch size: 2) x 15.20 ops/sec ±0.58% (42 runs sampled) 67754 us/op 30 sig/s
Sign (batch size: 4) x 7.63 ops/sec ±1.53% (23 runs sampled) 132366 us/op 30 sig/s
Sign (batch size: 8) x 3.87 ops/sec ±0.59% (14 runs sampled) 259093 us/op 31 sig/s
Sign (batch size: 16) x 1.96 ops/sec ±0.54% (9 runs sampled) 514358 us/op 31 sig/s
Sign (batch size: 32) x 0.95 ops/sec ±1.99% (7 runs sampled) 1051411 us/op 30 sig/s
Sign (batch size: 64) x 0.45 ops/sec ±5.08% (6 runs sampled) 2385445 us/op 27 sig/s
Verify (batch size: 1) x 30.09 ops/sec ±0.38% (53 runs sampled) 34477 us/op 29 sig/s
Verify (batch size: 2) x 15.02 ops/sec ±1.22% (41 runs sampled) 68379 us/op 29 sig/s
Verify (batch size: 4) x 7.37 ops/sec ±3.05% (23 runs sampled) 136874 us/op 29 sig/s
Verify (batch size: 8) x 3.79 ops/sec ±0.57% (14 runs sampled) 267222 us/op 30 sig/s
Verify (batch size: 16) x 1.89 ops/sec ±1.06% (9 runs sampled) 529846 us/op 30 sig/s
Verify (batch size: 32) x 0.95 ops/sec ±0.92% (7 runs sampled) 1051658 us/op 30 sig/s
Verify (batch size: 64) x 0.47 ops/sec ±0.77% (6 runs sampled) 2135796 us/op 30 sig/s
Batch Verify (batch size: 1) x 30.01 ops/sec ±1.29% (53 runs sampled) 34421 us/op 29 sig/s
Batch Verify (batch size: 2) x 12.14 ops/sec ±0.43% (34 runs sampled) 84276 us/op 24 sig/s
Batch Verify (batch size: 4) x 5.54 ops/sec ±0.65% (18 runs sampled) 181663 us/op 22 sig/s
Batch Verify (batch size: 8) x 2.66 ops/sec ±0.72% (11 runs sampled) 379037 us/op 21 sig/s
Batch Verify (batch size: 16) x 1.28 ops/sec ±3.25% (8 runs sampled) 780231 us/op 21 sig/s
Batch Verify (batch size: 32) x 0.64 ops/sec ±0.63% (6 runs sampled) 1557873 us/op 21 sig/s
Batch Verify (batch size: 64) x 0.32 ops/sec ±0.58% (5 runs sampled) 3145214 us/op 20 sig/s
Aggregate Signatures (batch size: 1) x 29.63 ops/sec ±1.14% (52 runs sampled) 34873 us/op 29 sig/s
Aggregate Signatures (batch size: 2) x 15.49 ops/sec ±0.83% (42 runs sampled) 66014 us/op 30 sig/s
Aggregate Signatures (batch size: 4) x 7.69 ops/sec ±0.61% (23 runs sampled) 132555 us/op 30 sig/s
Aggregate Signatures (batch size: 8) x 3.83 ops/sec ±1.08% (14 runs sampled) 262249 us/op 31 sig/s
Aggregate Signatures (batch size: 16) x 1.94 ops/sec ±0.68% (9 runs sampled) 518440 us/op 31 sig/s
Aggregate Signatures (batch size: 32) x 0.96 ops/sec ±0.30% (7 runs sampled) 1038215 us/op 31 sig/s
Aggregate Signatures (batch size: 64) x 0.48 ops/sec ±0.61% (6 runs sampled) 2092208 us/op 31 sig/s
Done in 333.35s.
```
