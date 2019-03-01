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

// aggregating signatures (naive Schnorr key aggregation, not part of BIP!)
const privateKey1 = BigInteger.fromHex('B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF');
const privateKey2 = BigInteger.fromHex('C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7');
const message = Buffer.from('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', 'hex');
const aggregatedSignature = schnorr.naiveKeyAggregation([privateKey1, privateKey2], message);

// verifying an aggregated signature
const publicKey1 = Buffer.from('02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659', 'hex');
const publicKey2 = Buffer.from('03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B', 'hex');
const sumOfPublicKeys = convert.pubKeyToPoint(publicKey1).add(convert.pubKeyToPoint(publicKey2));
try {
  schnorr.verify(convert.pointToBuffer(sumOfPublicKeys), message, aggregatedSignature);
  console.log('The signature is valid.');
} catch (e) {
  console.error('The signature verification failed: ' + e);
}

// muSig non-interactive (not part of any BIP yet, see https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures/)
const privateKey1 = BigInteger.fromHex('B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF');
const privateKey2 = BigInteger.fromHex('C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7');
const message = Buffer.from('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', 'hex');
const aggregatedSignature = schnorr.muSig.nonInteractive([privateKey1, privateKey2], message);

// verifying an aggregated signature
const publicKey1 = Buffer.from('02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659', 'hex');
const publicKey2 = Buffer.from('03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B', 'hex');
const X = schnorr.muSig.pubKeyCombine([publicKey1, publicKey2]);
try {
  schnorr.verify(convert.pointToBuffer(X), message, aggregatedSignature);
  console.log('The signature is valid.');
} catch (e) {
  console.error('The signature verification failed: ' + e);
}
```

## API

### schnorr.sign(privateKey : BigInteger, message : Buffer) : Buffer
Sign a 32-byte message with the private key, returning a 64-byte signature.

### schnorr.verify(pubKey : Buffer, message : Buffer, signature : Buffer) : void
Verify a 64-byte signature of a 32-byte message against the public key. Throws an `Error` if verification fails.

### schnorr.batchVerify(pubKeys : Buffer[], messages : Buffer[], signatures : Buffer[]) : void
Verify a list of 64-byte signatures as a batch operation. Throws an `Error` if verification fails.

### schnorr.naiveKeyAggregation(privateKeys : BigInteger[], message : Buffer) : Buffer
Aggregates multiple signatures of different private keys over the same message into a single 64-byte signature.

This is just a demo of how the naive Schnorr multi-signature (or key aggregation scheme) can work.  
**This scheme is not secure,** it is prone to so-called rogue-key attacks.  
See [Key Aggregation for Schnorr Signatures](https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures/)
by Blockstream.

Use the **muSig** scheme that prevents that attack.

### schnorr.muSig.nonInteractive(privateKeys : BigInteger[], message : Buffer) : Buffer
Aggregates multiple signatures of different private keys over the same message into a single 64-byte signature
using a scheme that is safe from rogue-key attacks.

This non-interactive scheme requires the knowledge of all private keys that are participating in the
multi-signature creation. Use the **muSig.interactive** scheme that requires two steps to create
a signature with parties not sharing their private key.

## Implementations in different languages
* [Go implementation](https://github.com/hbakhtiyor/schnorr/)

## Performance

The code is not yet optimized for performance.

The following results were achieved on an Intel Core i7-6500U running on linux/amd64 with node v10.15.0:

```text
$ node test/schnorr.benchmark.js
Sign (batch size: 1) x 29.81 ops/sec ±2.23% (53 runs sampled) 35344 us/op 28 sig/s
Sign (batch size: 2) x 15.28 ops/sec ±1.99% (42 runs sampled) 67103 us/op 30 sig/s
Sign (batch size: 4) x 7.51 ops/sec ±1.98% (23 runs sampled) 134388 us/op 30 sig/s
Sign (batch size: 8) x 3.83 ops/sec ±2.27% (14 runs sampled) 260547 us/op 31 sig/s
Sign (batch size: 16) x 1.92 ops/sec ±0.99% (9 runs sampled) 525121 us/op 30 sig/s
Sign (batch size: 32) x 0.96 ops/sec ±2.78% (7 runs sampled) 1044533 us/op 31 sig/s
Sign (batch size: 64) x 0.48 ops/sec ±1.51% (6 runs sampled) 2072564 us/op 31 sig/s
Verify (batch size: 1) x 29.96 ops/sec ±0.77% (53 runs sampled) 34513 us/op 29 sig/s
Verify (batch size: 2) x 15.30 ops/sec ±0.70% (42 runs sampled) 67126 us/op 30 sig/s
Verify (batch size: 4) x 7.64 ops/sec ±1.03% (23 runs sampled) 132236 us/op 30 sig/s
Verify (batch size: 8) x 3.85 ops/sec ±1.02% (14 runs sampled) 261091 us/op 31 sig/s
Verify (batch size: 16) x 1.93 ops/sec ±0.53% (9 runs sampled) 519554 us/op 31 sig/s
Verify (batch size: 32) x 0.97 ops/sec ±0.64% (7 runs sampled) 1033222 us/op 31 sig/s
Verify (batch size: 64) x 0.48 ops/sec ±0.69% (6 runs sampled) 2079248 us/op 31 sig/s
Batch Verify (batch size: 1) x 30.55 ops/sec ±0.93% (54 runs sampled) 33736 us/op 30 sig/s
Batch Verify (batch size: 2) x 12.35 ops/sec ±0.88% (35 runs sampled) 82398 us/op 24 sig/s
Batch Verify (batch size: 4) x 5.64 ops/sec ±1.25% (18 runs sampled) 178555 us/op 22 sig/s
Batch Verify (batch size: 8) x 2.71 ops/sec ±0.83% (11 runs sampled) 370195 us/op 22 sig/s
Batch Verify (batch size: 16) x 1.32 ops/sec ±0.72% (8 runs sampled) 760835 us/op 21 sig/s
Batch Verify (batch size: 32) x 0.66 ops/sec ±0.52% (6 runs sampled) 1523772 us/op 21 sig/s
Batch Verify (batch size: 64) x 0.33 ops/sec ±0.41% (5 runs sampled) 3061443 us/op 21 sig/s
Aggregate Signatures naive (batch size: 1) x 31.36 ops/sec ±0.76% (55 runs sampled) 33094 us/op 30 sig/s
Aggregate Signatures naive (batch size: 2) x 15.49 ops/sec ±0.83% (42 runs sampled) 66253 us/op 30 sig/s
Aggregate Signatures naive (batch size: 4) x 7.80 ops/sec ±1.06% (24 runs sampled) 128978 us/op 31 sig/s
Aggregate Signatures naive (batch size: 8) x 3.97 ops/sec ±0.22% (14 runs sampled) 254682 us/op 31 sig/s
Aggregate Signatures naive (batch size: 16) x 1.95 ops/sec ±0.78% (9 runs sampled) 515667 us/op 31 sig/s
Aggregate Signatures naive (batch size: 32) x 0.98 ops/sec ±0.53% (7 runs sampled) 1023110 us/op 31 sig/s
Aggregate Signatures naive (batch size: 64) x 0.49 ops/sec ±0.60% (6 runs sampled) 2038238 us/op 31 sig/s
Aggregate Signatures MuSig non-interactive (batch size: 1) x 19.99 ops/sec ±1.07% (37 runs sampled) 51157 us/op 20 sig/s
Aggregate Signatures MuSig non-interactive (batch size: 2) x 9.91 ops/sec ±1.68% (29 runs sampled) 102176 us/op 20 sig/s
Aggregate Signatures MuSig non-interactive (batch size: 4) x 4.99 ops/sec ±1.23% (17 runs sampled) 201754 us/op 20 sig/s
Aggregate Signatures MuSig non-interactive (batch size: 8) x 2.51 ops/sec ±0.75% (11 runs sampled) 400945 us/op 20 sig/s
Aggregate Signatures MuSig non-interactive (batch size: 16) x 1.26 ops/sec ±0.72% (8 runs sampled) 792623 us/op 20 sig/s
Aggregate Signatures MuSig non-interactive (batch size: 32) x 0.62 ops/sec ±2.60% (6 runs sampled) 1618385 us/op 20 sig/s
Aggregate Signatures MuSig non-interactive (batch size: 64) x 0.32 ops/sec ±0.71% (5 runs sampled) 3171948 us/op 20 sig/s
Done in 422.45s.
```
