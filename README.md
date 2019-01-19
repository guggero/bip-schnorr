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

## Performance

The code is not yet optimized for performance.