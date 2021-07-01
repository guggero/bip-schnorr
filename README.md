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

The MuSig implementation is based upon the C implementation in the
[secp256k1-zkp fork](https://github.com/ElementsProject/secp256k1-zkp)

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

// PrivateKey as BigInteger from bigi or valid hex string
const privateKey = BigInteger.fromHex('B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF');
const privateKeyHex = 'B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF';
const message = Buffer.from('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', 'hex');
const createdSignature = schnorr.sign(privateKey, message);
const createdSignatureFromHex = schnorr.sign(privateKeyHex, message);
console.log('The signature is: ' + createdSignature.toString('hex'));
console.log('The signature is: ' + createdSignatureFromHex.toString('hex'));

// verifying
const publicKey = Buffer.from('DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659', 'hex');
const signatureToVerify = Buffer.from('6D461BEB2F2DA00027D884FD13A24E2AE85CAECCA8AAA2D41777217EC38FB4960A67D47BC4F0722754EDB0E9017072600FFE4030C2E73771DCD3773F46A62652', 'hex');
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

### muSig

```javascript
const Buffer = require('safe-buffer').Buffer; 
const BigInteger = require('bigi');
const randomBytes = require('random-bytes');
const randomBuffer = (len) => Buffer.from(randomBytes.sync(len));
const schnorr = require('bip-schnorr');
const convert = schnorr.convert;
const muSig = schnorr.muSig;

// data known to every participant
const publicData = {
  pubKeys: [
    Buffer.from('846f34fdb2345f4bf932cb4b7d278fb3af24f44224fb52ae551781c3a3cad68a', 'hex'),
    Buffer.from('cd836b1d42c51d80cef695a14502c21d2c3c644bc82f6a7052eb29247cf61f4f', 'hex'),
    Buffer.from('b8c1765111002f09ba35c468fab273798a9058d1f8a4e276f45a1f1481dd0bdb', 'hex'),
  ],
  message: convert.hash(Buffer.from('muSig is awesome!', 'utf8')),
  pubKeyHash: null,
  pubKeyCombined: null,
  pubKeyParity: null,
  commitments: [],
  nonces: [],
  nonceCombined: null,
  partialSignatures: [],
  signature: null,
};

// data only known by the individual party, these values are never shared
// between the signers!
const signerPrivateData = [
  // signer 1
  {
    privateKey: BigInteger.fromHex('add2b25e2d356bec3770305391cbc80cab3a40057ad836bcb49ef3eed74a3fee'),
    session: null,
  },
  // signer 2
  {
    privateKey: BigInteger.fromHex('0a1645eef5a10e1f5011269abba9fd85c4f0cc70820d6f102fb7137f2988ad78'),
    session: null,
  },
  // signer 3
  {
    privateKey: BigInteger.fromHex('2031e7fed15c770519707bb092a6337215530e921ccea42030c15d86e8eaf0b8'),
    session: null,
  }
];

// -----------------------------------------------------------------------
// Step 1: Combine the public keys
// The public keys P_i are combined into the combined public key P.
// This can be done by every signer individually or by the initializing
// party and then be distributed to every participant.
// -----------------------------------------------------------------------
publicData.pubKeyHash = muSig.computeEll(publicData.pubKeys);
const pkCombined = muSig.pubKeyCombine(publicData.pubKeys, publicData.pubKeyHash);
publicData.pubKeyCombined = convert.intToBuffer(pkCombined.affineX);
publicData.pubKeyParity = math.isEven(pkCombined);

// -----------------------------------------------------------------------
// Step 2: Create the private signing session
// Each signing party does this in private. The session ID *must* be
// unique for every call to sessionInitialize, otherwise it's trivial for
// an attacker to extract the secret key!
// -----------------------------------------------------------------------
signerPrivateData.forEach((data, idx) => {
  const sessionId = randomBuffer(32); // must never be reused between sessions!
  data.session = muSig.sessionInitialize(
    sessionId,
    data.privateKey,
    publicData.message,
    publicData.pubKeyCombined,
    publicData.pubKeyParity,
    publicData.pubKeyHash,
    idx
  );
});
const signerSession = signerPrivateData[0].session;

// -----------------------------------------------------------------------
// Step 3: Exchange commitments (communication round 1)
// The signers now exchange the commitments H(R_i). This is simulated here
// by copying the values from the private data to public data array.
// -----------------------------------------------------------------------
for (let i = 0; i < publicData.pubKeys.length; i++) {
  publicData.commitments[i] = signerPrivateData[i].session.commitment;
}

// -----------------------------------------------------------------------
// Step 4: Get nonces (communication round 2)
// Now that everybody has commited to the session, the nonces (R_i) can be
// exchanged. Again, this is simulated by copying.
// -----------------------------------------------------------------------
for (let i = 0; i < publicData.pubKeys.length; i++) {
  publicData.nonces[i] = signerPrivateData[i].session.nonce;
}

// -----------------------------------------------------------------------
// Step 5: Combine nonces
// The nonces can now be combined into R. Each participant should do this
// and keep track of whether the nonce was negated or not. This is needed
// for the later steps.
// -----------------------------------------------------------------------
publicData.nonceCombined = muSig.sessionNonceCombine(signerSession, publicData.nonces);
signerPrivateData.forEach(data => (data.session.combinedNonceParity = signerSession.combinedNonceParity));

// -----------------------------------------------------------------------
// Step 6: Generate partial signatures
// Every participant can now create their partial signature s_i over the
// given message.
// -----------------------------------------------------------------------
signerPrivateData.forEach(data => {
  data.session.partialSignature = muSig.partialSign(data.session, publicData.message, publicData.nonceCombined, publicData.pubKeyCombined);
});

// -----------------------------------------------------------------------
// Step 7: Exchange partial signatures (communication round 3)
// The partial signature of each signer is exchanged with the other
// participants. Simulated here by copying.
// -----------------------------------------------------------------------
for (let i = 0; i < publicData.pubKeys.length; i++) {
  publicData.partialSignatures[i] = signerPrivateData[i].session.partialSignature;
}

// -----------------------------------------------------------------------
// Step 8: Verify individual partial signatures
// Every participant should verify the partial signatures received by the
// other participants.
// -----------------------------------------------------------------------
for (let i = 0; i < publicData.pubKeys.length; i++) {
  muSig.partialSigVerify(
    signerSession,
    publicData.partialSignatures[i],
    publicData.nonceCombined,
    i,
    publicData.pubKeys[i],
    publicData.nonces[i]
  );
}

// -----------------------------------------------------------------------
// Step 9: Combine partial signatures
// Finally, the partial signatures can be combined into the full signature
// (s, R) that can be verified against combined public key P.
// -----------------------------------------------------------------------
publicData.signature = muSig.partialSigCombine(publicData.nonceCombined, publicData.partialSignatures);

// -----------------------------------------------------------------------
// Step 10: Verify signature
// The resulting signature can now be verified as a normal Schnorr
// signature (s, R) over the message m and public key P.
// -----------------------------------------------------------------------
schnorr.verify(publicData.pubKeyCombined, publicData.message, publicData.signature);
```

## API

### schnorr.sign(privateKey : BigInteger | string, message : Buffer) : Buffer
Sign a 32-byte message with the private key, returning a 64-byte signature.

### schnorr.verify(pubKey : Buffer, message : Buffer, signature : Buffer) : void
Verify a 64-byte signature of a 32-byte message against the public key. Throws an `Error` if verification fails.

### schnorr.batchVerify(pubKeys : Buffer[], messages : Buffer[], signatures : Buffer[]) : void
Verify a list of 64-byte signatures as a batch operation. Throws an `Error` if verification fails.

### schnorr.muSig.computeEll(pubKeys : Buffer[]) : Buffer
Generate `ell` which is the hash over all public keys participating in a muSig session.

### schnorr.muSig.pubKeyCombine(pubKeys : Buffer[], pubKeyHash : Buffer) : Point
Creates the special rogue-key-resistant combined public key `P` by applying the MuSig coefficient
to each public key `P_i` before adding them together.

### schnorr.muSig.sessionInitialize(sessionId : Buffer, privateKey : BigInteger, message : Buffer, pubKeyCombined : Buffer, pkParity : boolean, ell : Buffer, idx : number) : Session
Creates a signing session. Each participant must create a session and *must not share* the content
of the session apart from the commitment and later the nonce.

**It is absolutely necessary that the session ID
is unique for every call of `sessionInitialize`. Otherwise
it's trivial for an attacker to extract the secret key!**

### schnorr.muSig.sessionNonceCombine(session : Session, nonces : Buffer[]) : Buffer
Combines multiple nonces `R_i` into the combined nonce `R`.

### schnorr.muSig.partialSign(session : Session, message : Buffer, nonceCombined : Buffer, pubKeyCombined : Buffer) : BigInteger
Creates a partial signature `s_i` for a participant.

### schnorr.muSig.partialSigVerify(session : Session, partialSig : BigInteger, nonceCombined : Buffer, idx : number, pubKey : Buffer, nonce : Buffer) : void
Verifies a partial signature `s_i` against the participant's public key `P_i`.
Throws an `Error` if verification fails.

### schnorr.muSig.partialSigCombine(nonceCombined : Buffer, partialSigs : BigInteger[]) : Buffer
Combines multiple partial signatures into a Schnorr signature `(s, R)` that can be verified against
the combined public key `P`.


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
