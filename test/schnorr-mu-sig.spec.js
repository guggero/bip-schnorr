/* global describe, it, beforeEach */
const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const convert = require('../src/convert');
const muSig = require('../src/mu-sig');
const schnorr = require('../src/schnorr');
const randomBytes = require('random-bytes');

const concat = Buffer.concat;
const testVectors = require('./test-vectors-mu-sig.json');

const randomBuffer = (len) => Buffer.from(randomBytes.sync(len));

describe('muSig', () => {
  describe('pubKeyCombine', () => {
    testVectors.forEach(vec => {
      it('can combine public keys into ' + vec.combined, () => {
        // given
        const pubKeys = vec.pubKeys.map(pk => Buffer.from(pk, 'hex'));

        // when
        const result = muSig.pubKeyCombine(pubKeys);

        // then
        assert.strictEqual(convert.pointToBuffer(result).toString('hex'), vec.combined);
      });
    });
  });

  describe('sessionInitialize', () => {
    testVectors
      .filter(vec => vec.privKeys)
      .forEach(vec => {
        it('can initialize session for combined key ' + vec.combined, () => {
          // given
          const combined = Buffer.from(vec.combined, 'hex');
          const pubKeys = vec.pubKeys.map(pk => Buffer.from(pk, 'hex'));
          const ell = muSig.computeEll(pubKeys);
          const message = Buffer.from(vec.message, 'hex');

          for (let i = 0; i < vec.privKeys.length; i++) {
            const sessionId = Buffer.from(vec.sessionIds[i], 'hex');
            const privateKey = BigInteger.fromHex(vec.privKeys[i]);

            // when
            const session = muSig.sessionInitialize(sessionId, privateKey, message, combined, ell, i);

            // then
            assert.strictEqual(session.commitment.toString('hex'), vec.commitments[i]);
          }
        });
      });
  });

  describe('full example', () => {
    it('can sign and verify example in README', () => {
      // data known to every participant
      const publicData = {
        pubKeys: [
          Buffer.from('0296acbd1454716cdc3022a7828f081cb7c5356d600e725fc1fd93ff92f6d82439', 'hex'),
          Buffer.from('02196edf1d50b22dbeadc0eb944db32a1afe74b6fd73b6cef65da347ac998e143f', 'hex'),
          Buffer.from('02026ded550bc7e02f6430ed1087139177ac45d92d76286589794c70b6fd1cf55a', 'hex'),
        ],
        message: Buffer.from('746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721', 'hex'), // TODO convert.hash(Buffer.from('muSig is awesome!', 'utf8')),
        pubKeyHash: null,
        pubKeyCombined: null,
        commitments: [],
        nonceCommitmentsHash: null,
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
          privateKey: BigInteger.fromHex('cfea8d9f0bc1957084b4671007217d2954c56ce5f871d917c2031d5110b5d3f5'),
          //sessionId: Buffer.from('ab4fb60a4e74dd81ead874c67e05c8923385a2d0e2433fb2bcadf6552cb64147', 'hex'), // TODO remove
          session: null,
          partialSignature: null,
        },
        // signer 2
        {
          privateKey: BigInteger.fromHex('85b0bec51767499757aa74cb10e830ec178703d32da014ffb4d2ad9e2d01f563'),
          //sessionId: Buffer.from('6a1276e19f683393ec8e21d43275f9e1abea9c058ef77a35db4abb49f52b2ced', 'hex'), // TODO remove
          session: null,
          partialSignature: null,
        },
        // signer 3
        {
          privateKey: BigInteger.fromHex('b3c38d7a87d4f0070787942b6bdd48902d10cfed71eaf77dccfb14a772a722f0'),
          //sessionId: Buffer.from('3ac3be5d76609a8f4e20e079f72e38e23c55a2a7188014c4dc69ae051a651d05', 'hex'), // TODO remove
          session: null,
          partialSignature: null,
        }
      ];

      // -----------------------------------------------------------------------
      // Step 1: Combine the public keys
      // This can be done by every signer individually or by the initializing
      // party and then be distributed to every participant.
      // -----------------------------------------------------------------------
      publicData.pubKeyHash = muSig.computeEll(publicData.pubKeys);
      publicData.pubKeyCombined = convert.pointToBuffer(muSig.pubKeyCombine(publicData.pubKeys, publicData.pubKeyHash));

      // -----------------------------------------------------------------------
      // Step 2: Create the private signing session
      // Each signing party does this in private.
      // -----------------------------------------------------------------------
      signerPrivateData.forEach((data, idx) => {
        const sessionId = randomBuffer(32); // must never be reused between sessions!
        // const sessionId = data.sessionId;
        data.session = muSig.sessionInitialize(
          sessionId,
          data.privateKey,
          publicData.message,
          publicData.pubKeyCombined,
          publicData.pubKeyHash,
          idx
        );
      });

      // -----------------------------------------------------------------------
      // Step 3: Exchange commitments (communication round 1)
      // The signers now exchange the commitments. This is simulated here by
      // copying the values from the private data to public data array.
      // -----------------------------------------------------------------------
      for (let i = 0; i < publicData.pubKeys.length; i++) {
        publicData.commitments[i] = signerPrivateData[i].session.commitment;
        console.log('commitment: ' + publicData.commitments[i].toString('hex'));
      }

      // Step 4: Get nonce commitments hash
      publicData.nonceCommitmentsHash = convert.hash(concat(publicData.commitments));

      // Step 5: Get nonces (communication round 2)
      for (let i = 0; i < publicData.pubKeys.length; i++) {
        publicData.nonces[i] = signerPrivateData[i].session.nonce;
      }

      // Step 6: Combine nonces
      publicData.nonceCombined = muSig.sessionNonceCombine(publicData.nonces);
      console.log('nonceCombined: ' + convert.pointToBuffer(publicData.nonceCombined).toString('hex'));

      // Step 7: Generate partial signatures
      signerPrivateData.forEach(data => {
        data.partialSignature = muSig.partialSign(data.session, publicData.message, publicData.nonceCombined, publicData.pubKeyCombined);
      });

      // Step 8: Exchange partial signatures (communication round 3)
      for (let i = 0; i < publicData.pubKeys.length; i++) {
        publicData.partialSignatures[i] = signerPrivateData[i].partialSignature;
      }

      // Step 9: Verify individual partial signatures
      for (let i = 0; i < publicData.pubKeys.length; i++) {
        muSig.partialSigVerify(
          publicData.partialSignatures[i],
          publicData.message,
          publicData.nonceCombined,
          publicData.pubKeyCombined,
          publicData.pubKeyHash,
          i,
          publicData.pubKeys[i],
          publicData.nonces[i]
        );
      }

      // Step 10: Combine partial signatures
      publicData.signature = muSig.partialSigCombine(publicData.nonceCombined, publicData.partialSignatures);
      console.log('signature: ' + publicData.signature.toString('hex'));

      // Step 11: Verify signature
      schnorr.verify(publicData.pubKeyCombined, publicData.message, publicData.signature);
    });
  });
});
