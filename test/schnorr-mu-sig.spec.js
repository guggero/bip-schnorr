/* global describe, it, beforeEach */
const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const convert = require('../src/convert');
const muSig = require('../src/mu-sig');
const schnorr = require('../src/schnorr');
const randomBytes = require('random-bytes');

const testVectors = require('./test-vectors-mu-sig.json');

const randomBuffer = (len) => Buffer.from(randomBytes.sync(len));

describe('muSig', () => {
  describe('pubKeyCombine', () => {
    testVectors.forEach(vec => {
      it('can combine public keys into ' + vec.pubKeyCombined, () => {
        // given
        const pubKeys = vec.pubKeys.map(pk => Buffer.from(pk, 'hex'));

        // when
        const result = muSig.pubKeyCombine(pubKeys);

        // then
        assert.strictEqual(result.toString('hex'), vec.pubKeyCombined);
      });
    });
  });

  describe('sessionInitialize', () => {
    testVectors
      .forEach(vec => {
        it('can initialize session for combined key ' + vec.pubKeyCombined, () => {
          // given
          const pubKeys = vec.pubKeys.map(pk => Buffer.from(pk, 'hex'));
          const pubKeyCombined = Buffer.from(vec.pubKeyCombined, 'hex');
          const ell = muSig.computeEll(pubKeys);
          const message = Buffer.from(vec.message, 'hex');

          for (let i = 0; i < vec.privKeys.length; i++) {
            const sessionId = Buffer.from(vec.sessionIds[i], 'hex');
            const privateKey = BigInteger.fromHex(vec.privKeys[i]);

            // when
            const session = muSig.sessionInitialize(sessionId, privateKey, message, pubKeyCombined, ell, i);

            // then
            assert.strictEqual(session.commitment.toString('hex'), vec.commitments[i]);
            assert.strictEqual(convert.intToBuffer(session.secretKey).toString('hex'), vec.secretKeys[i]);
            assert.strictEqual(convert.intToBuffer(session.secretNonce).toString('hex'), vec.secretNonces[i]);
          }
        });
      });
  });

  describe('sessionNonceCombine', () => {
    testVectors.forEach(vec => {
      it('can combine nonces into ' + vec.nonceCombined, () => {
        // given
        const pubKeys = vec.pubKeys.map(pk => Buffer.from(pk, 'hex'));
        const pubKeyCombined = Buffer.from(vec.pubKeyCombined, 'hex');
        const ell = muSig.computeEll(pubKeys);
        const message = Buffer.from(vec.message, 'hex');

        const sessions = [];
        for (let i = 0; i < vec.privKeys.length; i++) {
          const sessionId = Buffer.from(vec.sessionIds[i], 'hex');
          const privateKey = BigInteger.fromHex(vec.privKeys[i]);
          sessions[i] = muSig.sessionInitialize(sessionId, privateKey, message, pubKeyCombined, ell, i);
        }

        // when
        const result = muSig.sessionNonceCombine(sessions[0], sessions.map(s => s.nonce));

        // then
        assert.strictEqual(result.toString('hex'), vec.nonceCombined);
      });
    });
  });

  describe('partialSign', () => {
    testVectors.forEach((vec, index) => {
      it('can create partial signatures #' + (index + 1), () => {
        // given
        const pubKeys = vec.pubKeys.map(pk => Buffer.from(pk, 'hex'));
        const pubKeyCombined = Buffer.from(vec.pubKeyCombined, 'hex');
        const ell = muSig.computeEll(pubKeys);
        const message = Buffer.from(vec.message, 'hex');

        const sessions = [];
        for (let i = 0; i < vec.privKeys.length; i++) {
          const sessionId = Buffer.from(vec.sessionIds[i], 'hex');
          const privateKey = BigInteger.fromHex(vec.privKeys[i]);
          sessions[i] = muSig.sessionInitialize(sessionId, privateKey, message, pubKeyCombined, ell, i);
        }
        const signerSession = sessions[0];
        const nonceCombined = muSig.sessionNonceCombine(signerSession, sessions.map(s => s.nonce));

        for (let i = 0; i < sessions.length; i++) {
          // when
          sessions[i].nonceIsNegated = signerSession.nonceIsNegated;
          const result = muSig.partialSign(sessions[i], message, nonceCombined, pubKeyCombined);

          // then
          assert.strictEqual(convert.intToBuffer(result).toString('hex'), vec.partialSigs[i]);
        }
      });
    });
  });

  describe('partialSigCombine', () => {
    testVectors.forEach(vec => {
      it('can combine partial signatures into ' + vec.signature, () => {
        // given
        const pubKeys = vec.pubKeys.map(pk => Buffer.from(pk, 'hex'));
        const pubKeyCombined = Buffer.from(vec.pubKeyCombined, 'hex');
        const ell = muSig.computeEll(pubKeys);
        const message = Buffer.from(vec.message, 'hex');

        const sessions = [];
        for (let i = 0; i < vec.privKeys.length; i++) {
          const sessionId = Buffer.from(vec.sessionIds[i], 'hex');
          const privateKey = BigInteger.fromHex(vec.privKeys[i]);
          sessions[i] = muSig.sessionInitialize(sessionId, privateKey, message, pubKeyCombined, ell, i);
        }
        const signerSession = sessions[0];
        const nonceCombined = muSig.sessionNonceCombine(signerSession, sessions.map(s => s.nonce));
        const partialSignatures = sessions.map(s => {
          s.nonceIsNegated = signerSession.nonceIsNegated;
          return muSig.partialSign(s, message, nonceCombined, pubKeyCombined)
        });

        // when
        const result = muSig.partialSigCombine(nonceCombined, partialSignatures);

        // then
        assert.strictEqual(result.toString('hex'), vec.signature);
      });
    });
  });

  describe('full example', () => {
    it('can sign and verify example in README', () => {
      // data known to every participant
      const publicData = {
        pubKeys: [
          Buffer.from('03846f34fdb2345f4bf932cb4b7d278fb3af24f44224fb52ae551781c3a3cad68a', 'hex'),
          Buffer.from('02cd836b1d42c51d80cef695a14502c21d2c3c644bc82f6a7052eb29247cf61f4f', 'hex'),
          Buffer.from('03b8c1765111002f09ba35c468fab273798a9058d1f8a4e276f45a1f1481dd0bdb', 'hex'),
        ],
        message: convert.hash(Buffer.from('muSig is awesome!', 'utf8')),
        pubKeyHash: null,
        pubKeyCombined: null,
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
      publicData.pubKeyCombined = muSig.pubKeyCombine(publicData.pubKeys, publicData.pubKeyHash);

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
      signerPrivateData.forEach(data => (data.session.nonceIsNegated = signerSession.nonceIsNegated));

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
    });
  });
});
