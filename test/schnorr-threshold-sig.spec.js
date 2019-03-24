/* global describe, it, beforeEach */
const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const convert = require('../src/convert');
const muSig = require('../src/mu-sig');
const thresholdSig = require('../src/threshold-sig');
const schnorr = require('../src/schnorr');
const randomBytes = require('random-bytes');

const testVectors = require('./test-vectors-threshold-sig.json');
const testVectorsLagrange = require('./test-vectors-lagrange.json');

describe('thresholdSig', () => {
  describe('keySplit', () => {
    testVectors.forEach((vec, index) => {
      it('can split private keys into shards ' + index, () => {
        // given
        const privateKeys = vec.privKeys.map(d => BigInteger.fromHex(d));
        const numSigners = vec.pubCoefficients[0].length;
        const numSignersTotal = privateKeys.length;

        // when
        const results = privateKeys.map(d => thresholdSig.keySplit(d, numSigners, numSignersTotal));

        // then
        results.forEach((result, resultIndex) => {
          result.shards.forEach((shard, shardIndex) => {
            assert.strictEqual(convert.intToBuffer(shard).toString('hex'), vec.shards[resultIndex][shardIndex], `shard[${resultIndex}][${shardIndex}]`);
          });

          result.pubCoefficients.forEach((coefficient, coefficientIndex) => {
            assert.strictEqual(coefficient.toString('hex'), vec.pubCoefficients[resultIndex][coefficientIndex], `pubCoefficient[${resultIndex}][${coefficientIndex}]`);
          });
        });
      });
    });
  });

  describe('verifyShard', () => {
    testVectors.forEach((vec, index) => {
      it('can verify shard ' + index, () => {
        // given
        const privateKeys = vec.privKeys.map(d => BigInteger.fromHex(d));
        const pubKeys = vec.pubKeys.map(pk => Buffer.from(pk, 'hex'));
        const pubKeyCombined = Buffer.from(vec.pubKeyCombined, 'hex');
        const ell = muSig.computeEll(pubKeys);
        const numSigners = vec.pubCoefficients[0].length;
        const numSignersTotal = privateKeys.length;
        const parts = privateKeys.map(d => thresholdSig.keySplit(d, numSigners, numSignersTotal));

        privateKeys.forEach((privKey, index) => {
          const signingPubkey = Buffer.alloc(33, 0);
          for (let j = 0; j < numSigners; j++) {

            // when
            let result = false;
            try {
              thresholdSig.verifyShard(privKey, signingPubkey, numSignersTotal, ell, j > 0, parts[index].shards[j], index, j, parts[index].pubCoefficients, numSigners);
              result = true;
            } catch (e) {
              result = false;
            }

            // then
            assert.strictEqual(result, true);
          }
        });
      });
    });
  });

  describe('lagrangeCoefficient', () => {
    testVectorsLagrange.forEach((vec, index) => {
      it('can calculate lagrange coefficient ' + vec.coefficient, () => {
        // when
        const result = thresholdSig.lagrangeCoefficient(vec.indices, vec.numSigners, vec.myIndex);

        // then
        assert.strictEqual(convert.intToBuffer(result).toString('hex'), vec.coefficient);
      });
    });
  });

  describe('full example', () => {
    it('can sign and verify example in README', () => {
      // data known to every participant
      const publicData = {
        pubKeys: [
          Buffer.from('0295233e7089ebd1c148a86e83699cdb72a4e7a1ce9d1700b536d49538b7dc5bee', 'hex'),
          Buffer.from('039f33fa8f2cdd35d8db3af14623d5f5b604c35e85798c986d3181d822c6df62a8', 'hex'),
          Buffer.from('03de6c03e1ca88ec966cc7605508f2f75c36b813a2b87eec6c70df165f4e630923', 'hex'),
        ],
        message: Buffer.from('746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721', 'hex'), // TODO convert.hash(Buffer.from('muSig is awesome!', 'utf8')),
        pubKeyHash: null,
        pubKeyCombined: null,
        commitments: [],
        nonces: [],
        nonceCombined: null,
        partialSignatures: [],
        signature: null,
        numSigners: 2,
        numSignersTotal: 3,
        signerIndices: [0, 1]
      };

      // data only known by the individual party, these values are never shared
      // between the participants/signers!
      const participantPrivateData = [
        // signer 1
        {
          privateKey: BigInteger.fromHex('f09f1d4bac37919b7175ddde88157192266ba9e47de6a70ad61dade687f2dabd'),
          sessionId: Buffer.from('178fb2c2c2f6e26d84c265c1f414eb5364c42cb2a52d7a5c9b572ab3990e2450', 'hex'), // TODO remove
          session: null,
          parts: null,
        },
        // signer 2
        {
          privateKey: BigInteger.fromHex('05c87614f7f28a8d862630186cbd3957f99eba6c0857948d61bf8500fa86498e'),
          sessionId: Buffer.from('48ed54ce76bdc552b3f3c14d190afe4cc6243fce557124347e53a2372c64f6f0', 'hex'), // TODO remove
          session: null,
          parts: null,
        },
        // non-signing participant
        {
          privateKey: BigInteger.fromHex('6585df979b3b58d89bcfa6732c08d07dbeb33af1f829797e5c869c1f78e5c132'),
          session: null,
          parts: null,
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
      // Step 2: Split the private keys
      // -----------------------------------------------------------------------
      participantPrivateData.forEach((data, idx) => {
        data.parts = thresholdSig.keySplit(data.privateKey, publicData.numSigners, publicData.numSignersTotal);
      });

      // -----------------------------------------------------------------------
      // Step 3: Share the public coefficients (communication round 1)
      // -----------------------------------------------------------------------
      // TODO

      // -----------------------------------------------------------------------
      // Step 4: Verify shards
      // -----------------------------------------------------------------------
      // TODO

      // -----------------------------------------------------------------------
      // Step 5: Create the private signing session
      // Each signing party does this in private. The session ID *must* be
      // unique for every call to sessionInitialize, otherwise it's trivial for
      // an attacker to extract the secret key!
      // -----------------------------------------------------------------------
      publicData.signerIndices.forEach(signerIndex => {
        const signerData = participantPrivateData[signerIndex];
        const sessionId = signerData.sessionId; // TODO randomBuffer(32); // must never be reused between sessions!
        signerData.session = thresholdSig.sessionInitialize(
          sessionId,
          signerData.privateKey,
          publicData.message,
          publicData.pubKeyCombined,
          publicData.pubKeyHash,
          signerIndex,
          publicData.numSigners,
          publicData.signerIndices
        );
        console.log(`commitment[${signerIndex}]: ${signerData.session.commitment.toString('hex')}`);
      });
      const signerSession = participantPrivateData[0].session;

      // -----------------------------------------------------------------------
      // Step 6: Exchange commitments (communication round 2)
      // The signers now exchange the commitments H(R_i). This is simulated here
      // by copying the values from the private data to public data array.
      // -----------------------------------------------------------------------
      for (let i = 0; i < publicData.pubKeys.length; i++) {
        publicData.commitments[i] = participantPrivateData[i].session.commitment;
      }

      // -----------------------------------------------------------------------
      // Step 7: Get nonces (communication round 3)
      // Now that everybody has commited to the session, the nonces (R_i) can be
      // exchanged. Again, this is simulated by copying.
      // -----------------------------------------------------------------------
      for (let i = 0; i < publicData.pubKeys.length; i++) {
        publicData.nonces[i] = participantPrivateData[i].session.nonce;
      }

      // -----------------------------------------------------------------------
      // Step 8: Combine nonces
      // The nonces can now be combined into R. Each participant should do this
      // and keep track of whether the nonce was negated or not. This is needed
      // for the later steps.
      // -----------------------------------------------------------------------
      publicData.nonceCombined = muSig.sessionNonceCombine(signerSession, publicData.nonces);
      participantPrivateData.forEach(data => (data.session.nonceIsNegated = signerSession.nonceIsNegated));

      // -----------------------------------------------------------------------
      // Step 9: Generate partial signatures
      // Every participant can now create their partial signature s_i over the
      // given message.
      // -----------------------------------------------------------------------
      participantPrivateData.forEach(data => {
        data.session.partialSignature = muSig.partialSign(data.session, publicData.message, publicData.nonceCombined, publicData.pubKeyCombined);
      });

      // -----------------------------------------------------------------------
      // Step 10: Exchange partial signatures (communication round 4)
      // The partial signature of each signer is exchanged with the other
      // participants. Simulated here by copying.
      // -----------------------------------------------------------------------
      for (let i = 0; i < publicData.pubKeys.length; i++) {
        publicData.partialSignatures[i] = participantPrivateData[i].session.partialSignature;
      }

      // -----------------------------------------------------------------------
      // Step 11: Verify individual partial signatures
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
      // Step 12: Combine partial signatures
      // Finally, the partial signatures can be combined into the full signature
      // (s, R) that can be verified against combined public key P.
      // -----------------------------------------------------------------------
      publicData.signature = muSig.partialSigCombine(publicData.nonceCombined, publicData.partialSignatures);

      // -----------------------------------------------------------------------
      // Step 13: Verify signature
      // The resulting signature can now be verified as a normal Schnorr
      // signature (s, R) over the message m and public key P.
      // -----------------------------------------------------------------------
      schnorr.verify(publicData.pubKeyCombined, publicData.message, publicData.signature);
    });
  });
});
