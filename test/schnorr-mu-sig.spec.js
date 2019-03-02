/* global describe, it, beforeEach */
const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const convert = require('../src/convert');
const muSig = require('../src/mu-sig');
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
          Buffer.from('031a15f301cdc7c4c27e90e52c2b9ffce69630b54f06973c72579ed76cc3070d1b', 'hex'),
          Buffer.from('03f6b7c559c3a141d8b80ab3f85f971490f4ddf34946821587bb2f3a80a5b6cf1a', 'hex'),
          Buffer.from('028f53c4cd3188f264552320f11a513a09dd54c9b76e9b0cc118abcd88434a5bc0', 'hex'),
        ],
        message: Buffer.from('746869735f636f756c645f62655f7468655f686173685f6f665f615f6d736721', 'hex'), // TODO convert.hash(Buffer.from('muSig is awesome!', 'utf8')),
        pubKeyHash: null,
        pubKeyCombined: null,
        commitments: [],
        nonceCommitmentsHash: null,
        nonces: [],
        combinedNonce: null,
      };

      // data only known by the individual party, these values are never shared
      // between the signers!
      const signerPrivateData = [
        // signer 1
        {
          privateKey: BigInteger.fromHex('7982698434d4391b0ccda4171a6d16e8a45183651215a350754e12339292a3bb'),
          sessionId: Buffer.from('4575dfd17dd2c1b93e85770f90b9832fc542d61bfb4570baa35d0cb83d73b3ec', 'hex'), // TODO remove
          session: null,
        },
        // signer 2
        {
          privateKey: BigInteger.fromHex('4c3f608dedb0a12eb449782691b4a0e4a55c8202286b6dc1cb61faba46582e51'),
          sessionId: Buffer.from('34cc0d68a6d58342f7a8a935b3badc8e0c77e0baf1725a11689225e593313f54', 'hex'), // TODO remove
          session: null,
        },
        // signer 3
        {
          privateKey: BigInteger.fromHex('d4c3ea5563b7e4e7075707b7f6e7ac3222d11a005d28d35b6cdbffb78c49441f'),
          sessionId: Buffer.from('e9f349ae06dcfa12956df19b9f6cc549ef092478ce32de889790e94d6d9eef8e', 'hex'), // TODO remove
          session: null,
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
        // TODO const sessionId = randomBuffer(32); // must never be reused between sessions!
        const sessionId = data.sessionId;
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
      }

      // Step 4: Get nonce commitments hash
      publicData.nonceCommitmentsHash = convert.hash(concat(publicData.commitments));

      // Step 5: Get nonces (communication round 2)
      for (let i = 0; i < publicData.pubKeys.length; i++) {
        publicData.nonces[i] = signerPrivateData[i].session.nonce;
      }

      // Step 6: Combine nonces
      publicData.combinedNonce = muSig.sessionCombineNonces(publicData.nonces);

      // Step 7: Generate partial signatures
      signerPrivateData.forEach((data, idx) => {

      });
    });
  });
});
