/* global describe, it, beforeEach */
const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const convert = require('../src/convert');
const muSig = require('../src/mu-sig');
const ecurve = require('ecurve');
const randomBytes = require('random-bytes');

const curve = ecurve.getCurveByName('secp256k1');
const G = curve.G;

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
          Buffer.from('02d6a547d1e4d4478f7875bb5a3bfc2cd1051af6c3030f1dea85980410d69e4d26', 'hex'),
          Buffer.from('0270ac05596bef45b09d99b88a7a914450293dba1ba1f8368d50bc6b0c19ad20d7', 'hex'),
          Buffer.from('025bcc6d9ea5be8bdc34f01f28413942af0d7f72997ec393f5b15d103e0dbcefeb', 'hex'),
        ],
        message: convert.hash(Buffer.from('muSig is awesome!', 'utf8')),
        pubKeyHash: null,
        pubKeyCombined: null,
        commitments: [],
        nonces: []
      };

      // data only known by the individual party, these values are never shared
      // between the signers!
      const signerPrivateData = [
        // signer 1
        {
          privateKey: BigInteger.fromHex('bebb86c4a1562ad2c58e3ef534e15e5d712dc7cb83f50855366e8e659c4f5403'),
          session: null,
        },
        // signer 2
        {
          privateKey: BigInteger.fromHex('2871a7bf5ecf8cf2c07c735ab3ce997ecd3c1163f566648464b560e91f58a8ff'),
          session: null,
        },
        // signer 3
        {
          privateKey: BigInteger.fromHex('2bfcb47df62a2a4b1bed0a29378a92f3e851a13e0064dcdbdb5851ec29664d98')
          session: null,
        }
      ];

      // -----------------------------------------------------------------------
      // Step 1: Combine the public keys
      // This can be done by every signer individually or by the initializing
      // party and then be distributed to every participant.
      // -----------------------------------------------------------------------
      publicData.pubKeyHash = muSig.computeEll(publicData.pubKeys);
      publicData.pubKeyCombined = muSig.pubKeyCombine(publicData.pubKeys, publicData.pubKeyHash);

      // -----------------------------------------------------------------------
      // Step 2: Create the private signing session
      // Each signing party does this in private.
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

      // -----------------------------------------------------------------------
      // Step 3: Exchange commitments
      // The signers now exchange the commitments. This is simulated here by
      // copying the values from the private data to public data array.
      // -----------------------------------------------------------------------
      for (let i = 0; i < publicData.pubKeys.length; i++) {
        publicData.commitments[i] = signerPrivateData[i].session.commitment;
      }
    });
  });
});
