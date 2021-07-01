/* global describe, it, beforeEach */
const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const schnorr = require('../src/schnorr');
const ecurve = require('ecurve');

const curve = ecurve.getCurveByName('secp256k1');
const n = curve.n;

const testVectors = require('./test-vectors-schnorr.json');

function assertError(error, expectedMessage) {
  assert.strictEqual(error.message, expectedMessage);
}

describe('edge cases', () => {
  const positiveTestVectors = testVectors.filter(vec => vec.result);
  const vec = positiveTestVectors[0];
  const pubKey = Buffer.from(vec.pk, 'hex');
  const m = Buffer.from(vec.m, 'hex');
  const sig = Buffer.from(vec.sig, 'hex');

  describe('sign', () => {
    it('can check sign params', () => {
      try { schnorr.sign('foo', m); } catch (e) { assertError(e, 'privateKey must be a BigInteger or valid hex string'); }
      try { schnorr.sign('abdcefg', m) } catch(e) { assertError(e, 'privateKey must be a BigInteger or valid hex string') };
      try { schnorr.sign('@!$%', m) } catch(e) { assertError(e, 'privateKey must be a BigInteger or valid hex string') };
      try { schnorr.sign(BigInteger.valueOf(1), 'foo'); } catch (e) { assertError(e, 'message must be a Buffer'); }
      try { schnorr.sign(BigInteger.valueOf(1), Buffer.from([])); } catch (e) { assertError(e, 'message must be 32 bytes long'); }
      try { schnorr.sign(BigInteger.valueOf(0), m); } catch (e) { assertError(e, 'privateKey must be an integer in the range 1..n-1'); }
      try { schnorr.sign(BigInteger.valueOf(0), m); } catch (e) { assertError(e, 'privateKey must be an integer in the range 1..n-1'); }
      try { schnorr.sign(n, m); } catch (e) { assertError(e, 'privateKey must be an integer in the range 1..n-1'); }
    });
    it('can sign example code in README', () => {
      const privateKey = BigInteger.fromHex('B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF');
      const privateKeyHexString = 'B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF';
      const message = Buffer.from('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', 'hex');
      const signatureToVerify = Buffer.from('6D461BEB2F2DA00027D884FD13A24E2AE85CAECCA8AAA2D41777217EC38FB4960A67D47BC4F0722754EDB0E9017072600FFE4030C2E73771DCD3773F46A62652', 'hex');

      const createdSignature = schnorr.sign(privateKey, message);
      const createdSignatureFromPrivKeyString = schnorr.sign(privateKeyHexString, message);
      assert.strictEqual(createdSignature.toString('hex'), signatureToVerify.toString('hex'));
      assert.strictEqual(createdSignatureFromPrivKeyString.toString('hex'), signatureToVerify.toString('hex'));
    });
  });

  describe('verify', () => {
    it('can check verify params', () => {
      // when / then
      try { schnorr.verify('foo', m, sig); } catch (e) { assertError(e, 'pubKey must be a Buffer'); }
      try { schnorr.verify(Buffer.from([]), m, sig); } catch (e) { assertError(e, 'pubKey must be 32 bytes long'); }
      try { schnorr.verify(pubKey, 'foo', sig); } catch (e) { assertError(e, 'message must be a Buffer'); }
      try { schnorr.verify(pubKey, m, 'foo'); } catch (e) { assertError(e, 'signature must be a Buffer'); }
      try { schnorr.verify(pubKey, m.slice(0, 16), sig); } catch (e) { assertError(e, 'message must be 32 bytes long'); }
      try { schnorr.verify(pubKey, m, sig.slice(32)); } catch (e) { assertError(e, 'signature must be 64 bytes long'); }
      try { schnorr.verify(pubKey.slice(16), m, sig); } catch (e) { assertError(e, 'pubKey must be 32 bytes long'); }
    });
    it('can verify example code in README', () => {
      const message = Buffer.from('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', 'hex');
      const signatureToVerify = Buffer.from('6D461BEB2F2DA00027D884FD13A24E2AE85CAECCA8AAA2D41777217EC38FB4960A67D47BC4F0722754EDB0E9017072600FFE4030C2E73771DCD3773F46A62652', 'hex');
      const publicKey = Buffer.from('DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659', 'hex');
      try {
        schnorr.verify(publicKey, message, signatureToVerify);
        console.log('The signatures are valid.');
      } catch (e) {
        assert.fail(e);
      }
    });
  });

  describe('batchVerify', () => {
    it('can check batch verify params', () => {
      // when / then
      try { schnorr.batchVerify([], [m], [sig]); } catch (e) { assertError(e, 'pubKeys must be an array with one or more elements'); }
      try { schnorr.batchVerify([pubKey], [], [sig]); } catch (e) { assertError(e, 'messages must be an array with one or more elements'); }
      try { schnorr.batchVerify([pubKey], [m], []); } catch (e) { assertError(e, 'signatures must be an array with one or more elements'); }
      try { schnorr.batchVerify([pubKey], [m], [sig, sig]); } catch (e) { assertError(e, 'all parameters must be an array with the same length'); }
      try { schnorr.batchVerify([pubKey], [m, m], [sig, sig]); } catch (e) { assertError(e, 'all parameters must be an array with the same length'); }
      try { schnorr.batchVerify([pubKey, pubKey], [m, m], [sig]); } catch (e) { assertError(e, 'all parameters must be an array with the same length'); }

      try { schnorr.batchVerify(['foo'], [m], [sig]); } catch (e) { assertError(e, 'pubKey[0] must be a Buffer'); }
      try { schnorr.batchVerify([pubKey], ['foo'], [sig]); } catch (e) { assertError(e, 'message[0] must be a Buffer'); }
      try { schnorr.batchVerify([pubKey], [m], ['foo']); } catch (e) { assertError(e, 'signature[0] must be a Buffer'); }
      try { schnorr.batchVerify([pubKey], [m.slice(0, 16)], [sig]); } catch (e) { assertError(e, 'message[0] must be 32 bytes long'); }
      try { schnorr.batchVerify([pubKey], [m], [sig.slice(32)]); } catch (e) { assertError(e, 'signature[0] must be 64 bytes long'); }
    });
    it('can batch verify example code in README', () => {
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
        assert.fail(e);
      }
    });
  });
});
