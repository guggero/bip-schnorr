const schnorr = require('../src/schnorr');
const Benchmark = require('benchmark');
const microtime = require('microtime');
const randomBytes = require('random-bytes');
const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const ecurve = require('ecurve');

const BATCH_SIZES = [1, 2, 4, 8, 16, 32, 64];
const curve = ecurve.getCurveByName('secp256k1');
const G = curve.G;
const n = curve.n;

let startTime = 0;
let numberOfRuns = 0;
let processedSignatures = 0;

function benchmarkSign(size, privateKeys, messages) {
  return function () {
    try {
      for (let i = 0; i < size; i++) {
        const result = schnorr.sign(privateKeys[i], messages[i]);
        if (!result || result.length !== 64) {
          console.error('Signing failed!');
        }
      }
      processedSignatures += size;
      numberOfRuns++;
    } catch (e) {
      console.error(e);
    }
  };
}

function benchmarkVerify(size, publicKeys, messages, signatures) {
  return function () {
    try {
      for (let i = 0; i < size; i++) {
        schnorr.verify(publicKeys[i], messages[i], signatures[i]);
      }
      processedSignatures += size;
      numberOfRuns++;
    } catch (e) {
      console.error(e);
    }
  };
}

function benchmarkBatchVerify(size, publicKeys, messages, signatures) {
  return function () {
    try {
      schnorr.batchVerify(publicKeys, messages, signatures);
      processedSignatures += size;
      numberOfRuns++;
    } catch (e) {
      console.error(e);
    }
  };
}

function benchmarkNaiveKeyAggregation(size, privateKeys, messages) {
  return function () {
    try {
      const result = schnorr.naiveKeyAggregation(privateKeys, messages[0]);
      if (!result || result.length !== 64) {
        console.error('Aggregating signatures failed!');
      }
      processedSignatures += size;
      numberOfRuns++;
    } catch (e) {
      console.error(e);
    }
  }
}

function benchmarkMuSigNoInteractive(size, privateKeys, messages) {
  return function () {
    try {
      const result = schnorr.muSigNonInteractive(privateKeys, messages[0]);
      if (!result || result.length !== 64) {
        console.error('Aggregating signatures failed!');
      }
      processedSignatures += size;
      numberOfRuns++;
    } catch (e) {
      console.error(e);
    }
  }
}

const randomInt = (len) => BigInteger.fromBuffer(Buffer.from(randomBytes.sync(len))).mod(n);
const randomBuffer = (len) => Buffer.from(randomBytes.sync(len));

const onStart = () => {
  startTime = microtime.now();
  processedSignatures = 0;
  numberOfRuns = 0;
};
const onComplete = (event) => {
  const elapsedTime = microtime.now() - startTime;
  const signaturesPerSecond = Math.round(processedSignatures / (elapsedTime / 1000000));
  const microsecondsPerRun = Math.round(elapsedTime / numberOfRuns);
  console.log(`${event.target} ${microsecondsPerRun} us/op ${signaturesPerSecond} sig/s`);
};

// Sign
BATCH_SIZES.forEach(size => {
  const privateKeys = new Array(size);
  const messages = new Array(size);
  for (let i = 0; i < size; i++) {
    privateKeys[i] = randomInt(32);
    messages[i] = randomBuffer(32);
  }
  new Benchmark('Sign (batch size: ' + size + ')', benchmarkSign(size, privateKeys, messages), {
    onStart,
    onComplete,
  }).run();
});

// Verify
BATCH_SIZES.forEach(size => {
  const privateKeys = new Array(size);
  const publicKeys = new Array(size);
  const messages = new Array(size);
  const signatures = new Array(size);
  for (let i = 0; i < size; i++) {
    privateKeys[i] = randomInt(32);
    publicKeys[i] = G.multiply(privateKeys[i]).getEncoded(true);
    messages[i] = randomBuffer(32);
    signatures[i] = schnorr.sign(privateKeys[i], messages[i]);
  }
  new Benchmark('Verify (batch size: ' + size + ')', benchmarkVerify(size, publicKeys, messages, signatures), {
    onStart,
    onComplete,
  }).run();
});

// Batch Verify
BATCH_SIZES.forEach(size => {
  const privateKeys = new Array(size);
  const publicKeys = new Array(size);
  const messages = new Array(size);
  const signatures = new Array(size);
  for (let i = 0; i < size; i++) {
    privateKeys[i] = randomInt(32);
    publicKeys[i] = G.multiply(privateKeys[i]).getEncoded(true);
    messages[i] = randomBuffer(32);
    signatures[i] = schnorr.sign(privateKeys[i], messages[i]);
  }
  new Benchmark('Batch Verify (batch size: ' + size + ')', benchmarkBatchVerify(size, publicKeys, messages, signatures), {
    onStart,
    onComplete,
  }).run();
});

// Aggregate Signatures (naive)
BATCH_SIZES.forEach(size => {
  const privateKeys = new Array(size);
  const publicKeys = new Array(size);
  const messages = new Array(size);
  const signatures = new Array(size);
  for (let i = 0; i < size; i++) {
    privateKeys[i] = randomInt(32);
    publicKeys[i] = G.multiply(privateKeys[i]).getEncoded(true);
    messages[i] = randomBuffer(32);
    signatures[i] = schnorr.sign(privateKeys[i], messages[i]);
  }
  new Benchmark('Aggregate Signatures naive (batch size: ' + size + ')', benchmarkNaiveKeyAggregation(size, privateKeys, messages), {
    onStart,
    onComplete,
  }).run();
});

// Aggregate Signatures (MuSig non-interactive)
BATCH_SIZES.forEach(size => {
  const privateKeys = new Array(size);
  const publicKeys = new Array(size);
  const messages = new Array(size);
  const signatures = new Array(size);
  for (let i = 0; i < size; i++) {
    privateKeys[i] = randomInt(32);
    publicKeys[i] = G.multiply(privateKeys[i]).getEncoded(true);
    messages[i] = randomBuffer(32);
    signatures[i] = schnorr.sign(privateKeys[i], messages[i]);
  }
  new Benchmark('Aggregate Signatures MuSig non-interactive (batch size: ' + size + ')', benchmarkMuSigNoInteractive(size, privateKeys, messages), {
    onStart,
    onComplete,
  }).run();
});
