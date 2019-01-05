const schnorr = require('./bip-schnorr');

module.exports = {
  version: schnorr.VERSION,
  sign: schnorr.sign,
  verify: schnorr.verify,
  batchVerify: schnorr.batchVerify,
};
