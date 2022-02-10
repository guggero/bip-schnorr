const Buffer = require('safe-buffer').Buffer;
const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');
const math = require('./math');
const convert = require('./convert');

const concat = Buffer.concat;
const G = curve.G;

function taprootConstruct(pubKey, scripts) {
  const Px = convert.intToBuffer(pubKey.affineX);

  // If the spending conditions do not require a script path, the output key should commit to an unspendable script path
  // instead of having no script path. This can be achieved by computing the output key point as
  // Q = P + int(hashTapTweak(bytes(P)))G.
  // https://en.bitcoin.it/wiki/BIP_0341#cite_note-22
  if (!scripts) {
    scripts = [Px];
  }
  const h = taprootTree(scripts);
  const P = math.liftX(Px);
  const tweak = convert.bufferToInt(math.taggedHash('TapTweak', concat([Px, h])));
  const Q = P.add(G.multiply(tweak));
  return convert.intToBuffer(Q.affineX);
}

function taprootTree(scripts) {
  let h = Buffer.alloc(32, 0);
  if (scripts.length === 1 && scripts[0].length === 32) {
    return scripts[0];
  }

  return h;
}

module.exports = {
  taprootConstruct,
};
