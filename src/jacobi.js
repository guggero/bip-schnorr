const BigInteger = require('bigi');

const zero = BigInteger.ZERO;
const one = BigInteger.ONE;
const two = BigInteger.valueOf(2);
const three = BigInteger.valueOf(3);
const four = BigInteger.valueOf(4);
const five = BigInteger.valueOf(5);
const eight = BigInteger.valueOf(8);

function jacobi(a, b) {
  if (b.signum() <= 0 || b.mod(two).equals(zero)) {
    return 0;
  }
  let j = 1;
  if (a.signum() < 0) {
    a = a.negate();
    if (b.mod(four).equals(three)) {
      j = -j;
    }
  }
  while (!a.equals(zero)) {
    while (a.mod(two).equals(zero)) {
      a = a.divide(two);
      const bMod8 = b.mod(eight);
      if (bMod8.equals(three) || bMod8.equals(five)) {
        j = -j;
      }
    }
    let c = b;
    b = a;
    a = c;
    if (a.mod(four).equals(three) && b.mod(four).equals(three)) {
      j = -j;
    }
    a = a.mod(b);
  }
  if (b.equals(one)) {
    return j;
  }
  return 0;
}

module.exports = jacobi;
