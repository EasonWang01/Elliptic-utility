
# Install
```
yarn add elliptic-utility
```

# Usage
```js
const Elliptic = require('elliptic-utility').Elliptic
const BigInteger = require('elliptic-utility').BigInteger
```

```js
const ecparams = Elliptic.getSECCurveByName("secp256k1");
const curve = ecparams.getCurve();
```


# API
  #### Elliptic
  - FieldElementFp: { [Function] fastLucasSequence: [Function] },
  - PointFp: { [Function] decodeFrom: [Function] },
  - CurveFp: [Function],
  - fromHex: [Function],
  - integerToBytes: [Function],
  - X9Parameters: [Function],
  - secNamedCurves: { secp256k1: [Function: secp256k1] },
  - getSECCurveByName: [Function] }

  #### BigInteger
  - ZERO: BigInteger { t: 0, s: 0 },
  - ONE: BigInteger { '0': 1, t: 1, s: 0 },
  - valueOf: [Function: nbv],
  - fromByteArrayUnsigned: [Function],
  - fromByteArraySigned: [Function] }
  #### Instance
  ```
Instance
add
and
andNot
bitCount
byteCount
byteValue
clearBit
clone
divide
divideAndRemainder
equals
flipBit
gcd
getLowestSetBit
intValue
max
min
modInverse
modPow
multiply
not
or
pow
remainder
setBit
shiftLeft
shiftRight
shortValue
signum
subtract
testBit
toByteArray
toBuffer
toHex
xor
  ```
