#!/usr/bin/env python
# This file defines the curve parameters for Elliptic Curve Cryptography

import sys
sys.path += ['elliptic-curves-finite-fields']
from finitefield.finitefield import FiniteField
from elliptic import GeneralizedEllipticCurve, Point, Ideal

## 
## This is the definition of secp256k1, Bitcoin's elliptic curve.
##

# First the finite field
q = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
Fq = FiniteField(q,1) # elliptic curve over F_q

# Then the curve, always of the form y^2 = x^3 + {a6}
curve = GeneralizedEllipticCurve(a6=Fq(7)) # E: y2 = x3+7

# base point, a generator of the group
Gx = Fq(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
Gy = Fq(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
G = Point(curve, Gx, Gy)
I = Ideal(curve)

# This is the order (# of elements in) the curve
p = order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Fp = FiniteField(p,1)
