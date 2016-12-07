#!/usr/bin/env python

import sys
sys.path.append('../')
sys.path.append('../elliptic-curves-finite-fields')
import random
import math
from curveParams import G, I, order
from elgamal import elgamal_encrypt
from zkplib import rangeProof as zkp_range

def run():
    # generate secret-key
    sk = random.randint(0, order) 
    pk = sk*G 

    # message to encrypt
    m = int(1)
    m2 = int(3)
    mmax = 2
    # point on the curve corresponding to the message
    m_point = m * G
    m2_point = m2 * G

    # generate secret randomness
    L = math.ceil(math.log2(mmax))
    secrets = []
    for l in range(L):
        r = random.randint(0, order)
        secrets.append(r)

    r = 0
    for l in range(L):
        r += 2**(L - 1 - l)*secrets[l]

    (c1, c2) = elgamal_encrypt(pk, r, m_point)
    (c21, c22) = elgamal_encrypt(pk, r, m2_point)
    prf = zkp_range.gen_prf(c1, c2, pid=0, message=m, secrets=secrets, pubkey=pk, bound=mmax)
    prf2 = zkp_range.gen_prf(c21, c22, pid=1, message=m, secrets=secrets, pubkey=pk, bound=mmax)
    success = zkp_range.verify_prf(c1, c2, pid=0, pubkey=pk, bound=mmax, **prf)
    success2 = zkp_range.verify_prf(c21, c22, pid=1, pubkey=pk, bound=mmax, **prf2)

    print("ZKP verification 0 %s."%('Passed' if success is True else 'Failed'))
    print("ZKP verification 1 %s."%('Passed' if success2 is True else 'Failed'))

if __name__=="__main__":
    run()
