#!/usr/bin/env python

import sys
sys.path.append('../')
sys.path.append('../elliptic-curves-finite-fields')
import random
from curveParams import G, order
from elgamal import elgamal_encrypt
from zkplib import oneOutOfTwo as zkp_oneOutOfTwo

def run():
    # generate secret-key
    sk = random.randint(0, order) 
    pk = sk*G 

    # generate secret randomness
    r = random.randint(0, order)

    # message to encrypt
    m = int(1)
    # point on the curve corresponding to the message
    m_point = m * G

    (c1, c2) = elgamal_encrypt(pk, r, m_point)
    prf = zkp_oneOutOfTwo.gen_prf(c1, c2, pid=0, message=m, secret=r, pubkey=pk)
    success = zkp_oneOutOfTwo.verify_prf(c1, c2, pid=0, pubkey=pk, **prf)

    print("ZKP verification %s."%('Passed' if success is True else 'Failed'))

if __name__=="__main__":
    run()
