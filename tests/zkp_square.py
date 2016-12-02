#!/usr/bin/env python

import sys
sys.path.append('../')
sys.path.append('../elliptic-curves-finite-fields')
import random
from curveParams import G, order
from elgamal import elgamal_encrypt
from zkplib import square as zkp_square

def run():
    # generate secret-key
    sk = random.randint(0, order) 
    pk = sk*G 

    m = int(42)
    m_point = m * G
    r_m = random.randint(0, order) # secret for m

    m_sq = m**2 
    m_sq_point = m_sq * G
    r_m_sq = random.randint(0, order) # secret for m_sq 

    # ElGamal encryptions
    E_m = elgamal_encrypt(pk, r_m, m_point)
    E_m_sq = elgamal_encrypt(pk, r_m_sq, m_sq_point) 

    prf = zkp_square.gen_prf(E_m, E_m_sq, pid=0, secret1=r_m,
            secret2=r_m_sq, message=m, pubkey=pk)

    success = zkp_square.verify_prf(E_m, E_m_sq, pid=0, pubkey=pk, **prf)

    print("ZKP verification %s."%('Passed' if success is True else 'Failed'))

if __name__=="__main__":
    run()
