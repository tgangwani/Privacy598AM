#!/usr/bin/env python
# Given A = E(a), B = E(a^2), where E. donotes ElGamal encryption, the
# prover uses this proof to prove that B encrypts the square of the preimage of
# A, without revealing anything about the preimage. The structure of the proof
# is taken from "Collaborative Filtering with Privacy" by Canny

import logging
import sys, os
import random
from elgamal import elgamal_encrypt
from curveParams import G, order
from Crypto.Hash import SHA256                                    

logger = logging.getLogger('Main.zkp_square')

def gen_prf(*args, **kwargs) -> 'dict':
    """
    Generate proof of square relation between preimages of two ElGamal
    encrytions
    Positional args : tuple(A1, A2), tuple(B1, B2) - ElGamal encryptions
    Keyword args - as below
    """

    try:
        (A1, A2) = args[0]
        (B1, B2) = args[1]
        pid = kwargs['pid']
        s_a = kwargs['secret1']
        s_b = kwargs['secret2']
        a = kwargs['message']
        pk = kwargs['pubkey']
    except:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        sys.exit(1)
    
    logger.info("Generating proof of square relation for participant id {}".format(pid))
    
    # Canny, step1 
    x, r_a, r_b = random.randint(0, order), random.randint(0, order), random.randint(0, order)
    (C_a1, C_a2) = elgamal_encrypt(pk, r_a, x*G)
    (C_b1, C_b2) = elgamal_encrypt(pk, r_b, 0*G)
    (C_b1, C_b2) = (C_b1 + x*A1, C_b2 + x*A2) 

    # generate crs using SHA256
    crs = ''.join([str(_) for _ in [pid, A1, A2, B1, B2, C_a1, C_a2, C_b1, C_b2]])
    c = int(SHA256.new(crs.encode('utf-8')).hexdigest(),16) % order

    # Canny, step3
    v = (c*a + x) % order
    z_a = (c*s_a + r_a) % order
    z_b = (c*(s_b - a*s_a) + r_b) % order

    return {'C_a':(C_a1, C_a2), 'C_b':(C_b1, C_b2), 'v':v, 'z_a':z_a, 'z_b':z_b}

def verify_prf(*args, **kwargs) -> 'bool':
    """
    Verification of ZKP for square relation between preimages
    Positional args : tuple(A1, A2), tuple(B1, B2) - ElGamal encryptions
    Keyword args - as below
    """

    try:
        (A1, A2) = args[0]
        (B1, B2) = args[1]
        pid = kwargs['pid']
        pk = kwargs['pubkey']
        (C_a1, C_a2) = kwargs['C_a']
        (C_b1, C_b2) = kwargs['C_b']
        v = kwargs['v']
        z_a = kwargs['z_a']
        z_b = kwargs['z_b']
    except:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        sys.exit(1)
    
    logger.info("Verifying ZKP for square relation for participant id {}".format(pid))

    # generate crs using SHA256
    crs = ''.join([str(_) for _ in [pid, A1, A2, B1, B2, C_a1, C_a2, C_b1, C_b2]])
    c = int(SHA256.new(crs.encode('utf-8')).hexdigest(),16) % order
     
    # Canny, step4
    (e1, e2) = elgamal_encrypt(pk, z_a, v*G)
    (f1, f2) = elgamal_encrypt(pk, z_b, 0*G)

    # check statements
    if e1 !=  c*A1 + C_a1:
        return False

    if e2 != c*A2 + C_a2:
        return False

    if f1 + v*A1 != c*B1 + C_b1:
        return False

    if f2 + v*A2 != c*B2 + C_b2:
        return False

    # ZKP successful verification
    return True
