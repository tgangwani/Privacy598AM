#!/usr/bin/env python 
# This file implements the range prof using the oneOutOfTwo proof

import logging
import sys, os
import math
from curveParams import G, I, order
from elgamal import elgamal_encrypt
from zkplib import oneOutOfTwo as zkp_oneOutOfTwo                                    

logger = logging.getLogger('Main.zkp_range')

def gen_prf(*args, **kwargs) -> 'dict':
    """
    Generate proof that message \in {0,1}
    Positional args : (c1, c2) - ElGamal encryption of message
    Keyword args - as below
    """

    try:
        x = args[0]
        y = args[1]
        pid = kwargs['pid']
        v = kwargs['message']
        secrets = kwargs['secrets']
        pk = kwargs['pubkey']
        b = kwargs['bound']
    except:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        sys.exit(1)
    
    logger.info("Generating range ZKP for participant id {}".format(pid))

    # represent the original value in binary form 
    vb_str = "{0:b}".format(v)
    vb = []
    for c in vb_str:
        vb.append(int(c))
    v_new = 0
    L = len(vb)
    for l in range(L):
        v_new += vb[l] * 2**(L - 1 - l)
    assert v_new == v, "{}, {}".format(str(v_new), str(v))

    LB = math.ceil(math.log2(b))
    if L > LB:
    	print('Range Proof: input value {} exceeds bound {}'.format(v, b))
    	sys.exit(1)
    if len(secrets) < L:
    	print('Not enough secrets provided for proof: L = {}, number_of_secrets = {}'.format(L,len(secrets)))
    	sys.exit(1)

    vb_enc = []
    vb_prf = []
    for l in range(L):
    	bit = vb[l]
    	cbit = elgamal_encrypt(pk, secrets[l], bit * G)
    	(c1, c2) = cbit
    	prf = zkp_oneOutOfTwo.gen_prf(c1, c2, pid = pid, message = bit, secret = secrets[l], pubkey = pk)
    	vb_enc.append(cbit)
    	vb_prf.append(prf)
    return {'zkp01':vb_prf, 'encrypted_bits':vb_enc} 

def verify_prf(*args, **kwargs) -> 'bool':
    """
    Verification of ZKP that message \in {0,1}
    Positional args : (c1, c2) - ElGamal encryption of message
    Keyword args - as below
    """

    try:
        x = args[0]
        y = args[1]
        pid = kwargs['pid']
        pk = kwargs['pubkey']
        b = kwargs['bound']
        vb_prf = kwargs['zkp01']
        vb_enc = kwargs['encrypted_bits']
    except:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        sys.exit(1)
    
    logger.info("Verifying one out of two ZKP from participant id {}".format(pid))

    # verify that there are less than b bits
    L = len(vb_enc)
    LB = math.ceil(math.log2(b))
    if (L > LB):
    	print("{}: L = {}, bound on L = {}".format(pid, L, LB))
    	return False

    # check zkp01 for each bit
    if (len(vb_prf) < L):
    	return False
    for l in range(L):
    	(c1, c2) = vb_enc[l]
    	if (not zkp_oneOutOfTwo.verify_prf(c1, c2, pid = pid, pubkey = pk, **vb_prf[l])):
    		print("{}: ZKP one out of two failed!".format(pid))
    		return False

    # verify that the sum of bits equal to the encrypted value 
    vb_sum = I
    x_sum = I
    for l in range(L):
    	x_sum += 2**(L - 1 - l)*vb_enc[l][0]
    	vb_sum += 2**(L - 1 - l)*vb_enc[l][1]
    if (x != x_sum):
    	print('{}: Check sum failed for the first element in Elgamal'.format(pid))
    	return False
    if (y != vb_sum):
    	print('{}: Check sum failed for the second element in Elgamal'.format(pid))
    	return False

    # ZKP successful verification
    return True
