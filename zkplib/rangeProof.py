#!/usr/bin/env python 
# This file implements the range prof using the oneOutOfTwo proof

import logging
import sys, os
import math
import random
from curveParams import G, I, order
from elgamal import elgamal_encrypt
from zkplib import oneOutOfTwo as zkp_oneOutOfTwo, dhTuple as zkp_dhTuple                                

logger = logging.getLogger('Main.zkp_range')

def gen_prf(*args, **kwargs) -> 'dict':
    """
    Generate proof
    """

    try:
        (x,y) = args[0]
        pid = kwargs['pid']
        v = kwargs['message']
        secret = kwargs['secret']
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

    vb_enc = []
    vb_prf = []
    rsum = 0 # the randomness for the weighted sum
    # generate 1 out of 2 proofs
    for l in range(L):
    	bit = vb[l]
    	r = random.randint(0, order)
    	rsum += 2**(L-1-l)*r
    	cbit = elgamal_encrypt(pk, r, bit * G)
    	(c1, c2) = cbit
    	prf = zkp_oneOutOfTwo.gen_prf(c1, c2, pid = pid, message = bit, secret = r, pubkey = pk)
    	vb_enc.append(cbit)
    	vb_prf.append(prf)

    # generate dhtuple proof
    c1sum = I
    c2sum = I
    for l in range(L):
    	c1sum += 2**(L - 1 - l)*vb_enc[l][0]
    	c2sum += 2**(L - 1 - l)*vb_enc[l][1]
    dhtuple = (G, pk, x - c1sum, y - c2sum)
    dhtuple_prf = zkp_dhTuple.gen_prf(dhtuple, pid=pid, secret=secret - rsum)

    return {'zkp01':vb_prf, 'zkp_dhtuple':dhtuple_prf, 'encrypted_bits':vb_enc} 

def verify_prf(*args, **kwargs) -> 'bool':
    """
    Verification of ZKP 
    """

    try:
        (x,y) = args[0]
        pid = kwargs['pid']
        pk = kwargs['pubkey']
        b = kwargs['bound']
        vb_prf = kwargs['zkp01']
        vb_enc = kwargs['encrypted_bits']
        dhtuple_prf = kwargs['zkp_dhtuple']
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
    		print("{}: ZKP one out of two verification failed!".format(pid))
    		return False

    # verify that the sum of bits equal to the encrypted value 
    c1sum = I
    c2sum = I
    for l in range(L):
    	c1sum += 2**(L - 1 - l)*vb_enc[l][0]
    	c2sum += 2**(L - 1 - l)*vb_enc[l][1]

    dhtuple = (G, pk, x - c1sum, y - c2sum)
    if (not zkp_dhTuple.verify_prf(dhtuple, pid = pid, **dhtuple_prf)):
    	print("{}: ZKP dhtuple verification failed!".format(pid))
    	return False

    # ZKP successful verification
    return True
