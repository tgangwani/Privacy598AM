#!/usr/bin/env python 
# This file implements one out of two proof of knowledge. The structure of the
# proof is taken from Figure 1 at
# http://homepages.cs.ncl.ac.uk/feng.hao/files/OpenVote_IET.pdf

import logging
import sys, os
import random
from curveParams import G, order
from Crypto.Hash import SHA256                                    

logger = logging.getLogger('Main.zkp_oneOutOfTwo')

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
        secret = kwargs['secret']
        pk = kwargs['pubkey']
    except:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        sys.exit(1)
    
    logger.info("Generating one out of two ZKP for participant id {}".format(pid))
    w = random.randint(0, order)

    if v == 1:
        r1, d1 = random.randint(0, order), random.randint(0, order)
        a1 = r1*G + d1*x
        b1 = r1*pk + d1*y
        a2 = w*G
        b2 = w*pk
    else:
        r2, d2 = random.randint(0, order), random.randint(0, order)
        a1 = w*G
        b1 = w*pk
        a2 = r2*G + d2*x
        b2 = r2*pk + d2*(y-G)
    
    # generate crs using SHA256
    crs = ''.join([str(_) for _ in [pid, x, y, a1, b1, a2, b2]])
    c = int(SHA256.new(crs.encode('utf-8')).hexdigest(),16) % order

    if v == 1:
        d2 = c - d1
        r2 = w - secret*d2
    else:
        d1 = c - d2
        r1 = w - secret*d1

    return {'r1':r1, 'r2':r2, 'a1':a1, 'b1':b1, 'a2':a2, 'b2':b2, 'd1':d1, 'd2':d2} 

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
        r1 = kwargs['r1']
        r2 = kwargs['r2']
        a1 = kwargs['a1']
        b1 = kwargs['b1']
        a2 = kwargs['a2']
        b2 = kwargs['b2']
        d1 = kwargs['d1']
        d2 = kwargs['d2']
    except:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        sys.exit(1)
    
    logger.info("Verifying one out of two ZKP from participant id {}".format(pid))

    # generate crs using SHA256
    crs = ''.join([str(_) for _ in [pid, x, y, a1, b1, a2, b2]])
    c = int(SHA256.new(crs.encode('utf-8')).hexdigest(),16) % order

    # check statements
    if c != d1 + d2:
        return False

    if a1 != r1*G + d1*x:
        return False

    if b1 != r1*pk + d1*y:
        return False

    if a2 != r2*G + d2*x:
        return False

    if b2 != r2*pk + d2*(y-G):
        return False

    # ZKP successful verification
    return True
