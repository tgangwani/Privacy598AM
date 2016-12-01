#!/usr/bin/env python
# A prover uses this proof to prove that she knows x, the discrete logarithm of
# y=g^x. The structure of the proof is taken from
# https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic

import logging
import sys, os
import random
from curveParams import G, order
from Crypto.Hash import SHA256                                    

logger = logging.getLogger('Main.zkp_discretelog')

def gen_prf(*args, **kwargs) -> 'dict':
    """
    Generate proof of knowledge of discrete log
    Positional args : (x, y=g^x) 
    Keyword args - as below
    """

    try:
        x = args[0]
        y = args[1]
        pid = kwargs['pid']
    except:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        sys.exit(1)

    logger.info("Generating proof of discrete log for participant id {}".format(pid))

    v = random.randint(0, order)
    t = v*G

    # generate crs using SHA256
    crs = ''.join([str(_) for _ in [pid, y, t]])
    c = int(SHA256.new(crs.encode('utf-8')).hexdigest(),16) % order

    r = v - c*x
    return {'t':t, 'r':r}

def verify_prf(*args, **kwargs) -> 'bool':
    """
    Verification of ZKP of discrete log
    Positional args : y=g^x
    Keyword args - as below
    """
    
    try:
        y = args[0]
        pid = kwargs['pid'] 
        t = kwargs['t']
        r = kwargs['r']
    except:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        sys.exit(1)

    logger.info("Verifying discrete log ZKP from participant id {}".format(pid))

    # generate crs using SHA256
    crs = ''.join([str(_) for _ in [pid, y, t]])
    c = int(SHA256.new(crs.encode('utf-8')).hexdigest(),16) % order
    
    # check statement
    if t != r*G + c*y:
        return False

    # ZKP successful verification
    return True
