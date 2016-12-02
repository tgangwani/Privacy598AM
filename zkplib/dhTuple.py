#!/usr/bin/env python
# A prover uses this proof to prove that (g, h, u, v) is a Diffie-Hellman
# 4-tuple, which means that the prover knows a secret w, such that u = g^w,
# v=h^w

import logging
import sys, os
import random
from curveParams import order
from Crypto.Hash import SHA256                                    

logger = logging.getLogger('Main.zkp_dhTuple')

def gen_prf(dhtuple, **kwargs) -> 'dict':
    """
    Generate proof of DH 4-tuple
    dhtuple - (g, h, u, v)
    """

    try:
        (g, h, u, v) = dhtuple
        pid = kwargs['pid']
        w = kwargs['secret']
    except:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        sys.exit(1)

    logger.info("Generating proof of DH 4-tuple for participant id {}".format(pid))

    r = random.randint(0, order)
    a = r*g
    b = r*h

    # generate crs using SHA256
    crs = ''.join([str(_) for _ in [pid, a, b]])
    c = int(SHA256.new(crs.encode('utf-8')).hexdigest(),16) % order

    z = r + c*w
    return {'a':a, 'b':b, 'z':z}

def verify_prf(dhtuple, **kwargs) -> 'bool':
    """
    Verification of ZKP of DH 4-tuple
    dhtuple - (g, h, u, v)
    """

    try:
        (g, h, u, v) = dhtuple
        pid = kwargs['pid'] 
        a = kwargs['a']
        b = kwargs['b']
        z = kwargs['z']
    except:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        sys.exit(1)

    logger.info("Verifying DH 4-tuple ZKP from participant id {}".format(pid))

    # generate crs using SHA256
    crs = ''.join([str(_) for _ in [pid, a, b]])
    c = int(SHA256.new(crs.encode('utf-8')).hexdigest(),16) % order

    # check statments
    if z*g != a + c*u:
        return False

    if z*h != b + c*v:
        return False

    # ZKP successful verification
    return True
