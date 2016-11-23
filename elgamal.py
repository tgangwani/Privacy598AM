#!/usr/bin/env python
# Encrpytion and Decryption functions for ElGamal-ECC

import logging
from curveParams import G

# logger derived from the parent logger Main
logger = logging.getLogger('Main.elgamal')

def elgamal_encrypt(pk : 'public key', secret : 'random secret', message) -> '(g^secret, m * h^secret)':
    """
    Encryption method for ElGamal. Input parameters are the public key (h),
    randomness (secret) and the message to encrypt. Returns the ciphertext tuple
    (g^secret, m * h^secret)
    """
    logger.info("Elgamal encryption with pk:{} secret:{} message:{}".format(pk,
        secret, message))
    
    c1 = secret * G
    c2 = secret * pk + message 
    return (c1, c2)

def elgamal_decrypt(sk : 'secret key', c1, c2):
    """
    Decryption method for ElGamal. Input paramters are the secret key and the
    two pieces of cipher text. Returns the message (point on curve)
    """
    _c1 = sk * c1
    _c2 = c2 - _c1
    return _c2
