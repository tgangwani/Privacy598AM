#!/usr/bin/env python

import os
import random
import logging
from curveParams import G, order
from elgamal import elgamal_encrypt, elgamal_decrypt

def setup_logging(logdir, loglevel=logging.DEBUG):
    global logger
    logdir = os.path.abspath(logdir)

    if not os.path.exists(logdir):
        os.mkdir(logdir)

    logger = logging.getLogger('Main')
    logger.setLevel(loglevel)

    # formatter
    log_formatter = logging.Formatter("%(name)s - %(levelname)s :: %(message)s")

    # handler
    handler = logging.FileHandler(os.path.join(logdir, "Main.log"), mode='w')
    handler.setFormatter(log_formatter)
    logger.addHandler(handler)

    logger.info("Logger initialized.")

def simpleElGamal():
    # generate secret-key
    sk = random.randint(0, order) 
    pk = sk*G 

    # generate secret randomness
    r = random.randint(0, order)

    # message to encrypt
    m = int(42)
    # point on the curve corresponding to the message
    m_point = m * G

    (c1, c2) = elgamal_encrypt(pk, r, m_point)
    logger.info("ElGamal ciphertext {}, {}".format(c1,c2)) 

    plaintext = elgamal_decrypt(sk, c1, c2)
    logger.info("ElGamal decrypted plaintext {}".format(plaintext))

    # plaintext recovered from ElGamal is a point on the curve. We need to solve
    # the discrete log problem to get the message - exhaustive search or
    # Baby/Giant
    assert plaintext == m_point

if __name__=="__main__":
    setup_logging('/tmp/logs')
    simpleElGamal()
