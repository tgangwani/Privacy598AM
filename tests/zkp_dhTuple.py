#!/usr/bin/env python

import sys
sys.path.append('../')
sys.path.append('../elliptic-curves-finite-fields')
import random
from curveParams import G, order
from zkplib import dhTuple as zkp_dhTuple

def run():
    # generate secret-key
    sk = random.randint(0, order) 
    pk = sk*G 

    secret = random.randint(0, order)
    secret2 = random.randint(0, order)

    # correct tuple
    #dhtuple = (G, pk, secret*G, secret*pk)

    # incorrect tuple
    dhtuple = (G, pk, secret*G, secret2*pk)

    prf = zkp_dhTuple.gen_prf(dhtuple, pid=0, secret=secret)
    success = zkp_dhTuple.verify_prf(dhtuple, pid=0, **prf)

    print("ZKP verification %s."%('Passed' if success is True else 'Failed'))

if __name__=="__main__":
    run()
