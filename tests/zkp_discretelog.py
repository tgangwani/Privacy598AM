#!/usr/bin/env python

import sys
sys.path.append('../')
sys.path.append('../elliptic-curves-finite-fields')
import random
from curveParams import G, order
from zkplib import discretelog as zkp_discretelog

def run():
    # generate secret-key
    sk = random.randint(0, order) 
    pk = sk*G 

    prf = zkp_discretelog.gen_prf(sk, pk, pid=0)
    success = zkp_discretelog.verify_prf(pk, pid=0, **prf)

    print("ZKP verification %s."%('Passed' if success is True else 'Failed'))

if __name__=="__main__":
    run()
