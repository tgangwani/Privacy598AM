#!/usr/bin/env python
# Utility functions

from curveParams import G
import math

def baby_giant(beta : 'Point') -> 'int':
    """
    Shanks' algorithm for computing the discrete log, i.e.
    A value x satisfying G^x = beta
    """
    import sys

    factor = (-baby_giant.m)*G
    gamma = beta
    for i in range(baby_giant.m):
        if gamma in baby_giant.hashtable.keys():
            return i*baby_giant.m + baby_giant.hashtable[gamma]

        gamma -= baby_giant.m*G 

    # raise exception
    print('Failure in baby_giant! Could not compute discrete log.')
    sys.exit(1)

def init_baby_giant(ulimit : 'int'):
    """
    Fill the hashtable for baby_giant. Only values till ulimit are checked in
    the algorithm
    """
    global baby_giant
    baby_giant.hashtable = dict()
    baby_giant.m = math.ceil(math.sqrt(ulimit))
    
    for j in range(0, baby_giant.m):
        baby_giant.hashtable[j*G] = j
