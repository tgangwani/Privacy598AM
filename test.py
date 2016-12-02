#!/usr/bin/env python
# a test application 

from ledger import Ledger
from zorro import Zorro

def test_app():
    l = Ledger()
    g1 = [2, 3, 5]
    g2 = [1, 2, 2]
    g3 = [5, 4, 5]
    g_range = [0, 5]    # range of each element 
    g_length = 7    # length of the vector

    # Phase 0: initiate
    z1 = Zorro(l, 0, 3)
    #z2 = Zorro(l, 1, 3)
    #z3 = Zorro(l, 2, 3)

    print("Phase 1: commit...")
    # Phase 1: commit 
    if(l.phase('c') == 1):
        z1.commit(g1)
        #z2.commit(g2)
        #z3.commit(g3)
    else:
        print("Phase 1 failed!")

    print("Phase 2: proof...")
    # Phase 2: generate zkp proofs
    if(l.phase('p') == 1):
        z1.prove()
        #z2.prove()
        #z3.prove()
    else:
        print("Phase 2 failed!")

    print("Phase 3: results...")
    # Phase 3: get results
    if(l.phase('r') == 1):
        z1.results()
        #z2.results()
        #z3.results()
    else:
        print("Phase 3 failed!")

if __name__=="__main__":
    test_app()
