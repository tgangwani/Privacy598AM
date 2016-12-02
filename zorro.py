#!/usr/bin/env python

# the zorro client:
# 1. initiate the application 
# 2. encrypt inputs with elgamal
# 3. validate zkp1 and generate zkps for the input
# 4. validate zkps from the ledger, calculate the results

import random
from ledger import Ledger
from curveParams import G, I, order
from elgamal import elgamal_encrypt, elgamal_decrypt
from utils import init_baby_giant, baby_giant
from zkplib import discretelog as zkp_discretelog, dhTuple as zkp_dhTuple, oneOutOfTwo as zkp_oneOutOfTwo

class Zorro(object):
    def __init__(self, ledger, uid, length):
        self.ledger = ledger
        self.uid = uid
        self.len = length
        self.priv_key = random.randint(0,order)
        self.h = self.priv_key*G

    # Step 1: commit initial input to the ledger
    def commit(self, g):
        if(len(g) != self.len):
            print("invalid parameter length")
            return

        self.g = g
        self.sk_list = []
        self.pk_list = []
        zkp_discretelog_list = []
        for x in range(self.len):
            sk = random.randint(0,order)
            pk = sk*G
            self.sk_list.append(sk)
            self.pk_list.append(pk)
            zkp_discretelog_list.append(zkp_discretelog.gen_prf(sk, pk, pid=str(self.uid) + ":" + str(x)))

        if (self.ledger.zkp1(self.pk_list, zkp_discretelog_list, self.uid) == 0):
            print("Commit failed for {}".format(self.uid))

    # Step 2: generate proofs for the inputs
    def prove(self):
        if (self.ledger.cur_phase != 'p'):
            print("Not in proof phase!")
            return

        # verify zkp for discrete log
        all_pk_list = self.ledger.pk_list
        if (not self.check_zkp_discretelog(all_pk_list, self.ledger.zkp1_dict)):
            print("ZKP discrete log validation failed!")
            return

        # compute the encryption of g (equation 2)
        encrypted_g1 = []
        h_list = []
        for x in range(self.len):
            h = I
            for u in all_pk_list:
                if (u < self.uid):
                    h += all_pk_list[u][x]
                elif (u > self.uid):
                    h -= all_pk_list[u][x]
            h_list.append(h)
            encrypted_g1.append(self.g[x]*G + self.sk_list[x]*h)

        # compute another encryption of g, generate zkp for dhtuple (equation 3)
        encrypted_g2 = []
        zkp_dhtuple_list = []
        for x in range(self.len):
            encrypted_g2.append(self.g[x]*G + self.sk_list[x]*self.h)
            dhtuple = (G, h_list[x] - self.h, self.pk_list[x], encrypted_g1[x] - encrypted_g2[x])
            prf = zkp_dhTuple.gen_prf(dhtuple, pid=str(self.uid) + ":" + str(x), secret=self.sk_list[x])
            zkp_dhtuple_list.append(prf)

        if (self.ledger.zkp2(self.h, h_list, encrypted_g1, encrypted_g2, zkp_dhtuple_list, self.uid) == 0):
            print("Failed to upload ZKP of dhtuple for {}!".format(self.uid))
            return

        # generate square vector and its binary representation
        w = []
        s = 0
        for x in range(self.len):
            w.append(self.g[x]^2)
            s += w[x]
        sb_str = "{0:b}".format(s)
        print("Integer: {}, Binary: {}".format(str(s), sb_str))
        sb = []
        for c in sb_str:
            sb.append(int(c))
        s_new = 0
        L = len(sb)
        for x in range(L):
            s_new += sb[x] * 2**(L - 1 - x)
        assert s_new == s, "{}, {}".format(str(s_new), str(s))

        # encrypt the binary representation (equation 6), and generate zk01 for each binary value 
        encrypted_sb = []
        sk_list_sb = []
        pk_list_sb = []
        zkp01 = []
        for x in range(L):
            sk_sb = random.randint(0,order)
            pk_sb = sk_sb*G
            e = sb[x]*G + sk_sb*self.h
            prf = zkp_oneOutOfTwo.gen_prf(pk_sb, e, pid=str(self.uid) + ":" + str(x), message=sb[x], secret=sk_sb, pubkey=self.h)
            sk_list_sb.append(sk_sb)
            pk_list_sb.append(pk_sb)
            encrypted_sb.append(e)
            zkp01.append(prf)
        if (self.ledger.zkp3(encrypted_sb, pk_list_sb, zkp01, self.uid) == 0):
            print("Failed to upload ZKP01 for {}!".format(self.uid))
            return

    def check_zkp_discretelog(self, all_pk_list, all_zkp_discretelog) -> 'bool':
        print("Checking ZKP discrete log by {}".format(self.uid))
        assert len(all_pk_list) == len(all_zkp_discretelog)
        for u in all_pk_list:
            for x in range(self.len):
                if (not zkp_discretelog.verify_prf(all_pk_list[u][x], pid=str(u) + ":" + str(x), **all_zkp_discretelog[u][x])):
                    return False
        return True

    # Step 3: get results
    def results(self):
        assert self.check_zkp_dhtuple(self.ledger.pk, self.ledger.pk_list, self.ledger.h_list, self.ledger.encrypted_g1, self.ledger.encrypted_g2, self.ledger.zkp2_dict), "ZKP dhtuple validation failed!"
        assert self.check_zkp01(self.ledger.pk, self.ledger.pk_list_sb, self.ledger.encrypted_sb, self.ledger.zkp3_dict), "ZKP01 validation failed!"
        print(self.aggregate())

    def check_zkp_dhtuple(self, all_pk, all_pk_list, all_h_list, all_encrypted_g1, all_encrypted_g2, all_zkp_dhtuple) -> 'bool':
        print("Checking ZKP dhtuple by {}".format(self.uid))
        ucount = len(all_pk)
        assert len(all_h_list) == ucount
        assert len(all_encrypted_g1) == ucount
        assert len(all_encrypted_g2) == ucount
        assert len(all_zkp_dhtuple) == ucount
        for u in all_pk:
            for x in range(self.len):
                dhtuple = (G, all_h_list[u][x] - all_pk[u], all_pk_list[u][x], all_encrypted_g1[u][x] - all_encrypted_g2[u][x])
                if (not zkp_dhTuple.verify_prf(dhtuple, pid=str(u) + ":" + str(x), **all_zkp_dhtuple[u][x])):
                    return False
        return True

    def check_zkp01(self, all_pk, all_pk_list_sb, all_encrypted_sb, all_zkp01) -> 'bool':
        print("Checking ZKP01 by {}".format(self.uid))
        ucount = len(all_pk)
        assert len(all_encrypted_sb) == ucount
        assert len(all_pk_list_sb) == ucount
        assert len(all_zkp01) == ucount
        for u in all_pk:
            for x in range(self.len):
                if (not zkp_oneOutOfTwo.verify_prf(all_pk_list_sb[u][x], all_encrypted_sb[u][x], pid=str(self.uid) + ":" + str(x), pubkey=all_pk[u], **all_zkp01[u][x])):
                    return False
        return True

    def aggregate(self):
        return "Aggregated results"
