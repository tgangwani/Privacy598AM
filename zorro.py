#!/usr/bin/env python

# the zorro client:
# 1. initiate the application 
# 2. encrypt inputs with elgamal
# 3. validate zkp1 and generate zkps for the input
# 4. validate zkps from the ledger, calculate the results

import random
import math
from ledger import Ledger
from curveParams import G, I, order
from elgamal import elgamal_encrypt, elgamal_decrypt
from utils import init_baby_giant, baby_giant
from zkplib import discretelog as zkp_discretelog, dhTuple as zkp_dhTuple, oneOutOfTwo as zkp_oneOutOfTwo, square as zkp_square, rangeProof as zkp_range

class Zorro(object):
    def __init__(self, ledger, uid, length, gmax, total_bound):
        self.ledger = ledger
        self.uid = uid
        self.priv_key = random.randint(0,order)
        self.h = self.priv_key*G
        self.gmax = gmax
        self.bound = total_bound
        self.lmax = math.ceil(math.log2(total_bound))
        self.len = length

    # Step 1: commit initial input to the ledger
    def commit(self, g):
        if(len(g) != self.len):
            print("invalid parameter length")
            return

        self.g = g

        # generate secret randomness for each value
        self.secrets = []
        for x in range(self.len):
            r = random.randint(0, order)
            self.secrets.append(r)

        zkp_discretelog_list = []
        self.pk_list = []
        for x in range(self.len):
            pk = self.secrets[x]*G
            self.pk_list.append(pk)
            zkp_discretelog_list.append(zkp_discretelog.gen_prf(self.secrets[x], pk, pid=str(self.uid) + ":" + str(x)))

        if (self.ledger.commit_zkp_discretelog(self.pk_list, zkp_discretelog_list, self.uid) == 0):
            print("Commit failed for {}".format(self.uid))

    # Step 2: generate proofs for the inputs
    def prove(self):
        if (self.ledger.cur_phase != 'p'):
            print("Not in proof phase!")
            return

        # verify zkp for discrete log
        if (not self.check_zkp_discretelog(self.ledger.pk_list, self.ledger.zkp_discretelog_dict)):
            print("ZKP discrete log validation failed!")
            return

        # compute the encryption of g (equation 2), which cancels after addition; generate range proof for each value of g
        encrypted_g1 = []
        h_list = []
        zkp_range_g1 = []
        for x in range(self.len):
            h = I
            for u in self.ledger.pk_list:
                if (u < self.uid):
                    h += self.ledger.pk_list[u][x]
                elif (u > self.uid):
                    h -= self.ledger.pk_list[u][x]
            h_list.append(h)
            c = elgamal_encrypt(h, self.secrets[x], self.g[x]*G)
            encrypted_g1.append(c)
            prf = zkp_range.gen_prf(c, pid=str(self.uid) + ":" + str(x), message=self.g[x], secret=self.secrets[x], 
                    pubkey=h_list[x], bound=self.gmax)
            zkp_range_g1.append(prf)
        if (self.ledger.commit_zkp_range(zkp_range_g1, self.uid) == 0):
            print("Failed to upload ZKP of range proof for {}!".format(self.uid))
            return

        # compute another encryption of g, which uses the same public key for all values; generate zkp for dhtuple (equation 3)
        encrypted_g2 = []
        zkp_dhtuple_list = []
        for x in range(self.len):
            encrypted_g2.append(elgamal_encrypt(self.h, self.secrets[x], self.g[x]*G))
            dhtuple = (G, h_list[x] - self.h, self.secrets[x]*G, encrypted_g1[x][1] - encrypted_g2[x][1])
            prf = zkp_dhTuple.gen_prf(dhtuple, pid=str(self.uid) + ":" + str(x), secret=self.secrets[x])
            zkp_dhtuple_list.append(prf)

        if (self.ledger.commit_zkp_dhtuple(self.h, h_list, encrypted_g1, encrypted_g2, zkp_dhtuple_list, self.uid) == 0):
            print("Failed to upload ZKP of dhtuple for {}!".format(self.uid))
            return


        # generate range proof for sum
        g_sum = 0
        g_encsum1 = I
        g_encsum2 = I
        g_secsum = 0
        for x in range(self.len):
            g_sum += self.g[x]
            g_encsum1 += encrypted_g2[x][0]
            g_encsum2 += encrypted_g2[x][1]
            g_secsum += self.secrets[x]
        g_encsum = (g_encsum1, g_encsum2)
        zkp_sumRange = zkp_range.gen_prf(g_encsum, pid=str(self.uid), message=g_sum, secret=g_secsum, pubkey=self.h, bound=self.bound)
        if (self.ledger.commit_zkp_sumRange(zkp_sumRange, self.uid) == 0):
            print("Failed to upload ZKP of sum range for {}!".format(self.uid))
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
        assert self.check_zkp_dhtuple(self.ledger.h, self.ledger.pk_list, self.ledger.h_list, self.ledger.encrypted_g1, 
            self.ledger.encrypted_g2, self.ledger.zkp_dhtuple_dict), "ZKP dhtuple validation failed!"
        assert self.check_zkp_range(self.ledger.encrypted_g1, self.ledger.h_list, self.ledger.zkp_range_dict), "ZKP range validation failed!"
        assert self.check_zkp_sumRange(self.ledger.encrypted_g2, self.ledger.h, self.ledger.zkp_sumRange_dict), "ZKP sum range validation failed!"
        init_baby_giant(100)
        return self.aggregate(self.ledger.encrypted_g1)

    def check_zkp_dhtuple(self, all_h, all_pk_list, all_h_list, all_encrypted_g1, all_encrypted_g2, all_zkp_dhtuple) -> 'bool':
        print("Checking ZKP dhtuple by {}".format(self.uid))
        ucount = len(all_h)
        assert len(all_h_list) == ucount
        assert len(all_encrypted_g1) == ucount
        assert len(all_encrypted_g2) == ucount
        assert len(all_zkp_dhtuple) == ucount
        for u in all_h:
            print("user {}".format(str(u)))
            for x in range(self.len):
                dhtuple = (G, all_h_list[u][x] - all_h[u], all_pk_list[u][x], all_encrypted_g1[u][x][1] - all_encrypted_g2[u][x][1])
                if (not zkp_dhTuple.verify_prf(dhtuple, pid=str(u) + ":" + str(x), **all_zkp_dhtuple[u][x])):
                    print("zkp dhtuple validation failed for u = {}, x={}".format(str(u),str(x)))
                    return False
        return True

    def check_zkp_range(self, all_encrypted_g1, all_h_list, all_zkp_range) -> 'bool':
        print("Checking ZKP range by {}".format(self.uid))
        ucount = len(all_encrypted_g1)
        assert len(all_h_list) == ucount
        assert len(all_zkp_range) == ucount
        for u in all_encrypted_g1:
            print("user {}".format(str(u)))
            for x in range(self.len):
                if (not zkp_range.verify_prf(all_encrypted_g1[u][x], pubkey=all_h_list[u][x],pid=str(u) + ":" + str(x), bound=self.gmax, **all_zkp_range[u][x])):
                    print("zkp range validation failed for u = {}, x={}".format(str(u), str(x)))
                    return False
        return True

    def check_zkp_sumRange(self, all_encrypted_g2, all_h, all_zkp_sumRange) -> 'bool':
        print("Checking ZKP sum range by {}".format(self.uid))
        ucount = len(all_encrypted_g2)
        assert len(all_h) == ucount
        assert len(all_zkp_sumRange) == ucount
        for u in all_encrypted_g2:
            print("user {}".format(str(u)))
            gsum1 = I
            gsum2 = I
            for x in range(self.len):
                gsum1 += all_encrypted_g2[u][x][0]
                gsum2 += all_encrypted_g2[u][x][1]
            gsum = (gsum1, gsum2)
            if (not zkp_range.verify_prf(gsum, pid=str(u),pubkey=all_h[u],bound=self.bound,**all_zkp_sumRange[u])):
                print("zkp sum range validation failed for u = {}".format(str(u)))
                return False
        return True

    def aggregate(self, all_encrypted_g1):
        result = []
        for x in range(self.len):
            sumG = I
            for u in all_encrypted_g1:
                sumG += all_encrypted_g1[u][x][1]
            result.append(baby_giant(sumG))
        return result
