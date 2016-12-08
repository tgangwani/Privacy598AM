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
from zkplib import discretelog as zkp_discretelog, dhTuple as zkp_dhTuple, oneOutOfTwo as zkp_oneOutOfTwo, square as zkp_square

class Zorro(object):
    def __init__(self, ledger, uid, length, gmax):
        self.ledger = ledger
        self.uid = uid
        self.len = length
        self.priv_key = random.randint(0,order)
        self.h = self.priv_key*G
        self.gmax = gmax
        self.lmax = math.ceil(math.log2(self.gmax**2 * self.len))

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
            encrypted_g1.append(elgamal_encrypt(h, self.sk_list[x], self.g[x]*G))

        # compute another encryption of g, generate zkp for dhtuple (equation 3)
        encrypted_g2 = []
        zkp_dhtuple_list = []
        for x in range(self.len):
            encrypted_g2.append(elgamal_encrypt(self.h, self.sk_list[x], self.g[x]*G))
            dhtuple = (G, h_list[x] - self.h, self.pk_list[x], encrypted_g1[x][1] - encrypted_g2[x][1])
            prf = zkp_dhTuple.gen_prf(dhtuple, pid=str(self.uid) + ":" + str(x), secret=self.sk_list[x])
            zkp_dhtuple_list.append(prf)

        if (self.ledger.zkp2(self.h, h_list, encrypted_g1, encrypted_g2, zkp_dhtuple_list, self.uid) == 0):
            print("Failed to upload ZKP of dhtuple for {}!".format(self.uid))
            return

        # generate square vector and its binary representation
        w = []
        s = 0
        for x in range(self.len):
            w.append(self.g[x]**2)
            s += w[x]
        sb_str = "{0:b}".format(s)
        sb = []
        for c in sb_str:
            sb.append(int(c))
        s_new = 0
        L = len(sb)
        for x in range(L):
            s_new += sb[x] * 2**(L - 1 - x)
        assert s_new == s, "{}, {}".format(str(s_new), str(s))

        # encrypt the binary representation (equation 6), and generate zkp01 for each binary value 
        encrypted_sb = []
        r_list_sb = []
        zkp01 = []
        for x in range(L):
            r_sb = random.randint(0,order)
            e_sb = elgamal_encrypt(self.h, r_sb, sb[x]*G)
            (c1, c2) = e_sb
            prf = zkp_oneOutOfTwo.gen_prf(c1, c2, pid=str(self.uid) + ":" + str(x), message=sb[x], secret=r_sb, pubkey=self.h)
            r_list_sb.append(r_sb)
            encrypted_sb.append(e_sb)
            zkp01.append(prf)
        if (self.ledger.zkp3(encrypted_sb, zkp01, self.uid) == 0):
            print("Failed to upload ZKP01 for {}!".format(self.uid))
            return

        # generate randomness for w and encrypt w (equation 7, equation 8)
        r_list_w = []
        encrypted_w = []
        zkp_square_list = []
        for x in range(self.len):
            r_w = random.randint(0,order)
            r_list_w.append(r_w)
        sum_rw = 0
        sum_rw_new = 0
        for x in range(self.len):
            r_w = 0
            for y in range(self.len):
                if (y < x):
                    r_w += r_list_w[y]
                elif (y > x):
                    r_w -= r_list_w[y]
            r_w *= r_list_w[x]
            if (x < L):
                r_w_new = r_w + r_list_sb[x] * 2**(L - 1 - x)  
            else:
                r_w_new = r_w
            sum_rw += r_w
            sum_rw_new += r_w_new
            e_w = elgamal_encrypt(self.h, r_w_new, w[x]*G)
            prf = zkp_square.gen_prf(encrypted_g2[x], e_w, pid=str(self.uid) + ":" + str(x), 
                    secret1=self.sk_list[x], secret2=r_w_new, message=self.g[x], pubkey=self.h)
            encrypted_w.append(e_w)
            zkp_square_list.append(prf)
        if (self.ledger.zkp4(encrypted_w, zkp_square_list, self.uid) == 0):
            print("Failed to upload ZKP square for {}".format(self.uid))

        assert sum_rw == 0, "sum_rw = {}".format(sum_rw)
        sum_e_w = I
        sum_e_sb = I
        for x in range(self.len):
            sum_e_w += encrypted_w[x][1]
        for x in range(L):
            sum_e_sb += encrypted_sb[x][1] * 2**(L - 1 - x)  
        assert(sum_e_w == sum_e_sb), "check sum failed"

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
            self.ledger.encrypted_g2, self.ledger.zkp2_dict), "ZKP dhtuple validation failed!"
        assert self.check_zkp01(self.ledger.h, self.ledger.encrypted_sb, self.ledger.zkp3_dict), "ZKP01 validation failed!"
        assert self.check_zkp_square(self.ledger.h, self.ledger.encrypted_g2, self.ledger.encrypted_w, self.ledger.zkp4_dict), "ZKP square validation failed!"
        assert self.check_sum(self.ledger.encrypted_w, self.ledger.encrypted_sb), "Check sum failed!"
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

    def check_zkp01(self, all_h, all_encrypted_sb, all_zkp01) -> 'bool':
        print("Checking ZKP01 by {}".format(self.uid))
        ucount = len(all_h)
        assert len(all_encrypted_sb) == ucount
        assert len(all_zkp01) == ucount
        for u in all_h:
            print("user {}".format(str(u)))
            L = len(all_encrypted_sb[u])
            if L > self.lmax:
                print("L exceeds limit: L = {}, lmax = {}, u = {}".format(str(L), str(self.lmax),str(u)))
                return False
            for x in range(L):
                (c1, c2) = all_encrypted_sb[u][x]
                if (not zkp_oneOutOfTwo.verify_prf(c1, c2, 
                        pid=str(u) + ":" + str(x), pubkey=all_h[u], **all_zkp01[u][x])):
                    print("zkp01 validation failed for u = {}, x = {}".format(str(u), str(x)))
                    return False
        return True

    def check_zkp_square(self, all_h, all_encrypted_g2, all_encrypted_w, all_zkp_square) -> 'bool':
        print ("Checking ZKP sqaure by {}".format(self.uid))
        ucount = len(all_h)
        assert len(all_encrypted_g2) == ucount
        assert len(all_encrypted_w) == ucount
        assert len(all_zkp_square) == ucount
        for u in all_h:
            print("user {}".format(str(u)))
            for x in range(self.len):
                if (not zkp_square.verify_prf(all_encrypted_g2[u][x], all_encrypted_w[u][x], 
                        pid=str(u) + ":" + str(x), pubkey=all_h[u], **all_zkp_square[u][x])):
                    print("zkp sqaure validation failed for u = {}, x = {}".format(str(u),str(x)))
                    return False
        return True

    def check_sum(self, all_encrypted_w, all_encrypted_sb) -> 'bool':
        print ("Checking sum by {}".format(self.uid))
        assert len(all_encrypted_w) == len(all_encrypted_sb)
        for u in all_encrypted_w:
            print("user {}".format(u))
            sum_w = I
            sum_sb = I
            L = len(all_encrypted_sb[u])
            for x in range(self.len):
                sum_w += all_encrypted_w[u][x][1]
            for x in range(L):
                sum_sb += 2**(L - 1 - x)*all_encrypted_sb[u][x][1]
            if (sum_sb != sum_w):
                print("sum_sb = {}, sum_w = {}".format(sum_sb, sum_w))
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
