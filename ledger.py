#!/usr/bin/env python

# Simulate an ethereum smart contract:
# 1. store the encrypted inputs from users
# 2. store the zkps form users

class Ledger(object):
    # set up the phase of the application: 'c' -- commit, 'p' -- proof, 'r' -- results
    def phase(self, s):
        if (s == 'c'):
            self.cur_phase = 'c'
            self.pk = {}
            self.pk_list = {}
            self.h_list = {}
            self.encrypted_g1 = {}
            self.encrypted_g2 = {}
            self.encrypted_sb = {}
            self.pk_list_sb = {}
            self.zkp1_dict = {}
            self.zkp2_dict = {}
            self.zkp3_dict = {}
            return 1
        if (s == 'p' and self.cur_phase == 'c'):
            self.cur_phase = 'p'
            self.zkp2s = {}
            return 1
        if (s == 'r' and self.cur_phase == 'p'):
            self.cur_phase = 'r'
            return 1
        else:
            return 0

    def zkp1(self, pk, zkp_discretelog, uid):
        if (self.cur_phase != 'c'):
            return 0
        self.pk_list[uid] = pk
        self.zkp1_dict[uid] = zkp_discretelog
        print("ledger: {} commited zkp for discrete log".format(uid))

    def zkp2(self, pk, h_list, encrypted_g1, encrypted_g2, zkp_dhtuple, uid):
        if (self.cur_phase != 'p'):
            return 0
        self.pk[uid] = pk
        self.h_list[uid] = h_list
        self.encrypted_g1[uid] = encrypted_g1
        self.encrypted_g2[uid] = encrypted_g2
        self.zkp2_dict[uid] = zkp_dhtuple
        print("ledger: {} commited zkp for dhtuple".format(uid))

    def zkp3(self, encrypted_sb, pk_list_sb, zkp01, uid):
        if (self.cur_phase != 'p'):
            return 0
        self.encrypted_sb[uid] = encrypted_sb
        self.pk_list_sb[uid] = pk_list_sb
        self.zkp3_dict[uid] = zkp01
        print("ledger: {} commited zkp01".format(uid))
