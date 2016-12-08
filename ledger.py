#!/usr/bin/env python

# Simulate an ethereum smart contract:
# 1. store the encrypted inputs from users
# 2. store the zkps form users

class Ledger(object):
    # set up the phase of the application: 'c' -- commit, 'p' -- proof, 'r' -- results
    def phase(self, s):
        if (s == 'c'):
            self.cur_phase = 'c'
            self.h = {}
            self.h_list = {}
            self.pk_list = {}
            self.encrypted_g1 = {}
            self.encrypted_g2 = {}
            self.zkp_discretelog_dict = {}
            self.zkp_dhtuple_dict = {}
            self.zkp_range_dict = {}
            self.zkp_sumRange_dict = {}
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

    def commit_zkp_discretelog(self, pk, zkp_discretelog, uid):
        if (self.cur_phase != 'c'):
            return 0
        self.pk_list[uid] = pk
        self.zkp_discretelog_dict[uid] = zkp_discretelog
        print("ledger: {} commited zkp for discrete log".format(uid))

    def commit_zkp_dhtuple(self, h, h_list, encrypted_g1, encrypted_g2, zkp_dhtuple, uid):
        if (self.cur_phase != 'p'):
            return 0
        self.h[uid] = h
        self.h_list[uid] = h_list
        self.encrypted_g1[uid] = encrypted_g1
        self.encrypted_g2[uid] = encrypted_g2
        self.zkp_dhtuple_dict[uid] = zkp_dhtuple
        print("ledger: {} commited zkp for dhtuple".format(uid))

    def commit_zkp_range(self, zkp_range, uid):
        if (self.cur_phase != 'p'):
            return 0
        self.zkp_range_dict[uid] = zkp_range
        print("ledger: {} commited zkp for range".format(uid))

    def commit_zkp_sumRange(self, zkp_sumRange, uid):
        if (self.cur_phase != 'p'):
            return 0
        self.zkp_sumRange_dict[uid] = zkp_sumRange
        print("ledger: {} commited zkp for sum range".format(uid))