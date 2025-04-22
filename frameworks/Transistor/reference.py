#!/usr/bin/sage
#-*- Python -*-
# Time-stamp: <2025-02-07 17:27:19>

from sage.all import *
from hashlib import shake_128



def key_gen(master_key, k, w, IV = b""):
    """Uses the given master key and (facultative) IV to generate two
    vectors of integers modulo 17 of length `k` and `w` using
    rejection sampling.

    """
    assert len(master_key) == 16
    to_shake = master_key + IV + b"1"
    tmp = shake_128(to_shake).digest(k + w + 30) # we add extra length to make sure rejection sampling works
    cursor = 0
    # dealing with K
    k_content = []
    while len(k_content) < k:
        x = tmp[cursor]
        # `tmp` is a bytearray, so its entries are in [0, 255]
        if x < 255:
            k_content.append(x // 15)
        cursor += 1
    # dealing with W
    w_content = []
    while len(w_content) < w:
        x = tmp[cursor]
        if x < 255:
            w_content.append(x // 15)
        cursor += 1
    return k_content, w_content
        

class LFSR:
    def __init__(self, _taps, field):
        self.taps = [x for x in _taps]
        self.cells = []
        self.field = field

    def load_content(self, _content):
        assert len(_content) == len(self.taps)
        self.cells = [self.field(x) for x in _content]

    def clock(self):
        output = self.cells[-1]
        feedback =  sum(self.cells[i] * self.taps[i]
                     for i in range(0, len(self.cells)))
        self.cells =  [feedback] + self.cells[:-1]
        return output

    def __len__(self):
        return len(self.taps)



class Transistor:
    """!TODO! docstring for the Transistor class

    """
    def __init__(self):
        # setting parameters of the cipher
        self.p = 17
        self.a = 4
        self.field = GF(self.p)
        # choosing sub functions
        # -- initializing the LFSRs
        self.K = LFSR([9, 4, 6, 4, 8, 6, 6, 16, 3,
                       9, 15, 12, 8, 12, 11, 4, 4, 8, 1,
                       8, 8, 9, 4, 6, 6, 7, 6, 3, 16,
                       14, 14, 6, 10, 15, 14, 13, 10, 1, 1,
                       10, 13, 11, 14, 10, 7, 4, 15, 8, 16,
                       3, 13, 14, 15, 16, 3, 16, 9, 3, 6,
                       12, 15, 9, 12, 3], self.field)
        self.W = LFSR([8, 14, 14, 14, 1, 6, 12, 10, 14, 14,
                       14, 5, 2, 5, 6, 13, 6, 15, 14, 3,
                       13, 16, 1, 13, 9, 1, 7, 15, 13, 6,
                       14, 3], self.field)
        # -- initializing the S-box
        self.sw = [self.field(x) for x in [1,12,6,11,14,3,15,5,10,9,13,16,7,8,0,2,4]]
        # -- initializing the MixColumns matrix
        self.MC = Matrix(self.field, [
            [-1, -1, -1,  2],
            [-1, 1,  2, -1],
            [-1,  2,  1,  1],
            [ 2,  1, -1,  1]
        ])

    def set_key(self, master_key, IV):
        # setting content of the fsm
        self.fsm = [[self.field(0) for j in range(0, self.a)]
                      for i in range(0, self.a)]
        # setting content of the LFSRs
        k_content, w_content = key_gen(master_key,
                                       len(self.K),
                                       len(self.W),
                                       IV=IV)
        self.K.load_content(k_content)
        self.W.load_content(w_content)

        
    def __str__(self):
        result = "Transistor instance with:"
        result += "\np={:d}".format(self.p)
        result += "\na={:d}".format(self.a)
        result += "\ns={}".format(self.sw)
        result += "\nk={}".format(self.K)
        result += "\nw={}".format(self.W)
        return result

    
    def absorb_subkeys(self):
        # absorbing key schedule output
        for i in range(0, self.a):
            for j in range(0, self.a):
                self.fsm[i][j] += self.K.clock()

    def sub_word(self):
        # subWords
        for i in range(0, self.a):
            for j in range(0, self.a):
                self.fsm[i][j] = self.sw[self.fsm[i][j]]

    def phi(self):
        # applying filter function
        fsm_outputs = []
        for i in range(1, self.a, 2):
            for j in range(0, self.a, 2):
                fsm_outputs.append(self.fsm[i][j])
        return fsm_outputs

    def shift_rows(self):
        # shiftRows
        for i in range(0, self.a):
            new_row = [self.fsm[i][(j + i) % self.a]
                       for j in range(0, self.a)]
            self.fsm[i] = new_row[:]

    def mix_columns(self):
        # MixColumns
        for j in range(0, self.a):
            column_vector = [self.fsm[i][j] for i in range(0, self.a)]
            for i in range(0, self.a):
                self.fsm[i][j] = sum(column_vector[k]*self.MC[i][k]
                                     for k in range(0, self.a))
        
    def whiten(self, fsm_outputs):
        # adding whitening LFSR output
        result = []
        for y in fsm_outputs:
            result.append(y + self.W.clock())
        return result

    
    def clock(self):
        self.absorb_subkeys()
        self.sub_word()
        fsm_outputs = self.phi()
        self.shift_rows()
        self.mix_columns()
        return self.whiten(fsm_outputs)

        

# !SECTION!  Basic tests

if __name__ == "__main__":
    T = Transistor()
    T.set_key(b"0123456789abcdef", IV=b"")
    for i in range(0, 10):
        print(T.clock())


