# Transitor: a TFHE-friendly Stream Cipher
# File with print functions for the MILP solutions
from sage.all import *

def print_state(dico, round, shift=0):
    """
    Print a single state from the MILP solution, used to print the output state
    """
    for i in range(4):
        print(' '*shift, end="")
        for j in range(4):
            if (round, i*4 + j) not in dico or dico[(round, i*4 + j)] == 0:
                print('.', end='')
            else:
                print('X', end='')
        print()


def print_two_states(dico1, dico2, round, shift=0, shiftbetween=6):
    """
    Print two states from the MILP solution, used to print the two inner states
    """
    for i in range(4):
        print(' '*shift, end="")
        for j in range(4):
            if dico1[(round, i*4 + j)]:
                print('X', end='')
            else:
                print('.', end='')
        print(' ' * shiftbetween, end='')
        for j in range(4):
            if dico2[(round, i*4 + j)]:
                print('X', end='')
            else:
                print('.', end='')
        print()