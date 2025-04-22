# Transitor: a TFHE-friendly Stream Cipher
# MILP modelization of linear trails in transistor
from sage.all import *
from milp_print import *

# Bibliography:
# [MWGP12]
# Differential and Linear Cryptanalysis using Mixed-Integer Linear Programming
# Nicky Mouha, Qingju Wang, Dawu Gu, and Bart Preneel
# Available at : https://mouha.be/wp-content/uploads/milp.pdf
#
# [SageMILP]
# Mixed Integer Linear Programming interface of SageMath, online reference manual
# https://doc.sagemath.org/html/en/reference/numerical/sage/numerical/mip.html


# Global counters, for variable names
FORK = 0
MC = 0

# Numbering of the state cells
# 0 | 1 | 2 | 3
# 4 | 5 | 6 | 7
# 8 | 9 | a | b
# c | d | e | f


def add_fork_constraint(model, vars, name="fork"):
    """
    Add a 3-fork constraint to the model. If one the branches is active, then at least 3 of them are.
    :param model: the model
    :param vars: the list of the three variables
    :param name: the name of the constraint
    """
    global FORK

    # Naming
    if name == "fork":
        name += "_" + str(FORK)

    # The 4 needed constraints, together with the dummy variable (see [MWGP12] Section 2.2)
    d = model.new_variable(binary=True, name='dummy')
    model.add_constraint(vars[0] + vars[1] + vars[2] >= 2*d[name], name=name+'_3')
    for i in range(3):
        model.add_constraint(d[name] >= vars[i], name=name+"_"+str(i))
    FORK += 1


def mix_columns(model, col_i, col_o, name="mc"):
    """
    Add an MDS MixColumn constraint to the model. If one of the cell is active, then at least 5 of them are.
    :param model: the model
    :param col_i: the list of four input cells
    :param col_o: the list of four output cells
    :param name: the name of the constraint
    """
    global MC

    # Naming
    if name == "mc":
        name += "_" + str(MC)

    # The needed constraints, together with the dummy variable
    d = model.new_variable(binary=True, name='dummy')
    for i in range(4):
        model.add_constraint(col_i[i] <= d[name], name=name+'_in_'+str(i))
        model.add_constraint(col_o[i] <= d[name], name=name+'_out_'+str(i))
    model.add_constraint(sum(col_i + col_o) >= 5*d[name], name='mc_condition')


def build_solve_milp_model(nb_rounds):
    global MC
    global FORK
    MC, FORK = 0, 0

    # The indices of output cells, and of the cols before and after the ShiftRows operation.
    out_coor = [4, 6, 12, 14]
    in_cols = [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]]
    out_cols = [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]]

    # Build a minimization problem.
    p = MixedIntegerLinearProgram(maximization=False, solver="GLPK")

    # Create the three types of binary variables, respectively representing the linear masks after the Sbox layer,
    # the output values, and the masks before the ShiftRows
    # fork_left, fork_right, output can be seen as dictionaries of variables where the key is a tuple (i, j)
    # where i is the round index and j the cell index. See [SageMILP]
    fork_left = p.new_variable(binary=True, name='fork_left')
    fork_right = p.new_variable(binary=True, name='fork_right')
    output = p.new_variable(binary=True, name='output')

    # Initial constraints so that:
    # - at least an active cell appears among the first output cells,
    # - no active cells appears in the initial inner state.
    p.add_constraint(sum(output[(0, i)] for i in out_coor) >= 1, name='init_constraint')
    p.add_constraint(sum(fork_left[(0, i)] for i in range(16)) == 0, name='init_constraint')

    for i in range(nb_rounds):  # For each round
        for j in range(16):  # For each cell
            if j in out_coor:  # If the cell is output, add a 3-fork constraint between fork_left, output and fork_right
                add_fork_constraint(p, [fork_left[(i, j)], fork_right[(i, j)], output[(i, j)]],
                                    name='fork_r' + str(i) + 'c' + str(j))
            else:  # otherwise fork_left and fork_right are identical
                p.add_constraint(fork_left[(i, j)] == fork_right[(i, j)])

        #  Afterwards, we add a MixColumn constraints for each column of each round (except the last round)
        if i < nb_rounds - 1:
            for j in range(4):
                col_in = [fork_right[(i, k)] for k in in_cols[j]]
                col_out = [fork_left[(i + 1, k)] for k in out_cols[j]]
                mix_columns(p, col_in, col_out, name='mc_r' + str(i) + 'col' + str(j))

    # Final constraints so that:
    # - at least an active cell appears among the last output cells,
    # - no active cells appears in the final inner state.
    p.add_constraint(sum(output[(nb_rounds - 1, i)] for i in out_coor) >= 1, name='out_constraint')
    p.add_constraint(sum(fork_right[(nb_rounds - 1, i)] for i in range(16)) == 0, name='out_constraint')

    # The number of active Sbox must be minimized
    p.set_objective(sum(fork_left[(i, j)] for i in range(nb_rounds) for j in range(16)))

    # Solve the system
    p.solve()
    # p.show()

    # Recover the variable values
    val_fork_left = p.get_values(fork_left)
    val_fork_right = p.get_values(fork_right)
    val_output = p.get_values(output)

    return p.get_objective_value(), val_fork_left, val_fork_right, val_output


if __name__ == '__main__':
    nb_rounds = 4

    obj_value, val_fork_left, val_fork_right, val_output = build_solve_milp_model(nb_rounds)
    print('Rounds', nb_rounds, 'obj_value', obj_value)

    for i in range(nb_rounds):
        print_state(val_output, i, shift=5)
        print_two_states(val_fork_left, val_fork_right, i)
        print('-'*15)

