from math import ceil
from ldt_params import LDTParameters
from protocol import Protocol, Polynomial, NonOracleMessage, Round

def fri_round(params : LDTParameters, oracle : Polynomial, fold, stopping_condition):
    rnd = Round()
    
    oracle.fold(fold)
    degree_new = oracle.degree_virtual()
    rate_bits = oracle.rate_bits()
    rep = oracle.reps_full_sec()
    

    # if the next degree is small, then actually we don't need to do this round
    if degree_new <= stopping_condition:
        oracle.query(rep)
        final = NonOracleMessage(params, degree_new)
        rnd.addMessage(final)
        rnd.stop_protocol()
    else:
        oracle.query(rep)
        newPoly = Polynomial(params, degree_new, rate_bits)
        rnd.addMessage(newPoly)

    return rnd

def run_FRI(params : LDTParameters, fold, stopping_condition):
    prot = Protocol(params)
    msg = Polynomial(params, params.degree, params.rho_bits)
    rnd_init = Round()
    rnd_init.addMessage(msg)
    prot.addRound(rnd_init)
    i = 0
    while not prot.isStopped():
        current_fold = fold[-1] if i >= len(fold) else fold[i]
        prot.addRound(fri_round(params, prot.getLastOracle(), fold=current_fold, stopping_condition=stopping_condition))
        i += 1
    return prot