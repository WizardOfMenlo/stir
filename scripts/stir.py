from math import ceil, log2, floor
from iop import IOPNonOracleMessage, IOPOracleMessage
from ldt_params import LDTParameters

from protocol import Protocol, Polynomial, NonOracleMessage, Round

def correct_rate(ldt_params, rho_bit):
    r = rho_bit
    while ldt_params.repetition_parameter(r) == ldt_params.repetition_parameter(r-1):
        r -= 1
    return r

def stir_round(params : LDTParameters, oracle : Polynomial, fold, max_len_ratio, stopping_condition):
    
    # init round 
    rnd = Round()

    rate_bits = oracle.rate_bits()

    
    # virtual folding
    oracle.fold(fold)
    # get new degree
    degree_new = oracle.degree_virtual()
    # get the maximal repetitions needed for the oracle
    rep = oracle.reps_full_sec()
    
    
    # if the next degree is small, then actually we don't need to do this round
    if degree_new <= stopping_condition:
        # send final polynomial
        final = NonOracleMessage(params, degree_new)
        rnd.addMessage(final)
        
        # query oracle enough times
        oracle.query(rep)
        # stop the protocol
        rnd.stop_protocol()
    else:

        # new length is original length divided by the ratio
        max_len = oracle.proof_length() / max_len_ratio

        # make sure that the next length is reasonable
        assert(max_len > degree_new)

        # comprateute the next length
        # comprateute?
        rate_bits_new =  ceil(log2(max_len / degree_new ))
    
        # if 1 repetition, then change the rate to be minimal such that there is only one repetition 
        rate_bits_new = correct_rate(params, rate_bits_new)

        # send g polynomial
        newPoly = Polynomial(params, degree_new, rate_bits_new)
        rnd.addMessage(newPoly)

        # do ood sample
        ood_sample = NonOracleMessage(params, 2)
        rnd.addMessage(ood_sample)

        # do stir queries
        oracle.query(rep)

        # send Ans optimization
        ans_message = NonOracleMessage(params, rep)
        rnd.addMessage(ans_message)

    return rnd

def run_STIR(params : LDTParameters, fold, max_len_ratio, stopping_condition):
    prot = Protocol(params)
    msg = Polynomial(params, params.degree, params.rho_bits)
    rnd_init = Round()
    rnd_init.addMessage(msg)
    prot.addRound(rnd_init)
    i = 0
    while not prot.isStopped():
        current_max_len_ratio = max_len_ratio[-1] if i >= len(max_len_ratio) else max_len_ratio[i]
        current_fold = fold[-1] if i >= len(fold) else fold[i]
        rnd = stir_round(params=params, oracle=prot.getLastOracle(), fold=current_fold, max_len_ratio=current_max_len_ratio, stopping_condition=stopping_condition)
        prot.addRound(rnd)
        i = i+1
    return prot