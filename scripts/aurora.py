from ldt_params import LDTParameters
from fri import fri_round
from stir import stir_round
from protocol import Protocol, Polynomial, NonOracleMessage, Round, CombinePolynomial


def begin_aurora(params :LDTParameters):
    prot = Protocol(params)
    rnd_init = Round()
    init_msg = Polynomial(params, params.degree, params.rho_bits, stack = 4 )
    ood_init = NonOracleMessage(params, 4)
    rnd_init.addMessage(ood_init)
    sumcheck_msg = Polynomial(params, params.degree, params.rho_bits, stack=2)
    ood_sumcheck = NonOracleMessage(params,2)
    rnd_init.addMessage(ood_sumcheck)
    polys = [init_msg,sumcheck_msg]
    c = CombinePolynomial(params, polys, params.rho_bits)
    
    rnd_init.addMessage(c)
    prot.addRound(rnd_init)
    return prot

def run_aurora_FRI(params : LDTParameters, fold, stopping_condition):
    prot = begin_aurora(params)
    i = 0
    while not prot.isStopped():
        current_fold = fold[-1] if i >= len(fold) else fold[i]
        prot.addRound(fri_round(params, prot.getLastOracle(), fold=current_fold, stopping_condition=stopping_condition))
        i += 1
    return prot

def run_aurora_STIR(params : LDTParameters, fold, max_len_ratio, stopping_condition):
    prot = begin_aurora(params)
    i = 0
    while not prot.isStopped():
        current_max_len_ratio = max_len_ratio[-1] if i >= len(max_len_ratio) else max_len_ratio[i]
        current_fold = fold[-1] if i >= len(fold) else fold[i]
        rnd = stir_round(params=params, oracle=prot.getLastOracle(), fold=current_fold, max_len_ratio=current_max_len_ratio, stopping_condition=stopping_condition)
        prot.addRound(rnd)
        i = i+1
    return prot