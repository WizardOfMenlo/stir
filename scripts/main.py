from ldt_params import LDTParameters
from fri import run_FRI
from stir import stir_round, run_STIR
from math import log2
import matplotlib.pyplot as plt
from utils import convert_size
from protocol import Protocol, Round, Polynomial, NonOracleMessage
from aurora import run_aurora_FRI, run_aurora_STIR

def plot_degree():
    fig, ax = plt.subplots()
    degs = range(10,65,1)
    pow = 25
    ferrari_plot = []
    fri_plot = []
    stir_plot = []
    stir_slow_plot = []
    opt_plot = []
    baseline_plot = []
    trivial_plot = []
    for log_degree in degs:
        secparam = 100
        hashsize = secparam * 2
        pow = 20
        fieldsizebits = 192
        conj = 1
        rate_bits = 1
        

        ldt_params = LDTParameters(secparam=secparam, hashsize=hashsize, pow=pow, log_degree=log_degree, field_size_bits=fieldsizebits, rho_bits = rate_bits, conj=conj)

        ferrari = run_Ferrari(ldt_params, max_len_ratio=[2], stopping_condition=2**8)
        ferrari_size = ferrari.argument_size()
        #ferrari_plot.append(ferrari_size/ 8192)

        fri = run_FRI(ldt_params, fold=[8], stopping_condition=2**8)
        fri_size = fri.argument_size()
        fri_length = fri.proof_length()
        fri_plot.append(fri_size / 8192)
        #fri_plot.append(fri.queries())

        stir = run_STIR(ldt_params, fold=[16], max_len_ratio=[2],stopping_condition=2**8)
        stir_size = stir.argument_size()
        stir_length = stir.proof_length()
        stir_plot.append(stir_size / 8192)


        trivial = run_trivial(ldt_params)
        trivial_size = trivial.argument_size()
        trivial_length = trivial.proof_length()
        #trivial_plot.append(trivial_size.queries())
        trivial_plot.append(trivial_size / 8192)

        baseline = run_baseline_bound(ldt_params)
        baseline_size = baseline.argument_size()
        baseline_length = baseline.proof_length()
        #baseline_plot.append(trivial.queries())
        baseline_plot.append(baseline_size / 8192)
    
    #ax.plot(degs, [p for p in ferrari_plot], 'm-', label="ferrari")
    ax.plot(degs, [log2(p) for p in fri_plot], 'b-', label="fri")
    ax.plot(degs, [log2(p) for p in stir_plot] , 'g-', label="stir")
    #ax.plot(degs, [log2(p) for p in trivial_plot] , 'c--', label="trivial")
    ax.plot(degs, [log2(p) for p in baseline_plot] , 'r--', label="baseline")
    #ax.plot(degs, [p for p in opt_plot], 'r-', label="eureka")
    
    plt.xlabel("Degree (log scale)")
    plt.ylabel("Argument size")
    plt.legend(loc='best')
    plt.grid=True
    plt.show()

def run_one_ferrari_then_stir(params : LDTParameters, fold, max_len_ratio, stopping_condition):
    prot = Protocol(params)
    
    prot.getLastOracle().fold(2**(params.rho_bits+1))
    rnd = ferrari_round(params=params, oracle=prot.getLastOracle(), fold=1, max_len_ratio=max_len_ratio[0], stopping_condition=stopping_condition)
    prot.addRound(rnd)

    i = 0
    while not prot.isStopped():
        current_fold = fold[-1] if i >= len(fold) else fold[i]
        current_max_len_ratio = max_len_ratio[-1] if i >= len(max_len_ratio) else max_len_ratio[i]
        rnd = stir_round(params=params, oracle=prot.getLastOracle(), fold=current_fold, max_len_ratio=current_max_len_ratio, stopping_condition=stopping_condition)
        prot.addRound(rnd)
        i += 1
    return prot

def run_best(params : LDTParameters, fold, max_len_ratio, stopping_condition):
    prot = Protocol(params)
    if prot.getLastOracle().degree_real() / 2**(params.rho_bits+1) > 2**51 :
        prot.getLastOracle().fold(2**(params.rho_bits+1))
        fold[0] = 1 if prot.getLastOracle().degree_virtual() <= 2**51 else fold[0]

    while (not prot.isStopped()) and (prot.getLastOracle().degree_virtual() > 2**51) :
        rnd = ferrari_round(params=params, oracle=prot.getLastOracle(), fold=1, max_len_ratio=max_len_ratio[0], stopping_condition=stopping_condition)
        prot.addRound(rnd)
    i = 0
    while not prot.isStopped():
        current_fold = fold[-1] if i >= len(fold) else fold[i]
        current_max_len_ratio = max_len_ratio[-1] if i >= len(max_len_ratio) else max_len_ratio[i]
        rnd = stir_round(params=params, oracle=prot.getLastOracle(), fold=current_fold, max_len_ratio=current_max_len_ratio, stopping_condition=stopping_condition)
        prot.addRound(rnd)
        i += 1
    return prot

def run_trivial(params : LDTParameters):
    prot = Protocol(params)
    msg = Polynomial(params, params.degree, params.rho_bits)
    rnd_init = Round()
    rnd_init.addMessage(msg)
    p = NonOracleMessage(params, params.degree)
    rnd_init.addMessage(p)
    prot.addRound(rnd_init)
    prot.getLastOracle().query(prot.getLastOracle().reps_full_sec())
    return prot

def run_baseline_bound(params : LDTParameters):
    prot = Protocol(params)
    msg = Polynomial(params, params.degree, params.rho_bits)
    rnd_init = Round()
    rnd_init.addMessage(msg)
    prot.addRound(rnd_init)
    prot.getLastOracle().query(prot.getLastOracle().reps_full_sec())
    return prot

def plot_table_values():
    secparam = 128
    hashsize = 256
    pow = 22
    log_degrees = [18, 20, 22, 24, 26, 28, 30]
    fieldsizebits = 192
    stopping_condition = 2**6
    conj = 1
    rate_bits = [1, 2, 3, 4]

    result = []
    for r_bits in rate_bits:
        new_row = []
        for log_degree in log_degrees:
            ldt_params = LDTParameters(secparam=secparam, hashsize=hashsize, pow=pow, log_degree=log_degree, field_size_bits=fieldsizebits, rho_bits = r_bits, conj=conj)
            sum_fri = run_aurora_FRI(ldt_params, fold=[2,8], stopping_condition=stopping_condition)
            #fri.print()
            sum_fri_size = round(sum_fri.argument_size() / 8192)
            sum_stir = run_aurora_STIR(ldt_params, fold=[2,16], max_len_ratio=[2], stopping_condition=stopping_condition)
            #sum_stir.print()
            sum_stir_size = round(sum_stir.argument_size() / 8192)
            ratio = round(sum_fri_size/sum_stir_size, 2)
            new_row.append('$\\frac{{ {} }}{{ {} }} \\approx {} \\times $'.format(sum_fri_size, sum_stir_size, ratio))
        result.append(new_row)

    return '\\\\\n'.join([' & '.join(["$\\sfrac{{1}}{{{}}}$".format(2**rate)] + row) for rate,row in zip(rate_bits, result)])




if __name__ == '__main__':
    print(plot_table_values())
    exit(0)
    #plot_degree()
    secparam = 128
    hashsize = 256
    pow = 22
    log_degree = 18
    degree = 2**log_degree
    fieldsizebits = 192
    stopping_condition = 2**8
    conj = 1
    rate_bits = 2
    
    print()
    print("************************************************************************************")
    ldt_params = LDTParameters(secparam=secparam, hashsize=hashsize, pow=pow, log_degree=log_degree, field_size_bits=fieldsizebits, rho_bits = rate_bits, conj=conj)
    ldt_params.display()
    print("************************************************************************************")

    ferrari = run_Ferrari(ldt_params, max_len_ratio=[2], stopping_condition=stopping_condition)
    # ferrari.print()
    #ferrari_size = ferrari.argument_size()
    #print(f"FERRARI: {convert_size(ferrari_size)}")

    fri = run_FRI(ldt_params, fold=[8], stopping_condition=stopping_condition)
    #fri.print()
    fri_size = fri.argument_size()
    fri_length = fri.proof_length()
    fri_queries = fri.queries()
    print(f"FRI: {convert_size(fri_size)} : 2^{log2(fri_length):.2f} : 2^{log2(fri_queries):.2f}" )

    sum_fri = run_aurora_FRI(ldt_params, fold=[2,8], stopping_condition=stopping_condition)
    #fri.print()
    sum_fri_size = sum_fri.argument_size()
    sum_fri_length = sum_fri.proof_length()
    sum_fri_queries = sum_fri.queries()
    print(f"Aurora FRI: {convert_size(sum_fri_size)} : 2^{log2(sum_fri_length):.2f} : 2^{log2(sum_fri_queries):.2f}" )
    
    stir = run_STIR(ldt_params, fold=[16], max_len_ratio=[2], stopping_condition=stopping_condition)
    #stir.print()
    stir_size = stir.argument_size()
    stir_length = stir.proof_length()
    stir_queries = stir.queries()
    print(f"STIR: {convert_size(stir_size)} : 2^{log2(stir_length):.2f} : 2^{log2(stir_queries):.2f}")

    sum_stir = run_aurora_STIR(ldt_params, fold=[2,16], max_len_ratio=[2], stopping_condition=stopping_condition)
    #sum_stir.print()
    sum_stir_size = sum_stir.argument_size()
    sum_stir_length = sum_stir.proof_length()
    sum_stir_queries = sum_stir.queries()
    print(f"Aurora STIR: {convert_size(sum_stir_size)} : 2^{log2(sum_stir_length):.2f} : 2^{log2(sum_stir_queries):.2f}")

    

    #eureka = run_eureka(ldt_params, fold=[2,8], max_len_ratio=[2], stopping_condition=2**8)
    # stir.print()
    #eureka_size = eureka.argument_size()
    #eureka_length = eureka.proof_length()
    #eureka_queries = eureka.queries()
    #eureka.print()
    #print(f"Eureka: {convert_size(eureka_size)} : 2^{log2(eureka_length):.2f} : 2^{log2(eureka_queries):.2f}")

    
    #lower_bound = run_lower_bound(ldt_params)
    #lower_bound_size = lower_bound.argument_size()
    #print(f"Baseline: {convert_size(lower_bound_size)}")

    print()
    print(f"Aurora_FRI / Aurora_STIR Arg Size: x{sum_fri_size/sum_stir_size:.2f}")
    print(f"Aurora_FRI / Aurora_STIR Length: x{sum_fri_length/sum_stir_length:.2f}")
    #print(f"Aurora_FRI / eureka Arg Size: x{sum_fri_size/eureka_size:.2f}")
    #print(f"Aurora_STIR / eureka Arg Size: x{sum_stir_size/eureka_size:.2f}")
    print()
    print(f"FRI / STIR Arg Size: x{fri_size/stir_size:.2f}")
    print(f"FRI / STIR Length: x{fri_length/stir_length:.2f}")
    print(f"FRI / STIR Queries: x{fri_queries/stir_queries:.2f}")
    
