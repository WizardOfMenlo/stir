from ldt_params import LDTParameters
from fri import run_FRI
from stir import stir_round, run_STIR
from aurora import run_aurora_FRI, run_aurora_STIR

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
   
