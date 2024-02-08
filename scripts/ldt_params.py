from arg import ROMParameters
import utils
from fractions import Fraction


class LDTParameters:
    def __init__(self, secparam, hashsize, pow, field_size_bits, log_degree, rho_bits, conj):
        # Desired security level
        self.secparam = secparam

        # RS params
        self.log_degree = log_degree
        self.degree = 1 << log_degree
        self.field_size_bits = field_size_bits
        self.conj = conj
        self.rho_bits = rho_bits
        self.rho = 1/(1 << rho_bits)
        self.rom = ROMParameters(hashsize=hashsize)
        self.pow = pow

    def repetition_parameter(self, rhobits):
        return utils.num_of_repetitions(self.secparam-self.pow, rhobits, self.conj)
    
    def display(self):
        fraction_rate = Fraction(1/(2**self.rho_bits)).limit_denominator()
        print(f"Degree: 2^{self.log_degree}, sec_param: {self.secparam}, rate: {fraction_rate.numerator}/{fraction_rate.denominator}, field: {self.field_size_bits}, conj: {self.conj}, hashsize: {self.rom.hashsize}, pow: {self.pow}")

