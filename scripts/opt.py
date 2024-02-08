from math import ceil
from iop import IOPNonOracleMessage, IOPOracleMessage
from ldt_params import LDTParameters

class OPTIop:
    def __init__(self, 
                 ldt_params: LDTParameters,
                 folding_parameter,
                 stopping_condition,
                 ) -> None:
        self.name = 'OPT'
        self.rom = ldt_params.rom
        self.field_size_bits = ldt_params.field_size_bits
        self.folding_parameter = folding_parameter
        self.stoping_condition = stopping_condition
        self.degree = ldt_params.degree
        self.rho = ldt_params.rho
        self.repetition_parameter = ldt_params.repetition_parameter(ldt_params.rho_bits)


    def to_rounds(self):
        rounds = []
        domain_size = ceil(self.degree / self.rho)
        oracle = IOPOracleMessage(self, domain_size, self.field_size_bits,  self.folding_parameter, 'function_oracle')
        rounds.append(oracle)
        oracle.query(self.repetition_parameter)
        return rounds
