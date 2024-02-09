from arg import ArgRound 
import utils
from math import log2

class IOPNonOracleMessage:
    def __init__(self, iop, field_elements, oracle_name: str) -> None:
        self.oracle_name = oracle_name
        self.field_elements = field_elements
        self.message_size = field_elements * iop.field_size_bits

    def cc(self):
        return self.message_size

    def compile(self) -> ArgRound:
        return ArgRound(commitment_size=self.message_size, authentication_path_size=0, opening_size=0, oracle_name=self.oracle_name)

    def display(self):
        print(f"{self.oracle_name}:\n\tfield_elements: {self.field_elements}\n\tmessage_size: {self.message_size/(8*1024)} KB")

class IOPOracleMessage:
    def __init__(self, iop, proof_length, alphabet_size, folding, oracle_name: str) -> None:
        self.iop = iop

        # Size of proof oracles sent in this round (in alphabet elements)
        self.proof_length = proof_length
        # Number of queries by verifier to this round
        self.verifier_queries = 0
        self.oracle_name = oracle_name
        self.alphabet_size = alphabet_size
        self.folding = folding

    def cc(self):
        return self.proof_length * self.alphabet_size

    def query(self, queries):
        self.verifier_queries += queries

    def display(self):
        print(f"{self.oracle_name}:\n\tproof_length: 2^{log2(self.proof_length)}\n\tverifier_queries: {self.verifier_queries}")

    def compile(self) -> ArgRound:
        commitment_size = self.iop.rom.secparam
        authentication_path_size = self.iop.rom.authentication_path_size(self.proof_length//self.folding,self.verifier_queries) + self.verifier_queries * min(self.alphabet_size * self.folding, self.iop.rom.secparam) # Note this the term in the min is the opening of the leaf close to our
        opening_size = self.verifier_queries * self.alphabet_size * self.folding

        return ArgRound(commitment_size=commitment_size, authentication_path_size=authentication_path_size, opening_size=opening_size, oracle_name=self.oracle_name)


