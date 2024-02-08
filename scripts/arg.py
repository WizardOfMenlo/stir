import math
import utils

# Compile an IOP into an argument to compute sizes
class Argument:
    def __init__(self, iop):
        self.iop = iop 
        self.iop_rounds = iop.to_rounds()
        self.arg_rounds = [r.compile() for r in self.iop_rounds]

    # Give communication complexity (in field elements of the IOP)
    def prover_communication_complexity(self):
        return sum(r.cc()//self.iop.field_size_bits for r in self.iop_rounds)



    def size(self):
        return sum(r.size() for r in self.arg_rounds)
    
    def display(self):
        print(f"Argument: {self.iop.name}")
        for iop_round, arg_round in zip(self.iop_rounds, self.arg_rounds):
            iop_round.display()
            arg_round.display()
        print(utils.convert_size(self.size()))

    def display_short(self):
        argument_size = utils.convert_size(self.size())
        iop_length = math.log2(self.prover_communication_complexity())
        print(f"{self.iop.name}: {argument_size}, 2^{iop_length:.2f} FE")



class ArgRound:
    def __init__(self, commitment_size, authentication_path_size, opening_size, oracle_name) -> None:
        self.commitment_size = commitment_size
        self.authentication_path_size = authentication_path_size
        self.opening_size = opening_size
        self.oracle_name = oracle_name

    # In bits
    def size(self):
        return self.commitment_size + self.authentication_path_size + self.opening_size

    def display(self):
        print(f"\tcommitment_size: {self.commitment_size//8} B\n\tauth_path_size: {self.authentication_path_size/(8*1024)} KB\n\topening_size: {self.opening_size/(8*1024)} KB")


# Models the ROM, and Merkle trees
class ROMParameters:
    def __init__(self, hashsize) -> None:
        self.hashsize = hashsize

    # Size of Merkle tree root (in bits)
    def commitment_size(self):
        return self.hashsize

    # Size of an authentication_path in an (unsalted) Merkle tree of 2-arity
    # Note, we ignore the opening of the leaf close to the opened one, as that can depend on the alphabet size
    def authentication_path_size(self, num_committed_elements: int, num_queries: int):
        shared_depth = math.floor(math.log2(num_queries))
        tree_depth = math.ceil(math.log2(num_committed_elements)) - shared_depth - 1
        if tree_depth < 0:
            tree_depth = 0
        return num_queries * tree_depth * self.hashsize 


# Test:
if __name__ == '__main__':
    rom = ROMParameters(256)
    assert(rom.commitment_size() == 256)
    assert(rom.authentication_path_size(2**3, 2) == 2 * 256)
    assert(rom.authentication_path_size(2**3, 1) == 2 * 256)
