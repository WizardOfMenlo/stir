import math

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
