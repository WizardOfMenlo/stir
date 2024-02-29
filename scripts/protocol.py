from ldt_params import LDTParameters
from math import log2

from utils import convert_size
import math


class Message:
    def __init__(self, params : LDTParameters, name=""):
        self.name = name
        self.query_num = 0
        self.params = params
    
    def query(self, num = 1):
        self.query_num += num

    def field_size(self):
        return self.params.field_size_bits
    
    def queries(self):
        return self.query_num

    def argument_size(self):
        pass
    
    def proof_length(self):
        pass

    def print(self):
        pass

    def hash_size(self):
        return self.params.rom.hashsize

class GenericOracleMessage(Message):
    def __init__(self, params: LDTParameters, length, name=""):
        super().__init__(params, name)
        self.len = length

    def auth_path_size(self):
        if self.queries() == 0:
            return 0
        
        total_path_size = self.params.rom.authentication_path_size(self.len, self.queries())

        leaf_size = min(self.field_size(), self.hash_size())

        return total_path_size + self.queries() * leaf_size 
    
    def opening_size(self):
        return self.queries() * self.field_size()

    def commitment_size(self):
        return self.hash_size()

    def argument_size(self):
        return self.commitment_size() + self.auth_path_size() + self.opening_size()
    
    def print(self):
        print("Oracle Message")
        print("\tLength: 2^" + str(int(log2(self.len))))
        print("\tQueries: ", self.queries())
        print("\tTotal arg size: ", convert_size(self.argument_size()))
        print("\tOpening size: ", convert_size(self.opening_size()))
        print("\tAuth path size: ", convert_size(self.auth_path_size()))
        print("\tCommitment size: ", convert_size(self.commitment_size()))

class Polynomial(Message):
    def __init__(self, params : LDTParameters, degree, rate_bits, stack=1, name=""):
        Message.__init__(self,params, name)
        self.degree = degree
        self.rate = rate_bits
        self.stack = stack
        self.fold_param = 1
    
    def fold(self, k):
        if k != 1:
            assert(self.fold_param == 1)
            self.fold_param = k

    def fold_amount(self):
        return self.fold_param

    def rate_bits(self):
        return self.rate

    def degree_real(self):
        return self.degree

    def degree_virtual(self):
        return self.degree / self.fold_param
    
    def length_real(self):
        return self.degree_real() * 2**self.rate_bits() * self.stack
    
    def length_virtual(self):
        return self.degree_virtual() * 2**self.rate_bits()
    
    def auth_path_size(self):
        if self.queries() == 0:
            return 0
        
        total_path_size = self.params.rom.authentication_path_size(self.length_virtual(), self.queries())

        leaf_size = min(self.field_size() * self.stack * self.fold_amount(), self.hash_size())

        return total_path_size + self.queries() * leaf_size 
    
    def opening_size(self):
        return self.queries() * self.field_size() * self.fold_amount() * self.stack

    def commitment_size(self):
        return self.hash_size()

    def argument_size(self):
        return self.commitment_size() + self.auth_path_size() + self.opening_size()
    
    def proof_length(self):
        return self.length_real()
    
    def reps_full_sec(self):
        return self.params.repetition_parameter(self.rate_bits())
    
    def fixed_proof_of_work(self):
        rho = self.rate_bits()
        rep = math.ceil((self.params.secparam - self.params.pow)/rho)
        diff = rho * rep - (self.params.secparam - self.params.pow)
        return self.params.pow - diff
    
    

    def print(self):
        print("Polynomial")
        print("\tDegree: 2^" + str(int(log2(self.degree_real()))))
        if self.stack == 1:
            print("\tLength: 2^" + str(log2(self.proof_length())))
        else:
            print("\tLength: 2^" + str(log2(self.proof_length())) + " = " + str(self.stack) + " x 2^" + str(log2(self.degree_real() * 2**self.rate_bits())))
        print("\tRate: 2^-" + str(self.rate_bits()))
        print("\tFolding: 2^" + str(log2(self.fold_amount())))
        print("\tStack num: " + str(self.stack))
        print("\tQueries: ", self.queries())
        print("\tTotal arg size: ", convert_size(self.argument_size()))
        print("\tOpening size: ", convert_size(self.opening_size()))
        print("\tAuth path size: ", convert_size(self.auth_path_size()))
        print("\tCommitment size: ", convert_size(self.commitment_size()))
        print(f"\tProof of work: 2^{self.fixed_proof_of_work()}")
        

class CombinePolynomial(Polynomial):
    def __init__(self, params: LDTParameters, polys, rate_bits, name=""):
        self.list =polys
        d = max([p.degree_virtual() for p in self.list])
        super().__init__(params, d, rate_bits, stack=1, name=name)
        
    def proof_length(self):
        l = 0
        for msg in self.list:
            l += msg.proof_length()
        return l

    def query(self, num):
        for msg in self.list:
            msg.query(num)

    def auth_path_size(self):
        len = 0
        for msg in self.list:
            len += msg.auth_path_size()
        return len
    
    def opening_size(self):
        len = 0
        for msg in self.list:
            len += msg.opening_size()
        return len
    
    def commitment_size(self):
        len = 0
        for msg in self.list:
            len += msg.commitment_size()
        return len
    
    def fold(self, folding):
        assert(self.fold_amount() == 1)
        for msg in self.list:
            msg.fold(folding)
        self.fold_param = folding
    
    def print(self):
        print("**Combine begin**")
        print("\tCombine Degree: 2^" + str(int(log2(self.degree_real()))))
        print("\tCombine Length: 2^" + str(int(log2(self.proof_length()))))
        print("\tCombine Rate: 2^-" + str(self.rate_bits()))
        print("\tCombine Folding: 2^" + str(int(log2(self.fold_amount()))))
        print("\tCombine Queries: ", self.queries())
        for msg in self.list:
            msg.print()
        print("** Combine end **")

class NonOracleMessage(Message):
    def __init__(self, params : LDTParameters, length, name=""):
        Message.__init__(self, params, name)
        self.length = length

    def argument_size(self):
        return self.length * self.field_size()
    
    def proof_length(self):
        return self.length
    
    def queries(self):
        return 0
    
    def print(self):
        print("Field element")
        print("\tNum elements: 2^" + str(log2(self.proof_length())))
        print("\tSize: ", convert_size(self.argument_size()))
        
class Round:
    def __init__(self):
        self.stopped = False
        self.message_list = []
        self.lastOracle = None
    
    def stop_protocol(self):
        self.stopped = True

    def isStopped(self):
        return self.stopped

    def addMessage(self, msg : Message):
        self.message_list.append(msg)
        if isinstance(msg, Polynomial):
            self.lastOracle = msg

    def proof_length(self):
        s = 0
        for msg in self.message_list:
            s += msg.proof_length()
        return s

    def argument_size(self):
        s = 0
        for msg in self.message_list:
            s += msg.argument_size()
        return s
    
    def queries(self):
        q = 0
        for msg in self.message_list:
            q += msg.queries()
        return q
    
    def print(self):
        for msg in self.message_list:
            msg.print()
    
    def getLastOracle(self):
        return self.lastOracle

class Protocol:
    def __init__(self, ldt_params: LDTParameters):
        self.params = ldt_params
        #msg = Polynomial(ldt_params, ldt_params.degree, ldt_params.rho_bits)
        #rnd_init = Round()
        #rnd_init.addMessage(msg)
        #self.rounds = [rnd_init]
        self.stopped = False
        #self.lastOracle = msg
        self.rounds = []
        self.lastOracle = None

    def addRound(self, rnd : Round):
        if self.stopped == False:
            self.rounds.append(rnd)
            self.stopped = rnd.isStopped()
            self.lastOracle = rnd.lastOracle
        
    def getLastOracle(self):
        return self.lastOracle

    def stop(self):
        self.stopped = True

    def isStopped(self):
        return self.stopped

    def argument_size(self):
        len = 0
        for msg in self.rounds:
            len += msg.argument_size()
        return len
    
    def proof_length(self):
        len = 0
        for msg in self.rounds:
            len += msg.proof_length()
        return len
    
    def queries(self):
        q = 0
        for rnd in self.rounds:
            q += rnd.queries()
        return q
    
    def print_arg(self):
        for msg in self.rounds:
            print(convert_size(msg.argument_size()))

    def print(self):
        c = 1
        for msg in self.rounds:
            print("=========")
            print("Round " + str(c) + ":")
            c+=1
            msg.print()
            print("=========")
