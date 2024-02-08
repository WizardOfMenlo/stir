from math import ceil, sqrt

class ReedSolomonParameters:
    def __init__(self, degree, eval_domain_size, field_size):
        self.degree = degree
        self.eval_domain_size = eval_domain_size
        self.rate = (degree + 1) / eval_domain_size
        self.field_size = field_size
    
class ProximityGenerator:
    def __init__(self, rs_params, num_elements):
        self.rs_params = rs_params
        self.num_elements = num_elements
        pass

    def proximity_bound(self):
        # Proven one
        #return sqrt(self.rs_params.rate)
        # Conjectured one
        return self.rs_params.rate

    # What is nu real name? 
    def list_decodability(self, nu_parameter):
        sqrt_rate = sqrt(self.rs_params.rate)
        assert(nu_parameter > 0 and nu_parameter <= 1 - sqrt_rate)
        gamma = 1 - sqrt_rate - nu_parameter
        l = 1/(2 * nu_parameter * sqrt_rate)
        return gamma, l

    def error(self, proximity):
        # Computed as in Thm 4.2
        assert(proximity >= 0 and proximity <= 1)

        if proximity <= (1 - self.rs_params.rate) / 2:
            base_error = self.rs_params.evaluation_domain_size() / self.rs_params.field_size
        else:
            num = (self.rs_params.degree + 1)**2
            den = self.rs_params.field_size * (2 * min(1 + sqrt(self.rs_params.rate) - proximity, sqrt(self.rs_params.rate) / 20))**7
            base_error = num / den

        return self.num_elements * base_error

