from math import log2, ceil

def OOD(d, F, r, eta, ood_reps):
    list_size = d/(r * eta)
    den = d**ood_reps * list_size**2
    num = 2 *(F - d/r)**ood_reps
    return den / num
    
def proximity_gaps(d, F, r, eta, m):
    den = (m-1) * d
    num = eta * r**2 * F
    return den / num
    
def get_eta(secparam,d,F,r,k,ood_reps,t):
    err = (d * (t+ood_reps + 1)) / (F * r**2)
    return 2**secparam * err

def shift_err(r, eta, t):
    return (r + eta)**t

def get_t(secparam, r, eta):
    return ceil(secparam / -log2(r + eta))

if __name__ == '__main__':
    secparam = 106
    log_degree = 30
    
    fieldsizebits = 196
    conj = 1
    rate_bits = 4
    
    d = float(2**log_degree)
    r = float(2**(-rate_bits))
    F = float(2**fieldsizebits)
    k = float(16)
    ood_reps = 2
    stop_deg = 2**5
    
    eta = get_eta(secparam, d, F, r, k , 0, 0)
    t = get_t(secparam, r, eta)
    
    
    i = 0
    print("========================")
    print("========================\n")
    print(f"Deg_{i}: {log2(d)}, Reps_{i}: {t}, Rate_{i}: {-log2(r)}, Eta_{i}: {-log2(eta):.5f}")
    print(f"Err Fold: {-log2(proximity_gaps(d/k, F,r, eta, k)):.2f}")
    print("\r\n========================\r\n")
    while d > stop_deg:
        i = i + 1
        #Compute err(t_{i-1} + s) part
        se = shift_err(r, eta, t)
        d = d/k
        r = (2/k) * r
        eta = get_eta(secparam, d, F, r, k , ood_reps, t)
        if eta < r/d:
            eta = eta + r/d
        #eta = (2/k) * eta + (r / d)
        ood = OOD(d, F, r, eta, ood_reps)
        shift =  proximity_gaps(d, F, r, eta, t + ood_reps) + proximity_gaps(d/k, F, r, eta, k)
        
        print(f"Round {i}: Deg_{i}= {log2(d)}, Reps_{i-1}= {t}, Rate_{i}= {-log2(r)}, Eta_{i}= {-log2(eta):.5f}")
        print(f"Err Out_{i}= {-log2(ood):.5f}")
        print(f"Err Shift_{i}= {-log2(se + shift):.5f} by {-log2(se):.5f} and {-log2(shift):.5f}")
        print("\r\n========================\r\n")
        
        # update t
        t = get_t(secparam, r, eta)
        
    print(f"Round {i}: Deg_{i}= {log2(d)}, Reps_{i-1}= {t}, Rate_{i}= {-log2(r)}, Eta_{i}= {-log2(eta):.5f}")   
    print(f"Err Fin: {-log2(shift_err(r, eta, t)):.5f}\n")
    print("========================")
    print("========================")
    
