import math

def next_even_power_of_two(x):
    p = (x-1).bit_length()
    if p % 2 == 1:
        p += 1
    return 1<<p

def convert_size(size_bits):
    if size_bits == 0:
        return "0B"
    size_bytes = size_bits / 8
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])

def num_of_repetitions(sec_param, rhobits, conj):
    if conj == 1:
        return math.ceil(sec_param/rhobits)
    else:
        return math.ceil(2*sec_param/rhobits)