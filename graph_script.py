import pandas as pd
import matplotlib.pyplot as plt
import json
from math import log2

def time_ms(x, reps=1):
    return round((x['secs'] * 1e9 + x['nanos']) / (reps * 1e6), 2)

def time_s(x, reps=1):
    return round((x['secs'] * 1e9 + x['nanos']) / (reps * 1e9), 2)


#prover_data_json = open('outputs/prover_output_sha3.json', 'r')
#verifier_data_json = open('outputs/verifier_output_sha3.json', 'r')

prover_data_json = open('outputs/prover_output_poseidon.json', 'r')
verifier_data_json = open('outputs/verifier_output_poseidon.json', 'r')

prover_data = []
for l in prover_data_json:
    prover_data.append(json.loads(l))

verifier_data = []
for l in verifier_data_json:
    verifier_data.append(json.loads(l))

prover_data = pd.DataFrame(prover_data)
verifier_data = pd.DataFrame(verifier_data)

# Convert to right units
for k in ['stir_prover_time', 'fri_prover_time']:
    prover_data[k] = prover_data[k].apply(time_s)

for k in ['stir_argument_size', 'fri_argument_size']:
    prover_data[k] = prover_data[k].apply(lambda x: x / 1024)

for k in ['stir_verifier_time', 'fri_verifier_time']:
    verifier_data[k] = verifier_data[k].apply(lambda x: time_ms(x, reps=1000))

def set_size(fraction=1, subplots=(1, 1)):
    """Set figure dimensions to avoid scaling in LaTeX.

    Parameters
    ----------
    width: float or string
            Document width in points, or string of predined document type
    fraction: float, optional
            Fraction of the width which you wish the figure to occupy
    subplots: array-like, optional
            The number of rows and columns of subplots.
    Returns
    -------
    fig_dim: tuple
            Dimensions of figure in inches
    """
    width_pt = 469.75502

    # Width of figure (in pts)
    fig_width_pt = width_pt * fraction
    # Convert from pt to inches
    inches_per_pt = 1 / 72.27

    # Golden ratio to set aesthetic figure height
    # https://disq.us/p/2940ij3
    golden_ratio = (5**.5 - 1) / 2

    # Figure width in inches
    fig_width_in = fig_width_pt * inches_per_pt
    # Figure height in inches
    fig_height_in = fig_width_in * golden_ratio * (subplots[0] / subplots[1])

    return (fig_width_in, fig_height_in)

tex_fonts = {
    # Use LaTeX to write all text
    "text.usetex": True,
    "font.family": "serif",
    # Use 10pt font in plots, to match 10pt font in document
    "axes.labelsize": 10,
    "font.size": 10,
    # Make the legend/label fonts a little smaller
    "legend.fontsize": 8,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8
}

plt.rcParams.update(tex_fonts)


linestyle = '-'
stir_marker = '.'
fri_marker = '^'
stir_color = 'tab:blue'
fri_color = 'tab:red'

def plot_per_rate(rate):
    fig, [[ax1, ax2], [ax3, ax4]] = plt.subplots(2, 2, figsize=set_size())
    #fig, [ax1, ax2, ax3, ax4] = plt.subplots(1, 4, figsize=set_size())


    pdata = prover_data[prover_data['starting_rate'] == rate]
    vdata = verifier_data[verifier_data['starting_rate'] == rate]

    # Proving time picture
    ax1.set_title('Prover time')
    ax1.plot('starting_degree', 'stir_prover_time', data=pdata, linestyle=linestyle, marker=stir_marker, color=stir_color)
    ax1.plot('starting_degree', 'fri_prover_time', data=pdata, linestyle=linestyle, marker=fri_marker, color=fri_color)
    ax1.grid()
    ax1.set_xscale('log', base=2)
    ax1.set_yscale('log', base=2)
    ax1.set_ylabel('Time (s)')
    ax1.set_xticks(ticks=pdata['starting_degree'], labels=["$2^{{{}}}$".format(str(int(log2(x)))) for x in pdata['starting_degree']])

    # Verifying time picture
    ax2.set_title('Verifier time')
    ax2.plot('starting_degree', 'stir_verifier_time', data=vdata, linestyle=linestyle, marker=stir_marker, color=stir_color)
    ax2.plot('starting_degree', 'fri_verifier_time', data=vdata, linestyle=linestyle, marker=fri_marker, color=fri_color)
    ax2.grid()
    ax2.set_xscale('log', base=2)
    ax2.set_ylabel('Time (ms)')
    ax2.set_xticks(ticks=pdata['starting_degree'], labels=["$2^{{{}}}$".format(str(int(log2(x)))) for x in pdata['starting_degree']])

    # Argument size
    ax3.set_title('Argument size')
    ax3.plot('starting_degree', 'stir_argument_size', data=pdata, linestyle=linestyle, marker=stir_marker, color=stir_color)
    ax3.plot('starting_degree', 'fri_argument_size', data=pdata, linestyle=linestyle, marker=fri_marker, color=fri_color)
    ax3.grid()
    ax3.set_xscale('log', base=2)
    ax3.set_ylabel('Size (KiB)')
    ax3.set_xticks(ticks=pdata['starting_degree'], labels=["$2^{{{}}}$".format(str(int(log2(x)))) for x in pdata['starting_degree']])

    # Verifier hashes
    ax4.set_title('Verifier hashes')
    ax4.plot('starting_degree', 'stir_verifier_hashes', data=vdata, linestyle=linestyle, marker=stir_marker, color=stir_color)
    ax4.plot('starting_degree', 'fri_verifier_hashes', data=vdata, linestyle=linestyle, marker=fri_marker, color=fri_color)
    ax4.grid()
    ax4.set_xscale('log', base=2)
    ax4.set_ylabel('Hashes')
    ax4.set_xticks(ticks=pdata['starting_degree'], labels=["$2^{{{}}}$".format(str(int(log2(x)))) for x in pdata['starting_degree']])

    plt.tight_layout()

    # Save and remove excess whitespace
    fig.savefig(str(rate) + '_graph.pdf', format='pdf', bbox_inches='tight')

def plot_all(rates):
    rate_colors = {1: 'tab:blue', 2: 'tab:green', 3: 'tab:orange', 4: 'tab:red'}
    xs = prover_data['starting_degree'].unique()
    xs.sort()

    # Proving time
    fig, ax = plt.subplots(figsize=set_size())
    ax.set_title('Prover time')
    for r in rates:
        color = rate_colors[r]
        pdata = prover_data[prover_data['starting_rate'] == r]
        ax.plot('starting_degree', 'stir_prover_time', data=pdata, linestyle=linestyle, marker=stir_marker, color=color)
        ax.plot('starting_degree', 'fri_prover_time', data=pdata, linestyle=linestyle, marker=fri_marker, color=color)
    ax.grid()
    ax.set_xscale('log', base=2)
    ax.set_yscale('log', base=2)
    ax.set_ylabel('Time (s)')
    ax.set_xticks(ticks=xs, labels=["$2^{{{}}}$".format(str(int(log2(x)))) for x in xs])
    plt.tight_layout()
    # Save and remove excess whitespace
    fig.savefig('provertime_graph.pdf', format='pdf', bbox_inches='tight')


    # Verifier time
    fig, ax = plt.subplots(figsize=set_size())
    ax.set_title('Verifier time')
    for r in rates:
        color = rate_colors[r]
        vdata = verifier_data[prover_data['starting_rate'] == r]
        ax.plot('starting_degree', 'stir_verifier_time', data=vdata, linestyle=linestyle, marker=stir_marker, color=color)
        ax.plot('starting_degree', 'fri_verifier_time', data=vdata, linestyle=linestyle, marker=fri_marker, color=color)
    ax.grid()
    ax.set_xscale('log', base=2)
    ax.set_ylabel('Time (ms)')
    ax.set_xticks(ticks=xs, labels=["$2^{{{}}}$".format(str(int(log2(x)))) for x in xs])
    plt.tight_layout()
    # Save and remove excess whitespace
    fig.savefig('verifiertime_graph.pdf', format='pdf', bbox_inches='tight')


    # Argument size
    fig, ax = plt.subplots(figsize=set_size())
    ax.set_title('Argument size')
    for r in rates:
        color = rate_colors[r]
        pdata = prover_data[prover_data['starting_rate'] == r]
        ax.plot('starting_degree', 'stir_argument_size', data=pdata, linestyle=linestyle, marker=stir_marker, color=color)
        ax.plot('starting_degree', 'fri_argument_size', data=pdata, linestyle=linestyle, marker=fri_marker, color=color)
    ax.grid()
    ax.set_xscale('log', base=2)
    ax.set_ylabel('Size (KiB)')
    ax.set_xticks(ticks=xs, labels=["$2^{{{}}}$".format(str(int(log2(x)))) for x in xs])
    plt.tight_layout()
    # Save and remove excess whitespace
    fig.savefig('argumentsize_graph.pdf', format='pdf', bbox_inches='tight')

    # Verifier hashes
    fig, ax = plt.subplots(figsize=set_size())
    ax.set_title('Verifier hashes')
    for r in rates:
        color = rate_colors[r]
        vdata = verifier_data[verifier_data['starting_rate'] == r]
        ax.plot('starting_degree', 'stir_verifier_hashes', data=vdata, linestyle=linestyle, marker=stir_marker, color=color)
        ax.plot('starting_degree', 'fri_verifier_hashes', data=vdata, linestyle=linestyle, marker=fri_marker, color=color)
    ax.grid()
    ax.set_xscale('log', base=2)
    ax.set_ylabel('Hashes')
    ax.set_xticks(ticks=xs, labels=["$2^{{{}}}$".format(str(int(log2(x)))) for x in xs])
    plt.tight_layout()
    # Save and remove excess whitespace
    fig.savefig('vhashes_graph.pdf', format='pdf', bbox_inches='tight')

from math import floor, log10
def round_to_n(x, n): 
    initial = round(x, -int(floor(log10(x))) + (n - 1)) 
    if round(initial * 10) % 10 == 0:
        return round(initial)
    return initial

def get_table(data, stir_key, fri_key, xs, rates):
    table_entries = []
    for rate in rates:
        row = []
        for d in xs:
            entry = data[(data['starting_degree'] == d) & (data['starting_rate'] == rate)]
            if entry.empty:
                row.append(None)
            else:
                stir_time = entry[stir_key].values[0]
                fri_time = entry[fri_key].values[0]
                row.append((stir_time, fri_time))
        table_entries.append(row)
    return table_entries

def format_prover(table, rates):
    result = []
    for row in table:
        new_row = []
        for i in range(len(row)):
            if row[i] is None:
                new_row.append('-')
            else:
                stir_time, fri_time = row[i]
                ratio = round(fri_time / stir_time, 2)
                stir_time = round_to_n(stir_time, 2)
                fri_time = round_to_n(fri_time, 2)
                new_row.append('$\\frac{{ {} }}{{ {} }} \\approx {} \\times $'.format(fri_time, stir_time, ratio))
        result.append(new_row)

    return '\\\\\n'.join([' & '.join(["$\\sfrac{{1}}{{{}}}$".format(2**rate)] + row) for rate,row in zip(rates, result)])


def format_table(table, rates, round_precision=None):
    result = []
    for row in table:
        new_row = []
        for i in range(len(row)):
            if row[i] is None:
                new_row.append('-')
            else:
                stir_time, fri_time = row[i]
                ratio = round(fri_time / stir_time, 2)
                stir_time = round(stir_time, round_precision)
                fri_time = round(fri_time, round_precision)
                new_row.append('$\\frac{{ {} }}{{ {} }} \\approx {} \\times $'.format(fri_time, stir_time, ratio))
        result.append(new_row)

    return '\\\\\n'.join([' & '.join(["$\\sfrac{{1}}{{{}}}$".format(2**rate)] + row) for rate,row in zip(rates, result)])



def make_latex_tables(rates):
    xs = prover_data['starting_degree'].unique()
    xs.sort()

    prover_time = get_table(prover_data, 'stir_prover_time', 'fri_prover_time', xs, rates)
    prover_time = format_prover(prover_time, rates)
    print(prover_time)
    print('------------------')

    verifier_time = get_table(verifier_data, 'stir_verifier_time', 'fri_verifier_time', xs, rates)
    verifier_time = format_table(verifier_time, rates, round_precision=1)
    print(verifier_time)
    print('------------------')

    argument_size = get_table(prover_data, 'stir_argument_size', 'fri_argument_size', xs, rates)
    argument_size = format_table(argument_size, rates)
    print(argument_size)
    print('------------------')

    verifier_hashes = get_table(verifier_data, 'stir_verifier_hashes', 'fri_verifier_hashes', xs, rates)
    verifier_hashes = format_table(verifier_hashes, rates)
    print(verifier_hashes)
    print('------------------')


make_latex_tables([1, 2, 3])
plot_all([1, 2, 3])
plot_per_rate(1)
plot_per_rate(2)
plot_per_rate(3)
