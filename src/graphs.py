from pathlib import Path
import pprint

import seaborn as sns
import matplotlib
import matplotlib.pyplot as plt


# ------------------------------------------------------------------------------
def create_bar_graph(df, title=' ', max_x: float = None, max_y: float = None, filename: Path = None):
    pp = pprint.PrettyPrinter(indent=4)

    sns.set()
    sns.set_style('ticks')

    # Assume first column are the periods
    datax = df.columns[0]
    datay = df.columns[1]

    categories = list(df.columns)

    plt.figure(figsize=(16, 8))
    ax = plt.subplot()
    ax.set_title(title, fontsize='large', y=1.05)
    ax.set_ylabel(datay, fontsize='medium', loc='center')
    ax.set_xlabel(datax, fontsize='medium', loc='center', labelpad=15.0)

    if max_y:
        ax.set_ylim(0, max_y)
    else:
        ax.set_ylim(0, df[datay].max())
    ax.yaxis.set_minor_locator(matplotlib.ticker.AutoMinorLocator())
    plt.tick_params(axis='y', which='minor', direction='out', length=3, width=0.5)
    plt.tick_params(axis='y', which='major', width=0.5, labelsize='small')

    if max_x:
        ax.set_xlim(0, max_x)
    else:
        ax.set_xlim(0, df[datax].max())
    loc = matplotlib.ticker.MultipleLocator(base=10)
    ax.xaxis.set_major_locator(loc)
    ax.xaxis.set_minor_locator(matplotlib.ticker.MultipleLocator(5))
    plt.tick_params(axis='x', which='minor', direction='out', length=3, width=0.5, rotation=90, labelsize='x-small')
    plt.tick_params(axis='x', which='major', length=5, width=0.5, rotation=0, labelsize='small')

    plt.xticks()
    plt.yticks()

    plt.grid(which='major', linestyle='dashed', color='black', linewidth=1)
    plt.grid(which='minor', linestyle='solid', color='grey', linewidth=0.5)

    plt.bar(df[datax], df[datay], color='darkgreen', width=1)

    plt.tight_layout()
    if filename:
        plt.savefig(str(filename) + '.svg', bbox_inches='tight')
        plt.savefig(str(filename) + '.png', bbox_inches='tight')
    plt.close()


# ------------------------------------------------------------------------------
def create_line_graph(df, title=' ', normalize_x: bool = False, normalize_y: bool = False, filename: Path = None):
    pp = pprint.PrettyPrinter(indent=4)

    sns.set()
    sns.set_style('ticks')

    datax = df.columns[0]
    datay = df.columns[1]

    plt.figure(figsize=(16, 8))
    ax = plt.subplot()
    ax.set_title(title, fontsize='large', y=1.05)
    ax.set_ylabel(datay, fontsize='medium', loc='center')
    ax.set_xlabel(datax, fontsize='medium', loc='center', labelpad=15.0)

    if normalize_y:
        df[datay] = df[datay] / df[datay].max()
    ax.set_ylim(0, df[datay].max())
    ax.yaxis.set_minor_locator(matplotlib.ticker.AutoMinorLocator())
    plt.tick_params(axis='y', which='minor', direction='out', length=3, width=0.5)
    plt.tick_params(axis='y', which='major', width=0.5, labelsize='small')

    if normalize_x:
        df[datax] = df[datax] / df[datax].max()
    ax.set_xlim(0, df[datax].max())
    ax.xaxis.set_minor_locator(matplotlib.ticker.AutoMinorLocator())
    plt.tick_params(axis='x', which='minor', direction='out', length=3, width=0.5, rotation=90, labelsize='x-small')
    plt.tick_params(axis='x', which='major', length=5, width=0.5, rotation=0, labelsize='small')

    plt.xticks()
    plt.yticks()

    plt.grid(which='major', linestyle='dashed', color='black', linewidth=1)
    plt.grid(which='minor', linestyle='solid', color='grey', linewidth=0.5)

    plt.plot(df[datax], df[datay], color='darkgreen')

    plt.tight_layout()
    if filename:
        plt.savefig(str(filename) + '.svg', bbox_inches='tight')
        plt.savefig(str(filename) + '.png', bbox_inches='tight')
    plt.close()
