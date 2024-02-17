#! /usr/bin/env python3

###############################################################################
import sys
import os
import logging
import argparse
from pathlib import Path
from argparse import RawTextHelpFormatter
import textwrap

import pandas as pd
import pprint
from math import pi
import duckdb

import seaborn as sns
import matplotlib
import matplotlib.pyplot as plt


# # ------------------------------------------------------------------------------
# def createBarGraph_old(df, title=' ', y_label='score/percentage', label_suffix='', palette=paletteR, widegraph=False):
#     pp = pprint.PrettyPrinter(indent=4)
#
#     sns.set_style('ticks')
#
#     # Assume first column are the periods
#     df = df.set_index(df.columns[0])
#
#     categories = list(df.columns)
#     # print("Categories ({}): {}".format(len(categories), categories))
#
#     periods = list(df.index.values)
#     if isinstance(df.index, pd.DatetimeIndex):
#         periods = [str(prd)[:10] for prd in df.index.values]
#     # print("Periods ({}): {}".format(len(periods), periods))
#
#     nr_of_bars = len(periods) * len(categories)
#
#     # Create a linear color map from the palette given
#     # to avoid overrunning the palette
#     segments = len(periods)
#     my_cmap = LinearSegmentedColormap.from_list('Custom', palette, segments)
#
#     # if (df.columns)
#     figwidth = 3 + (len(df.columns) * len(df)) / 5.5
#     barWidth = 1.0
#     # Number of bars as gap in between categories
#     cat_gap = 1
#
#     if widegraph:
#         figwidth *= 3
#         barWidth = 0.5
#
#     plt.figure(figsize=(figwidth, 8))
#     ax = plt.subplot()
#     ax.set_title(title, fontname=_graph_font, fontsize='large', y=1.05)
#     ax.set_ylabel('score/percentage', fontname=_graph_font, fontsize='medium', loc='center')
#     ax.set_xlabel('category', fontname=_graph_font, fontsize='medium', loc='center', labelpad=15.0)
#     ax.spines['bottom'].set_linewidth(0.5)
#     ax.spines['left'].set_linewidth(0.5)
#
#     ax.set_ylim(0, 100)
#     loc = matplotlib.ticker.MultipleLocator(base=10)
#     ax.yaxis.set_major_locator(loc)
#     ax.yaxis.set_minor_locator(matplotlib.ticker.MultipleLocator(2))
#     plt.tick_params(axis='y', which='minor', direction='out', length=3, width=0.5)
#     plt.tick_params(axis='y', which='major', width=0.5, labelsize='small')
#     plt.grid(which='major', axis='y', linestyle='dotted', linewidth=0.5, color='black', alpha=0.3)
#
#     ax.xaxis.set_minor_locator(matplotlib.ticker.MultipleLocator(len(periods) + 1))
#     ax.xaxis.set_major_locator(matplotlib.ticker.MultipleLocator(len(periods) + cat_gap))
#     plt.tick_params(axis='x', which='minor', direction='out', length=0, width=0.5, rotation=90, labelsize='x-small')
#     plt.tick_params(axis='x', which='major', direction='out', length=0, width=0.5, labelsize='small')
#
#     plt.xticks(fontname=_graph_font)
#     plt.yticks(fontname=_graph_font)
#
#     for i in range(0, len(periods)):
#         rbars = range(i + 1, nr_of_bars + cat_gap * len(categories) + 1, len(periods) + cat_gap)
#         plt.bar(rbars,
#                 df.iloc[i, :].tolist(),
#                 width=barWidth,
#                 color=my_cmap(i),
#                 edgecolor=(1, 1, 1, 1),
#                 linewidth=1,
#                 label=periods[i],
#                 zorder=2,
#                 )
#         # Plot the values on top
#         for j, r in enumerate(rbars):
#             x = r - 0.2
#             rotation = 'vertical'
#             if widegraph:
#                 x = r - 0.05
#                 rotation = 'horizontal'
#             y = df.iloc[i, j] + 1.5
#             s = str(int(df.iloc[i, j]))
#             plt.text(x=x, y=y, s=s, fontname=_graph_font, fontweight='normal', fontsize='small', rotation=rotation)
#
#     barsx = []
#     for i in range(0, len(categories)):
#         barsx.append(i * (len(periods) + cat_gap) + len(periods) / 2 + 0.5)
#
#     xticks = categories
#     if len(df) > 3:
#         plt.xticks(barsx, xticks, rotation='horizontal', fontname=_graph_font)
#     else:
#         plt.xticks(barsx, xticks, rotation='vertical', fontname=_graph_font)
#
#     leg = plt.legend(prop={'family': _graph_font}, framealpha=0.5, edgecolor='grey')
#     for line in leg.get_lines():
#         line.set_linewidth(7)
#
#     barslots = (len(periods) + cat_gap) * len(categories) - cat_gap
#     plt.margins(x=0.51 / barslots)
#     ax.set_xlim(0, barslots + 1)
#
#     plt.tight_layout()
#     sns.despine()
#     # plt.show()
#
#     return ax


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
    # ax.set_title(title, fontname=_graph_font, fontsize='large', y=1.05)
    # ax.set_ylabel(datay, fontname=_graph_font, fontsize='medium', loc='center')
    # ax.set_xlabel(datax, fontname=_graph_font, fontsize='medium', loc='center', labelpad=15.0)
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
