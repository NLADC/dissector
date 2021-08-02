#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###############################################################################
# Concordia Project
#
# This project has received funding from the European Union’s Horizon
# 2020 Research and Innovation program under Grant Agreement No 830927.
#
# Maintained by
# Thijs van den Hout (SIDN) - thijs.vandenhout@sidn.nl
###############################################################################

import sys
import signal
import pandas as pd

# Local imports
from config import ctrl_c_handler, LOGGER, CHECK_VERSION, CHECK_DB_STATUS, FILE_NAMES
from ddosdb_interaction import check_ddosdb_availability
from user_interaction import print_logo
from file_loader import load_file
from analysis import infer_target, infer_attack_vectors

__version__: str = "4.0"


def main():
    # Start up
    print_logo()  # Print Dissector logo
    signal.signal(signal.SIGINT, ctrl_c_handler)  # Ctrl C handler for async events

    # Terminating actions
    if CHECK_VERSION:
        print(f"Dissector version: {__version__}")
        sys.exit(0)

    if CHECK_DB_STATUS:
        check_ddosdb_availability()
        sys.exit(0)

    # Read traffic capture file(s)
    if FILE_NAMES is None or len(FILE_NAMES) == 0:
        LOGGER.error("No network traffic capture files provided. Provide them with -f <filename(s)>.")
        sys.exit(-1)

    global df  # FIXME this is here for debugging purposes only
    df = pd.DataFrame()
    filetype = None

    for filename in FILE_NAMES:
        filetype_, df_ = load_file(filename)
        if filetype not in [None, filetype_]:
            LOGGER.error("Please provide only traffic capture files of the same file type (PCAP or flows)")
            sys.exit(-1)
        filetype = filetype_
        df = pd.concat([df, df_])  # Combine DataFrames of multiple input files

    if len(df) == 0:
        LOGGER.error("Traffic files were read, but no data was found.")
        sys.exit(-1)

    # Infer attack target from data. Dataframe might have changed to homogenize the target IP addresses in case of
    # a carpet bombing attack.
    target_ip, df = infer_target(df)

    # Infer attack vector(s)
    infer_attack_vectors(df)


if __name__ == '__main__':
    main()
