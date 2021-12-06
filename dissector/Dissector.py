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
import hashlib
import sys
import signal
import pandas as pd
from pathlib import Path

# Local imports
from config import ctrl_c_handler, LOGGER, CHECK_VERSION, CHECK_DB_STATUS, FILE_NAMES, FINGERPRINT_DIR, Filetype, \
    SAMPLING_RATE
from ddosdb_interaction import check_ddosdb_availability
from file_loader import load_file
from analysis import infer_target, infer_attack_vectors, generate_vector_fingerprint, generate_fingerprint
from user_interaction import print_logo, print_fingerprint, save_fingerprint
from fingerprint import Fingerprint, AttackVector

__version__: str = "4.0"


def main():
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
            LOGGER.error("Please provide only traffic capture files of the same file type (PCAP or FLOWs)")
            sys.exit(-1)
        filetype = filetype_
        if len(df_) > 0:
            df = pd.concat([df, df_])  # Combine DataFrames of multiple input files

    if filetype == Filetype.FLOW and (SAMPLING_RATE is None or not isinstance(SAMPLING_RATE, int) or SAMPLING_RATE < 1):
        LOGGER.error("When using Flow files, please provide the sampling rate (1 in ?) of the capture file with the -r "
                     "flag (e.g. -r 128)")
        sys.exit(-1)

    if len(df) == 0:
        LOGGER.error("Traffic files were read, but no data was found.")
        sys.exit(-1)

    # Infer attack target from data. Dataframe might have changed to homogenize the target IP addresses in case of
    # a carpet bombing attack.
    target_ip, df = infer_target(df)
    # Filter dataframe to only contain traffic sent to the target
    df = df[df.ip_dst == target_ip]

    fingerprint = Fingerprint(filetype, df)

    # Infer attack vector(s)
    attack_vectors = infer_attack_vectors(df)
    df_filtered = pd.concat(attack_vectors)

    vector_fingerprints = [generate_vector_fingerprint(vector) for vector in attack_vectors]
    fingerprint = generate_fingerprint(df_filtered, vector_fingerprints)

    save_fingerprint(Path(FINGERPRINT_DIR) / (fingerprint['ddos_attack_key'][:15] + '.json'), fingerprint)
    print_fingerprint(fingerprint)


if __name__ == '__main__':
    main()
