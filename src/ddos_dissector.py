from multiprocessing.pool import Pool

from functions.file_type_parser import *
from functions.dataframe_analysis import *
from functions.attack_vector_anonymizer import *
from functions.upload_fingerprint import *


def anonymize(_input_file, _file_type, _victim_ip, _fingerprint):
    return anonymize_attack_vector(_input_file, _file_type, _victim_ip, _fingerprint)


def ddos_dissector(input_file):
    print('1. Analysing the type of input file (e.g., pcap, pcapng, nfdump, netflow, and ipfix)...') 
    file_type = determine_file_type(input_file)
    
    print('2. Converting input file to dataframe...') 
    df = convert_to_dataframe(input_file, file_type) 
    
    print('3. Analysing the dataframe for finding attack patterns...')
    victim_ip, fingerprints = analyze_dataframe(df, file_type)

    print('4. Creating annonymized files containing only the attack vectors...\n')

    with Pool(len(fingerprints)) as p:
        # Run all fingerprints at the same time
        items = [(input_file, file_type, victim_ip, x) for x in fingerprints]
        p.starmap(anonymize, items)

    print('\n\nDONE!!!!!')


if __name__ == '__main__':
    import argparse
    import os.path

    parser = argparse.ArgumentParser(description='')

    parser.add_argument('--input', metavar='input_file', required=True,
                        help='Path of a input file')

    args = parser.parse_args()
    input_file = args.input

    if os.path.isfile(input_file):
        ddos_dissector(input_file)
    else:
        print("We were unable to find the file. Please check the file path!")

