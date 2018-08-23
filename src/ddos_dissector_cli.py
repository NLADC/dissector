#!/usr/bin/env python
import platform
import shutil
import sys
import subprocess
import os.path
import hashlib
import json

# In case no settings.py is found, use the default one as new settings config
try:
    import settings
except ImportError:
    shutil.copy2("settings.example.py", "settings.py")
    import settings

import ddos_dissector as ddd

# Circumvent issue macOS High Sierra has with pools
if platform.system() == "Darwin":
    from multiprocessing.dummy import Pool
else:
    from multiprocessing.pool import Pool


def check_requirements():
    # dummy function that tries all the stuff you will need
    f = open(os.path.join(settings.OUTPUT_LOCATION, 'logs.log'), 'w')


def anonymize(_input_file, _file_type, _victim_ip, _fingerprint, _multivector_key):
    return ddd.anonymize_attack_vector(_input_file, _file_type, _victim_ip, _fingerprint, _multivector_key)


def ddos_dissector(input_file):
    orig_stdout = sys.stdout
    f = open(os.path.join(settings.OUTPUT_LOCATION, 'logs.log'), 'w')
    sys.stdout = f

    print('1. Analysing the type of input file (e.g., pcap, pcapng, nfdump, netflow, and ipfix)...') 
    file_type = ddd.determine_file_type(input_file)
    
    print('2. Converting input file to dataframe...') 
    df = ddd.convert_to_dataframe(input_file, file_type) 
    
    print('3. Analysing the dataframe for finding attack patterns...')
    victim_ip, fingerprints = ddd.analyze_dataframe(df, file_type)

    print('4. Creating annonymized files containing only the attack vectors...\n')
    
    multivector_key = str(hashlib.md5(str(fingerprints[0]['start_timestamp']).encode()).hexdigest())
    # printing key, multivector_key and original filename in the logs file
    print("original_name = " + input_file)
    print("multivector_key = " + multivector_key)
    thekey = [str(hashlib.md5(str(x['start_timestamp']).encode()).hexdigest()) for x in fingerprints]
    print("key = " + str(thekey))

    logfilename = os.path.join(settings.OUTPUT_LOCATION, multivector_key + ".log")
    with open(logfilename, "w+") as outfile:
        json.dump({
            "original_name": input_file,
            "multivector_key": multivector_key,
            "key": [str(hashlib.md5(str(x['start_timestamp']).encode()).hexdigest()) for x in fingerprints]
        }, outfile)

    with Pool(settings.POOL_SIZE) as p:
        # Run all fingerprints at the same time
        items = [(input_file, file_type, victim_ip, x, multivector_key) for x in fingerprints]
        p.starmap(anonymize, items)

    sys.stdout = orig_stdout
    f.close()

    process = subprocess.Popen("clear")
    output, error = process.communicate()

    print('DDoS dissector completed task! Please check output folder.\n\n')


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='')

    parser.add_argument('--input', metavar='input_file', required=True,
                        help='Path of a input file')

    args = parser.parse_args()
    input_file = args.input
    
    check_requirements()

    if os.path.isfile(input_file):
        ddos_dissector(input_file)
    else:
        print("We were unable to find the file. Please check the file path!")
