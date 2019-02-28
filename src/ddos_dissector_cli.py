#!/usr/bin/env python
import os.path
import platform
import shutil
import sys
import tempfile

# Tries to import the settings for the system (settings.py) if not found then use the default one as new settings config
try:
    import settings
except ImportError:
    shutil.copy2("settings.example.py", "settings.py")
    import settings

import ddos_dissector as ddd

# Circumvent issue macOS High Sierra has with pools (for parallel processing)
if platform.system() == "Darwin":
    from multiprocessing.dummy import Pool
else:
    from multiprocessing.pool import Pool


def check_requirements():
    # dummy function that tries all the stuff you will need

    # Tries to create a folder for the output
    try:
        os.makedirs(settings.OUTPUT_LOCATION)
    except FileExistsError:
        # directory already exists
        pass

# For calling the anonymizer in parallel
def anonymize(_input_file, _file_type, _victim_ip, _fingerprint):
    return ddd.anonymize_attack_vector(_input_file, _file_type, _victim_ip, _fingerprint)

def ddos_dissector(input_file, dst_ip):
    # For storing the logs
    orig_stdout = sys.stdout
    f, f_name = tempfile.mkstemp()
    f = open(f_name, "w")
    sys.stdout = f

    print('1. Analysing the type of input file (e.g., pcap, pcapng, nfdump, netflow, and ipfix)...\n')
    file_type = ddd.determine_file_type(input_file)

    print('2. Converting input file to dataframe...\n')
    df = ddd.convert_to_dataframe(input_file, file_type)

    print('3. Analysing the dataframe for finding attack patterns...\n')
    victim_ip, fingerprints = ddd.analyze_dataframe(df, dst_ip, file_type)

    if len(fingerprints) > 0:
        print('4. Export fingerprints to json files and annonymizing each attack vector...\n')
        with Pool(settings.POOL_SIZE) as p:
            items = [(input_file, file_type, victim_ip, x) for x in fingerprints]
            p.starmap(anonymize, items)

        print('5. Uploading the fingerprints and the anonymized .pcap to ddosdb.org...\n')
        for x in fingerprints:
            pcap_file = os.path.join(settings.OUTPUT_LOCATION, x['key'] + '.pcap')
            fingerprint_path = os.path.join(settings.OUTPUT_LOCATION, x['key'] + '.json')
            key = x['key']
            try:
                ddd.upload(pcap_file, fingerprint_path, settings.USERNAME, settings.PASSWORD, key)
            except:
                print('Fail! The output files were not uploaded to ddosdb.org')

        print(os.path.basename(input_file), fingerprints[0]['multivector_key'], [x['key'] for x in fingerprints], sep='\t')

        ##Closing and renaming the log file
        sys.stdout = orig_stdout
        f.close()
        shutil.copy(f_name, os.path.join(settings.OUTPUT_LOCATION, fingerprints[0]['multivector_key'] + ".log"))
        os.remove(f_name)

    else:
        print('There are NO DDoS attacks in the input traffic. Possibly only a DoS attack!')
        sys.stdout = orig_stdout
        f.close()
        shutil.copy(f_name, os.path.join(settings.OUTPUT_LOCATION,"failed.log"))
        os.remove(f_name)

    ##Informing the user that the attack was analyzed 
    print('\n\nDDoS dissector completed task! Please check the log file at the output folder.\n\n')


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='')

    parser.add_argument('--input', metavar='input_file', required=True, help='Path of a input file')
    parser.add_argument('--dst-ip', metavar='dst_ip', required=False, help='IP that was attacked')

    args = parser.parse_args()
    input_file = args.input
    dst_ip = args.dst_ip or False

    check_requirements()

    if os.path.isfile(input_file):
        ddos_dissector(input_file, dst_ip)
    else:
        print("We were unable to find the file. Please check the file path!")