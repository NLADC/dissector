#!/usr/bin/env python
import os.path
import platform
import shutil
import sys
import tempfile
import logging
import signal
import argparse

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


def signal_handler(sig, frame):
    print('Ctrl+C detected.')
    sys.exit(0)

def check_requirements():
    # dummy function that tries all the stuff you will need

    # logging
    handle, temp_file = tempfile.mkstemp()
    os.close(handle)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.FileHandler(temp_file)]
    )
    # print also in stdeer
    if (args.verbose):
        logging.getLogger().addHandler(logging.StreamHandler())


    # ovewrite configuration file parameters 
    if (args.target):
        settings.DDOSDB_URL = args.target

    # ovewrite configuration file parameters
    if (args.username):
        settings.USERNAME= args.username

    # ovewrite configuration file parameters
    if (args.password):
        settings.PASSWORD= args.password

    # Tries to create a folder for the output
    try:
        os.makedirs(settings.OUTPUT_LOCATION)
    except FileExistsError:
        # directory already exists
        pass
    return (temp_file)

# For calling the anonymizer in parallel
def anonymize(_input_file, _file_type, _victim_ip, _fingerprint):
    return ddd.anonymize_attack_vector(_input_file, _file_type, _victim_ip, _fingerprint)

def ddos_dissector(input_file, dst_ip, temp_file,args):

    print ("processing file {}".format(input_file))
    logging.info('1. Analysing the type of input file (e.g., pcap, pcapng, nfdump, netflow, and ipfix)...\n')
    file_type = ddd.determine_file_type(input_file)

    logging.info('2. Converting input file to dataframe...\n')
    df = ddd.convert_to_dataframe(input_file, file_type)

    logging.info('3. Analysing the dataframe for finding attack patterns...\n')
    victim_ip, fingerprints = ddd.analyze_dataframe(df, dst_ip, file_type)

    if len(fingerprints) > 0:
        logging.info('4. Export fingerprints to json files and annonymizing each attack vector...\n')
        with Pool(settings.POOL_SIZE) as p:
            items = [(input_file, file_type, victim_ip, x) for x in fingerprints]
            p.starmap(anonymize, items)

        logging.info('5. Uploading the fingerprints and the anonymized .pcap to {}...\n'.format(settings.DDOSDB_URL))
        for x in fingerprints:
            pcap_file = os.path.join(settings.OUTPUT_LOCATION, x['key'] + '.pcap')
            fingerprint_path = os.path.join(settings.OUTPUT_LOCATION, x['key'] + '.json')
            key = x['key']
             
            try:
                http_return = ddd.upload(pcap_file, fingerprint_path, key, settings.DDOSDB_URL, settings.USERNAME, settings.PASSWORD)
                logging.warning("status_code:",http_return, pcap_file)
                print (http_return)
            except:
                logging.error('Fail! The output files were not uploaded to {}'.format(settings.DDOSDB_URL))

        # Storing the summary of the execution
        logging.info("\nSUMMARY:")
        logging.info(os.path.basename(input_file))
        logging.info(fingerprints[0]['multivector_key'])
        logging.info(str(';'.join([x['key'] for x in fingerprints])))
        logging.info(str(';'.join([x['vector_filter'] for x in fingerprints])))
        logging.info(str(';'.join([str(x['total_src_ips']) for x in fingerprints])))

        ##defining the name of the log file
        logfile_name = os.path.join(settings.OUTPUT_LOCATION, fingerprints[0]['multivector_key'] + ".log")

    else:
        logging.info("\nTHERE ARE NO DDOS ATTACK IN THE INPUT TRAFFIC. POSSIBLY ONLY A DOS ATTACK!\n")
        
        logging.info("\nSUMMARY:")
        logging.info(os.path.basename(input_file)+";NA;NA;NA;NA")
        ##defining the name of the log file
        logfile_name = os.path.join(settings.OUTPUT_LOCATION,os.path.basename(input_file)+".log")

    # mv tempfile to filename

    ##Informing the user that the attack was analyzed 
    print ('\nDDoS dissector completed task! Please check:', logfile_name)
    shutil.copy(temp_file, logfile_name)
    os.remove(temp_file)


if __name__ == '__main__':

    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--input', metavar='input_file', required=True, help='Path of a input file')
    parser.add_argument('--dst-ip', metavar='dst_ip', required=False, help='IP that was attacked')
    parser.add_argument("-v","--verbose", help="print info msg", action="store_true")
    parser.add_argument("-t","--target", nargs='?', help='Database IP address to submit the fingerprints')
    parser.add_argument("-u","--username", nargs='?', help='Database username used to submit the fingerprints')
    parser.add_argument("-p","--password", nargs='?', help='Database password used to submit the fingerprints')

    args = parser.parse_args()
    input_file = args.input
    dst_ip = args.dst_ip or False

    temp_file = check_requirements()

    if os.path.isfile(input_file):
        ddos_dissector(input_file, dst_ip, temp_file, args)
    else:
        print("We were unable to find the file. Please check the file path!")
