import hashlib
import json
import os
import platform
import subprocess
import tempfile

import numpy as np

from ddos_dissector.exceptions.UnsupportedFileTypeError import UnsupportedFileTypeError
from ddos_dissector.upload_fingerprint import *

BITTWISTE = "/usr/bin/bittwiste"
TSHARK = "/usr/bin/tshark"
EDITCAP = "/usr/bin/editcap"
OUTPUT_LOCATION = "output/"


def anonymize_attack_vector(input_file, file_type, victim_ip, fingerprint, multivector_key):
    """
    Remove all sensitive information from this attack vector
    :param input_file:
    :param file_type:
    :param victim_ip:
    :param fingerprint:
    :return:
    """
    if file_type == "pcap" or file_type == "pcapng":
        return anonymize_pcap(input_file, victim_ip, fingerprint, multivector_key, file_type)
    elif file_type == "nfdump":
        return anonymize_nfdump(input_file, victim_ip, fingerprint, multivector_key, file_type)
    else:
        raise UnsupportedFileTypeError("The file type " + file_type + " is not supported.")


def anonymize_pcap(input_file, victim_ip, fingerprint, multivector_key, file_type):
    
    filter_out = "\"ip.dst == " + victim_ip

    if str(fingerprint['protocol']).lower() == 'ipv4':
        filter_out += " and ip.flags.mf == 1 and ip.frag_offset > 0"

    else:
        if len(fingerprint['src_ports']) == 1 and fingerprint['src_ports'][0] != np.nan:
            filter_out += " and (tcp.srcport == " + str(int(fingerprint["src_ports"][0])) + " or udp.srcport == " + str(int(fingerprint["src_ports"][0])) + ")"

        elif len(fingerprint['dst_ports']) == 1 and fingerprint['dst_ports'][0] != np.nan:
            filter_out += " and (tcp.dstport == " + str(int(fingerprint["dst_ports"][0])) + " or udp.dstport == " + str(int(fingerprint["dst_ports"][0])) + ")"

        else:
            pass

        filter_out += " and "+str(fingerprint['protocol']).lower()

        if str(fingerprint['protocol']).lower() == 'icmp':
            filter_out += " and icmp.type== "+str(fingerprint['additional']['icmp_type'])

        # if str(fingerprint['protocol']).lower() == 'udp':
            
        if str(fingerprint['protocol']).lower() == 'dns':
            filter_out += " and dns.qry.name contains " + str(fingerprint['additional']['dns_query'])
            filter_out += " and dns.qry.type == " + str(fingerprint['additional']['dns_type'])
            
        # if str(fingerprint['protocol']).lower() == 'http': 
            
        # if str(fingerprint['protocol']).lower() == 'quic':

        # if str(fingerprint['protocol']).lower() == 'udp':

        # if str(fingerprint['protocol']).lower() == 'ntp':

        # if str(fingerprint['protocol']).lower() == 'chargen:

        # if str(fingerprint['protocol']).lower() == 'ssdp':
            #to be filled-in later

        if str(fingerprint['protocol']).lower() != 'icmp':
            filter_out += " and not icmp"
    
    filter_out += "\""

    # Filter fingerprint Int64
    def filter_fingerprint(items):
        if type(items) is dict:
            for key, value in items.items():
                if type(value) is np.int64:
                    items[key] = int(value)
                elif type(value) is dict or type(value) is list:
                    items[key] = filter_fingerprint(value)
        elif type(items) is list:
            for i in range(len(items)):
                value = items[i]
                if type(value) is np.int64:
                    items[i] = int(value)
                elif type(value) is dict or type(value) is list:
                    items[i] = filter_fingerprint(value)

        return items

    md5 = str(hashlib.md5(str(fingerprint['start_timestamp']).encode()).hexdigest())
    fingerprint["key"] = md5
    fingerprint["multivector_key"] = multivector_key
    with open(os.path.join(OUTPUT_LOCATION, md5 + '.json'), 'w+') as outfile:
        fingerprint = filter_fingerprint(fingerprint)
        json.dump(fingerprint, outfile)

    filename = md5 + "." + str(file_type)

    temporary_pcapng_fd, temporary_pcapng_name = tempfile.mkstemp()
    temporary_pcap_fd, temporary_pcap_name = tempfile.mkstemp()

    p = subprocess.Popen([TSHARK + " -r \"" + input_file + "\" -w \"" + temporary_pcapng_name + "\" -Y " + filter_out],
                         shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()

    p = subprocess.Popen([EDITCAP + " -F libpcap -T ether \"" +
                          temporary_pcapng_name + "\" \"" + temporary_pcap_name + "\""],
                         shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()

    if os.path.exists(temporary_pcap_name):
        command = BITTWISTE + " -I \"" + temporary_pcap_name + "\" " \
                  "-O " + os.path.join(OUTPUT_LOCATION,filename) + " -T ip -d " + victim_ip + ",127.0.0.1"
        print("Running: " + command)
        p = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE)
        p.communicate()
        p.wait()

    try:
        os.remove(temporary_pcap_name)
    except IOError:
        pass

    try:
        os.remove(temporary_pcapng_name)
    except IOError:
        pass

    print('Uploading the anonymized .pcap file and fingerprint to the database.')
    fingerprint_path = os.path.join(OUTPUT_LOCATION,md5+'.json')
    key = md5
    pcap_file = os.path.join(OUTPUT_LOCATION,md5+'.pcap')
    try:
        upload(pcap_file, fingerprint_path, key)
    except ValueError:
        print('Fail! The output files were not uploaded to the database.')
        

def anonymize_nfdump(input_file, victim_ip, fingerprint, multivector_key, file_type):
    # Filtering based on host/proto and ports

    if len(fingerprint['src_ports']) > 1:
        filter_out = "dst ip " + victim_ip + " and proto " + str(fingerprint['ip_protocol']) + " and dst port " + \
                     str(list(fingerprint["dst_ports"].keys())[0])
    else:
        filter_out = "dst ip " + victim_ip + " and proto " + str(fingerprint['ip_protocol']) + " and src port " + \
                     str(list(fingerprint["src_ports"].keys())[0])

    # proper filename based on start timestamp and selected port
    timestamp = fingerprint["start_timestamp"].split()
    filename = timestamp[0].replace("-", "") + timestamp[1].replace(":", "") + \
        "_" + str(fingerprint["selected_port"]) + ".nfdump"

    temporary_file_fd, temporary_file_name = tempfile.mkstemp()

    # running nfdump with the filters created above
    p = subprocess.Popen(["nfdump_modified/bin/nfdump -r " + input_file +
                          " -w " + temporary_file_name + " " + "'" + filter_out + "'"],
                         shell=True,
                         stdout=subprocess.PIPE)
    p.communicate()
    p.wait()

    p = subprocess.Popen(["nfdump_modified/bin/nfanon -r " + temporary_file_name + " -w " + os.path.join(OUTPUT_LOCATION,filename)],
                         shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()

    try:
        os.remove(temporary_file_name)
    except IOError:
        pass
