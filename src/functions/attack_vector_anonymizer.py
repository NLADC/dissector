import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
from pprint import pprint

import numpy as np

from functions.exceptions.UnsupportedFileTypeError import UnsupportedFileTypeError


def anonymize_attack_vector(input_file, file_type, victim_ip, fingerprint):
    """
    Remove all sensitive information from this attack vector
    :param input_file:
    :param file_type:
    :param victim_ip:
    :param fingerprint:
    :return:
    """
    if file_type == "pcap" or file_type == "pcapng":
        return anonymize_pcap(input_file, victim_ip, fingerprint, file_type)
    elif file_type == "nfdump":
        return anonymize_nfdump(input_file, victim_ip, fingerprint, file_type)
    else:
        raise UnsupportedFileTypeError("The file type " + file_type + " is not supported.")


def anonymize_pcap(input_file, victim_ip, fingerprint, file_type):
    if len(fingerprint['src_ports']) == 1 and fingerprint['src_ports'][0] != np.nan:
        filter_out = "\"ip.dst == " + victim_ip + " and " + str(
            fingerprint['protocol']).lower() + " and (tcp.srcport == " + str(
            int(fingerprint["src_ports"][0])) + " or udp.srcport == " + str(int(fingerprint["src_ports"][0])) + ")\""

    elif len(fingerprint['dst_ports']) == 1 and fingerprint['dst_ports'][0] != np.nan:
        filter_out = "\"ip.dst == " + victim_ip + " and " + str(
            fingerprint['protocol']).lower() + " and (tcp.dstport == " + str(
            int(fingerprint["dst_ports"][0])) + " or udp.dstport == " + str(int(fingerprint["dst_ports"][0])) + ")\""

    else:
        filter_out = "\"ip.dst == " + victim_ip + " and " + str(fingerprint['protocol']).lower() + "\""

    print(filter_out)

    md5 = str(hashlib.md5(str(fingerprint['start_timestamp']).encode()).hexdigest())
    with open('./output/' + md5 + '.json', 'w+') as outfile:
        json.dump(fingerprint, outfile)

    filename = md5 + "." + str(file_type)

    temporary_pcapng_fd, temporary_pcapng_name = tempfile.mkstemp()
    temporary_pcap_fd, temporary_pcap_name = tempfile.mkstemp()

    p = subprocess.Popen(["tshark -r \"" + input_file + "\" -w \"" + temporary_pcapng_name + "\" -Y " + filter_out],
                         shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()

    p = subprocess.Popen(["editcap -F libpcap -T ether \"" +
                          temporary_pcapng_name + "\" \"" + temporary_pcap_name + "\""],
                         shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()

    if os.path.exists(temporary_pcap_name):
        if platform.system() == 'Darwin':
            command = "/usr/local/Cellar/bittwist/2.0/bin/bittwiste -I \"" + temporary_pcap_name + "\" " \
                      "-O output/" + filename + " -T ip -d " + victim_ip + ",127.0.0.1"
            p = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE)
            p.communicate()
            p.wait()

        else:
            command = "bittwiste -I \"" + temporary_pcap_name + "\" -O output/" + \
                      filename + " -T ip -d " + victim_ip + ",127.0.0.1"
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


def anonymize_nfdump(input_file, victim_ip, fingerprint, file_type):
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

    p = subprocess.Popen(["nfdump_modified/bin/nfanon -r " + temporary_file_name + " -w output/" + filename],
                         shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()

    try:
        os.remove(temporary_file_name)
    except IOError:
        pass
