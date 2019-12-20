import os
import subprocess
import tempfile

import pandas as pd

import settings
from ddos_dissector.exceptions.UnsupportedFileTypeError import UnsupportedFileTypeError


def determine_file_type(input_file):
    """
    Determine what sort of file the input is.
    :param input_file: The path to the file, e.g. /home/user/example.pcap
    :return: The file type of the input file as a string
    :raises UnsupportedFileTypeError: If input file is not recognised or not supported
    """
    file_info, error = subprocess.Popen([settings.FILE, input_file], stdout=subprocess.PIPE).communicate()

    file_type = file_info.decode("utf-8").split()[1]

    if file_type == "tcpdump":
        return "pcap"
    elif file_type == "pcap-ng":
        return "pcapng"
    elif file_type == "data" and (b"nfdump" in file_info or b"nfcapd" in file_info):
        return "nfdump"
    else:
        raise UnsupportedFileTypeError("The file type " + file_type + " is not supported.")


def convert_to_dataframe(input_file, file_type):
    """
    Get the Pandas dataframe of the input file, based on the file_type
    :param input_file: The path to the file, e.g. /home/user/example.pcap
    :param file_type: The file type of the input file as a string, obtained from determine_file_type
    :return: The Pandas dataframe
    """
    if file_type == "pcap" or file_type == "pcapng":
        return convert_pcap_to_dataframe(input_file)
    elif file_type == "nfdump":
        return convert_nfdump_to_dataframe(input_file)
    else:
        raise UnsupportedFileTypeError("The file type " + file_type + " is not supported.")


def convert_pcap_to_dataframe(input_file):
    """
    Convert a pcap file to a Pandas dataframe
    :param input_file: The path to the file, e.g. /home/user/example.pcap
    :return: The Pandas dataframe
    """
    if not os.path.exists(input_file):
        raise IOError("File " + input_file + " does not exist")

    tshark_fields = "-e frame.time_epoch " \
                    "-e _ws.col.Source " \
                    "-e _ws.col.Destination " \
                    "-e _ws.col.Protocol " \
                    "-e frame.len " \
                    "-e ip.ttl " \
                    "-e ip.flags.mf " \
                    "-e ip.frag_offset " \
                    "-e icmp.type " \
                    "-e tcp.srcport " \
                    "-e tcp.dstport " \
                    "-e udp.srcport " \
                    "-e udp.dstport " \
                    "-e dns.qry.name " \
                    "-e dns.qry.type " \
                    "-e http.request " \
                    "-e http.response " \
                    "-e http.user_agent " \
                    "-e tcp.flags.str " \
                    "-e ntp.priv.reqcode "

    temporary_file = tempfile.TemporaryFile("r+b")

    # print(shutil.which(command))

    p = subprocess.Popen([settings.TSHARK + " -n -r \"" + input_file + "\" -E separator='\x03'  -E header=y -T fields " + tshark_fields],
                         shell=True, stdout=temporary_file) #\x03 is ETX
    p.communicate()
    p.wait()

    # Reset file pointer to start of file
    temporary_file.seek(0)

    df = pd.read_csv(temporary_file, sep="\x03", low_memory=False, error_bad_lines=False)

    temporary_file.close()

    if ('tcp.srcport' in df.columns) and ('udp.srcport' in df.columns) and ('tcp.dstport' in df.columns) and \
            ('udp.dstport' in df.columns):
        # Combine source and destination ports from tcp and udp
        df['srcport'] = df['tcp.srcport'].fillna(df['udp.srcport'])
        df['dstport'] = df['tcp.dstport'].fillna(df['udp.dstport'])

        df['srcport'] = df['srcport'].apply(lambda x: int(x) if str(x).replace('.', '', 1).isdigit() else 0)
        df['dstport'] = df['dstport'].apply(lambda x: int(x) if str(x).replace('.', '', 1).isdigit() else 0)

    # Remove columns: 'tcp.srcport', 'udp.srcport','tcp.dstport', 'udp.dstport'
    df.drop(['tcp.srcport', 'udp.srcport', 'tcp.dstport', 'udp.dstport'], axis=1, inplace=True)

    # Drop all empty columns (for making the analysis more efficient! less memory.)
    df.dropna(axis=1, how='all', inplace=True)
    df = df.fillna(0)

    if 'icmp.type' in df.columns:
        df['icmp.type'] = df['icmp.type'].astype(str)

    if 'ip.frag_offset' in df.columns:
        df['ip.frag_offset'] = df['ip.frag_offset'].astype(str)

    if 'ip.flags.mf' in df.columns:
        df['ip.flags.mf'] = df['ip.flags.mf'].astype(str)

    if ('ip.flags.mf' in df.columns) and ('ip.frag_offset' in df.columns):
        # Analyse fragmented packets
        df['fragmentation'] = (df['ip.flags.mf'] == '1') | (df['ip.frag_offset'] != '0')
        df.drop(['ip.flags.mf', 'ip.frag_offset'], axis=1, inplace=True)

    if 'tcp.flags.str' in df.columns:
        df['tcp.flags.str'] = df['tcp.flags.str'].str.encode("utf-8")  

    df['ip.ttl'] = df['ip.ttl']
    df['tcp.flags.str'] = df['tcp.flags.str'].str.decode("utf-8")

    return df


def convert_nfdump_to_dataframe(input_file):
    """
    Convert an nfdump file to a Pandas dataframe
    :param input_file: The path to the file, e.g. /home/user/example.nfdump
    :return: The Pandas dataframe
    """
    temporary_file_fd, temporary_file_name = tempfile.mkstemp()

    # Convert nflow to csv
    p = subprocess.Popen(
        ["nfdump_modified/bin/nfdump -r " + input_file + " -o extended -o csv > " + temporary_file_name],
        shell=True,
        stdout=subprocess.PIPE)
    p.communicate()
    p.wait()

    columns = ['start_time',  # ts,
               'end_time',  # te,
               'time duration',  # td,
               'src_ip',  # sa,
               'dst_ip',  # da,
               'src_port',  # sp,
               'dst_port',  # dp,
               'ip_proto',  # pr,
               'tcp_flag',  # flg,
               'forwarding',  # fwd,
               'src_tos',  # stos,
               'i_packets',  # ipkt,
               'i_bytes',  # ibyt,
               'o_packets',  # opkt,
               'o_bytes',  # obyt,
               'i_interface_num',  # in,
               'o_interface_num',  # out,
               'src_as',  # sas,
               'dst_as',  # das,
               'src_mask',  # smk,
               'dst_mask',  # dmk,
               'dst_tos',  # dtos,
               'direction',  # dir,
               'next_hop_ip',  # nh,
               'bgt_next_hop_ip',  # enhb,
               'src_vlan_label',  # svln,
               'dst_vlan_label',  # dvln,
               'i_src_mac',  # ismc,
               'o_dst_mac',  # odmc,
               'i_dst_mac',  # idmc,
               'o_src_mac',  # osmc,
               'mpls1',
               'mpls2',
               'mpls3',
               'mpls4',
               'mpls5',
               'mpls6',
               'mpls7',
               'mpls8',
               'mpls9',
               'mpls10',
               'cl',
               'sl',
               'al',
               'ra',
               'eng',
               'exid',
               'tr']

    # Reset file pointer to start of file

    df = pd.read_csv(temporary_file_name, low_memory=False)

    df.dropna(inplace=True, how='any')

    df['dp'] = df['dp'].astype('int32')
    df['ibyt'] = df['ibyt'].astype('int32')
    df['sp'] = df['sp'].astype('int32')

    df.columns = columns

    try:
        os.remove(temporary_file_name)
    except IOError:
        pass

    return df


#######################
#######################
# if __name__ == '__main__':
#   import argparse
#   import os.path
#   parser = argparse.ArgumentParser(description='')
#   parser.add_argument('--input', metavar='input_file', required=True,help='Path of a input file')
#   args = parser.parse_args()
#   input_file = args.input

#   if os.path.isfile(input_file):
#       # convert_pcap_to_dataframe(input_file)
#       df = convert_pcap_to_dataframe(input_file)
#       print(type(df['icmp.type'][6]),df['icmp.type'][6])
#   else:
#       print("We were unable to find the file. Please check the file path!")
