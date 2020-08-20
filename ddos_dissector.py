#!/usr/bin/env python3
###############################################################################
#  
#  
# @copyright - Joao Ceron - joaoceron@sidn.nl
###############################################################################

###############################################################################
### Python modules
import argparse
import logging
import os
import pandas as pd
import re
import signal
import sys
from subprocess import check_output, STDOUT
from io import StringIO
import multiprocessing as mp
import queue as queue
import threading
import time 
import cursor
import logging
import numpy as np
import requests
import hashlib
import json
from datetime import datetime
import configparser
from argparse import RawTextHelpFormatter

from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter

###############################################################################
### Program settings
verbose = False
program_name = os.path.basename(__file__)
version = open("VERSION.TXT", "r").read()

# GLOBAL parameters
# percentage used to determine correlation between to lists
SIMILARITY_THRESHOLD = 80
NONE = -1

###############################################################################
### Subrotines
#------------------------------------------------------------------------------
def parser_args ():

    parser = argparse.ArgumentParser(prog=program_name, usage='%(prog)s [options]', epilog="Example: ./%(prog)s -f attack.pcap --summary --upload ", formatter_class=RawTextHelpFormatter)
    parser.add_argument("--version", help="print version and exit", action="store_true")
    parser.add_argument("-v","--verbose", help="print info msg", action="store_true")
    parser.add_argument("-d","--debug", help="print debug info", action="store_true")
    parser.add_argument("-q","--quiet", help="ignore animation", action="store_true")
    parser.add_argument("--status", dest='status', help="check available repositories", action="store_true")
    parser.add_argument("-s","--summary", help="present fingerprint evaluation summary", action="store_true")
    parser.add_argument("-u","--upload", help="upload to the selected repository", action="store_true")
    parser.add_argument("--log", default='log.txt', nargs='?',help="Log filename. Default =./log.txt\"")
    parser.add_argument("--config", default='ddosdb.conf', nargs='?',help="Configuration File. Default =./log.txt\"")
    parser.add_argument("-g","--graph", help="build dot file (graphviz). It can be used to plot a visual representation\n of the attack using the tool graphviz. When this option is set, youn will\n received information how to convert the generate file (.dot) to image (.png).", action="store_true")

    parser.add_argument('-f','--filename', nargs='?', required=False, help="")
    return parser

#------------------------------------------------------------------------------
def signal_handler(sig, frame):
    print('Ctrl+C detected.')
    cursor.show()
    sys.exit(0)
#------------------------------------------------------------------------------
class CustomConsoleFormatter(logging.Formatter):
    def format(self, record):
        formater = "%(levelname)s - %(message)s"
        if record.levelno == logging.INFO:
            GREEN = '\033[32m'
            reset = "\x1b[0m"
            log_fmt = GREEN + formater + reset
            self._style._fmt = log_fmt
            return super().format(record)
        if record.levelno == logging.DEBUG:
            CYAN = '\033[36m'
            reset = "\x1b[0m"
            log_fmt = CYAN + formater + reset
            self._style._fmt = log_fmt
            return super().format(record)
        if record.levelno == logging.ERROR:
            MAGENTA = '\033[35m'
            reset = "\x1b[0m"
            log_fmt = MAGENTA + formater + reset
            self._style._fmt = log_fmt
            return super().format(record)
        if record.levelno == logging.WARNING:
            YELLOW = '\033[33m'
            reset = "\x1b[0m"
            log_fmt = YELLOW + formater + reset
            self._style._fmt = log_fmt
        else:
            self._style._fmt = formater
        return super().format(record)

#------------------------------------------------------------------------------
def logger(args):

    logger = logging.getLogger(__name__)

    # root logging
    if (args.debug):
       logger.setLevel(logging.DEBUG)
    elif (args.verbose):
       logger.setLevel(logging.INFO)

    # Create handlers
    console_handler = logging.StreamHandler()
    file_handler = logging.FileHandler(args.log)
    #console_handler.setLevel(logging.DEBUG)
    #file_handler.setLevel(logging.INFO)

    # add custom formater
    my_formatter = CustomConsoleFormatter()
    console_handler.setFormatter(my_formatter)

    f_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)")
    file_handler.setFormatter(f_format)

    # add handlers to the logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger

#------------------------------------------------------------------------------
def upload(pcap, fingerprint, labels, df_fingerprint, config):
    """
    Upload a fingerprint and attack vector to DDoSDB
    :param pcap: Path to the pcap file
    :param fingerprint: Path to the fingerprint file
    :param username: DDoSDB username
    :param password: DDoSDB password
    :param key: ID to identify this attack, also the filename of the pcap_file.
    :return:
    """
    #timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    # timestamp fields
    initial_timestamp  = df_fingerprint['frame_time_epoch'].min()
    initial_timestamp = datetime.utcfromtimestamp(initial_timestamp).strftime('%Y-%m-%d %H:%M:%S')
    fingerprint.update( {"start_time": initial_timestamp} )

    # packet stats
    duration_sec = df_fingerprint['frame_time_epoch'].max() - df_fingerprint['frame_time_epoch'].min()
    fingerprint.update( {"duration_sec": duration_sec} )
    fingerprint.update( {"avg_bps": df_fingerprint.frame_len.sum()/duration_sec })
    fingerprint.update( {"total_packetsduration_sec": len(df_fingerprint)} )
    fingerprint.update( {"avg_pps": len(df_fingerprint)/duration_sec} )
    fingerprint.update( {"total_dst_ports": len(df_fingerprint['dstport'].unique().tolist())} )
    fingerprint.update( {"total_packets": len(df_fingerprint)} )

    # keys used on the repository
    key = str(hashlib.md5(str(fingerprint).encode()).hexdigest())
    fingerprint.update( {"key": key} )
    fingerprint.update( {"multivector_key": key} )

    # set field name based on label 
    if ("AMPLIFICATION" in labels):
       fingerprint.update( {"amplifiers": df_fingerprint['ip_src'].unique().tolist()} )
       fingerprint.update( {"src_ips": df_fingerprint['ip_src'].unique().tolist()} )
    else:
       fingerprint.update( {"attackers": df_fingerprint['ip_src'].unique().tolist()} )
       fingerprint.update( {"src_ips": df_fingerprint['ip_src'].unique().tolist()} )

    # save fingerprint to local file in order to enable the upload via POST
    json_file = "{}.json".format(key)
    with open(json_file, 'w') as f_fingerprint:
        json.dump(fingerprint, f_fingerprint)

    files = {
        "json": open(json_file, "rb"),
        # ignoring pcap file upload for now
        "pcap": open(json_file, "rb"),
    }
    headers = {
        "X-Username": config['repository']['user'],
        "X-Password": config['repository']['passwd'],
        "X-Filename": key
    }

    ddosdb_url = (config['repository']['host'])
    try:
        r = requests.post(ddosdb_url+"upload-file", files=files, headers=headers,verify=True)
    except requests.exceptions.RequestException as e:  
        logger.critical("Cannot connect to the server to upload fingerprint")
        logger.debug("Cannot connect to the server to upload fingerprint: {}".format(e))
        print (e)
        return None

    if (r.status_code==403):
        print ("Invalid credentials or no permission to upload fingerprints:")
    elif (r.status_code==500):
        print ("Internal Server Error. Check repository Django logs.")
    elif (r.status_code==201):
        print ("Upload success: \n\tHTTP CODE [{}] \n\tFingerprint ID [{}]".format(r.status_code,key))
    return r.status_code

#------------------------------------------------------------------------------
def prepare_tshark_cmd(input_path):
    """Prepare the tshark command that converts a PCAP to a CSV."""
    cmd = ['/usr/local/bin/tshark', '-r', input_path, '-T', 'fields']

    # fields included in the csv
    fields = [
                'dns.qry.type', 'ip.dst','ip.flags.mf', 'tcp.flags', 'ip.proto',
                'ip.src', '_ws.col.Destination', '_ws.col.Protocol', '_ws.col.Source',
                'dns.qry.name', 'eth.type', 'frame.len',  '_ws.col.Info',
                'http.request', 'http.response', 'http.user_agent', 'icmp.type',
                'ip.frag_offset', 'ip.ttl', 'ntp.priv.reqcode', 'tcp.dstport',
                'tcp.srcport', 'udp.dstport', 'udp.srcport', 'frame.time_epoch',
            ]

    for f in fields:
        cmd.append('-e')
        cmd.append(f)

    # field options
    options = ['header=y', 'separator=,', 'quote=d', 'occurrence=f']
    for o in options:
        cmd.append('-E')
        cmd.append(o)
    return cmd

#------------------------------------------------------------------------------
def pcap_to_df(ret,filename):
    """Convert PCAP file to DataFrame."""

    cmd = prepare_tshark_cmd(filename)
    data = check_output(cmd, stderr=STDOUT)
    data = str(data, 'utf-8')
    data = StringIO(data)

    df = pd.read_csv(data,low_memory=False,error_bad_lines=False)

    # src/dst port
    if (set(['tcp.srcport','udp.srcport','tcp.dstport','udp.dstport']).issubset(df.columns)):

        # Combine source and destination ports from tcp and udp
        df['srcport'] = df['tcp.srcport'].fillna(df['udp.srcport'])
        df['dstport'] = df['tcp.dstport'].fillna(df['udp.dstport'])
        df['dstport'] = df['dstport'].fillna(NONE).astype(float).astype(int)
        df['srcport'] = df['srcport'].fillna(NONE).astype(float).astype(int)

    if (set(['ip.src','ip.dst','_ws.col.Source','_ws.col.Destination']).issubset(df.columns)):

        # Combine source and destination IP - works for IPv6 
        df['ip.src'] = df['ip.src'].fillna(df['_ws.col.Source'])
        df['ip.dst'] = df['ip.dst'].fillna(df['_ws.col.Destination'])

    # rename protocol field
    df = df.rename({'_ws.col.Protocol': 'highest_protocol'},axis=1)

    df['ip.ttl'] = df['ip.ttl'].fillna(NONE).astype(float).astype(int)
    df['ip.proto'] = df['ip.proto'].fillna(NONE).astype(float).astype(int)
    df['ntp.priv.reqcode'] = df['ntp.priv.reqcode'].fillna(NONE).astype(float).astype(int)

    # timestamp 

    df['start_timestamp'] = df['frame.time_epoch'].iloc[0]

    # Remove columns: 'tcp.srcport', 'udp.srcport','tcp.dstport', 'udp.dstport', _ws.col.Source, _ws.col.Destination
    df.drop(['tcp.srcport', 'udp.srcport', 'tcp.dstport', 'udp.dstport','_ws.col.Source', '_ws.col.Destination'], axis=1, inplace=True)

    # Drop all empty columns (for making the analysis more efficient! less memory.)
    df.dropna(axis=1, how='all', inplace=True)

    df = df.fillna(NONE)
    if 'icmp.type' in df.columns:
        df['icmp.type'] = df['icmp.type'].astype(int)

    if 'ip.frag_offset' in df.columns:
        df['ip.frag_offset'] = df['ip.frag_offset'].astype(str)

    if 'ip.flags.mf' in df.columns:
        df['ip.flags.mf'] = df['ip.flags.mf'].astype(str)

    if ('ip.flags.mf' in df.columns) and ('ip.frag_offset' in df.columns):
        # Analyse fragmented packets
        df['fragmentation'] = (df['ip.flags.mf'] == '1') | (df['ip.frag_offset'] != '0')
        df.drop(['ip.flags.mf', 'ip.frag_offset'], axis=1, inplace=True)

#     if 'tcp.flags.str' in df.columns:
#         df['tcp.flags.str'] = df['tcp.flags.str'].str.encode("utf-8")

    df.columns = [c.replace('.', '_') for c in df.columns]    
    ret.put(df)
#    return df

#------------------------------------------------------------------------------
## Function for calculating the TOP 'N' and aggregate the 'others'
## Create a dataframe with the top N values and create an 'others' category
def top_n_dataframe(dataframe_field,top_n=20):
    
    field_name = dataframe_field.name

    # ignore timestamp field
    if (field_name == "frame_time_epoch"):
        return  pd.DataFrame()

    top  = dataframe_field.value_counts()[:top_n].to_frame().reset_index()

    new_row = pd.DataFrame(data = {
        'count' : [ dataframe_field.value_counts()[top_n:].sum()],
        field_name : ['others'],
    })

    top.columns = [field_name, 'count']
    top.set_index([field_name]).reset_index()
    top_result = pd.concat([top, new_row],sort=False)

    # percentage field
    df = top_result.groupby(field_name).sum()
    df=df.sort_values(by="count", ascending=False)
    df['percent'] = df.transform(lambda x: (x/np.sum(x)*100).round()).astype(int)

    if (len(df)< 16):
        # z-score useless when few elements 
        df['zscore'] = -1
    else:
        # z-score of 2 indicates that an observation is two standard deviations above the average 
        # a z-score of zero represents a value that equals the mean.
        df['zscore'] = ((df['count'] - df['count'].mean())/df['count'].std(ddof=0)).round().fillna(-1)
    return (df.reset_index())

#------------------------------------------------------------------------------
def infer_target_ip (df):
    """
    df: dataframe from pcap
    return: list of target IPs 
    """
    outlier = find_outlier(df['ip_dst'])

    if (len(outlier) ==0):
        return (list(df['ip_dst'].value_counts().keys()[0]))
    else:
        return (outlier)

#------------------------------------------------------------------------------
# print loading animation
def animated_loading(msg="loading "):
    chars = "▁▂▃▄▅▆▇█▇▆▅▄▃▁"
    cursor.hide()
    for char in chars:
        sys.stdout.write('\r'+msg+''+char)
        time.sleep(.1)
        sys.stdout.flush()
    cursor.show()

#------------------------------------------------------------------------------
# Find fingerprint based on protocol and dataframe
def find_fingerprint (df, protocol):

    return 0
#------------------------------------------------------------------------------
def find_outlier(df):
    data = top_n_dataframe(df)

    if (data.empty):
        return None
    data = data[(data['percent']> SIMILARITY_THRESHOLD) | (data['zscore']>2)]
    if (len(data)==0):
        return None

    logger.debug("Finding outlier for .:{}:.\n {}" .format(data.columns[0], data.head(5).to_string(index=False) ))
    outliers = data.iloc[:,0].tolist()
    if ("others" in outliers):
        # `others` is the sum of remains elements from top_n_dataframe
        outliers.remove('others')

    if (len(outliers)>0):
        logger.debug("Outliers for the field `{}`: {}".format(data.columns[0],outliers))
        return outliers
    else:
        logger.debug("No outlier for the field `{}`".format(data.columns[0]))
        return None

#------------------------------------------------------------------------------
# Infer the attack based on filtered dataframe
def infer_protocol_attack(df):
    """
    return: the list of top protocols and if the framentation protocol has found
    """
    target_ip = df['ip_dst'].iloc[0]
    logger.info("A total of {} IPs have attacked the victim {}".format(df_filtered.ip_src.nunique(), target_ip))

    data = top_n_dataframe(df['highest_protocol'])
    data = data[(data['percent']> SIMILARITY_THRESHOLD) | (data['zscore']>2)]
    if (len(data) <1):
        logger.info("Assuming top1 protocol as attack protocol")
        logger.debug("No protocol outlier found in the significance level")
        top1_protocol = df["highest_protocol"].value_counts().keys()[0]
    elif (len(data)>1):
        logger.debug("More than 1 protocol can be classified as outlier")
        #TODO handle multiples protocol
        top1_protocol = data['highest_protocol'].iloc[0]
    else:
        logger.debug("Top1  protocol can be classified as outlier")
        top1_protocol = data['highest_protocol'].iloc[0]

    # fragmentation protocol found
    frag = False

    # generic fragmementation attack 
    # where there is not information about source/destination port
    if bool(re.search('IPv[46]',top1_protocol)):
        frag = df[(df['ip_dst'] == target_ip) & (df['highest_protocol'] == top1_protocol)]['fragmentation'].value_counts().keys()[0]
        array_protocols = []
        if (frag):
            # top protocol is regarding fragmentation attack
            frag_proto = df[(df['ip_dst'] == target_ip) & (df['highest_protocol'] == top1_protocol)]['ip_proto'].value_counts().keys()[0]
            logger.debug("Fragmented based on protocol {}".format(frag_proto))
            array_protocols.append(top1_protocol)
            # drop this protocol and find other 
            df = df[df["highest_protocol"] != top1_protocol]
            top1_protocol_frag = top1_protocol
            # find the top1 protocol again
            top1_protocol = df["highest_protocol"].value_counts().keys()[0]
            array_protocols.append(top1_protocol)
            return (array_protocols, top1_protocol_frag)
        else:
            # it is not frag attack. However, the top1 protocol is IPv4|IPv6. This means that highest_protocol is not the top1
            # regular IP attack where highest_protocol is not defined
            array_protocols = []
            array_protocols.append(top1_protocol)
            return (array_protocols,frag)

    else:
        # not frag attack
        array_protocols = []
        array_protocols.append(top1_protocol)
        return (array_protocols,frag)

    return None

#------------------------------------------------------------------------------
def ip_src_fragmentation_attack_similarity(df,lst_attack_protocols,frag):

    if (not frag):
        return False

    ip_frag    = df[(df['ip_dst'] == target_ip) & (df['highest_protocol'] == lst_attack_protocols[0])]['ip_src'].unique().tolist()
    ip_nonfrag = df[(df['ip_dst'] == target_ip) & (df['highest_protocol'] == lst_attack_protocols[-1])]['ip_src'].unique().tolist()
    ip_list_union = set(ip_frag + ip_nonfrag)
    ip_intersection  = list(set(ip_frag) & set(ip_nonfrag))

    # percentage of IPs in both lists
    percentage_in_intersection = round(len(ip_intersection)*100/len(set(ip_list_union)))
    if (percentage_in_intersection > SIMILARITY_THRESHOLD):
        logger.info("The fragmentation attack is consequence of attack using the protocol {}".format(lst_attack_protocols[-1]))
        logger.debug("A total of {}% IPs in the fragmentation attacks is also performing attack using {}".format(percentage_in_intersection,lst_attack_protocols[-1] ))
        return True

    return False
#------------------------------------------------------------------------------
def load_file(args):
    """
        Load file and return a dataframe
    """
    # load dataframe using threading
    ret = queue.Queue()
    the_process = threading.Thread(name='process', target=pcap_to_df, args=(ret,args.filename))
    the_process.start()
    msg = "Loading network file: `{}' ".format(args.filename)
    while the_process.is_alive():
        animated_loading(msg) if not (args.quiet) else 0
    the_process.join()
    df = ret.get()
    sys.stdout.write('\r'+msg+'.... done!\n')
    return (df)

#------------------------------------------------------------------------------
def inspect_smtp(df):

    attack_protocol = df_filtered['highest_protocol'].iloc[0]
    logger.info("Processing attack based on {}".format(attack_protocol))

    fields = df.columns.tolist()
    fields.remove("eth_type")
    fields.remove("ip_dst")

    fingerprint  = {}
    for field in fields:
        outlier = find_outlier(df_filtered[field])
        if (outlier):
            if (outlier != [NONE]):
                 fingerprint.update( {field : outlier} )

    return (fingerprint)

#------------------------------------------------------------------------------
def inspect_ntp(df):

    attack_protocol = df_filtered['highest_protocol'].iloc[0]
    logger.info("Processing attack based on {}".format(attack_protocol))

    fields = df.columns.tolist()
    fields.remove("eth_type")
    fields.remove("_ws_col_Info")
    fields.remove("dstport")

    fingerprint  = {}
    for field in fields:
        outlier = find_outlier(df_filtered[field])
        if (outlier):
            if (outlier != [NONE]):
                fingerprint.update( {field : outlier} )


    return (fingerprint)

#------------------------------------------------------------------------------
def inspect_harder(df_filtered,df_full):

    logger.info("Trying harder")
    fields = df_filtered.columns.tolist()
    #fields.remove("eth_type")
    fields.remove("ip_dst")

    fingerprint  = {}
    for field in fields:
        outlier = find_outlier(df_filtered[field])
        if (outlier):
            if (outlier != [NONE]):
                fingerprint.update( {field : outlier} )

    df = df_filtered

    results = {}
    # how many rows each field can filter
    for key, value in fingerprint.items():
        total_rows_matched = len(df_full[df_full[key].isin(value)])
        percentage = round(total_rows_matched*100/len(df_full))
        # dict with all the fields and results
        results.update( {key: percentage} )
    results_sorted = {k: v for k, v in sorted(results.items(), key=lambda item: item[1],  reverse=True)}

    for label, percentage in results_sorted.items():
        printProgressBar(percentage,label,"▭ ")

    return (fingerprint)

#------------------------------------------------------------------------------
def inspect_dns(df_fingerprint):

    attack_protocol = df_filtered['highest_protocol'].iloc[0]
    logger.info("Processing attack based on {}".format(attack_protocol))

    fields = df_filtered.columns.tolist()
    #fields.remove("eth_type")
    fields.remove("ip_dst")

    fingerprint  = {}
    for field in fields:
        outlier = find_outlier(df_filtered[field])
        if (outlier):
            if (outlier != [NONE]):
                fingerprint.update( {field : outlier} )

    return (fingerprint)

#------------------------------------------------------------------------------
def generate_dot_file(df,fingerprint,args,similarity=False):

    df_fingerprint = df.loc[df[fingerprint.keys()].isin(fingerprint.values()).all(axis=1),:]
    total_rows_matched  =  len(df.loc[df[fingerprint.keys()].isin(fingerprint.values()).all(axis=1), :])
    total_ips_matched_using_fingerprint = df_fingerprint['ip_src'].unique().tolist()

    if (similarity):

        # SRC_IP from frag attack and generated fingerprint are very correlated.
        # Here we add 'frag attack filter' to the matched dataframe to compute the match rate using both attacks (frag + fingerprint)
        df_frag = df[(df['ip_dst'] == target_ip) & (df['fragmentation'] ==1) & (df['dstport'] ==0) & (df['ip_src'].isin(total_ips_matched_using_fingerprint))]
        df_fingerprint = pd.concat([df_fingerprint,df_frag], ignore_index=True)
        df_fingerprint = df_fingerprint.drop_duplicates(keep="first")


    # sum up dataframe to plot
    df_fingerprint = df_fingerprint[['ip_src','ip_dst']].drop_duplicates(keep="first")
    df_fingerprint['match'] = 1
    df_remain = df[~df.ip_src.isin(df_fingerprint.ip_src.tolist())][['ip_src','ip_dst']].drop_duplicates(keep="first")
    df_remain['match'] = 0

    df_plot = pd.concat([df_fingerprint,df_remain], ignore_index=True)

    # anonymize plot data
    df_plot.reset_index(inplace=True)
    df_plot.drop('ip_src',axis=1,inplace=True)
    df_plot = df_plot.rename(columns={"index": "ip_src"})
    df_plot['ip_dst'] = "victim"
    logger.debug("Distribution of filtered traffic: \n{}".format(df_plot.match.value_counts(normalize=True).mul(100)))

    filename, file_extension = os.path.splitext(args.filename)
    with open(filename+".dot", 'w+', encoding = 'utf-8') as f:
        f.write("graph {\n")
        for index, row in df_plot.iterrows():
            if (row['match'] == 0 ):
                f.write("\t {} -- {}[color=green,penwidth=1.0];\n".format(row["ip_src"], row["ip_dst"]))
            else:
                f.write("\t {} -- {}[color=red,penwidth=2.0];\n".format(row["ip_src"], row["ip_dst"]))
        f.write("}\n")
    print ("Use the following command to generate an image:")
    print ("\t sfdp -x -Goverlap=scale -Tpng {}.dot  > {}.png".format(filename,filename))
#    print ("\t convert {}.png  -gravity North   -background YellowGreen  -splice 0x18 -annotate +0+2 'Dissector'  {}.gif ".format(filename,filename))


#------------------------------------------------------------------------------
def entropy(x, bins=None):
    N   = x.shape[0]
    if bins is None:
        counts = np.bincount(x)
    else:
        counts = np.histogram(x, bins=bins)[0] # 0th idx is counts
    p   = counts[np.nonzero(counts)]/N # avoids log(0)
    H   = -np.dot( p, np.log2(p) )
    return H 

#------------------------------------------------------------------------------
def printProgressBar(value,label,fill_chars="■-"):

    n_bar = 40 #size of progress bar
    max = 100
    j= value/max
    sys.stdout.write('\r')
    bar = fill_chars[0] * int(n_bar * j)
    bar = bar + fill_chars[1] * int(n_bar * (1-j))

    sys.stdout.write(f"{label.ljust(16)} | [{bar:{n_bar}s}] {int(100 * j)}% ")
    sys.stdout.flush()
    print ("")
    return True

#------------------------------------------------------------------------------
def filter_fingerprint(df,fingerprint,similarity=False):

    # filter full DF using the built fingerprint filter
    df_fingerprint = df
    for key, value in fingerprint.items():
        df_fingerprint = df_fingerprint[df_fingerprint[key].isin(value)]
    total_ips_matched_using_fingerprint = df_fingerprint['ip_src'].unique().tolist()

    if (similarity):

        # SRC_IP from frag attack and generated fingerprint are very correlated.
        # Here we add 'frag attack filter' to the matched dataframe to compute the match rate using both attacks (frag + fingerprint)
        df_frag = df[(df['ip_dst'] == target_ip) & (df['fragmentation'] ==1) & (df['dstport'] ==0) & (df['ip_src'].isin(total_ips_matched_using_fingerprint))]
        df_fingerprint = pd.concat([df_fingerprint,df_frag], ignore_index=True)
        df_fingerprint = df_fingerprint.drop_duplicates(keep="first")
        total_ips_matched_using_fingerprint = df_fingerprint['ip_src'].unique().tolist()
        logger.debug("Frag attack filter added to the matched dataframe")

    return (df_fingerprint)

#------------------------------------------------------------------------------
def evaluate_fingerprint(df,df_fingerprint,fingerprint):

    # filter full DF using the built fingerprint
    total_rows_matched  =  len(df_fingerprint)
    total_ips_matched_using_fingerprint = df_fingerprint['ip_src'].unique().tolist()

    logger.info("TRAFFIC MATCHED: {0}%. The generated fingerprint will filter {0}% of the analysed traffic".format(round(len(df_fingerprint)*100/len(df))))
    percentage_of_ips_matched = len(df_fingerprint['ip_src'].unique().tolist() )*100/len(df.ip_src.unique().tolist())
    logger.info("IPS MATCHED    : {0}%. The generated fingerprint will filter {0}% of SRC_IPs".format(round(percentage_of_ips_matched)))

    if not (args.quiet):
        value = round(len(df_fingerprint)*100/len(df))
        printProgressBar(value,"TRAFFIC MATCHED")
        printProgressBar(round(percentage_of_ips_matched),"IPs MATCHED")

    # remove added tags fields
    fingerprint.pop('tags',None)

    if (args.verbose) or (args.debug):
         results = {}
         # how many rows each field can filter
         for key, value in fingerprint.items():
             total_rows_matched = len(df[df[key].isin(value)])
             percentage = round(total_rows_matched*100/len(df))
             # dict with all the fields and results
             results.update( {key: percentage} )
         results_sorted = {k: v for k, v in sorted(results.items(), key=lambda item: item[1],  reverse=True)}
 
         logger.info("          ================ FIELDS COVERAGE ================ ")
         for label, percentage in results_sorted.items():
             printProgressBar(percentage,label,"▭ ")
    accuracy_ratio = round(len(df_fingerprint)*100/len(df))

    return (accuracy_ratio)

#------------------------------------------------------------------------------
def check_repository():
    logger.info("Checking repository")
    url = "https://raw.githubusercontent.com/ddos-clearing-house/ddos_dissector/2.0/repository.txt"
    response = requests.get(url)
    servers = response.content.decode("utf-8").split()

    table_column = 2
    row_format ="{:>15}" * (table_column)
    print(row_format.format("Server", "Status"))
    print ("--"*18)
    for server in servers:
        try:
            code = requests.get(server).status_code
        except: 
            code = "OFFLINE"
        if (code ==200): code = "ONLINE"
        print(row_format.format(server, code))

    sys.exit(0)

#------------------------------------------------------------------------------
def inspect_generic(df):

    attack_protocol = df_filtered['highest_protocol'].iloc[0]
    logger.info("Processing attack based on {}".format(attack_protocol))

    fields = df.columns.tolist()
    fields.remove("eth_type")
    fields.remove("ip_dst")
    if "icmp_type" in fields: fields.remove("icmp_type")

    fields.remove("_ws_col_Info")

    fingerprint  = {}
    for field in fields:
        outlier = find_outlier(df_filtered[field])
        if (outlier):
            if (outlier != [NONE]):
                fingerprint.update( {field : outlier} )
    return (fingerprint)

#------------------------------------------------------------------------------
# plot the graph
def bar(row):
    percent = int(row['percent'])
    bar_chunks, remainder = divmod(int(percent * 8 / increment), 8)
    count = str(row['counts'])
    label = row['index']
    percent = str(percent)

    bar = '█' * bar_chunks
    if remainder > 0:
        bar += chr(ord('█') + (8 - remainder))
    # If the bar is empty, add a left one-eighth block
    bar = bar or  '▏'
    print ("{} | {} - {}%  {}".format( label.rjust(longest_label_length), count.rjust(longest_count_length),percent.rjust(3), bar ))
    return ()

#------------------------------------------------------------------------------
def add_label(fingerprint):
    label = []
    try:
        if (fingerprint['srcport'] == [53]) and ('dns_qry_name' in fingerprint) :
            label.append("DNS")
            label.append("AMPLIFICATION")
    except:
       pass

    try:
        if (fingerprint['srcport'] == [25]):
            label.append("SMTP")
            label.append("AMPLIFICATION")
    except:
       pass

    try:
        if (fingerprint['srcport'] == [123]):
            label.append("NTP")
            label.append("AMPLIFICATION")
    except:
       pass
    return (label)

#------------------------------------------------------------------------------
def logo():

   print ('''
 _____  _____        _____ _____  ____  
|  __ \|  __ \      / ____|  __ \|  _ \ 
| |  | | |  | | ___| (___ | |  | | |_) |
| |  | | |  | |/ _ \\___ \| |  | |  _ < 
| |__| | |__| | (_) |___) | |__| | |_) |
|_____/|_____/ \___/_____/|_____/|____/ 
''')

#------------------------------------------------------------------------------
def import_logfile(args):

    if (args.config):
        if os.path.isfile(args.config) and os.access(args.config, os.R_OK):
            print ("Upload using configuration file [{}]".format(args.config))
            logger.debug("Configuration found: {}".format(args.config))
            config = configparser.ConfigParser()
            config.read(args.config)
            return (config)
        else: 
            print ("Configuration file provided [{}] not found ".format(args.config))
            return None


###############################################################################
### Main Process
if __name__ == '__main__':

    logo()
    signal.signal(signal.SIGINT, signal_handler)
    parser = parser_args()
    args = parser.parse_args()
    logger = logger(args)

    if (args.version):
        print ("version: {}".format(version))
        sys.exit(0)

    if (args.status):
        check_repository()

    if (not args.filename):
        parser.print_help()
        sys.exit(IOError("\nInput file not provided. Use '-f' for that."))
    if (not os.path.exists(args.filename)):
        logger.error(IOError("File " + args.filename + " is not readble"))
        sys.exit(IOError("File " + args.filename + " is not readble"))

    # load network file
    df = load_file(args)
    fingerprints = []

    # usually is only one target, but on anycast/load balanced networksit  might have more
    target_ip_list = infer_target_ip(df)
    logger.info("Attack target(s): {}".format(target_ip_list))

    # for each target IP
    for idx, target_ip in enumerate(target_ip_list):

        # build filter for victim IP
        logger.debug("Processing target IP address: {}".format(target_ip))
        print("Processing target IP address: {}".format(target_ip))

        df_filtered = df[df['ip_dst'] == target_ip]
        (lst_attack_protocols, frag) = infer_protocol_attack(df_filtered)

        # correlation flag - see function ip_src_fragmentation_attack_similarity
        similarity = False

        if (frag):
            frag_proto = lst_attack_protocols[0]
            # is this fragmentation attack caused by another attack?
            similarity = ip_src_fragmentation_attack_similarity(df,lst_attack_protocols,frag)

            if (similarity):
                # lets use the top2 protocol since there is a big overlap of src_ip between frag attack and top2 proto
                logger.debug("Fragmentation attack likely to stop if we filter the {} attack".format(lst_attack_protocols[-1]))
                df_filtered = df_filtered[df_filtered['highest_protocol'] == lst_attack_protocols[-1]]

            else:
                logger.debug("Fragmentation attack is not correlated to the top2 protocol")
                logger.debug("We should do something to filter that")
                #TODO add new attack_vector

        else:
            # filter based on top1, since the top1 is not fragmentation
            logger.debug("Fragmentation attack not found")
            df_filtered = df_filtered[df_filtered['highest_protocol'] == lst_attack_protocols[0]]

        # protocol used to find the fingerprint
        attack_protocol = df_filtered['highest_protocol'].iloc[0]

        if (attack_protocol == "DNS"):
            logger.info("ATTACK TYPE: DNS")
            fingerprint = inspect_dns(df_filtered)
        elif (attack_protocol == "NTP"):
            logger.info("ATTACK TYPE: NTP")
            fingerprint = inspect_ntp(df_filtered)
        elif (attack_protocol == "SMTP"):
            logger.info("ATTACK TYPE: SMTP")
            fingerprint = inspect_smtp(df_filtered)
        else:
            logger.info("ATTACK TYPE: GENERIC")
            fingerprint = inspect_generic(df_filtered)

        if (args.graph): generate_dot_file(df,fingerprint,args,similarity)

        ## return dataframe filtered
        df_fingerprint = filter_fingerprint(df,fingerprint,similarity)

        # infer tags based on the generated fingerprint
        labels = add_label(fingerprint)
        fingerprint.update( {"tags": labels} )

        print ("Generated fingerprint: ")
        json_str = json.dumps(fingerprint, indent=4, sort_keys=True)
        print(highlight(json_str, JsonLexer(), TerminalFormatter()))

        if (args.summary):
            # evaluate fingerprint generated
            accuracy_ratio = evaluate_fingerprint(df,df_fingerprint,fingerprint)

        if (args.upload):
            config = import_logfile(args)
            # upload to the repository
            ret = upload(args.filename, fingerprint, labels, df_fingerprint, config)

    sys.exit(0)

