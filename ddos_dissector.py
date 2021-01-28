#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###############################################################################
# Concordia Project
#  
# This project has received funding from the European Union’s Horizon
# 2020 Research and Innovation program under Grant Agreement No 830927.
#  
# Joao Ceron - joaoceron@sidn.nl
###############################################################################

###############################################################################
### Python modules
import time 
import threading
import sys
import subprocess
import socket
import signal
import shutil
import requests
import re
import queue as queue
import pandas as pd
import os
import numpy as np
import logging
import json
import hashlib
import cursor
import configparser
import ipaddr
import argparse
from subprocess import check_output, STDOUT
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter
from pygments import highlight
from io import StringIO
from datetime import datetime
from argparse import RawTextHelpFormatter
from hashlib import sha256

###############################################################################
### Program settings
verbose = False
program_name = os.path.basename(__file__)
version = "3.1"

# GLOBAL parameters
# percentage used to determine correlation between to lists
SIMILARITY_THRESHOLD = 80
NONE = -1
FLOW_TYPE = 0
PCAP_TYPE = 1 

###############################################################################
### Subrotines
#------------------------------------------------------------------------------
def parser_add_arguments():
    """
        Parse comamnd line parameters
    """
    parser = argparse.ArgumentParser(prog=program_name, usage='%(prog)s [options]', epilog="Example: ./%(prog)s -f ./pcap_samples/sample1.pcap --summary --upload ", formatter_class=RawTextHelpFormatter)
    parser.add_argument("--version", help="print version and exit", action="store_true")
    parser.add_argument("-v","--verbose", help="print info msg", action="store_true")
    parser.add_argument("-d","--debug", help="print debug info", action="store_true")
    parser.add_argument("-q","--quiet", help="ignore animation", action="store_true")
    parser.add_argument("--status", dest='status', help="check available repositories", action="store_true")
    parser.add_argument("-s","--summary", help="present fingerprint evaluation summary", action="store_true")
    parser.add_argument("-u","--upload", help="upload to the selected repository", action="store_true")
    parser.add_argument("--log", default='log.txt', nargs='?',help="Log filename. Default =./log.txt\"")
    parser.add_argument("--fingerprint_dir", default='fingerprints', nargs='?',help="Fingerprint storage directory. Default =./fingerprints\"")
    parser.add_argument("--config", default='ddosdb.conf', nargs='?',help="Configuration File. Default =./ddosdb.conf\"")
    parser.add_argument("--host", nargs='?',help="Upload host. ")
    parser.add_argument("--user", nargs='?',help="repository user. ")
    parser.add_argument("--passwd", nargs='?',help="repository password.")
    parser.add_argument("-g","--graph", help="build dot file (graphviz). It can be used to plot a visual representation\n of the attack using the tool graphviz. When this option is set, youn will\n received information how to convert the generate file (.dot) to image (.png).", action="store_true")

    parser.add_argument('-f','--filename', nargs='?', required=False, help="")
    return parser

#------------------------------------------------------------------------------
def signal_handler(signum, handler):
    """
        Signal handler
    """
    sys.stdout.flush()
    print('\nCtrl+C detected.')
    cursor.show()
    sys.exit(0)
#------------------------------------------------------------------------------
class CustomConsoleFormatter(logging.Formatter):
    """
        Log facility format
    """
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
    """
    Instanciate logging facility. By default, info logs are also
    stored in the logfile.
    param: cmd line args
    """
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
    file_handler.setLevel(logging.INFO)

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
def upload(fingerprint, json_file, user, passw, host, key):
    """
    Upload a fingerprint and attack vector to DDoSDB
    :param fingerprint: Path to the fingerprint file
    :param json_file: fingerprint generated file
    :param username: DDoSDB username
    :param password: DDoSDB password
    :return: status_code describing HTTP code received
    """

    if not os.path.isfile(json_file):
        logger.critical("Could not read the fingerprint json file {}".format(json_file))

    files = {
        "json": open(json_file, "rb"),
        # ignoring pcap file upload for now
        "pcap": open(json_file, "rb"),
    }

    # build headers for repo fingerprint submission
    headers = {
        "X-Username": user,
        "X-Password": passw,
        "X-Filename": key
    }

    try:
        r = requests.post(host+"upload-file", files=files, headers=headers,verify=True)
    except requests.exceptions.RequestException as e:  
        logger.critical("Cannot connect to the server to upload fingerprint")
        logger.debug("Cannot connect to the server to upload fingerprint: {}".format(e))
        print (e)
        return None

    if (r.status_code==403):
        print ("Invalid credentials or no permission to upload fingerprints:")
    elif (r.status_code==201):
        print ("Upload success: \n\tHTTP CODE [{}] \n\tFingerprint ID [{}]".format(r.status_code,key))
        print ("\tURL: {}query?q={}".format(host,key))
    else: 
        print ("Internal Server Error. Check repository Django logs.")
        print ("Error Code: {}".format(r.status_code))
    return r.status_code

#------------------------------------------------------------------------------
def get_repository(args,config):
    """
    Check credentials and repository based on configuration file or cmd line args
    :param args: cmd args
    :param config: configuration file
    return: user,pass,host: credentials for the repository 
    """
    user,passw,host = (None,)*3

    # look for the repository to upload
    if not (args.host):
        logger.info("Upload host not defined. Pick the first one in the configuration file.")
        config_host =  config.sections()[0]
        if not (config_host):
            logger.critical("Could not find repository configuration. Check configuration file [dddosdb.conf].")
        else: 
            logger.info("Assumming configuration section [{}].".format(config_host))
            user  = config[config_host]['user']
            passw = config[config_host]['passwd']
            host  = config[config_host]['host']

    elif args.host:
        host = args.host
        if (args.user and args.passwd):
            user = args.user
            passw = args.passwd
        # user/pass not defined by cmd line
        else:
            # try to find in the configuration file
            if args.host in config.sections():
                logger.info("Host found in the configuration file")
                user = config[args.host]['user']
                passw = config[args.host]['passwd']
            else:    
                logger.critical("Credentials not found for [{}].".format(args.host))
    else:
        logger.critical("Cannot find repository {} credentials. You should define in the cmd line or configuration file [dddosdb.conf].".format(args.host))
        return None

    return (user,passw,host)

#------------------------------------------------------------------------------
def prepare_tshark_cmd(input_path):
    """
        Prepare the tshark command that converts a PCAP to a CSV.
        :param input_path: filename
        return: tshark command line to be used to convert the file
    """

    tshark =  shutil.which("tshark")
    if not tshark:
        logger.error("Tshark software not found. It should be on the path.\n")
        return 

    cmd = [tshark, '-r', input_path, '-T', 'fields']

    # fields included in the csv
    fields = [
                'dns.qry.type', 'ip.dst','ip.flags.mf', 'tcp.flags', 'ip.proto',
                'ip.src', '_ws.col.Destination', '_ws.col.Protocol', '_ws.col.Source',
                'dns.qry.name', 'eth.type', 'frame.len',  '_ws.col.Info', 'udp.length',
                'http.request', 'http.response', 'http.user_agent', 'icmp.type',
                'ip.frag_offset', 'ip.ttl', 'ntp.priv.reqcode', 'tcp.dstport',
                'tcp.srcport', 'udp.dstport', 'udp.srcport', 'frame.time_epoch',
            ]

    for f in fields:
        cmd.append('-e')
        cmd.append(f)

    # field options
    options = ['header=y', 'separator=,', 'quote=d', 'occurrence=f' ]
    for o in options:
        cmd.append('-E')
        cmd.append(o)
    return cmd

#------------------------------------------------------------------------------
def flow_to_df(ret,filename):
    """
        Convert flow file (nfdump) to DataFrame structure.
        :param ret: buffer used to return the dataframe itself
        :param filename: flow file
        return ret: dataframe
    """
    nfdump =  shutil.which("nfdump")
   
    if not nfdump:
        logger.error("NFDUMP software not found. It should be on the path.")
        ret.put(NONE)

    cmd = [nfdump, '-r', args.filename, '-o', 'extended', '-o', 'json' ]

    try:
        cmd_stdout = check_output(cmd, stderr=subprocess.DEVNULL)
    except:
        ret.put(NONE)
        sys.exit()

    if not cmd_stdout:
        ret.put(NONE)
        sys.exit()

    data = str(cmd_stdout, 'utf-8')
    data = StringIO(data)

    df = pd.read_json(data).fillna(NONE)
    df = df[['t_first', 't_last', 'proto', 'src4_addr', 'dst4_addr',
	     'src_port', 'dst_port', 'fwd_status', 'tcp_flags',
	     'src_tos', 'in_packets', 'in_bytes', 'icmp_type',
	     'icmp_code', 
	 ]]
    df = df.rename(columns={'dst4_addr': 'ip_dst',
			     'src4_addr': 'ip_src', 
                             'src_port': 'srcport', 
                             'dst_port': 'dstport',
                             't_start' : 'frame_time_epoch',
			    })
    df.dstport = df.dstport.astype(float).astype(int) 
    df.srcport = df.srcport.astype(float).astype(int) 

    # convert protocol number to name
    protocol_names = {num:name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")} 
    df['proto'] = df['proto'].apply(lambda x: protocol_names[x])

    # convert protocol/port to service
    def convert_protocol_service(row):
        try:
            highest_protocol = socket.getservbyport(row['dstport'], row['proto'].lower()).upper()
            return highest_protocol
        except:
            return "UNKNOWN"
    df['highest_protocol'] = df[['dstport','proto']].apply(convert_protocol_service,axis=1)
    # convert to unix epoch (sec)
    df['frame_time_epoch'] = pd.to_datetime(df['t_first']).astype(int) / 10**9
    df = df.drop(['t_last','t_first','fwd_status'],axis=1) 
    ret.put(df)

#------------------------------------------------------------------------------
def pcap_to_df(ret,filename):
    """
        Convert pcap file to DataFrame structure.
        :param ret: buffer used to return the dataframe itself
        :param filename: flow file
        return ret: dataframe
    """

    cmd = prepare_tshark_cmd(filename)
    if not cmd:
         ret.put(NONE)
         sys.exit()

    try:
        cmd_stdout = check_output(cmd, stderr=subprocess.DEVNULL)
    except:
        ret.put(NONE)
        sys.exit()

    if not cmd_stdout:
        ret.put(NONE)
        sys.exit()
            
    data = str(cmd_stdout, 'utf-8')
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

    # protocol number to name
    protocol_names = {num:name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")}
    df['ip.proto'] = df['ip.proto'].fillna(NONE).astype(float).astype(int)
    df['ip.proto'] = df['ip.proto'].apply(lambda x: protocol_names[x] if (x>0) else -1)

    df['ip.ttl'] = df['ip.ttl'].fillna(NONE).astype(float).astype(int)
    df['udp.length'] = df['udp.length'].fillna(NONE).astype(float).astype(int)
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

# translate flags to string
#     if 'tcp.flags.str' in df.columns:
#         df['tcp.flags.str'] = df['tcp.flags.str'].str.encode("utf-8")

    df.columns = [c.replace('.', '_') for c in df.columns]    

    # remove info field
    del df['_ws_col_Info']
    ret.put(df)

#------------------------------------------------------------------------------
## Function for calculating the TOP 'N' and aggregate the 'others'
## Create a dataframe with the top N values and create an 'others' category
def top_n_dataframe(dataframe_field,df,n_type,top_n=20):
    """
        Find top n values in one dataframe
        :param dataframe_field: field to be evaluated
        :param df: full dataframe
        :param n_type: network file type (pcap or flow)
        :param top_n: build dataframe with the top_n results
        return df: dataframe itself
    """
    field_name = dataframe_field.name
    if (field_name == "frame_time_epoch" or field_name=="start_timestamp"):
        return  pd.DataFrame()
    
    # flow - different heuristic
    if (n_type==FLOW_TYPE):

        if (field_name == "in_packets"):
            return  pd.DataFrame()
        data = df.groupby(field_name)["in_packets"].sum().sort_values(ascending=False)
        top = data[:top_n].reset_index()
        top.columns = [field_name,'count']
        new_row = pd.DataFrame(data = {
            'count' : [ data[top_n:].reset_index().iloc[:,1].sum()],
            field_name : ['others'],
        })

    # pcap
    else:
        top = df[field_name].value_counts().reset_index()[:top_n]
        new_row = pd.DataFrame(data = {
            'count' : [df[field_name].value_counts().reset_index()[top_n:][field_name].sum()],
            field_name : ['others'],
        })

    # combine the result dataframe (top_n + aggregated 'others')
    top.columns = [field_name, 'count']
    top_result = pd.concat([top, new_row],sort=False)

    # percentage field
    df = top_result.groupby(field_name).sum()
    df=df.sort_values(by="count", ascending=False)
    df['percent'] = df.transform(lambda x: (x/np.sum(x)*100).round()).astype(int)

    if (len(df)< 16):
        # z-score useless when few elements 
        df['zscore'] = NONE
    else:
        # z-score of 2 indicates that an observation is two standard deviations above the average 
        # a z-score of zero represents a value that equals the mean.
        df['zscore'] = ((df['count'] - df['count'].mean())/df['count'].std(ddof=0)).round().fillna(NONE)
    return (df.reset_index())

#------------------------------------------------------------------------------
def infer_target_ip (df,n_type):
    """
    df: dataframe from pcap
    n_type: network file type (flows,pcap)
    return: list of target IPs 
    """
    outlier = find_outlier(df['ip_dst'],df,n_type)

    if (not outlier or len(outlier)<1):
        logger.debug("We cannot find the DDoS target IP address. Not enought info to find the outlier.") 
        logger.debug("Trying to aggregate top IPs")
        
        data = top_n_dataframe(df['ip_dst'],df,n_type)

        # Outlier was not found (attack targeting multiples IP address)
        # Try to cluster the victim IPs. Usually, there are (IPs) part of the same network block.
        # Select IPs responsible for more than 20% of the traffic and try to cluster them.
        # If we succeed IPs are in the same range (network mask bigger than 21) we assume the target.
        data_ = data[(data['percent']> 20)]['ip_dst'].tolist()
        ip_lst = sorted(data[(data['percent']> 20)]['ip_dst'].tolist())

        # filter ipv4|ipv6 only
        ips = []
        for ip in ip_lst:
            try:
                ipaddr.IPAddress(ip)
            except:
                continue
            ips.append(ip)
        
        # only one IP address has return
        if (len(ips)<2):
            return (ips,df)

        lowest_ip  = ips[0]  
        highest_ip = ips[-1] 

        # aggregation mask size
        mask_length = ipaddr._get_prefix_length(int(lowest_ip), int(highest_ip), lowest_ip.max_prefixlen)

        if (mask_length > 21):
            logger.debug("Top IPs are correlated")

            # rewrite to one IP address
            for ip in ip_lst[:1]:
                df.loc[df['ip_dst'] == ip,"ip_dst"] = ip_lst[0]
            return ( (ip_lst[0]).split(), df)

        else:
            # return the top 1
            return (list(df['ip_dst'].value_counts().keys()[0]),df)
    else:
        return (outlier,df)

#------------------------------------------------------------------------------
def animated_loading(msg="loading "):
    """
        print loading animation
        :param msg: prefix label
    """
    
    chars = "▁▂▃▄▅▆▇▇▇▆▅▄▃▁"
    cursor.hide()
    for char in chars:
        #sys.stdout.write('\r'+msg+''+char)
        sys.stdout.write('\r'+'['+char+'] '+msg)
        time.sleep(.1)
        sys.stdout.flush()
    cursor.show()

#------------------------------------------------------------------------------
def find_outlier(df_filtered,df,n_type,strict=0):
    """
        Find outlier based in zscore
        :param df_filtered: dataframe filtered by target_ip
        :param df: full dataframe used for flows analysis
        :param n_type: network file type (flows,pcap)
        :param strict: turn the outlier process less flexible
    """

    field_name = df_filtered.name

    # summarization dataframe
    data = top_n_dataframe(df_filtered,df,n_type)
    if (data.empty): 
        return 

    outlier_field = data.columns[0]

    # be more strict in the filter 
    if (strict):
        data_ = data[(data['percent']> SIMILARITY_THRESHOLD) & (data['zscore']>2)]
    
	# if the filter does not return anything, check if the df is
	# composed by only one field
        if (data_.size==0):

            # get first line from summarization dataframe
            data = data.head(1)
            data = data[(data['percent']> SIMILARITY_THRESHOLD) & (data['zscore']<0) & (data[outlier_field]!="others")] 
            if (data.empty): return 
            outliers = data.iloc[:,0].tolist()
            logger.debug("Outliers for .:{}:. --> {} \n {}" .format(outlier_field, outliers, data.head(5).to_string(index=False) ))
            logger.debug('-' * 60)
            return (outliers)
        else:
            # return the filtered dataframe saved in aux var
            data = data_

    # regular process - no strict
    else:
        data = data[(data['percent']> SIMILARITY_THRESHOLD) | (data['zscore']>2)]
        if (len(data)==0): return None

    outliers = data.iloc[:,0].tolist()
    if (outliers == NONE):
        logger.debug("Outliers for .:{}:. --> None \n {}" .format(data.columns[0], data.head(5).to_string(index=False) ))
        return

    # remove outlier when dispersion is equal to `others` values, for example:
    # srcport  count  percent  zscore
    #  443      2157       39     3.0
    #  others   2135       38     3.0
    zscore_others = data.loc[data[outlier_field] == "others", 'zscore'].tolist()
    if (zscore_others):
        # remove all fields with the same values than `others`
        outliers = data[data.zscore!=zscore_others[0]].iloc[:,0].tolist()
    logger.debug('-' * 60)

    if (len(outliers)>0):
        logger.debug("Outliers for .:{}:. --> {} \n {}" .format(data.columns[0], outliers,  data.head(5).to_string(index=False) ))
        return outliers
    else:
        logger.debug("Outliers for .:{}:. --> None \n {}" .format(data.columns[0], data.head(5).to_string(index=False) ))
        return None

#------------------------------------------------------------------------------
# Infer the attack based on filtered dataframe
def infer_protocol_attack(df,n_type):
    """
        Evaluate protocol distribution and return the used in the attack
        :param df: dataframe
        :param n_type: network file type (flows,pcap)
        return: the list of top protocols and if the framentation protocol has found
    """
    target_ip = df['ip_dst'].iloc[0]
    logger.info("A total of {} IPs have attacked the victim {}".format(df_filtered.ip_src.nunique(), target_ip))

    data = top_n_dataframe(df['highest_protocol'],df,n_type)
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
        logger.debug("Top1 protocol could be classified as outlier")
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
def ip_src_fragmentation_attack_similarity(df,lst_attack_protocols,frag, target_ip):
    """
        Find IPs related to fragmentation attack
        :param df: full dataframe
        :param lst_attack_protocols: list of protocol used in the attack
        :param frag: fragmentation flag (frag detect or not)
    """
    if (not frag):
        return False

    ip_frag = df[(df['ip_dst'] == target_ip) & (df['highest_protocol'] == lst_attack_protocols[0])]['ip_src'].unique().tolist()
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
def determine_file_type(input_file):
    """
    Determine what sort of file the input is.
    :param input_file: The path to the file, e.g. /home/user/example.pcap
    :return: The file type of the input file as a string
    :raises UnsupportedFileTypeError: If input file is not recognised or not supported
    """

    file_ = shutil.which("file")
    if not file_:
        logger.error("File software not found. It should be on the path.\n")
        return (NONE)

    file_info, error = subprocess.Popen([file_, input_file], stdout=subprocess.PIPE).communicate()
    file_type = file_info.decode("utf-8").split()[1]
   
    if file_type == "tcpdump":
        return "pcap"
    if file_type == "pcap":
        return "pcap"
    elif file_type == "pcap-ng":
        return "pcapng"
    elif file_type == "data" and (b"nfdump" in file_info or b"nfcapd" in file_info):
        return "nfdump"
    else:
        raise UnsupportedFileTypeError("The file type " + file_type + " is not supported.")

#------------------------------------------------------------------------------
def load_file(args):
    """
        Wrapper to call attack file to dataframe
        :param args: command line parameters
        :return n_type: network file type (flows,pcap)
        :return df: dataframe itself
    """

    file_type = determine_file_type(args.filename)
    if (file_type == NONE):
        return (NONE,NONE)

    if re.search(r'nfdump', file_type):
        load_function = flow_to_df
        n_type = FLOW_TYPE

    elif re.search(r'pcap', file_type):
        load_function = pcap_to_df
        n_type = PCAP_TYPE

    # load dataframe using threading
    ret = queue.Queue()

    the_process = threading.Thread(name='process', target=load_function, args=(ret,args.filename))
    the_process.start()
    msg = "Loading network file: `{}' ".format(args.filename)

    try:
        while the_process.is_alive():
            if the_process:
                animated_loading(msg) if not (args.quiet) else 0
        the_process.join()
    except (KeyboardInterrupt, SystemExit):
        signal_handler(None,None)

    df = ret.get()

    # not a dataframe

    if not isinstance(df, pd.DataFrame):
        print ("\n")
        return(NONE,NONE)
        
    sys.stdout.write('\r'+'['+'\u2713'+'] '+ msg+'\n')
    return (n_type,df)

#------------------------------------------------------------------------------
def clusterization_non_multifrag(df,df_filtered,n_type):
    """
        Generic heuristic to deal with low accuracy ratio fingerprint
        :param df: dataframe filtered by target_ip
        :param n_type: network file type (flows,pcap)
        :return fingerprint: json file
    """
    fields = df_filtered.columns.tolist()
    if "eth_type" in fields: fields.remove("eth_type")

    fingerprint = {}
    for field in fields:
        outlier = find_outlier(df_filtered[field],df_filtered,n_type,True)
        if (outlier):
            if (outlier != [NONE]):
                fingerprint.update( {field : outlier} )

    return (fingerprint)

#------------------------------------------------------------------------------
def clusterization_multifrag(df,df_filtered,n_type):
    """
        Determine if multiples protocol were used for fragmentation attack
        :param df: dataframe filtered by target_ip
        :param n_type: network file type (flows,pcap)
        :return fingerprint: json file
    """

    fingerprint  = {}
    df_ = df.fragmentation.value_counts(normalize=True).mul(100).reset_index()
    value = df_.loc[:,"fragmentation"].values[0]
    df_['index']=df_['index'].astype(bool)

    # percentage of packets with fragmentation
    try:
        frag_percentage = df_[(df_['fragmentation']>SIMILARITY_THRESHOLD) & (df_['index'].values)[0]==True].values[0][1]
    except (ValueError,IndexError):
        return None

    # high chances to have multi protocol frag attack
    if (frag_percentage > SIMILARITY_THRESHOLD):

        logger.info("ATTACK TYPE: MULTIPROTOCOL FRAGMENTATION ATTACK")

        # find protocols responsible for that fragmentation
        df_ = df.groupby(['highest_protocol','fragmentation'])['fragmentation'].count().to_frame().\
            rename(columns={'fragmentation':'count'}).reset_index()

        # may have more than one protocol responsible for that fragmementaiton percentage per group
        # then, find the percentage of frag per protocol
        df_['percent_frag'] = df_.groupby(['highest_protocol'])['count'].transform(lambda x: (x/x.sum()).mul(100))
        df_['percent'] = (df_['count'] / df_['count'].sum()) * 100
        df_['fragmentation']=df_['fragmentation'].astype(bool)

        # protocol with high percentage of frag
        protocols = df_[(df_.fragmentation == True) & (df_.percent>SIMILARITY_THRESHOLD) & \
                    (df_.percent_frag>SIMILARITY_THRESHOLD) ]['highest_protocol'].tolist()

        if not protocols:
            return 

        # find respective src_port
        logger.info("Reprocessing attack based on protocols: {}".format(protocols))

        df_filtered = df_filtered[df_filtered.highest_protocol.isin(protocols)]
        srcports_frag = df[df.highest_protocol.isin(protocols)]['srcport'].unique().tolist()

        outlier = find_outlier(df[df.highest_protocol.isin(protocols)]['srcport'],df_filtered,n_type)

        # remove port "NONE" (assigned to IPv4 frag protocol)
        if (NONE in srcports_frag) or (not outlier):
            #srcports_frag.remove(NONE)
            srcports_frag = [NONE]
        else:

            # add srcport to the fingerprint
            fingerprint.update( { "srcport" : srcports_frag } )

        fields = df_filtered.columns.tolist()
        if "eth_type" in fields: fields.remove("eth_type")

        for field in fields:
            outlier = find_outlier(df_filtered[field],df,n_type)
            if (outlier):
                if (outlier != [NONE]):
                     fingerprint.update( {field : outlier} )

        # revome fields the may overlap srcports outliers
        if 'ip_proto' in fingerprint:
            del fingerprint['ip_proto']
        if 'ip_ttl' in fingerprint:
            del fingerprint['ip_ttl']

        return (fingerprint)

#------------------------------------------------------------------------------
def generate_dot_file(df_fingerprint, df):
    """
    Build .dot file that is used to generate a png file showing the
    fingerprint match visualization
    :param df_fingerprint: dataframe filtered based on matched fingerprint
    :param df: dataframe itself 
    """
    # sum up dataframe to plot
    df_fingerprint = df_fingerprint[['ip_src','ip_dst']].drop_duplicates(keep="first")
    df_fingerprint['match'] = 1

    df_remain = df[['ip_src','ip_dst']].drop_duplicates(keep="first")
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
def printProgressBar(value,label,fill_chars="■-"):
    """
        Print progress bar 
        :param value: value to be printed
        :param label: label used as title
        :param fill_chars: char used in the animation
    """
    if (args.quiet): return True
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
    """
        Use the generated fingerprint to filter the traffic in the dataframe.
        :param df: datafram itself
        :param fingerprints: json file
        :param similarity: flag used to add IP fragmentation attacks to the filtered dataframe
        :return df_fingerprint: dataframe filtered based on matched fingerprint
    """
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
        logger.debug("Fragmentation attack filter added to the matched dataframe")

    return (df_fingerprint)

#------------------------------------------------------------------------------
def evaluate_fingerprint(df,df_fingerprint,fingerprint):
    """
        :param df: datafram itself       
        :param df_fingerprint: dataframe filtered based on matched fingerprint
        :param fingerprint: json file
        :return accuracy_ratio: the percentage that generated fingerprint can match in the full dataframe
    """

    total_rows_matched = len(df_fingerprint)
    total_ips_matched_using_fingerprint = df_fingerprint['ip_src'].unique().tolist()

    msg = "Fingerprint evaluation"
    sys.stdout.write('\r'+'['+'\u2713'+'] '+ msg+'\n')

    logger.info("TRAFFIC MATCHED: {0}%. The generated fingerprint will filter {0}% of the analysed traffic".format(round(len(df_fingerprint)*100/len(df))))
    percentage_of_ips_matched = len(df_fingerprint['ip_src'].unique().tolist() )*100/len(df.ip_src.unique().tolist())
    logger.info("IPS MATCHED    : {0}%. The generated fingerprint will filter {0}% of SRC_IPs".format(round(percentage_of_ips_matched)))

    if not (args.quiet):
        value = round(len(df_fingerprint)*100/len(df))
        printProgressBar(value,"TRAFFIC MATCHED")
        printProgressBar(round(percentage_of_ips_matched),"IPs MATCHED")

    # remove fields that are not in the dataframe
    fingerprint.pop('tags',None)
    fingerprint.pop('one_line',None)
    fingerprint.pop('key_sha256',None)
    fingerprint.pop('start_time',None)
    fingerprint.pop('duration_sec',None)
    fingerprint.pop('total_dst_ports',None)
    fingerprint.pop('avg_bps',None)
    fingerprint.pop('total_packets',None)
    fingerprint.pop('key',None)
    fingerprint.pop('multivector_key',None)
    fingerprint.pop('total_ips',None)
    fingerprint.pop('amplifiers',None)
    fingerprint.pop('attackers',None)

    if (args.verbose) or (args.debug):
         results = {}
         # how many rows each field can filter
         for key, value in fingerprint.items():
             total_rows_matched = len(df[df[key].isin(value)])
             percentage = round(total_rows_matched*100/len(df))
             # dict with all the fields and results
             results.update( {key: percentage} )
         results_sorted = {k: v for k, v in sorted(results.items(), key=lambda item: item[1],  reverse=True)}
 
         logger.info("          =============== FIELDS BREAKDOWN ================ ")
         for label, percentage in results_sorted.items():
             printProgressBar(percentage,label,"▭ ")
    accuracy_ratio = round(len(df_fingerprint)*100/len(df))

    return (accuracy_ratio)

#------------------------------------------------------------------------------
def check_repository(config):

    """
        Check repository access and credentials
        :param config: configuration file path
    """
    logger.info("Checking repository")
    url = "https://raw.githubusercontent.com/ddos-clearing-house/ddos_dissector/2.0/repository.txt"
    response = requests.get(url)
    servers = response.content.decode("utf-8").split()

    login = ""
    table_column = 3
    row_format ="{:>22}" * (table_column)
    print(row_format.format("\nServer", "Status", "Credentials"))
    print ("--"*25)

    for server in servers:
        try:
            code = requests.get(server, timeout=2).status_code
        except: 
            code = "OFFLINE"

        if (code ==200): 
            code = "ONLINE"

            # check credentials
            headers = {
                "X-Username": config['repository']['user'],
                "X-Password": config['repository']['passwd'],
            }

            server_config = re.search('https?://(.*)/?', server).group(1)

            # check if the configuration file has credentials for the online server
            if (server_config in config.sections()):
                 if (config[server_config]):
                    headers = {
                        "X-Username": config[server_config]['user'],
                        "X-Password": config[server_config]['passwd'],
                    }

            else:
                logger.info("Credentials from {} is not available in the configuration file [ddosdb.conf]")
                login = "NOT_OK"

            try:
                r = requests.get(server+"/my-permissions", headers=headers,verify=False)

            except requests.exceptions.RequestException as e:  
                logger.critical("Cannot connect to the server to check credentials")
                logger.debug("{}".format(e))
                print (e)

            if (r.status_code==403):
                 print ("Invalid credentials or no permission to upload fingerprints:")
                 login = "NOT_OK"

            elif (r.status_code==200):
                 login = "SUCCESS"
 
        row_format ="{:>15}" * (table_column)
        print(row_format.format(server, code, login))
    sys.exit(0)

#------------------------------------------------------------------------------
def get_matching_ratio(df,fingerprint,similarity):

    if not fingerprint:
        return (NONE,NONE)
    ## filter dataframe using the produced fingerprint
    df_fingerprint = filter_fingerprint(df,fingerprint,similarity)

     # evaluate fingerprint matching ratio
    accuracy_ratio = round(len(df_fingerprint)*100/len(df))

    d = { "ratio"       : accuracy_ratio, 
          "fingerprint" : fingerprint
        }
    return (df_fingerprint,d)

#------------------------------------------------------------------------------
def clusterization_heuristic_generic(df,df_fingerprint,n_type):

    fields = df_filtered.columns.tolist()
    if "eth_type" in fields: fields.remove("eth_type")

    fingerprint  = {}
    for field in fields:
        outlier = find_outlier(df_filtered[field],df,n_type)
        if (outlier):
            if (outlier != [NONE]):
                fingerprint.update( {field : outlier} )

    return (fingerprint)
#------------------------------------------------------------------------------
def build_attack_fingerprint(df,df_filtered,n_type,similarity):
    """
        Inspect generic protocol
        :param df: datafram itself
        :param n_type: network file type (flows,pcap)
        :return fingerprints: json file
    """
    attack_protocol = df_filtered['highest_protocol'].iloc[0]
    logger.info("Processing attack based on {}".format(attack_protocol))

    # DETECTION HEURISTIC 
    dic_ratio_array = []

    ### FIRST HEURISTIC
    fingerprint = clusterization_heuristic_generic(df,df_filtered,n_type)
    (df_fingerprint,dict_accuracy_ratio) = get_matching_ratio(df,fingerprint,similarity)
    logger.debug(dict_accuracy_ratio)

    if (dict_accuracy_ratio != NONE):
        logger.debug('-' * 60)
        logger.debug("First heuristic matching ratio = {}".format(dict_accuracy_ratio.get("ratio")))
        logger.debug("First heuristic fingerprint  = {}".format((dict_accuracy_ratio.get("fingerprint"))))
        logger.debug("First fingerprint lengh = {}".format(len(dict_accuracy_ratio.get("fingerprint"))))
        if (len(dict_accuracy_ratio.get("fingerprint"))>2):
            logger.debug('-' * 60)
            dict_accuracy_ratio['size'] = len(dict_accuracy_ratio.get("fingerprint"))
            dic_ratio_array.append(dict_accuracy_ratio)

    ### SECOND HEURISTIC
    fingerprint = clusterization_multifrag(df,df_filtered,n_type)
    (df_fingerprint,dict_accuracy_ratio) = get_matching_ratio(df,fingerprint,similarity)
    logger.debug(dict_accuracy_ratio)

    if (dict_accuracy_ratio != NONE):
        logger.debug('-' * 60)
        logger.debug("Second heuristic matching ratio = {}".format(dict_accuracy_ratio.get("ratio")))
        logger.debug("Second heuristic fingerprint  = {}".format((dict_accuracy_ratio.get("fingerprint"))))
        logger.debug("Second fingerprint lengh = {}".format(len(dict_accuracy_ratio.get("fingerprint"))))
        logger.debug('-' * 60)
        dict_accuracy_ratio['size'] = len(dict_accuracy_ratio.get("fingerprint"))
        dic_ratio_array.append(dict_accuracy_ratio)

    ### THIRD HEURISTIC
    fingerprint = clusterization_non_multifrag(df,df_filtered,n_type)
    (df_fingerprint,dict_accuracy_ratio) = get_matching_ratio(df,fingerprint,similarity)
    if (dict_accuracy_ratio != NONE):
        logger.debug("Third heuristic matching ratio = {}".format(dict_accuracy_ratio.get("ratio")))
        logger.debug("Third heuristic fingerprint  = {}".format((dict_accuracy_ratio.get("fingerprint"))))
        logger.debug("Third fingerprint lengh = {}".format(len(dict_accuracy_ratio.get("fingerprint"))))
        logger.debug('-' * 60)
        dict_accuracy_ratio['size'] = len(dict_accuracy_ratio.get("fingerprint"))
        dic_ratio_array.append(dict_accuracy_ratio)

    # pick the best matching rate
    df_ = pd.DataFrame(dic_ratio_array)
    logger.debug("Fingerprint found")
    logger.debug(df_)

    data = df_.sort_values(by="size",ascending=True)
    # filter fingerprint with more than 2 fields
    data = data[data['size'] > 2]
    data["diff"] = data.ratio.diff().fillna(0).astype(int)

    # Pick the longest fingerprint (it is more specific)
    # If the signature has less detection ratio (-10) get the biggest fingerprint
    fingerprint = data[data['diff']>-10].sort_values(by="size",ascending=False).head(1)['fingerprint'].values[0]

    if not fingerprint:
        fingerprint = df_.sort_values(by="ratio",ascending=False).loc[0,"fingerprint"]

    return (fingerprint)

#------------------------------------------------------------------------------
def bar(row):
    """
        Plot ASCII bar 
        :param row: line to be printed
    """
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
def add_label(fingerprint,df):
    """
       Add labels to fingerprint generated
    """

    label = []
    # UDP Service Mapping
    udp_service = {
        25:    'SMTP',
        123:   'NTP',
        1121:  'Memcached',
        1194:  'OpenVPN', 
        1434:  'SQL server',
        1718:  'H323',
        1900:  'SSDP', 
        3074:  'Game Server',
        3283:  'Apple Remote Desktop',
        3702:  'WSD - Web Services Discovery', 
        5683:  'CoAP',
        20800: 'Game Server',
        27015: 'Game Server',
        30718: 'IoT Lantronix',
        33848: 'Jenkins Server',
        37810: 'DVR DHCPDiscover',
        47808: 'BACnet', 
    }

    generic_amplification_ports = [53, 389, 123, 161, 672]

    # add protocol name to label list
    if 'highest_protocol' in fingerprint:
        label.append(", ".join(fingerprint['highest_protocol']))

    if 'dns_qry_name' in fingerprint:
        label.append("DNS_QUERY")

    if 'udp_length' in fingerprint:

        # Based on FBI Flash Report MU-000132-DD
        df_length = (df.groupby(['srcport'])['udp_length'].max()).reset_index()
        if (len(df_length.udp_length>468)):
            label.append("UDP_SUSPECT_LENGTH")
            for port in udp_service:
                if ("srcport" in fingerprint):
                    if (fingerprint['srcport'] == [port]):
                        label.append("AMPLIFICATION")
                        label.append("RDDoS")
                        label.append(udp_service[port])

    # Frag attack
    if 'fragmentation' in fingerprint:
        value = fingerprint.get('fragmentation')[0]
        if (value=="True"):
            label.append("FRAGMENTATION")

    # Generic amplification attack
    if ("srcport" in fingerprint):
        if (len(fingerprint['srcport']) > 1):
            label.append("MULTIPROTOCOL")
        for port in generic_amplification_ports:
            if (port in list(fingerprint['srcport'])):
                label.append("AMPLIFICATION")
                break

    return (label)

#------------------------------------------------------------------------------
def logo():

   print ('''
 _____  _____        _____ _____  ____  
|  __ \|  __ \      / ____|  __ \|  _ \ 
| |  | | |  | | ___| (___ | |  | | |_) |
| |  | | |  | |/ _ \\\___ \| |  | |  _ < 
| |__| | |__| | (_) |___) | |__| | |_) |
|_____/|_____/ \___/_____/|_____/|____/ 
''')

#------------------------------------------------------------------------------
def import_logfile(args):
    """
        Load configuration file to structured format
        :param args: command line parameters
        :return config: structured format
    """
    if (args.config):
        if os.path.isfile(args.config) and os.access(args.config, os.R_OK):
            msg = "Using configuration file [{}]".format(args.config)
            sys.stdout.write('\r'+'['+'\u2713'+'] '+ msg+'\n')
            logger.debug("Configuration found: {}".format(args.config))
            config = configparser.ConfigParser()
            config.read(args.config)
            return (config)
        else: 
            print ("Configuration file provided [{}] not found ".format(args.config))
            return None

#------------------------------------------------------------------------------
def prepare_fingerprint_upload(df_fingerprint,df,fingerprint,n_type,labels,fingerprint_dir):
    """
        Add addicional fields and stats to the generated fingerprint
        :param df_fingerprint: dataframe filtered based on matched fingerprint
        :param df: datafram itself
        :param fingerprint: json file
        :param n_type: network file type (flows,pcap)
        :return json file
    """
    # timestamp fields
    initial_timestamp  = df_fingerprint['frame_time_epoch'].min()
    initial_timestamp = datetime.utcfromtimestamp(initial_timestamp).strftime('%Y-%m-%d %H:%M:%S')
    fingerprint.update( {"start_time": initial_timestamp} )
    duration_sec = df_fingerprint['frame_time_epoch'].max() - df_fingerprint['frame_time_epoch'].min()
    fingerprint.update( {"duration_sec": int(duration_sec)} )
    fingerprint.update( {"total_dst_ports": len(df_fingerprint['dstport'].unique().tolist())} )

    if (n_type == FLOW_TYPE):
      fingerprint.update( {"avg_bps": int(df_fingerprint.in_packets.mean())})
      fingerprint.update( {"total_packets": int(df_fingerprint.in_packets.sum())})
    else:
      fingerprint.update( {"avg_bps": int(df_fingerprint.frame_len.sum()/duration_sec) })
      fingerprint.update( {"total_packets": len(df_fingerprint)} )

    # keys used on the repository
    key = str(hashlib.md5(str(fingerprint).encode()).hexdigest())
    fingerprint.update( {"key": key} )
    sha256 = hashlib.sha256(str(fingerprint).encode()).hexdigest()
    fingerprint.update( {"key_sha256": sha256} )
    fingerprint.update( {"multivector_key": sha256} )
    fingerprint.update( {"total_ips": len(df_fingerprint['ip_src'].unique().tolist()) })

    # set field name based on label 
    fingerprint.update( {"amplifiers": "None"} )
    fingerprint.update( {"attackers": df_fingerprint['ip_src'].unique().tolist()} )

    if labels:
        if ("AMPLIFICATION" in labels):
            fingerprint.update( {"amplifiers": df_fingerprint['ip_src'].unique().tolist()} )
            fingerprint.update( {"attackers": "None"} )

    # save fingerprint to local file in order to enable the upload via POST
    if not os.path.exists(fingerprint_dir):
        os.makedirs(fingerprint_dir)

    json_file = "{}/{}.json".format(fingerprint_dir,key)
    try:
        with open(json_file, 'w') as f_fingerprint:
            json.dump(fingerprint, f_fingerprint)
    
        files = {
            "json": open(json_file, "rb"),
            # ignoring pcap file upload for now
            "pcap": open(json_file, "rb"),
        }
    except:
        logger.info("Could not save fingerprint {}".format(json_file))

    return (fingerprint,json_file)

#------------------------------------------------------------------------------
def print_fingerprint(fingerprint):

        # print fingerprint and remove IPs
        fingerprint_anon = fingerprint
        fingerprint_anon.update({"one_line": one_line_fingerprint})
        fingerprint_anon.update({"attackers": "ommited"})
        fingerprint_anon.update({"amplifiers": "ommited"})

        json_str = json.dumps(fingerprint_anon, indent=4, sort_keys=True)
        msg = "Generated fingerprint"
        sys.stdout.write('\r'+'['+'\u2713'+'] '+ msg+'\n')
        print(highlight(json_str, JsonLexer(), TerminalFormatter()))

###############################################################################
### Main Process
if __name__ == '__main__':

    logo()
    signal.signal(signal.SIGINT, signal_handler)
    parser = parser_add_arguments()
    args = parser.parse_args()
    logger = logger(args)
    config = import_logfile(args)

    if (args.version):
        print ("version: {}".format(version))
        sys.exit(0)

    if (args.status):
        check_repository(config)
    
    if (not args.filename):
        parser.print_help()
        sys.exit(IOError("\nInput file not provided. Use '-f' for that."))

    if (not os.path.exists(args.filename)):
        logger.error(IOError("File " + args.filename + " is not readble"))
        sys.exit(IOError("File " + args.filename + " is not readble"))

    # load network file
    n_type,df = load_file(args)

    if not isinstance(df, pd.DataFrame):
        logger.error("could not convert input file <{}>".format(args.filename))
        sys.exit(1)

    # checking if the provided file could be converted to dataframe
    if (len(df)<2):
        logger.error("could not read data from file <{}>".format(args.filename))
        sys.exit(1)

    # usually is only one target, but on anycast/load balanced might have more
    (target_ip_list,df) = infer_target_ip(df,n_type)

    if not target_ip_list:
        print ("Target IP could not be infered.") 
        sys.exit(0)

    logger.info("Attack target(s): {}".format(target_ip_list))
    target_ip = target_ip_list[0]
    # build filter for victim IP
    logger.debug("Processing target IP address: {}".format(target_ip))
    msg = "Processing target IP address: {}".format(target_ip)
    sys.stdout.write('\r'+'['+'\u2713'+'] '+ msg+'\n')

    df_filtered = df[df['ip_dst'] == target_ip]
    (lst_attack_protocols, frag) = infer_protocol_attack(df_filtered,n_type)
    
    # remove target IP from dataframe since it will be anonymized
    del df_filtered['ip_dst']

    # correlation flag - see function ip_src_fragmentation_attack_similarity
    similarity = False

    if (frag):
        frag_proto = lst_attack_protocols[0]
        # is this fragmentation attack caused by another attack?
        similarity = ip_src_fragmentation_attack_similarity(df,lst_attack_protocols,frag,target_ip)

        if (similarity):
            # lets use the top2 protocol since there is a big overlap of src_ip between frag attack and top2 proto
            logger.debug("Fragmentation attack likely to stop if we filter the {} attack".format(lst_attack_protocols[-1]))
            df_filtered = df_filtered[df_filtered['highest_protocol'] == lst_attack_protocols[-1]]

        else:
            logger.debug("Fragmentation attack is not correlated to the top2 protocol")
            logger.debug("We should do something to filter that")

    else:
        # filter based on top1, since the top1 is not fragmentation
        logger.debug("Fragmentation attack not found")
        df_filtered = df_filtered[df_filtered['highest_protocol'] == lst_attack_protocols[0]]

    # build attack fingerprint 
    fingerprint = build_attack_fingerprint(df,df_filtered,n_type,similarity)
    
    if not fingerprint:
        print ("Could not find fingerprint for this network file :(" )
        sys.exit()

    # filter dataframe using the selected fingerprint
    df_fingerprint = filter_fingerprint(df,fingerprint,similarity)

    if (len(df_fingerprint)<1):
        print ("Could not find fingerprint for this network file :(" )
        sys.exit()

    # remove brackets from string
    one_line_fingerprint = str(fingerprint).translate(str.maketrans("", "", "[]"))

    # infer tags based on the generated fingerprint
    labels = add_label(fingerprint,df_fingerprint)
    fingerprint.update({"tags": labels})

    #c add extra fields/stats and save file locally
    (fingerprint,json_file) = prepare_fingerprint_upload(df_fingerprint,df,fingerprint,n_type,labels,args.fingerprint_dir)

    # show anon fingerprint
    print_fingerprint(fingerprint)

    # evaluate fingerprint generated - does not considerer src_ips 
    if (args.summary): evaluate_fingerprint(df,df_fingerprint,fingerprint)

    # generate graphic file 
    if (args.graph): generate_dot_file(df_fingerprint, df)

    print ("Fingerprint saved on {}".format(json_file))

    if (args.upload):
        (user,passw,host) = get_repository(args,config)

        # upload to the repository
        ret = upload(fingerprint, json_file, user, passw, host, fingerprint.get("key"))

    sys.exit(0)
#EOF
