
# coding: utf-8

# In[ ]:


import pandas as pd
import numpy as np
import collections
import math
from datetime import datetime
import json
import hashlib
import time

import warnings
warnings.filterwarnings('ignore')


# In[ ]:


from functions.protocolnumber2name import *
from functions.portnumber2name import *
from functions.tcpflagletters2names import *
from functions.pcap2dataframe_tshark import *


# In[ ]:


# #FOR TESTING PURPOSE
# from protocolnumber2name import *
# from portnumber2name import *
# from tcpflagletters2names import *
# from pcap2dataframe_tshark import *


# In[ ]:


def analyse_df_pcap_tshark(df, debug=False, ttl_variation_threshold = 4):
    """
    Analysis only top traffic stream

    :param dataframe (df) containing the pcap/pcapng file converted:
    :return (1) print the summary of attack vectors and :
    """

    total_packets = len(df)
    ############################################################################
    fingerprints= []
    attack_vector = {}
    df_attackvectors=[]
    df_attackvectors_string =[]
    attackvectors_source_ips=[]
    counter = 1
    ############################################################################
    ############################################################################
    if debug: print(df['_ws.col.Destination'].value_counts())
    top1_dst_ip = df['_ws.col.Destination'].value_counts().keys()[0]
    ############################################################################
    ############################################################################
    df_remaining = df[df['_ws.col.Destination']==top1_dst_ip]
    ############################################################################
    ############################################################################
    while len(df_remaining) > 1:
        attack_vector['file_type'] = 'pcap'
        #Analysing the distribution of IP protocols (and defining the top1)
        protocol_distribution = df_remaining['_ws.col.Protocol'].value_counts()
        if debug: print ('DISTRIBUTION OF PROTOCOLS:', protocol_distribution)
        top1_protocol = protocol_distribution.keys()[0]
        filter_top_protocol_string = "df_remaining['_ws.col.Protocol']=='"+str(top1_protocol)+"'"
        attack_vector['protocol']=top1_protocol

        #Defining if the remaining is based on the top1 source OR destination port
        if top1_protocol == 'IPv4':
            fragmentation_distribution = df_remaining[df_remaining['_ws.col.Protocol']=='IPv4']['fragmentation'].value_counts()
            if debug: print('FRAGMENTATION DISTRIBUTION',fragmentation_distribution)    
            if fragmentation_distribution.keys()[0] == True:
                filter_fragmentation_string="df_remaining['fragmentation']==True"
                attackvector_filter_string = '('+str(filter_top_protocol_string)+')&('+str(filter_fragmentation_string)+')'
            attack_vector['additional'] = {'fragmentation': True}

        else:
            ###Analysing the distribution of SOURCE ports AND defining the top1
            port_source_distribution = df_remaining[df_remaining['_ws.col.Protocol']==top1_protocol]['srcport'].value_counts().head()
            if debug: print('DISTRIBUTION OF SOURCE PORT:', port_source_distribution)
            top1_source_port = math.floor(port_source_distribution.keys()[0])

            ###Analysing the distribution of DESTINATION ports AND defining the top1
            port_destination_distribution = df_remaining[df_remaining['_ws.col.Protocol']==top1_protocol]['dstport'].value_counts().head()
            if debug: print('DISTRIBUTION OF DESTINATION PORTS:',port_destination_distribution)
            top1_destination_port = math.floor(port_destination_distribution.keys()[0])

            ###Checking wich port type (source or destination) AND number had most occurrences
            if port_source_distribution.iloc[0] > port_destination_distribution.iloc[0]:
                filter_top_port = "df_remaining['srcport']=="+str(top1_source_port)
            else:
                filter_top_port = "df_remaining['dstport']=="+str(top1_destination_port)
            
            
            #Defining the conclusion of the analysis (of the remaining traffic)
            attackvector_filter_string = '('+str(filter_top_protocol_string)+')&('+str(filter_top_port)+')' 

            ###########
            if top1_protocol == 'ICMP':
                icmp_type_distribution = df_remaining[df_remaining['_ws.col.Protocol']=='ICMP']['icmp.type'].value_counts()
                if debug: print('DISTRIBUTION ICMP TYPES:',icmp_type_distribution)
                top1_icmp_type = icmp_type_distribution.keys()[0]
                filter_icmp_type = "df_remaining['icmp.type']=='"+str(top1_icmp_type)+"'"
                attackvector_filter_string = '('+str(filter_top_protocol_string)+')&('+str(filter_icmp_type)+')' 
                attack_vector['additional'] = {'icmp_type':top1_icmp_type}

        #     ###########
        #     if top1_protocol == 'QUIC':
        #         quic_payload_distribution = df_remaining[df_remaining['_ws.col.Protocol']=='QUIC']['quic.payload'].value_counts()
        #         if debug: print('DISTRIBUTION QUIC PAYLOADS:',quic_payload_distribution.head())
        #         top1_quic_payload_distribution = quic_payload_distribution.keys()[0]
        #         filter_quic = "df_remaining['quic.payload']=='"+str(top1_quic_payload_distribution)+"'"
        #         attackvector_filter_string += '&('+str(filter_quic)+')'
        #
        #         attack_vector['additional'] = {'quic_payload':top1_quic_payload_distribution}

            ###########
            if top1_protocol == 'TCP':
                tcp_flag_distribution = df_remaining[df_remaining['_ws.col.Protocol']=='TCP']['tcp.flags.str'].value_counts()
                if debug: print('DISTRIBUTION TCP FLAGS:',tcp_flag_distribution.head())
                top1_tcp_flag = tcp_flag_distribution.keys()[0]
                filter_tcp_flag = "df_remaining['tcp.flags.str']=='"+str(top1_tcp_flag)+"'"
                attackvector_filter_string += '&('+str(filter_tcp_flag)+')'  

                attack_vector['additional'] = {'tcp_flag': top1_tcp_flag}
            ###########
            if top1_protocol == 'DNS':
                dns_query_distribution = df_remaining[df_remaining['_ws.col.Protocol']=='DNS']['dns.qry.name'].value_counts()
                if debug: print('DISTRIBUTION DNS QUERIES:',dns_query_distribution.head())
                top1_dns_query = dns_query_distribution.keys()[0]
                filter_dns_query = "df_remaining['dns.qry.name']=='"+str(top1_dns_query)+"'"
                attackvector_filter_string += '&('+str(filter_dns_query)+')'

                dns_type_distribution = df_remaining[df_remaining['_ws.col.Protocol']=='DNS']['dns.qry.type'].value_counts()
                if debug: print('DISTRIBUTION DNS TYPES:',dns_type_distribution.head())
                top1_dns_type = dns_type_distribution .keys()[0]
                attack_vector['additional'] = {'dns_query': top1_dns_query,
                                       'dns_type': top1_dns_type}
        ############################################################################
        df_attackvectors_string.append(attackvector_filter_string)

        df_attackvector_current = df_remaining[eval(attackvector_filter_string)]
        src_ips_attackvector_current = df_attackvector_current['_ws.col.Source'].unique()   
        ###If the number of source IPs involved in this potential attack vector is 1, then it is NOT a DDoS! STOP!
        if len(src_ips_attackvector_current) < 2:
            if debug: print ('STOP ANALYSIS!!! THERE IS ONLY ONE SOURCE IP RELATED TO THIS ATTACK VECTOR!')
            break
        
        ############################################################################
        ### SAVING FOR FURTHER ANALYSIS OF THE CURRENT DATAFRAME
        ### df_attackvectors.append(df_attackvector_current)
        ############################################################################
        
        ### For later comparing the list of IPs
        attackvectors_source_ips.append(src_ips_attackvector_current)

        start_time =df_attackvector_current['frame.time_epoch'].iloc[0]
        end_time= df_attackvector_current['frame.time_epoch'].iloc[-1]

        attack_vector['src_ips'] = src_ips_attackvector_current.tolist()
        
        if str(df_attackvector_current['srcport'].iloc[0]) != 'nan':
            attack_vector['src_ports'] = df_attackvector_current['srcport'].unique().tolist()
        else:
            attack_vector['src_ports']=[]
        
        if str(df_attackvector_current['dstport'].iloc[0]) != 'nan':
            attack_vector['dst_ports'] = df_attackvector_current['dstport'].unique().tolist()
        else:
            attack_vector['dst_ports']=[]

        attack_vector['start_timestamp'] = start_time
        attack_vector['start_time'] = datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')
        attack_vector['duration_sec'] = end_time-start_time
        
        start_time_formated = datetime.fromtimestamp(start_time).strftime('%Y%m%d%H%M%S%f')

    #     ttl_variations = df_attackvector_current.groupby(['_ws.col.Source'])['ip.ttl'].agg(np.ptp).value_counts().sort_index()
    #     if debug: print('TTL VARIATION FOR IPS:',ttl_variations)
    #     if debug: print('TTL VALUE DISTRIBUTION:',df_attackvector_current['ip.ttl'].value_counts().head())

        ############################################################################  
        print('\nATTACK VECTOR '+str(counter)+': '+str(attackvector_filter_string).replace("df_remaining",""))
        print('  - Packets:'+str(len(df_attackvector_current)))
        print('  - #Src_IPs:'+str(len(src_ips_attackvector_current)))

        fingerprints.append(attack_vector)
        ############################################################################
        md5=str(hashlib.md5(str(start_time).encode()).hexdigest())
        with open('output/'+md5+'.json', 'w+') as outfile:
            json.dump(attack_vector, outfile)
        ############################################################################
        df_remaining = df_remaining[eval(attackvector_filter_string.replace('==','!=').replace('&','|'))]
        ############################################################################
        counter += 1
        attack_vector = {}

    matrix_source_ip_intersection = pd.DataFrame()
    for m in range(counter-1):
        for n in range(counter-1):    
            matrix_source_ip_intersection.set_value(str(m+1),str(n+1),int(len(np.intersect1d(attackvectors_source_ips[m], attackvectors_source_ips[n]))))

    print('\nINTERSECTION OF SOURCE IPS IN ATTACK VECTORS:\n',matrix_source_ip_intersection) 

    return top1_dst_ip, fingerprints


# In[ ]:


# #FOR TESTING PURPOSE
# input_file = '../input4test/1.pcap'
# df = pcap2dataframe_tshark(input_file)
# dst_ip, fingerprints =analyse_df_pcap_tshark(df)


# In[ ]:


# display(dst_ip)
# display(fingerprints[0])

