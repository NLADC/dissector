
# coding: utf-8

# In[1]:


input_file='input_file_for_test/1.pcap'

#check exist!!!!


# ## Libraries for data analysis

# In[2]:


import pandas as pd
import numpy as np


# ## Functions 

# ### F1. Protocol number to protocol name

# In[3]:


import functions/protocolnumber2name.ipynb


# usage:

# In[4]:


protocolnumber2name(17)


# ### F2. Port number to port name 

# In[5]:


import functions/portnumber2name.ipynb


# usage:

# In[6]:


portnumber2name(53)


# ### F3. TCP flag letter(s) to the name of the flags

# In[7]:


import functions/tcpflagletters2names.ipynb


# usage:

# In[8]:


tcpflagletters2names('R')


# ### F4. Determining the type of the input file (pcap, pcapng, sflow, nfdump)
# Sometimes a tool has an extension, for example pcap, but it is another type of file, for example pcapng.

# In[9]:


import functions/check_filetype.ipynb


# usage:

# In[33]:


check_filetype(input_file)


# ### F5. Converting packet-based input file (depending on the type of file) to dataframe

# In[34]:


import functions/pcap2dataframe.ipynb
import functions/pcapng2dataframe.ipynb
# %run functions/sflow2dataframe.ipynb


# ## Converting the input file into a dataframe 

# In[42]:


input_file


# In[45]:


file_type


# In[81]:


file_type = check_filetype (input_file)

if file_type == 'pcap':
    df = pcap2dataframe(input_file)
    
elif file_type == 'pcapng':
    df = pcapng2dataframe(input_file)
    
elif file_type == 'sflow':
    df = sflow2dataframe(input_file)
    
elif file_type == 'nfdump':
    print "SORRY! We didn't developed a parser for this type of file!\n\nPLEASE contact us and we will develop it as soon as possible!"
    
else:
    print "SORRY! We neither developed the parser for this type of file (YET) OR we recognized the format of your file!"


# ## Checking what we have, so far.

# In[47]:


print len(df)

df.head()


# ## DDoS attack vector (pattern) identification/recognition

# In[51]:


top_ip_dst = df['ip_dst'].value_counts().index[0]


# In[55]:


top_proto = df[df['ip_dst'] == top_ip_dst]['ip_proto'].value_counts().index[0]


# In[60]:


a = df[df['ip_dst'] == top_ip_dst]
df_filtered =  a[a['ip_proto'] == top_proto]


# In[70]:


df_filtered['dport'].value_counts().sort_index()
# .divide(float(total_packets_filtered) / 100)


# In[94]:


import collections

def analyse(df, debug=False, ttl_variation_threshold = 4):
    """
    Analysis only top traffic stream

    :param dataframe (df) containing the pcap/pcapng file converted:
    :return (1) print the summary of attack vectors and :
    """

    attack_case = "-1"
    reflection_label=""
    spoofed_label=""
    fragment_label=""

    allpatterns = {
        "dst_ip" : "",
        "patterns": []
    }
#     result_structure = {
#         "start_timestamp":0,
#         "end_timestamp":0,
#         "ip_protocol":0,
#         "dst_ip":[],
#         "src_ips":[],
#         "dst_ports":[], #(port,share)
#         "src_ports":[], #(port,share)
#         "reflected":False,
#         "spoofed":False,
#         "fragmented":False,
#         "pattern_traffic_share":0.0,
#         "pattern_packet_count":0,
#         "pattern_total_megabytes":0,
#         "ttl_variation":[],
# #         "packets":[]
#     }    
    
    if debug: print "Total number packets: "+ str(len(df))
    if debug: print "\n###################################\nIDENTIFYING MAIN CHARACTERISTICS:\n###################################"
    
    top_ip_dst = df['ip_dst'].value_counts().index[0]
    
    if debug: print "Target (destination) IP: "+ top_ip_dst
    allpatterns["dst_ip"] = top_ip_dst
    
    #Restricting attacks from outside the network!
    #df_filtered = df[(df['ip_dst'] == top_ip_dst) & ~df['ip_src'].str.contains(".".join(top_ip_dst.split('.')[0:2]), na=False) ]

    df_filtered = df[(df['ip_dst'] == top_ip_dst) ]
    
    total_packets_to_target = len(df_filtered)
    if debug: print "Number of packets: "+str(total_packets_to_target)    
        
##############################
##############################
    while (len(df_filtered)>0):
        if debug: print "\n###################################################################################################################"
        result = {}
        top_ip_proto = df[df['ip_dst'] == top_ip_dst]['ip_proto'].value_counts().index[0]
        result['ip_protocol']=top_ip_proto
        if debug: print "IP protocol used in packets going to target IP: "+str(top_ip_proto)
        
        df_filtered = df_filtered[df_filtered['ip_proto'] == top_ip_proto]

        # Performing a first filter based on the top_ip_dst (target IP), the source IPs canNOT be from the \16 of the
        # target IP, and the top IP protocol that targeted the top_ip_dst

        ####
        # Calculating the number of packets after the first filter 
        total_packets_filtered = len(df_filtered)
        if debug: print "Number of packets: "+str(total_packets_filtered)
        result["total_nr_packets"] = total_packets_filtered
    
        ####
        # For attacks in the IP protocol level
#!!!!!CHANGE FUNCTION
        attack_label = protocolnumber2name(top_ip_proto) + "-based attack"
        result["transport_protocol"] = protocolnumber2name(top_ip_proto)

        ####
        # For attacks based on TCP or UDP, which have source and destination ports
        if ((top_ip_proto == 6) or (top_ip_proto == 17)):

            if debug: print "\n#############################\nPORT FREQUENCY OF REMAINING PACKETS\n##############################"
            ####
            # Calculating the distribution of source ports based on the first filter
            percent_src_ports = df_filtered['sport'].value_counts().divide(float(total_packets_filtered) / 100)

            if debug: print "SOURCE ports frequency" 
            if debug: print percent_src_ports.head() 

            ####
            # Calculating the distribution of destination ports after the first filter
            percent_dst_ports = df_filtered['dport'].value_counts().divide(float(total_packets_filtered) / 100)
            if debug: print "\nDESTINATION ports frequency" 
            if debug: print percent_dst_ports.head()

   #####   #####
   #####   #####
   #####   #####
            #####
            ## WARNING packets are filtered here again#####
            # Using the top 1 (source or destination) port to analyse a pattern of packets
            if (len(percent_src_ports) > 0) and (len(percent_dst_ports) > 0):
                if percent_src_ports.values[0] > percent_dst_ports.values[0]:
                    if debug: print "\nUsing top source port: ", percent_src_ports.keys()[0] 
                    df_pattern = df_filtered[df_filtered['sport'] == percent_src_ports.keys()[0]]
                    result["selected_port"] = "src_" + str(percent_src_ports.keys()[0])
                else:
                    if debug: print "\n Using top dest port: ", percent_dst_ports.keys()[0]
                    df_pattern = df_filtered[df_filtered['dport'] == percent_dst_ports.keys()[0]]
                    result["selected_port"] = "dst_" + str(percent_dst_ports.keys()[0])
            else:
                if debug: print 'no top source/dest port' 
                return None

            

            #####
            # Calculating the total number of packets involved in the attack
            pattern_packets = len(df_pattern)
            
            result["pattern_packet_count"] = pattern_packets

            #WARNING Can be wrong
            result['raw_attack_size_megabytes'] = (df_pattern['raw_size'].sum() /1000000).item()
            result["pattern_total_megabytes"] = (df_pattern[df_pattern['fragments'] == 0]['ip_length'].sum() / 1000000).item()

            #####
            # Calculating the percentage of the current pattern compared to the raw input file
            representativeness = float(pattern_packets) * 100 / float(total_packets_to_target)
            result["pattern_traffic_share"] = representativeness
            attack_label = 'In %.2f' % representativeness + "\n " + attack_label

            #####
            # Checking the existence of HTTP data
            http_data = df_pattern['http_data'].value_counts().divide(float(pattern_packets) / 100)

            #####
            # Checking the existence of TCP flags
            percent_tcp_flags = df_pattern['tcp_flag'].value_counts().divide(float(pattern_packets) / 100)

            #####
            # Calculating the number of source IPs involved in the attack
            ips_involved = df_pattern['ip_src'].unique()
######      
            print ips_involved
            if len(ips_involved) < 2:
                
                if debug: print "\n###################################################################################################################"
                if debug: print "\n###################################################################################################################"
                if debug: print "\n###################################################################################################################"
                if debug: print("\nNO MORE PATTERNS")
                break
            
            if debug: print("\n############################\nPATTERN (ATTACK VECTOR) LABEL "+ "\n############################")
            attack_label = attack_label + "\n"+ str(len(ips_involved)) + " source IPs"
            result["src_ips"] = ips_involved.tolist()

            #####
            # Calculating the number of source IPs involved in the attack
            result["start_timestamp"] = df_pattern['timestamp'].min().item()
            result["end_timestamp"] = df_pattern['timestamp'].max().item()

            ####
            # Calculating the distribution of TTL variation (variation -> number of IPs)
            ttl_variations = df_pattern.groupby(['ip_src'])['ip_ttl'].agg(np.ptp).value_counts().sort_index()
    #         if debug: print('TTL variation : NR of source IPs')
    #         if debug: print(ttl_variations)
            ips_ttl_greater_4 = ttl_variations.groupby(np.where(ttl_variations.index > 4, '>4', ttl_variations.index)).sum()
#             if debug: print('\n IPs TTL variation >4')
#             if debug: print(ips_ttl_greater_4)
            result["ttl_variation"] = ttl_variations.to_dict()

            ####
            # Calculating the distribution of IP fragments (fragmented -> percentage of packets)
            percent_fragments = df_pattern['fragments'].value_counts().divide(float(pattern_packets) / 100)
            ####
            # Calculating the distribution of source ports that remains
            percent_src_ports = df_pattern['sport'].value_counts().divide(float(pattern_packets) / 100)
            result["src_ports"] = percent_src_ports.to_dict()

            ####
            # Calculating the distribution of destination ports after the first filter
            percent_dst_ports = df_pattern['dport'].value_counts().divide(float(pattern_packets) / 100)
            result["dst_ports"] = percent_dst_ports.to_dict()

            ####
            # There are 3 possibilities of attacks cases!
            if (percent_src_ports.values[0] == 100):
                df_filtered = df_filtered[df_filtered['sport'].isin(percent_src_ports.keys()) == False]
                if (len(percent_dst_ports) == 1):
                    # if debug: print("\nCASE 1: 1 source port to 1 destination port") if debug else next
                    port_label = "From " + portnumber2name(
                        percent_src_ports.keys()[0]) + "\n   - Against " + portnumber2name(
                        percent_dst_ports.keys()[0]) + "[" + '%.1f' % percent_dst_ports.values[0] + "%]"
                else:
                    # if debug: print("\nCASE 2: 1 source port to a set of destination ports") if debug else next
                    if (percent_dst_ports.values[0] >= 50):
                        port_label = "From " + portnumber2name(
                            percent_src_ports.keys()[0]) + "\n   - Against a set of (" + str(
                            len(percent_dst_ports)) + ") ports, such as " + portnumber2name(
                            percent_dst_ports.keys()[0]) + "[" + '%.2f' % percent_dst_ports.values[
                            0] + "%]" + " and " + portnumber2name(percent_dst_ports.keys()[1]) + "[" + '%.2f' % \
                                                                                                     percent_dst_ports.values[
                                                                                                         1] + "%]"
                    elif (percent_dst_ports.values[0] >= 33):
                        port_label = "From " + portnumber2name(
                            percent_src_ports.keys()[0]) + "\n   - Against a set of (" + str(
                            len(percent_dst_ports)) + ") ports, such as " + portnumber2name(
                            percent_dst_ports.keys()[0]) + "[" + '%.2f' % percent_dst_ports.values[
                            0] + "%]" + "; " + portnumber2name(percent_dst_ports.keys()[1]) + "[" + '%.2f' % \
                                                                                                  percent_dst_ports.values[
                                                                                                      1] + "%], and " + portnumber2name(
                            percent_dst_ports.keys()[2]) + "[" + '%.2f' % percent_dst_ports.values[2] + "%]"
                    else:
                        port_label = "From " + portnumber2name(
                            percent_src_ports.keys()[0]) + "\n   - Against a set of (" + str(
                            len(percent_dst_ports)) + ") ports, such as " + portnumber2name(
                            percent_dst_ports.keys()[0]) + "[" + '%.2f' % percent_dst_ports.values[
                            0] + "%]" + "; " + portnumber2name(percent_dst_ports.keys()[1]) + "[" + '%.2f' % \
                                                                                                  percent_dst_ports.values[
                                                                                                      1] + "%], and " + portnumber2name(
                            percent_dst_ports.keys()[2]) + "[" + '%.2f' % percent_dst_ports.values[2] + "%]"
            else:
                if (len(percent_src_ports) == 1):
                    df_filtered = df_filtered[df_filtered['sport'].isin(percent_src_ports.keys()) == False]

                    # if debug: print("\nCASE 1: 1 source port to 1 destination port") if debug else next
                    port_label = "Using " + portnumber2name(percent_src_ports.keys()[0]) + "[" + '%.1f' %                                                                                                                   percent_src_ports.values[
                                                                                                                      0] + "%]" + "\n   - Against " + portnumber2name(
                        percent_dst_ports.keys()[0]) + "[" + '%.1f' % percent_dst_ports.values[0] + "%]"


                else:
                    # if debug: print("\nCASE 3: 1 source port to a set of destination ports") if debug else next
                    df_filtered = df_filtered[df_filtered['sport'].isin(percent_src_ports.keys()) == False]

                    if (percent_src_ports.values[0] >= 50):
                        port_label = "From a set of (" + str(
                            len(percent_src_ports)) + ") ports, such as " + portnumber2name(
                            percent_src_ports.keys()[0]) + "[" + '%.2f' % percent_src_ports.values[
                            0] + "%] and " + portnumber2name(percent_src_ports.keys()[1]) + "[" + '%.2f' % \
                                                                                                percent_src_ports.values[
                                                                                                    1] + "%]" + "\n   - Against " + portnumber2name(
                            percent_dst_ports.keys()[0]) + "[" + '%.1f' % percent_dst_ports.values[0] + "%]"
                    elif (percent_src_ports.values[0] >= 33):
                        port_label = "From a set of (" + str(
                            len(percent_src_ports)) + ") ports, such as " + portnumber2name(
                            percent_src_ports.keys()[0]) + "[" + '%.2f' % percent_src_ports.values[
                            0] + "%], " + portnumber2name(percent_src_ports.keys()[1]) + "[" + '%.2f' % \
                                                                                             percent_src_ports.values[
                                                                                                 1] + "%], and " + portnumber2name(
                            percent_src_ports.keys()[2]) + "[" + '%.2f' % percent_src_ports.values[
                            2] + "%]" + "\n   - Against " + portnumber2name(percent_dst_ports.keys()[0]) + "[" + '%.1f' % \
                                                                                                            percent_dst_ports.values[
                                                                                                                0] + "%]"
                    else:
                        df_filtered = df_filtered[df_filtered['dport'].isin(percent_dst_ports.keys()) == False]
                        port_label = "From a set of (" + str(
                            len(percent_src_ports)) + ") ports, such as " + portnumber2name(
                            percent_src_ports.keys()[0]) + "[" + '%.2f' % percent_src_ports.values[
                            0] + "%], " + portnumber2name(percent_src_ports.keys()[1]) + "[" + '%.2f' % \
                                                                                             percent_src_ports.values[
                                                                                                 1] + "%], " + portnumber2name(
                            percent_src_ports.keys()[2]) + "[" + '%.2f' % percent_src_ports.values[
                            2] + "%]" + "; and " + portnumber2name(percent_src_ports.keys()[3]) + "[" + '%.2f' % \
                                                                                                      percent_src_ports.values[
                                                                                                          3] + "%]" + "\n   - Against " + portnumber2name(
                            percent_dst_ports.keys()[0]) + "[" + '%.1f' % percent_dst_ports.values[0] + "%]"

            ####
            # Testing HTTP request
#            if len(http_data) > 0 and ((percent_dst_ports.index[0] == 80) or (percent_dst_ports.index[0] == 443)):            
            if len(http_data) > 0 :
                attack_label = attack_label + "; " + http_data.index[0]

            ####
            # Testing TCP flags
            if (len(percent_tcp_flags) > 0) and (percent_tcp_flags.values[0] > 50):
                attack_label = attack_label + "; TCP flags: " + tcpflagletters2names(
                    percent_tcp_flags.index[0]) + "[" + '%.1f' % percent_tcp_flags.values[0] + "%]"

            ####
            # IP fragmentation
            if '1' in percent_fragments.keys():
                if (percent_fragments['1'] > 0.3):
                    fragment_label = "%.2f" % percent_fragments['1'] + "packets with fragments marked"
                    result["fragmented"] = True

            ####
            # IP spoofing (if (more than 0) src IPs had the variation of the ttl higher than a treshold)
            if '>4' in ips_ttl_greater_4.keys():
                if (ips_ttl_greater_4['>4'] > len(ips_involved)*0.1 ):
                    result["spoofed"]=True
                    spoofed_label = "Likely involving spoofed IPs"
                else:
                    ####involved in 
                    # Reflection and Amplification
##!!!! include the possibility to check top src_ips open port (censys) 
                    if percent_src_ports.values[0] >= 1:
                        result["reflected"]=True
                        reflection_label = "Reflection & Amplification"

            print "\nSUMMARY:\n"                    +"- %.2f" % representativeness +"% of the packets targeting "+top_ip_dst+"\n"                    +"   - Involved "+str(len(ips_involved))+" source IP addresses\n"                    +"   - Using IP protocol "+protocolnumber2name(top_ip_proto)+"\n"                    +"   - "+port_label+"\n"                    +"   - "+fragment_label                    +"   - "+reflection_label                    +"   - "+spoofed_label
            
            allpatterns["patterns"].append(result)


    return allpatterns


# <h1 align='center'> !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!<br>  THE DEMO <br>!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!</h1>
# 

# - 1: UDP attack against HTTP (~0.2'')
# - 2: NTP  against HTTP (~20'')
# - 3: Multi-vector attack (DNS reflection and netbios) (1' 20'')

# In[95]:


# %%time
allpatterns = analyse(df, True)


# 
# # Let's take a look on the attack pattern!!!!

# In[96]:


print allpatterns.keys()
# print "\n"
print allpatterns['patterns'][0].keys()


# In[97]:


allpatterns['patterns'][0]['src_ports']


# In[98]:


allpatterns['patterns'][0]['dst_ports']


# In[99]:


allpatterns['patterns'][0]['src_ips']


# In[100]:


allpatterns['dst_ip']

