
# coding: utf-8

# In[1]:


from functions.portnumber2name import *
from functions.tcpflagletters2names import *
from functions.protocolnumber2name import *


# In[ ]:


# # FOR TESTING PURPOSE
# from portnumber2name import *
# from tcpflagletters2names import *
# from protocolnumber2name import *


# In[3]:


def analyse_df_nfdump(df_plus, debug=False, ttl_variation_threshold=4):
    """
    Analysis only top traffic stream

    :param dataframe (df) containing the pcap/pcapng file converted:
    :return (1) print the summary of attack vectors and :
    """
    attack_case = "-1"
    reflection_label = ""
    spoofed_label = ""
    fragment_label = ""

    allpatterns = {
        "dst_ip" : "",
        "patterns": []
    }  
    
    df = df_plus[0]
    summary = df_plus[1]
    
    total_packets = summary[2]
    
    if debug:
        print ("Total number packets: " + total_packets)
        print ("\n###################################\nIDENTIFYING MAIN CHARACTERISTICS:\n###################################")

    top_dst_ip = df.groupby(by=['dst_ip'])['i_packets'].sum().sort_values().index[-1]
    allpatterns["dst_ip"] = top_dst_ip
    
    if debug: print ("Target (destination) IP: " + top_dst_ip)
    

    # Restricting attacks from outside the network!
    # df_filtered = df[(df['dst_ip'] == top_dst_ip) & ~df['src_ip'].str.contains(".".join(top_dst_ip.split('.')[0:2]), na=False) ]

    df_filtered = df[df['dst_ip'] == top_dst_ip]
    
    total_packets_to_target = df_filtered['i_packets'].sum()
    
    if debug: print ("Number of packets: " + str(total_packets_to_target))

    while (len(df_filtered) > 0):
        if debug: print ("\n###################################################################################################################")
        
        result = {}
        
        top_ip_proto = df_filtered.groupby(by=['ip_proto'])['i_packets'].sum().sort_values().index[-1]
        result['ip_protocol'] = top_ip_proto
        
        if debug: print ("IP protocol used in packets going to target IP: " + str(top_ip_proto))

        df_filtered = df_filtered[df_filtered['ip_proto'] == top_ip_proto]

        # Performing a first filter based on the top_dst_ip (target IP), the source IPs can NOT be from the \16 of the
        # target IP, and the top IP protocol that targeted the top_dst_ip

        # Calculating the number of packets after the first filter
        total_packets_filtered = df_filtered['i_packets'].sum()
        
        if debug: print ("Number of packets: " + str(total_packets_filtered))
        
        result["total_nr_packets"] = total_packets_filtered

        # For attacks in the IP protocol level
        attack_label = top_ip_proto + "-based attack"
        result["transport_protocol"] = top_ip_proto
        
        # For attacks based on TCP or UDP, which have source and destination ports
        if ((top_ip_proto == 'TCP') or (top_ip_proto == 'UDP')):            
            
            if debug: print ("\n#############################\nPORT FREQUENCY OF REMAINING PACKETS\n##############################")
            
            # Calculating the distribution of source ports based on the first filter
            percent_src_ports = df_filtered.groupby(by=['src_port'])['i_packets'].sum().sort_values(ascending=False).divide(float(total_packets_filtered) / 100)
            
            if debug: print ("SOURCE ports frequency")
            if debug: print (percent_src_ports.head())

            # Calculating the distribution of destination ports after the first filter
            percent_dst_ports = df_filtered.groupby(by=['dst_port'])['i_packets'].sum().sort_values(ascending=False).divide(float(total_packets_filtered) / 100)

            if debug: print ("\nDESTINATION ports frequency")
            if debug: print (percent_dst_ports.head())

            ## WARNING packets are filtered here again
            # Using the top 1 (source or destination) port to analyse a pattern of packets
            if (len(percent_src_ports) > 0) and (len(percent_dst_ports) > 0):
                if percent_src_ports.values[0] > percent_dst_ports.values[0]:
                    if debug: print ("\nUsing top source port: ", percent_src_ports.keys()[0])
                    
                    df_pattern = df_filtered[df_filtered['src_port'] == percent_src_ports.keys()[0]]
                    result["selected_port"] = "src" + str(percent_src_ports.keys()[0])
                else:
                    if debug: print ("\n Using top dest port: ", percent_dst_ports.keys()[0])
                    
                    df_pattern = df_filtered[df_filtered['dst_port'] == percent_dst_ports.keys()[0]]
                    result["selected_port"] = "dst" + str(percent_dst_ports.keys()[0])
            else:
                if debug: print ('no top source/dest port')
                
                return None

            # Calculating the total number of packets involved in the attack
            pattern_packets = df_pattern['i_packets'].sum()
            result["pattern_packet_count"] = pattern_packets

            # Calculating the percentage of the current pattern compared to the raw input file
            representativeness = float(pattern_packets) * 100 / float(total_packets_to_target)
            result["pattern_traffic_share"] = representativeness
            attack_label = 'In %.2f' % representativeness + "\n " + attack_label

            # Checking the existence of HTTP data
            #http_data = df_pattern['http_data'].value_counts().divide(float(pattern_packets) / 100)
            http_data = ''
            
            # Checking the existence of TCP flags
            percent_tcp_flags = df_pattern.groupby(by=['tcp_flag'])['i_packets'].sum().sort_values(ascending=False).divide(float(pattern_packets) / 100)
            
            # Calculating the number of source IPs involved in the attack
            ips_involved = df_pattern['src_ip'].unique()
            ######
            if len(ips_involved) < 2:
                if debug: print ("\n###################################################################################################################")
                if debug: print ("\n###################################################################################################################")
                if debug: print ("\n###################################################################################################################")
                if debug: print("\nNO MORE PATTERNS")
                break

            if debug: print("\n############################\nPATTERN (ATTACK VECTOR) LABEL " + "\n############################")
            
            attack_label = attack_label + "\n" + str(len(ips_involved)) + " source IPs"
            result["src_ips"] = ips_involved.tolist()

            # Calculating the number of source IPs involved in the attack
            result["start_timestamp"] = df_pattern['start_time'].min()
            result["end_timestamp"] = df_pattern['start_time'].max()

            # Calculating the distribution of source ports that remains
            percent_src_ports = df_pattern.groupby(by=['src_port'])['i_packets'].sum().sort_values(ascending=False).divide(float(pattern_packets) / 100)
            result["src_ports"] = percent_src_ports.to_dict()
            
            # Calculating the distribution of destination ports after the first filter
            percent_dst_ports = df_pattern.groupby(by=['dst_port'])['i_packets'].sum().sort_values(ascending=False).divide(float(pattern_packets) / 100)
            result["dst_ports"] = percent_dst_ports.to_dict()

            # There are 3 possibilities of attacks cases!
            if (percent_src_ports.values[0] == 100):
                df_filtered = df_filtered[df_filtered['src_port'].isin(percent_src_ports.keys()) == False]
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
                                         0] + "%]" + " and " + portnumber2name(
                            percent_dst_ports.keys()[1]) + "[" + '%.2f' % \
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
                    df_filtered = df_filtered[df_filtered['src_port'].isin(percent_src_ports.keys()) == False]

                    # if debug: print("\nCASE 1: 1 source port to 1 destination port") if debug else next
                    port_label = "Using " + portnumber2name(percent_src_ports.keys()[0]) + "[" + '%.1f' %                                  percent_src_ports.values[
                                     0] + "%]" + "\n   - Against " + portnumber2name(
                        percent_dst_ports.keys()[0]) + "[" + '%.1f' % percent_dst_ports.values[0] + "%]"


                else:
                    # if debug: print("\nCASE 3: 1 source port to a set of destination ports") if debug else next
                    df_filtered = df_filtered[df_filtered['src_port'].isin(percent_src_ports.keys()) == False]

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
                                         2] + "%]" + "\n   - Against " + portnumber2name(
                            percent_dst_ports.keys()[0]) + "[" + '%.1f' % \
                                     percent_dst_ports.values[
                                         0] + "%]"
                    else:
                        df_filtered = df_filtered[df_filtered['dst_port'].isin(percent_dst_ports.keys()) == False]
                        port_label = "From a set of (" + str(
                            len(percent_src_ports)) + ") ports, such as " + portnumber2name(
                            percent_src_ports.keys()[0]) + "[" + '%.2f' % percent_src_ports.values[
                                         0] + "%], " + portnumber2name(percent_src_ports.keys()[1]) + "[" + '%.2f' % \
                                     percent_src_ports.values[
                                         1] + "%], " + portnumber2name(
                            percent_src_ports.keys()[2]) + "[" + '%.2f' % percent_src_ports.values[
                                         2] + "%]" + "; and " + portnumber2name(
                            percent_src_ports.keys()[3]) + "[" + '%.2f' % \
                                     percent_src_ports.values[
                                         3] + "%]" + "\n   - Against " + portnumber2name(
                            percent_dst_ports.keys()[0]) + "[" + '%.1f' % percent_dst_ports.values[0] + "%]"

            # Testing HTTP request
            if len(http_data) > 0 and ((percent_dst_ports.index[0] == 80) or (percent_dst_ports.index[0] == 443)):
                attack_label = attack_label + "; " + http_data.index[0]

            # Testing TCP flags
            if (len(percent_tcp_flags) > 0) and (percent_tcp_flags.values[0] > 50):
                attack_label = attack_label + "; TCP flags: " + tcpflagletters2names(
                    percent_tcp_flags.index[0]) + "[" + '%.1f' % percent_tcp_flags.values[0] + "%]"

            # Must discuss if it actually stands for nfdump files
            if percent_src_ports.values[0] >= 1:
                result["reflected"] = True
                reflection_label = "Reflection & Amplification"

            print ("\nSUMMARY:\n"                   + "- %.2f" % representativeness + "% of the packets targeting " + top_dst_ip + "\n"                   + "   - Involved " + str(len(ips_involved)) + " source IP addresses\n"                   + "   - Using IP protocol " + protocolnumber2name(top_ip_proto) + "\n"                   + "   - " + port_label + "\n"                   + "   - " + fragment_label                   + "   - " + reflection_label                   + "   - " + spoofed_label)

            allpatterns["patterns"].append(result)
            
    return allpatterns

