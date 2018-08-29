import math
from datetime import datetime
import numpy as np
import pandas as pd
import hashlib
from ddos_dissector.exceptions.UnsupportedFileTypeError import UnsupportedFileTypeError
from ddos_dissector.portnumber2name import portnumber2name
from ddos_dissector.protocolnumber2name import protocolnumber2name
from ddos_dissector.tcpflagletters2names import tcpflagletters2names


def analyze_dataframe(df, file_type):
    """
    Analyze a dataframe, and return the fingerprints
    :param df: The Pandas dataframe
    :param file_type: The file type string
    :return: The fingerprints
    :raises UnsupportedFileTypeError: If the file type is not supported
    """
    if file_type == "pcap" or file_type == "pcapng":
        return analyze_pcap_dataframe(df)
    elif file_type == "nfdump":
        return analyze_nfdump_dataframe(df)
    else:
        raise UnsupportedFileTypeError("The file type " + file_type + " is not supported.")


def analyze_pcap_dataframe(df):
    debug = True
    total_packets = len(df)
    fingerprints = []
    attack_vector = {}
    df_attackvectors = []
    attack_vector_labels = []
    attack_vector_source_ips = []
    counter = 1

    dst_ip_distribution = df['_ws.col.Destination'].value_counts()
    if debug:
        print("\nDISTRIBUTION OF DESTINATION IPS:")
        print(dst_ip_distribution)
    top1_dst_ip = dst_ip_distribution.keys()[0]
    df_remaining = df[df['_ws.col.Destination'] == top1_dst_ip]

    while len(df_remaining) > 1 :
        attack_vector['file_type'] = 'pcap'
        # Analyse the distribution of IP protocols (and defining the top1)
        protocol_distribution = df_remaining['_ws.col.Protocol'].value_counts()
        if debug:
            print("\nDISTRIBUTION OF PROTOCOLS:")
            print(protocol_distribution)
        top1_protocol = protocol_distribution.keys()[0]
        filter_top_protocol_string = "df_remaining['_ws.col.Protocol']=='" + str(top1_protocol) + "'"
        attack_vector['protocol'] = top1_protocol

        attack_vector_filter_string = ""

        # Define if the remaining is based on the top1 source OR destination port
        if top1_protocol == 'IPv4':
            fragmentation_distribution = \
                df_remaining[df_remaining['_ws.col.Protocol'] == 'IPv4']['fragmentation'].value_counts()
            if debug:
                print("\nFRAGMENTATION DISTRIBUTION:")
                print(fragmentation_distribution)

            if fragmentation_distribution.keys()[0]:
                filter_fragmentation_string = "df_remaining['fragmentation']==True"
                attack_vector_filter_string = '(' + str(filter_top_protocol_string) + ')&(' + str(
                    filter_fragmentation_string) + ')'
            attack_vector['additional'] = {'fragmentation': True}

        else:
            # Analyse the distribution of SOURCE ports AND define the top1
            port_source_distribution = \
                df_remaining[df_remaining['_ws.col.Protocol'] == top1_protocol]['srcport'].value_counts().head()
            if debug:
                print("\nDISTRIBUTION OF SOURCE PORT:")
                print(port_source_distribution)
            top1_source_port = math.floor(port_source_distribution.keys()[0])

            # Analyse the distribution of DESTINATION ports AND define the top1
            port_destination_distribution = \
                df_remaining[df_remaining['_ws.col.Protocol'] == top1_protocol]['dstport'].value_counts().head()
            if debug:
                print("\nDISTRIBUTION OF DESTINATION PORTS:")
                print(port_destination_distribution)
            top1_destination_port = math.floor(port_destination_distribution.keys()[0])

            # Check which port type (source or destination) AND number had most occurrences
            if port_source_distribution.iloc[0] > port_destination_distribution.iloc[0]:
                filter_top_port = "df_remaining['srcport']==" + str(top1_source_port)
            else:
                filter_top_port = "df_remaining['dstport']==" + str(top1_destination_port)

            # Define the conclusion of the analysis (of the remaining traffic)
            attack_vector_filter_string = '(' + str(filter_top_protocol_string) + ')&(' + str(filter_top_port) + ')'

            #Analysis for ICMP
            if top1_protocol == 'ICMP':
                icmp_type_distribution = df_remaining[df_remaining['_ws.col.Protocol'] == 'ICMP'][
                    'icmp.type'].value_counts()
                if debug: print('\nDISTRIBUTION ICMP TYPES:\n', icmp_type_distribution)
                top1_icmp_type = icmp_type_distribution.keys()[0]
                filter_icmp_type = "df_remaining['icmp.type']=='" + str(top1_icmp_type)+"'"
                attack_vector_filter_string = '(' + str(filter_top_protocol_string) + ')&(' + str(filter_icmp_type) + ')'
                attack_vector['additional'] = {'icmp_type': top1_icmp_type}

                # if top1_protocol == 'QUIC':
                #     quic_payload_distribution = \
                #         df_remaining[df_remaining['_ws.col.Protocol']=='QUIC']['quic.payload'].value_counts()
                #     if debug: print('DISTRIBUTION QUIC PAYLOADS:',quic_payload_distribution.head())
                #     top1_quic_payload_distribution = quic_payload_distribution.keys()[0]
                #     filter_quic = "df_remaining['quic.payload']=='"+str(top1_quic_payload_distribution)+"'"
                #     attack_vector_filter_string += '&('+str(filter_quic)+')'
                #
                #     attack_vector['additional'] = {'quic_payload':top1_quic_payload_distribution}
            
            #Analysis for TCP
            if top1_protocol == 'TCP':
                tcp_flag_distribution = \
                    df_remaining[df_remaining['_ws.col.Protocol'] == 'TCP']['tcp.flags.str'].value_counts()
                if debug:
                    print("\nDISTRIBUTION TCP FLAGS:")
                    print(tcp_flag_distribution.head())
                top1_tcp_flag = tcp_flag_distribution.keys()[0]
                filter_tcp_flag = "df_remaining['tcp.flags.str']=='" + str(top1_tcp_flag) + "'"
                attack_vector_filter_string += '&(' + str(filter_tcp_flag) + ')'

                attack_vector['additional'] = {'tcp_flag': top1_tcp_flag}
            
            #Analysis for DNS
            if top1_protocol == 'DNS':
                dns_query_distribution = \
                    df_remaining[df_remaining['_ws.col.Protocol'] == 'DNS']['dns.qry.name'].value_counts()
                if debug:
                    print("\nDISTRIBUTION DNS QUERIES:")
                    print(dns_query_distribution.head())
                top1_dns_query = dns_query_distribution.keys()[0]
                filter_dns_query = "df_remaining['dns.qry.name']=='" + str(top1_dns_query) + "'"
                attack_vector_filter_string += '&(' + str(filter_dns_query) + ')'

                dns_type_distribution = \
                    df_remaining[df_remaining['_ws.col.Protocol'] == 'DNS']['dns.qry.type'].value_counts()
                if debug:
                    print("\nDISTRIBUTION DNS TYPES:")
                    print(dns_type_distribution.head())
                top1_dns_type = dns_type_distribution.keys()[0]
                attack_vector['additional'] = {
                    'dns_query': top1_dns_query,
                    'dns_type': top1_dns_type
                }
            
            #Analysis for NTP
            if top1_protocol == "NTP":
                    ntp_mode_distribution = \
                            df_remaining[df_remaining['_ws.col.Protocol'] == 'NTP']['ntp.priv.monlist.mode'].value_counts()
                    if debug:
                            print("\nNTP_RESPONSE_DISTRIBUTION")
                            print(ntp_mode_distribution.head())
                    top1_ntp_response = ntp_mode_distribution.keys()[0]
                    filter_ntp_response = "df_remaining['ntp.priv.monlist.mode']=='" + str(top1_ntp_response) +"'"
                    attack_vector_filter_string += '&(' + str(filter_ntp_response) + ')'


        attack_vector_labels.append(attack_vector_filter_string.replace("df_remaining", ""))

        df_attack_vector_current = df_remaining[eval(attack_vector_filter_string)]

        src_ips_attack_vector_current = df_attack_vector_current['_ws.col.Source'].unique()

        # If the number of source IPs involved in this potential attack vector is 1, then it is NOT a DDoS!
        if len(src_ips_attack_vector_current) < 2:
            if debug:
                print("STOP ANALYSIS; THERE IS ONLY ONE SOURCE IP RELATED TO THIS ATTACK VECTOR!")
            break

        # SAVE FOR FURTHER ANALYSIS OF THE CURRENT DATAFRAME
        # df_attackvectors.append(df_attackvector_current)

        # For later comparing the list of IPs
        attack_vector_source_ips.append(src_ips_attack_vector_current)

        attack_vector['src_ips'] = src_ips_attack_vector_current.tolist()
        attack_vector['total_src_ips'] = len(attack_vector['src_ips'])

        if str(df_attack_vector_current['srcport'].iloc[0]) != 'nan':
            attack_vector['src_ports'] = [int(x) for x in df_attack_vector_current['srcport'].unique().tolist() if
                                          not math.isnan(x)]
        else:
            attack_vector['src_ports'] = []

        attack_vector['total_src_ports'] = len(attack_vector['src_ports'])

        if str(df_attack_vector_current['dstport'].iloc[0]) != 'nan':
            attack_vector['dst_ports'] = [int(x) for x in df_attack_vector_current['dstport'].unique().tolist() if
                                          not math.isnan(x)]
        else:
            attack_vector['dst_ports'] = []
        
        attack_vector['total_dst_ports'] = len(attack_vector['dst_ports'])

        attack_vector['start_timestamp'] = df_attack_vector_current['frame.time_epoch'].iloc[0]
        attack_vector['key'] = str(hashlib.md5(str(attack_vector['start_timestamp']).encode()).hexdigest())
        attack_vector['start_time'] = datetime.fromtimestamp(attack_vector['start_timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        attack_vector['duration_sec'] = df_attack_vector_current['frame.time_epoch'].iloc[-1] - attack_vector['start_timestamp']
        attack_vector['avg_pps'] = len(df_attack_vector_current)/attack_vector['duration_sec']
        
        attack_vector_current_size = 0
        for i in range(0,len(df_attack_vector_current)):
            attack_vector_current_size += df_attack_vector_current['frame.len'].iloc[i]
        attack_vector['avg_bps'] = attack_vector_current_size/attack_vector['duration_sec']

        # ttl_variations = \
        #     df_attack_vector_current.groupby(['_ws.col.Source'])['ip.ttl'].agg(np.ptp).value_counts().sort_index()
        # if debug:
        #     print("TTL VARIATION FOR IPS:")
        #     print(ttl_variations)
        #     print("TTL VALUE DISTRIBUTION:")
        #     print(df_attack_vector_current['ip.ttl'].value_counts().head())

        print("\nATTACK VECTOR " + str(counter) + ": " + str(attack_vector_filter_string).replace("df_remaining", ""))
        print("  - Packets:" + str(len(df_attack_vector_current)))
        print("  - #Src_IPs:" + str(len(src_ips_attack_vector_current)))

        fingerprints.append(attack_vector)

        #In case of loop stop
        if len(fingerprints)>10:
            if debug:
                print("STOP ANALYSIS; LOOKS LIKE A LOOP; RE-CHECK THE DISSECTOR SOURCE CODE!!")
            break

        df_remaining = df_remaining[eval(attack_vector_filter_string.replace('==', '!=').replace('&', '|'))]

        counter += 1
        attack_vector = {}


    ##Changing keys whether there are attack vectors with the same key   
    attackvector_keys = [x['key'] for x in fingerprints]
    for k, i in enumerate(attackvector_keys):
        repetition_times = attackvector_keys.count(i)
        if repetition_times >1:
            attackvector_keys[k]=i+'_'+str(repetition_times)
            repetition_times -=1   
    for k, i in enumerate(attackvector_keys):
        fingerprints[k]['key']=i

    ##Adding the multivector key to each attack vector
    for x in fingerprints:
        x['multivector_key']= fingerprints[0]['key']

    ##Comparing the source IPs involved in each attack vector
    matrix_source_ip_intersection = pd.DataFrame()
    for m in range(counter - 1):
        for n in range(counter - 1):
            intersection = len(np.intersect1d(attack_vector_source_ips[m], attack_vector_source_ips[n]))
            matrix_source_ip_intersection.loc[str(m + 1), str(n + 1)] = intersection
        matrix_source_ip_intersection.loc[str(m + 1), 'Attack vector'] = str(attack_vector_labels[m])

    print("\nINTERSECTION OF SOURCE IPS IN ATTACK VECTORS:")
    print(matrix_source_ip_intersection,'\n')

    return top1_dst_ip, fingerprints


def analyze_nfdump_dataframe(df_plus):
    """
    Analysis only top traffic stream
    :param df_plus: containing the pcap/pcapng file converted
    :return: (1) print the summary of attack vectors and
    """
    debug = True
    attack_case = "-1"
    reflection_label = ""
    spoofed_label = ""
    fragment_label = ""

    all_patterns = {
        "dst_ip": "",
        "patterns": []
    }

    df = df_plus

    total_packets = df["i_packets"].sum()

    if debug:
        print("Total number packets: " + str(total_packets))
        print("IDENTIFYING MAIN CHARACTERISTICS:")

    top_dst_ip = df.groupby(by=['dst_ip'])['i_packets'].sum().sort_values().index[-1]
    all_patterns["dst_ip"] = top_dst_ip

    if debug:
        print("Target (destination) IP: " + top_dst_ip)

    # Restrict attacks from outside the network!
    # df_filtered = df[(df['dst_ip'] == top_dst_ip) &
    #                  ~df['src_ip'].str.contains(".".join(top_dst_ip.split('.')[0:2]), na=False)]

    df_filtered = df[df['dst_ip'] == top_dst_ip]

    total_packets_to_target = df_filtered['i_packets'].sum()

    if debug:
        print("Number of packets: " + str(total_packets_to_target))

    while len(df_filtered) > 0:
        if debug:
            print("---")

        result = {}

        top_ip_proto = df_filtered.groupby(by=['ip_proto'])['i_packets'].sum().sort_values().index[-1]
        result['ip_protocol'] = top_ip_proto

        if debug: print("IP protocol used in packets going to target IP: " + str(top_ip_proto))

        df_filtered = df_filtered[df_filtered['ip_proto'] == top_ip_proto]

        # Perform a first filter based on the top_dst_ip (target IP), the source IPs can NOT be from the \16 of the
        # target IP, and the top IP protocol that targeted the top_dst_ip

        # Calculating the number of packets after the first filter
        total_packets_filtered = df_filtered['i_packets'].sum()

        if debug:
            print("Number of packets: " + str(total_packets_filtered))

        result["total_nr_packets"] = total_packets_filtered

        # For attacks in the IP protocol level
        attack_label = top_ip_proto + "-based attack"
        result["transport_protocol"] = top_ip_proto

        # For attacks based on TCP or UDP, which have source and destination ports
        if (top_ip_proto == 'TCP') or (top_ip_proto == 'UDP'):

            if debug:
                print("PORT FREQUENCY OF REMAINING PACKETS")

            # Calculate the distribution of source ports based on the first filter
            percent_src_ports = df_filtered.groupby(by=['src_port'])['i_packets'].sum().sort_values(
                ascending=False).divide(float(total_packets_filtered) / 100)

            if debug:
                print("SOURCE ports frequency")
                print(percent_src_ports.head())

            # Calculate the distribution of destination ports after the first filter
            percent_dst_ports = df_filtered.groupby(by=['dst_port'])['i_packets'].sum().sort_values(
                ascending=False).divide(float(total_packets_filtered) / 100)

            if debug:
                print("\nDESTINATION ports frequency")
                print(percent_dst_ports.head())

            # WARNING packets are filtered here again
            # Using the top 1 (source or destination) port to analyse a pattern of packets
            if (len(percent_src_ports) > 0) and (len(percent_dst_ports) > 0):
                if percent_src_ports.values[0] > percent_dst_ports.values[0]:
                    if debug:
                        print("\nUsing top source port: ", percent_src_ports.keys()[0])

                    df_pattern = df_filtered[df_filtered['src_port'] == percent_src_ports.keys()[0]]
                    result["selected_port"] = "src" + str(percent_src_ports.keys()[0])
                else:
                    if debug:
                        print("\nUsing top dest port: ", percent_dst_ports.keys()[0])

                    df_pattern = df_filtered[df_filtered['dst_port'] == percent_dst_ports.keys()[0]]
                    result["selected_port"] = "dst" + str(percent_dst_ports.keys()[0])
            else:
                if debug:
                    print('No top source/destination port')

                return None

            # Calculate the total number of packets involved in the attack
            pattern_packets = df_pattern['i_packets'].sum()
            result["pattern_packet_count"] = pattern_packets

            # Calculate the percentage of the current pattern compared to the raw input file
            representativeness = float(pattern_packets) * 100 / float(total_packets_to_target)
            result["pattern_traffic_share"] = representativeness
            attack_label = 'In %.2f' % representativeness + "\n " + attack_label

            # Check the existence of HTTP data
            # http_data = df_pattern['http_data'].value_counts().divide(float(pattern_packets) / 100)
            http_data = ''

            # Check the existence of TCP flags
            percent_tcp_flags = df_pattern.groupby(by=['tcp_flag'])['i_packets'].sum().sort_values(
                ascending=False).divide(float(pattern_packets) / 100)

            # Calculating the number of source IPs involved in the attack
            ips_involved = df_pattern['src_ip'].unique()
            if len(ips_involved) < 2:
                if debug:
                    print("\nNO MORE PATTERNS")
                break

            if debug:
                print("\nPATTERN (ATTACK VECTOR) LABEL")

            attack_label = attack_label + "\n" + str(len(ips_involved)) + " source IPs"
            result["src_ips"] = ips_involved.tolist()
            result["total_src_ips"] = len(ips_involved)

            # Calculating the number of source IPs involved in the attack
            result["start_timestamp"] = df_pattern['start_time'].min()
            result["end_timestamp"] = df_pattern['start_time'].max()
            result["avg_pps"] = pattern_packets/(result["end_timestamp"]-result["start_timestamp"])
            result["avg_bps"] = df_pattern['i_bytes'].sum()/(result["end_timestamp"]-result["start_timestamp"])

            # Calculating the distribution of source ports that remains
            percent_src_ports = df_pattern.groupby(by=['src_port'])['i_packets'].sum().sort_values(
                ascending=False).divide(float(pattern_packets) / 100)
            result["total_src_ports"] = len(percent_src_ports)

            # Calculating the distribution of destination ports after the first filter
            percent_dst_ports = df_pattern.groupby(by=['dst_port'])['i_packets'].sum().sort_values(
                ascending=False).divide(float(pattern_packets) / 100)
            result["dst_ports"] = percent_dst_ports.to_dict()
            result["total_dst_ports"] = len(result["dst_ports"])

            # There are 3 possibilities of attacks cases!
            if percent_src_ports.values[0] == 100:
                df_filtered = df_filtered[df_filtered['src_port'].isin(percent_src_ports.keys()) == False]
                if len(percent_dst_ports) == 1:
                    # if debug: print("\nCASE 1: 1 source port to 1 destination port") if debug else next
                    port_label = "From " + portnumber2name(
                        percent_src_ports.keys()[0]) + "\n   - Against " + portnumber2name(
                        percent_dst_ports.keys()[0]) + "[" + '%.1f' % percent_dst_ports.values[0] + "%]"
                else:
                    # if debug: print("\nCASE 2: 1 source port to a set of destination ports") if debug else next
                    if percent_dst_ports.values[0] >= 50:
                        port_label = "From " + portnumber2name(
                            percent_src_ports.keys()[0]) + "\n   - Against a set of (" + str(
                            len(percent_dst_ports)) + ") ports, such as " + portnumber2name(
                            percent_dst_ports.keys()[0]) + "[" + '%.2f' % percent_dst_ports.values[
                                         0] + "%]" + " and " + portnumber2name(
                            percent_dst_ports.keys()[1]) + "[" + '%.2f' % \
                                     percent_dst_ports.values[
                                         1] + "%]"
                    elif percent_dst_ports.values[0] >= 33:
                        port_label = "From " + portnumber2name(
                            percent_src_ports.keys()[0]) + "\n   - Against a set of (" + str(
                            len(percent_dst_ports)) + ") ports, such as " + portnumber2name(
                            percent_dst_ports.keys()[0]) + "[" + '%.2f' % percent_dst_ports.values[
                                         0] + "%]" + "; " + portnumber2name(
                            percent_dst_ports.keys()[1]) + "[" + '%.2f' % \
                                     percent_dst_ports.values[
                                         1] + "%], and " + portnumber2name(
                            percent_dst_ports.keys()[2]) + "[" + '%.2f' % percent_dst_ports.values[2] + "%]"
                    else:
                        port_label = "From " + portnumber2name(
                            percent_src_ports.keys()[0]) + "\n   - Against a set of (" + str(
                            len(percent_dst_ports)) + ") ports, such as " + portnumber2name(
                            percent_dst_ports.keys()[0]) + "[" + '%.2f' % percent_dst_ports.values[
                                         0] + "%]" + "; " + portnumber2name(
                            percent_dst_ports.keys()[1]) + "[" + '%.2f' % \
                                     percent_dst_ports.values[
                                         1] + "%], and " + portnumber2name(
                            percent_dst_ports.keys()[2]) + "[" + '%.2f' % percent_dst_ports.values[2] + "%]"
            else:
                if len(percent_src_ports) == 1:
                    df_filtered = df_filtered[df_filtered['src_port'].isin(percent_src_ports.keys()) == False]

                    # if debug: print("\nCASE 1: 1 source port to 1 destination port") if debug else next
                    port_label = "Using " + portnumber2name(percent_src_ports.keys()[0]) + "[" + '%.1f' % \
                                 percent_src_ports.values[
                                     0] + "%]" + "\n   - Against " + portnumber2name(
                        percent_dst_ports.keys()[0]) + "[" + '%.1f' % percent_dst_ports.values[0] + "%]"

                else:
                    # if debug: print("\nCASE 3: 1 source port to a set of destination ports") if debug else next
                    df_filtered = df_filtered[df_filtered['src_port'].isin(percent_src_ports.keys()) == False]

                    if percent_src_ports.values[0] >= 50:
                        port_label = "From a set of (" + str(len(percent_src_ports)) + ") ports, such as " + \
                                     portnumber2name(percent_src_ports.keys()[0]) + \
                                     "[" + '%.2f' % percent_src_ports.values[0] + "%] and " + \
                                     portnumber2name(percent_src_ports.keys()[1]) + \
                                     "[" + '%.2f' % percent_src_ports.values[1] + "%]" + "\n   - Against " + \
                                     portnumber2name(percent_dst_ports.keys()[0]) + \
                                     "[" + '%.1f' % percent_dst_ports.values[0] + "%]"
                    elif percent_src_ports.values[0] >= 33:
                        port_label = "From a set of (" + str(len(percent_src_ports)) + ") ports, such as " + \
                                     portnumber2name(percent_src_ports.keys()[0]) + \
                                     "[" + '%.2f' % percent_src_ports.values[0] + "%], " + \
                                     portnumber2name(percent_src_ports.keys()[1]) + \
                                     "[" + '%.2f' % percent_src_ports.values[1] + "%], and " + \
                                     portnumber2name(percent_src_ports.keys()[2]) + \
                                     "[" + '%.2f' % percent_src_ports.values[2] + "%]" + "\n   - Against " + \
                                     portnumber2name(percent_dst_ports.keys()[0]) + \
                                     "[" + '%.1f' % percent_dst_ports.values[0] + "%]"
                    else:
                        df_filtered = df_filtered[df_filtered['dst_port'].isin(percent_dst_ports.keys()) == False]
                        port_label = "From a set of (" + str(len(percent_src_ports)) + ") ports, such as " + \
                                     portnumber2name(percent_src_ports.keys()[0]) + \
                                     "[" + '%.2f' % percent_src_ports.values[0] + "%], " + \
                                     portnumber2name(percent_src_ports.keys()[1]) + \
                                     "[" + '%.2f' % percent_src_ports.values[1] + "%], " + \
                                     portnumber2name(percent_src_ports.keys()[2]) + \
                                     "[" + '%.2f' % percent_src_ports.values[2] + "%]; and " + \
                                     portnumber2name(percent_src_ports.keys()[3]) + \
                                     "[" + '%.2f' % percent_src_ports.values[3] + "%]\n   - Against " + \
                                     portnumber2name(percent_dst_ports.keys()[0]) + \
                                     "[" + '%.1f' % percent_dst_ports.values[0] + "%]"

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

            print(
                "\nSUMMARY:\n" + "- %.2f" % representativeness + "% of the packets targeting " + top_dst_ip + "\n" +
                "   - Involved " + str(len(ips_involved)) + " source IP addresses\n" +
                "   - Using IP protocol " + protocolnumber2name(top_ip_proto) + "\n" +
                "   - " + port_label + "\n" +
                "   - " + fragment_label +
                "   - " + reflection_label +
                "   - " + spoofed_label)

            all_patterns["patterns"].append(result)

    return top_dst_ip, all_patterns["patterns"]
