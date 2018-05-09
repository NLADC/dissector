
# coding: utf-8

# In[2]:


import dpkt
import socket
import pandas as pd

def pcap2dataframe_dpkt(filename):
    """
    Read PCAP and produce Pandas dataframe
    using dpkt (that is ONLY in python2).
    dpkt is faster than using tshark and python-scapy
    dpkt is slower than tcpdump but easier to get specific values of the pcap
    """
    
    inputfile = open(filename)

    #tcpdump, tshark
    #dpkt, scapy, 
    
    pcapfile = dpkt.pcap.Reader(inputfile)
    data = []
    for ts, buf in pcapfile:
        eth = dpkt.ethernet.Ethernet(buf)

        # FILTERING ONLY FOR IPv4 instead of packets ARP or IPv6
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data  # Loading the content of the ethernet into a variable 'ip'

            timestamp = ts  # 1
            ip_ttl = ip.ttl  # 2

            ip_proto = ip.p  # 3
            sport = ""
            dport = ""
            tcp_flag = ""
            http_request_method = ""
            if not (ip_proto == 6 or ip_proto == 17):  # It is not TCP or UDP
                continue

            ip_length = ip.len  # 4
            ip_src = socket.inet_ntoa(ip.src)  # 5
            ip_dst = socket.inet_ntoa(ip.dst)  # 6

            try:
                proto = ip.data  # Loading the content of the 'ip' into a variable 'protocol' that can be for example ICMP, TCP, and UDP.
            except:
                continue
            if isinstance(proto, str):
                continue
            sport = proto.sport  # 7
            dport = proto.dport  # 8

            if ip.p == 6:
                try:
                    tcp_flag += ("F" if (int(proto.flags & dpkt.tcp.TH_FIN) != 0) else ".")  # 27
                    tcp_flag += ("S" if (int(proto.flags & dpkt.tcp.TH_SYN) != 0) else ".")  # 26
                    tcp_flag += ("R" if (int(proto.flags & dpkt.tcp.TH_RST) != 0) else ".")  # 25
                    tcp_flag += ("P" if (int(proto.flags & dpkt.tcp.TH_PUSH) != 0) else ".")  # 24
                    tcp_flag += ("A" if (int(proto.flags & dpkt.tcp.TH_ACK) != 0) else ".")  # 23
                    tcp_flag += ("U" if (int(proto.flags & dpkt.tcp.TH_URG) != 0) else ".")  # 22
                    tcp_flag += ("E" if (int(proto.flags & dpkt.tcp.TH_ECE) != 0) else ".")  # 21
                    tcp_flag += ("C" if (int(proto.flags & dpkt.tcp.TH_CWR) != 0) else ".")  # 20
                except:
                    print
                    "EXCEPTION TCP FLAG" if debug else next

                if (proto.dport == 80) or (proto.dport == 443):
                    if proto.data == '':
                        http_request_method = ''
                    else:
                        try:
                            http_request_method = dpkt.http.Request(proto.data).method
                        except:
                            http_request_method = ''

            fragments = 1 if (
            int(ip.off & dpkt.ip.IP_MF) != 0) else 0  # 8 This flag is set to a 1 for all fragments except the last one


            data.append((timestamp, ip_ttl, ip_proto, ip_length, ip_src, ip_dst, sport, dport, tcp_flag, fragments, http_request_method, len(buf)))


    columns = [
        'timestamp',
        'ip_ttl',
        'ip_proto',
        'ip_length',
        'src_ip',
        'dst_ip',
        'src_port',
        'dst_port',
        'tcp_flag',
        'fragments',
        'http_data',
        'raw_size']
    return pd.DataFrame(data, columns=columns)

