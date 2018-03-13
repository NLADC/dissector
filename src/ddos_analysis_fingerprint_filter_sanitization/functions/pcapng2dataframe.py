
# coding: utf-8

# In[2]:


def pcapng2dataframe(filename):
    """
    Read PCAPNG, converts to PCAP, and produce Pandas dataframe
    using dpkt (that is ONLY in python2).
    dpkt is faster than using tshark and python-scapy
    dpkt is slower than tcpdump but easier to get specific values of the pcap
    """
    
    #'1. Converting pcapng to pcap.'
    get_ipython().system('editcap -F libpcap -T ether $filename temp.pcap')
    
    #'2. Converting pcap to pandas dataframe.'
    df = pcap2dataframe ('temp.pcap')
    
    return df

