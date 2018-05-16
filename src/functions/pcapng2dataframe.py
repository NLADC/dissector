
# coding: utf-8

# In[3]:


import subprocess
from pcap2dataframe import *


# In[14]:


def pcapng2pcap2dataframe(file_name):
    """
    Read PCAPNG, converts to PCAP, and produce Pandas dataframe
    using dpkt (that is ONLY in python2).
    dpkt is faster than using tshark and python-scapy
    dpkt is slower than tcpdump but easier to get specific values of the pcap
    """
    print file_name
    
    #'1. Converting pcapng to pcap.'
    p = subprocess.Popen(["editcap -F libpcap -T ether " + file_name + " temp.pcap"], shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()
    
    #'2. Converting pcap to pandas dataframe.'
    df = pcap2dataframe ('temp.pcap')
    
    p = subprocess.Popen(["rm temp.pcap"], shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()
    
    return df

