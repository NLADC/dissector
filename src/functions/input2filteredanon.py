
# coding: utf-8

# In[1]:


from functions.nfdump_filter_anon import *
from functions.tshark_filter_anon import *


# In[3]:


def input2fileredanon(input_file, file_type, victim_ip, fingerprint):
    if file_type == "nfdump":
        nfdump_filter_anon(input_file,  fingerprint, victim_ip)
    elif file_type == "pcap" or file_type == "pcapng":
        tshark_filter_anon(input_file, fingerprint, victim_ip,file_type)
    else:
        print ("Problem at input2filteredanon!")

