
# coding: utf-8

# In[1]:


from functions.pcap2dataframe_tshark import *
from functions.netflow2dataframe import *


# In[24]:


def input2dataframe (input_file, file_type):
    if file_type == "pcap" or file_type == "pcapng": 
        return pcap2dataframe_tshark(input_file)

    elif file_type == "nfdump": 
        return netflow2dataframe(input_file)
    
    else:
        print("Problem in the input2dataframe") 

