
# coding: utf-8

# In[1]:


import subprocess
from pcap2dataframe import *
#from pcapng2datafame import *
#from sflow2dataframe import *
from netflow2dataframe import *


# In[2]:


def input2dataframe (input_file):
    """<short_description>
    <more description>
    <more description>
    
    :param <train_data>: <meaning>
    :return
    """
    
    file_info, error = subprocess.Popen(["file",input_file], stdout=subprocess.PIPE).communicate()

    if file_info.split()[1] == 'tcpdump':
        return pcap2dataframe(input_file)

    elif file_info.split()[1] == 'pcap-ng':
        return pcapng2dataframe(input_file)
    
    #elif 'sflow' in file_path:
    elif 'sflow' in file_info:
        return sflow2dataframe(input_file)
 
    #elif file_info.split()[1] == 'data' and ('nfdump' in file_path or 'nfcapd' in file_path):
    elif file_info.split()[1] == 'data' and ('nfdump' in file_info or 'nfcapd' in file_info):
        return netflow2dataframe(input_file)
    
    else:
        print "SORRY! We neither developed the parser for this type of file (YET) OR we recognized the format of your file!"
        
    

