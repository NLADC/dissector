
# coding: utf-8

# In[ ]:


import subprocess


# In[1]:


def input2filetype (input_file):
    
    file_info, error = subprocess.Popen(["file",input_file], stdout=subprocess.PIPE).communicate()
    
    if file_info.decode("utf-8").split()[1] == 'tcpdump':
        return "pcap"

    if file_info.decode("utf-8").split()[1] == 'pcap-ng':
        return "pcapng"

    elif file_info.decode("utf-8").split()[1] == 'data' and ('nfdump' in file_info or 'nfcapd' in file_info):
        return "nfdump"
    
    else:
        print("SORRY! We neither developed the parser for this type of file (YET) OR we recognized the format of your file!")

