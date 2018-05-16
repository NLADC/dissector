
# coding: utf-8

# In[3]:


def check_filetype (file_path):
    """<short_description>
    <more description>
    <more description>
    
    :param <train_data>: <meaning>
    :return
    """
    
    file_info = get_ipython().getoutput('file $file_path')

    if file_info[0].split()[1] == 'tcpdump':
        return 'pcap'

    elif file_info[0].split()[1] == 'pcap-ng':
        return 'pcapng'
    
    elif 'sflow' in file_path:
        return 'sflow'
        
    elif file_info[0].split()[1] == 'data' and ('nfdump' in file_path or 'nfcapd' in file_path):
        return 'nfdump'

