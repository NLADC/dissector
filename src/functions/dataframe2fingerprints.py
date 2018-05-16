
# coding: utf-8

# In[ ]:


from functions.nfdump_filter_anon import *
from functions.analyse_df_pcap_tshark import *


# In[ ]:


def dataframe2fingerprints(df, file_type, debug):
    #FOR NETFLOW, IPFIX
    if file_type == "nfdump":
        return analyse_df_nfdump(df, debug)
              
    #FOR PCAP or PCAPNG
    elif file_type == "pcap" or file_type == "pcapng":
        return analyse_df_pcap_tshark(df, debug)        

    else:
        print("Problem in dataframe2fingerprints")

