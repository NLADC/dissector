
# coding: utf-8

# In[13]:


from functions.input2dataframe import *
from functions.analyse_df_pcap import *
from functions.analyse_df_nfdump import *
from functions.nfdump_filter import *
from functions.tcpdump_filter import *
from functions.replace_dst import *



# In[3]:


input_file = "input/20170522_16_55.pcap"


# In[10]:


df = input2dataframe(input_file)
all_patterns = analyse_df_pcap(df)
#all_patterns = analyse_df_nfdump(df)
        
vector_ids = []
for pattern in all_patterns["patterns"]:
    vector_ids.append(tcpdump_filter(input_file, pattern))


# In[15]:


input_pcap = "output/attack_vector_" + vector_ids[0] + ".pcap"
replace_ipinpcap(input_pcap,all_patterns["dst_ip"])

