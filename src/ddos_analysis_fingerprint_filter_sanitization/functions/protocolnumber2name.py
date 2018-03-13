
# coding: utf-8

# In[6]:


import pandas as pd

df_ip_proto_name = pd.read_csv('functions/ip_proto_name.txt',delimiter=",", names=['proto_num','proto_name'])

def protocolnumber2name(ip_proto_number):
    try:
        return df_ip_proto_name[df_ip_proto_name['proto_num']==ip_proto_number]['proto_name'].values[0]
    except:
        return str(ip_proto_number)

