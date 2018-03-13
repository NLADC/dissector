
# coding: utf-8

# In[1]:


import pandas as pd

df_port_name = pd.read_csv('functions/port_name.txt',delimiter=",", names=['port_num','port_name'])

def portnumber2name(port_number):
    try:
        return df_port_name[df_port_name['port_num']==port_number]['port_name'].values[0]+" service port"
    except:
        return "port "+str(int(port_number))

