
# coding: utf-8

# In[1]:


import pandas

def replace_ip(df,dst_ip):
    df.replace(
        to_replace=dst_ip,
        value='8.8.8.8', #any value you wish to replace it to
        inplace=True,
        limit=None,
        regex=False, 
        method='pad',
        axis=None)
    
    return
    




